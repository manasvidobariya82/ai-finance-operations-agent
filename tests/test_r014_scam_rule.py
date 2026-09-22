"""R014 - large first payment to a brand-new beneficiary - and the evidence behind its threshold.

The first half pins the rule's behaviour on hand-made transactions, one fact changed at a time. The
second half runs the threshold evaluation over a generated bank with labelled APP scams and their
legitimate look-alikes, and checks the claims the rule's design rests on: it catches scams nothing
else catches, it moves them into review without deciding anything, and no threshold that still
catches scams stops it flagging the genuine payments that look exactly like them.

None of this changes R014: the evaluation uses a copy of its condition, checked against the rule.
"""
import statistics
from datetime import timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import Base
from app.fraud_investigation import evaluation, models, pipeline, synthetic
from app.fraud_investigation.detection.rules import RULES, rule_score
from app.fraud_investigation.history import load_all_histories
from app.fraud_investigation.intel import transaction_intel
from app.fraud_investigation.scoring import combine
from tests import fraud_factory as factory

WHEN = factory.BASE - timedelta(hours=3)
RULE = {rule.id: rule for rule in RULES}


def hit(rule_id: str) -> dict:
    rule = RULE[rule_id]
    return {"id": rule.id, "name": rule.name, "severity": rule.severity, "weight": rule.weight, "floor": rule.floor}


def customer_average(db, customer_id: str = "CUST-0001") -> float:
    """The 90-day average `amount_vs_customer_avg` divides by, as of WHEN."""
    amounts = db.query(models.Transaction.amount).filter(
        models.Transaction.customer_id == customer_id,
        models.Transaction.timestamp >= WHEN - timedelta(days=90),
        models.Transaction.timestamp < WHEN,
    )
    return statistics.fmean(amount for (amount,) in amounts)


def transfer_at(db, multiple: float, counterparty_id: str, txn_id: str = "TX-900100", **kwargs):
    """A transfer at an exact multiple of the customer's own average."""
    amount = round(multiple * customer_average(db), 2)
    return factory.transaction(db, txn_id, "CUST-0001", amount=amount, when=WHEN, counterparty_id=counterparty_id, **kwargs)


def new_payee(db, ben_id: str = "BEN-09100", name: str = "SafeVault Account Services"):
    """A payee added from the customer's own phone minutes before the payment - the scam set-up."""
    factory.beneficiary(db, ben_id, name)
    factory.event(db, "CUST-0001", "login_success", WHEN - timedelta(minutes=20))
    factory.event(db, "CUST-0001", "beneficiary_added", WHEN - timedelta(minutes=8))
    return ben_id


def fired(assessment) -> set:
    return {h["id"] for h in assessment.rule_hits}


# --- Regression: when R014 fires -------------------------------------------------------------------


@pytest.mark.parametrize("multiple", [4.05, 6.0, 8.0])
def test_an_app_scam_at_or_above_4x_fires_r014_and_goes_to_review(db_session, multiple):
    factory.baseline(db_session)
    scam = transfer_at(db_session, multiple, new_payee(db_session))
    assessment = pipeline.assess(db_session, scam)

    assert assessment.features.values["amount_vs_customer_avg"] == pytest.approx(multiple, rel=1e-3)
    assert fired(assessment) == {"R014"}
    assert assessment.risk_level == "medium"


def test_the_same_payment_to_an_existing_beneficiary_does_not_fire(db_session):
    """Identical in every way except the customer has paid this account before."""
    factory.baseline(db_session)
    factory.event(db_session, "CUST-0001", "login_success", WHEN - timedelta(minutes=20))
    known = transfer_at(db_session, 6.0, "BEN-00001")
    assessment = pipeline.assess(db_session, known)

    assert assessment.features.values["recipient_is_new"] == 0
    assert "R014" not in fired(assessment)


def test_a_new_beneficiary_just_under_4x_does_not_fire(db_session):
    factory.baseline(db_session)
    modest = transfer_at(db_session, 3.95, new_payee(db_session))
    assessment = pipeline.assess(db_session, modest)

    assert assessment.features.values["amount_vs_customer_avg"] < 4
    assert "R014" not in fired(assessment)
    assert assessment.risk_level == "low"


def test_a_customer_with_no_baseline_cannot_fire_it(db_session):
    """Without three prior transactions the multiple is undefined, so a new account never fires."""
    factory.customer(db_session, opened_days_ago=3)
    factory.beneficiary(db_session, "BEN-00001", "Sunil Kumar")
    for day in (2, 1):
        factory.transaction(
            db_session, f"TX-00000{day}", "CUST-0001", amount=500.0, when=WHEN - timedelta(days=day), counterparty_id="BEN-00001",
        )
    huge = transfer_at(db_session, 500.0, new_payee(db_session))
    assessment = pipeline.assess(db_session, huge)

    assert assessment.features.values["has_history"] == 0
    assert "R014" not in fired(assessment)


def test_a_large_card_purchase_is_not_a_first_payment(db_session):
    """A big one-off purchase is a legitimate large payment of another kind; R014 reads transfers only."""
    factory.baseline(db_session)
    factory.merchant(db_session, "MER-002", "Voltline Electronics", "electronics")
    amount = round(6.0 * customer_average(db_session), 2)
    purchase = factory.transaction(
        db_session, "TX-900101", "CUST-0001", amount=amount, when=WHEN, counterparty_id="MER-002",
        txn_type="card_purchase", payment_method="card", channel="mobile_app",
    )
    assert "R014" not in fired(pipeline.assess(db_session, purchase))


def test_a_genuine_large_first_payment_is_reviewed_not_escalated(db_session):
    """The accepted cost of the rule: a real rental deposit looks exactly like a scam to it.

    It is sent to review at medium risk - someone asks the customer - and nothing more.
    """
    factory.baseline(db_session)
    deposit = transfer_at(db_session, 6.0, new_payee(db_session, name="Sunrise Residency Rentals"))
    alert, case = pipeline.process_transaction(db_session, deposit)

    assert "R014" in {h["id"] for h in alert.rule_hits}
    assert alert.risk_level == "medium"
    assert alert.triage_decision == "investigate"
    assert case is not None and case.priority == "medium"


# --- Regression: what R014 can and cannot do to a score --------------------------------------------


@pytest.mark.parametrize("with_model", [False, True], ids=["no-model", "model-says-zero"])
def test_r014_alone_cannot_reach_high_risk(with_model):
    hits = [hit("R014")]
    zero = 0.0 if with_model else None
    result = combine({"ml": zero, "rules": rule_score(hits), "graph": zero, "behavior": 0.0, "anomaly": zero}, hits)

    assert RULE["R014"].floor == 0.0
    assert result["risk_level"] == "medium"
    assert result["risk_score"] < settings.fraud_high_risk_min


def test_r014_with_other_risk_signals_can_tip_a_transaction_into_high_risk():
    """It asks for a look on its own, and it still counts when other evidence is present."""
    others = [hit("R003"), hit("R006"), hit("R013")]
    components = {"ml": None, "rules": 0.0, "graph": None, "behavior": 0.0, "anomaly": None}

    without = combine({**components, "rules": rule_score(others)}, others)
    with_r014 = combine({**components, "rules": rule_score(others + [hit("R014")])}, others + [hit("R014")])

    assert without["risk_level"] == "medium"
    assert with_r014["risk_level"] == "high"


# --- Threshold evaluation over a labelled population --------------------------------------------

CUSTOMERS = 120  # 10 APP scams, 10 of each large look-alike, 5 supplier payments


@pytest.fixture(scope="module")
def bank():
    """One generated bank for the whole module; every test below only reads it."""
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(bind=engine)
    db = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    synthetic.generate(db, synthetic.SyntheticConfig(customers=CUSTOMERS, seed=7, end=evaluation.EVALUATION_END))
    try:
        yield db
    finally:
        db.close()


@pytest.fixture(scope="module")
def population(bank):
    return evaluation.build_population(bank)


@pytest.fixture(scope="module")
def result(bank, population):
    return evaluation.evaluate(bank, rows=population)


def rows_for(population, scenario):
    return [row for row in population if row.scenario == scenario]


def test_the_generator_injects_labelled_app_scams(population):
    scams = rows_for(population, synthetic.APP_SCAM)
    assert len(scams) == CUSTOMERS // 12
    assert all(row.is_fraud for row in scams)


def test_the_scams_look_like_app_scams_not_takeovers(population):
    """Established customer, own device, home city, no credential change, new payee, 4-8x."""
    for row in rows_for(population, synthetic.APP_SCAM):
        f = row.features
        assert 4.0 <= f["amount_vs_customer_avg"] < 8.5, row.transaction_id
        assert f["has_history"] == 1 and f["recipient_is_new"] == 1 and f["is_transfer"] == 1
        assert f["new_device"] == 0 and f["foreign_country"] == 0 and f["distance_from_usual_km"] == 0
        assert f["password_reset_24h"] == 0 and f["mfa_changed_24h"] == 0 and f["failed_logins_24h"] < 3


def test_no_other_rule_sees_the_scams(population):
    """Which is why R014 exists: every other rule looks for something a scam does not have."""
    assert all(row.other_hits == [] for row in rows_for(population, synthetic.APP_SCAM))


def test_every_hard_negative_cohort_is_present_and_legitimate(population):
    for scenario in evaluation.HARD_NEGATIVES:
        cohort = rows_for(population, scenario)
        assert cohort, f"no {scenario} transactions generated"
        assert not any(row.is_fraud for row in cohort)


def test_each_hard_negative_probes_the_part_of_the_rule_it_is_named_for(population):
    for row in rows_for(population, "legit_large_known_payee"):
        assert row.features["amount_vs_customer_avg"] >= 4
        assert not evaluation.r014_fires(row.features, 3.0), "a payee paid before is never new"
    for scenario in ("legit_large_new_payee", "legit_business_supplier"):
        for row in rows_for(population, scenario):
            assert evaluation.r014_fires(row.features, evaluation.SHIPPED_THRESHOLD), row.transaction_id


def test_the_threshold_copy_agrees_with_the_shipped_rule(result, population):
    assert any(row.shipped_r014 for row in population)
    assert result.shipped_rule_disagreements == []


def test_the_warm_up_removes_payees_that_only_look_new_because_the_data_starts(bank, population, result):
    """Early in the window, the first payment in the data to a years-old payee reads as a first
    payment ever. Scoring from day 30 drops those without losing a single labelled transaction."""
    cold = evaluation.evaluate(bank, rows=population, warmup_days=0)

    def ordinary(evaluated):
        return evaluated.at(evaluation.SHIPPED_THRESHOLD)["false_positives_by_source"].get(evaluation.ORDINARY, 0)

    assert result.population["app_scams"] == cold.population["app_scams"]
    assert result.population["hard_negatives"]["legit_large_new_payee"] == cold.population["hard_negatives"]["legit_large_new_payee"]
    assert ordinary(result) < ordinary(cold)


def test_the_cached_intel_lookup_agrees_with_transaction_intel(bank, population):
    lookup = evaluation.IntelLookup(bank)
    histories, _ = load_all_histories(bank)
    records = {txn.id: txn for history in histories.values() for txn in history.transactions}
    sample = population[::40] + [row for row in population if row.is_fraud]
    for row in sample:
        reference = transaction_intel(bank, bank.get(models.Transaction, row.transaction_id))
        cached = lookup(records[row.transaction_id])
        assert cached.ip == reference.ip
        assert [h.to_dict() for h in cached.watchlist_hits] == [h.to_dict() for h in reference.watchlist_hits]


def test_at_the_shipped_threshold_every_scam_is_caught_by_r014_alone(result):
    shipped = result.at(evaluation.SHIPPED_THRESHOLD)
    scams = result.population["app_scams"]
    assert shipped["recall"] == 1.0
    assert shipped["app_scams_only_r014_catches"] == scams
    # Before R014 each of them was auto-closed; it is what puts them in front of an analyst.
    assert shipped["moved_to_review_by_label"]["app_scam"] == scams


def test_the_threshold_trades_scams_caught_for_false_positives(result):
    results = result.thresholds
    for lower, higher in zip(results, results[1:]):
        assert higher["fired"] <= lower["fired"]
        assert higher["app_scams_caught"] <= lower["app_scams_caught"]
        assert higher["false_positives"] <= lower["false_positives"]
    assert result.at(6.0)["recall"] < result.at(evaluation.SHIPPED_THRESHOLD)["recall"]
    assert result.at(6.0)["false_positives"] < result.at(3.0)["false_positives"]


def test_genuine_large_first_payments_are_flagged_at_every_threshold_that_catches_scams(result):
    """The irreducible cost: the rule cannot tell a rental deposit from a scam, only a person can."""
    for item in result.thresholds:
        if item["app_scams_caught"]:
            assert item["false_positives_by_source"].get("legit_large_new_payee", 0) > 0


def test_r014_never_puts_a_transaction_in_high_risk_on_its_own(result):
    for item in result.thresholds:
        assert item["high_risk_on_r014_alone"] == 0


def test_cases_follow_the_pipelines_48_hour_linking():
    def row(txn_id, customer, hours):
        return evaluation.Row(txn_id, customer, factory.BASE + timedelta(hours=hours), "ordinary", False, {}, [], False, 0.0)

    assert evaluation.count_cases([row("a", "C1", 0), row("b", "C1", 47), row("c", "C2", 1)]) == 2
    assert evaluation.count_cases([row("a", "C1", 0), row("b", "C1", 49)]) == 2


def test_the_report_covers_every_threshold(result):
    report = evaluation.format_report(result)
    for label in ("3x", "4x (shipped)", "5x", "6x"):
        assert label in report
    for section in ("## Detection", "## Workload and score", "## Where the false positives come from", "## Overlap with the other rules"):
        assert section in report
    assert "WARNING" not in report
