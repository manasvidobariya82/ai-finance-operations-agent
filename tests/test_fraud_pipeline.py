"""Detection pipeline: triage, alert creation, case linking, and the point-in-time guarantee."""
from datetime import timedelta

import pytest

from app.fraud_investigation import models, pipeline
from app.fraud_investigation.detection.rules import rule_score
from app.fraud_investigation.history import InMemoryNetworkIndex, SqlNetworkLookup, load_all_histories
from app.fraud_investigation.scoring import combine, risk_level, triage
from tests import fraud_factory as factory


# --- Score combination ----------------------------------------------------------------------------


def test_missing_detectors_are_renormalised_not_treated_as_zero():
    """A detector that could not run must not be scored as if it had said "no risk".

    With no trained model, the rule engine's 0.2 weight has to carry proportionally more of the
    average, otherwise every transaction scores near zero until a model exists.
    """
    with_model = combine({"ml": 0.0, "rules": 0.8, "graph": None, "behavior": 0.0, "anomaly": 0.0}, [])
    without_model = combine({"ml": None, "rules": 0.8, "graph": None, "behavior": 0.0, "anomaly": None}, [])

    assert without_model["weighted_average"] > with_model["weighted_average"] * 2
    for result in (with_model, without_model):
        assert sum(item["weight"] for item in result["breakdown"]) == pytest.approx(1.0, abs=0.01)
    assert {item["component"] for item in without_model["breakdown"]} == {"rules", "behavior"}


def test_a_confident_detector_is_not_averaged_away():
    result = combine({"ml": 0.95, "rules": 0.0, "graph": 0.0, "behavior": 0.0, "anomaly": 0.0}, [])
    assert result["method"] == "strong_ml"
    assert result["risk_score"] >= 80


def test_a_critical_rule_puts_a_floor_under_the_score():
    hits = [{"id": "R004", "name": "Sanctions", "severity": "critical", "weight": 0.95, "floor": 0.9}]
    result = combine({"ml": 0.0, "rules": rule_score(hits), "graph": 0.0, "behavior": 0.0, "anomaly": 0.0}, hits)
    assert result["risk_score"] >= 90
    assert result["method"] == "floor_R004"


def test_every_point_of_the_score_is_attributable():
    result = combine({"ml": 0.6, "rules": 0.4, "graph": 0.2, "behavior": 0.3, "anomaly": 0.1}, [])
    assert sum(item["weight"] for item in result["breakdown"]) == pytest.approx(1.0, abs=0.01)
    assert sum(item["contribution"] for item in result["breakdown"]) == pytest.approx(
        result["weighted_average"], abs=0.01
    )


def test_triage_sends_only_low_risk_to_auto_close():
    assert triage(risk_level(5)) == "auto_close"
    assert triage(risk_level(50)) == "investigate"
    assert triage(risk_level(95)) == "investigate"


# --- Alerts and cases -----------------------------------------------------------------------------


def test_low_risk_is_alerted_and_auto_closed_not_discarded(db_session):
    factory.baseline(db_session)
    ordinary = factory.transaction(
        db_session, "TX-900010", "CUST-0001", amount=6000.0,
        when=factory.BASE - timedelta(hours=2), counterparty_id="BEN-00001",
    )
    alert, case = pipeline.process_transaction(db_session, ordinary)

    assert alert.risk_level == "low"
    assert alert.triage_decision == "auto_close"
    assert alert.status == "auto_closed"
    assert case is None
    # The alert still exists: it is the denominator for measuring precision later.
    assert db_session.query(models.FraudAlert).count() == 1


def test_high_risk_opens_a_case_with_a_full_case_file(db_session):
    factory.baseline(db_session)
    alert, case = pipeline.process_transaction(db_session, factory.takeover_transaction(db_session))

    assert alert.triage_decision == "investigate"
    assert case is not None
    assert case.status == "open"
    assert case.priority == "high"
    assert alert.case_id == case.id
    assert case.case_file["agents_run"] == [
        "evidence", "behavior", "intel", "network", "history", "hypothesis", "recommendation", "narrative",
    ]
    assert case.summary and case.case_file["headline"]


def test_a_transaction_is_never_scored_twice(db_session):
    factory.baseline(db_session)
    txn = factory.takeover_transaction(db_session)
    pipeline.process_transaction(db_session, txn)
    with pytest.raises(pipeline.AlreadyScored):
        pipeline.process_transaction(db_session, txn)


def test_a_second_alert_in_the_window_joins_the_open_case(db_session):
    """An attack in progress is one investigation, not one per payment."""
    factory.baseline(db_session)
    first = factory.takeover_transaction(db_session)
    _, case = pipeline.process_transaction(db_session, first)

    followup = factory.transaction(
        db_session, "TX-900011", "CUST-0001", amount=85000.0,
        when=first.timestamp + timedelta(hours=1), counterparty_id="BEN-09001",
        device_id="DEV-attacker1", ip_address="203.0.113.77", city="Amsterdam", country="NL",
    )
    alert2, case2 = pipeline.process_transaction(db_session, followup)

    assert case2.id == case.id
    assert alert2.status == "linked_to_case"
    assert sorted(case2.alert_ids) == sorted([case.alert_id, alert2.id])
    assert db_session.query(models.FraudCase).count() == 1


def test_case_linking_uses_transaction_time_not_scoring_time(db_session):
    """Backfilling stamps every alert with the same wall clock; months apart must stay separate."""
    factory.baseline(db_session)
    old = factory.transaction(
        db_session, "TX-900012", "CUST-0001", amount=90000.0,
        when=factory.BASE - timedelta(days=40), counterparty_id="BEN-09005",
        device_id="DEV-attacker9", ip_address="203.0.113.90", city="Amsterdam", country="NL",
    )
    factory.beneficiary(db_session, "BEN-09005", "Old Mule")
    recent = factory.takeover_transaction(db_session)

    _, case_recent = pipeline.process_transaction(db_session, recent)
    _, case_old = pipeline.process_transaction(db_session, old)

    assert case_recent is not None and case_old is not None
    assert case_old.id != case_recent.id


# --- Point-in-time guarantee -----------------------------------------------------------------------


def test_the_two_network_lookups_agree(db_session):
    """The training and serving paths share the feature code, so their lookups must agree.

    `history.py` keeps two implementations - an in-memory index for bulk work and indexed SQL for
    serving - precisely so features are computed identically in both. If they drift, a model trains
    on numbers it will never see in production.
    """
    factory.baseline(db_session)
    factory.takeover_transaction(db_session)
    histories, memory_index = load_all_histories(db_session)
    sql_lookup = SqlNetworkLookup(db_session)

    checked = 0
    for history in histories.values():
        for txn in history.transactions:
            for name in ("device_customers", "ip_customers"):
                key = txn.device_id if name == "device_customers" else txn.ip_address
                assert getattr(memory_index, name)(key, txn.timestamp, txn.customer_id) == getattr(
                    sql_lookup, name
                )(key, txn.timestamp, txn.customer_id), f"{name} disagreed on {txn.id}"
            if txn.counterparty_kind == "beneficiary":
                assert memory_index.counterparty_senders(
                    txn.counterparty_id, txn.timestamp, txn.customer_id
                ) == sql_lookup.counterparty_senders(txn.counterparty_id, txn.timestamp, txn.customer_id)
            checked += 1
    assert checked > 10


def test_features_never_see_the_transaction_being_scored(db_session):
    """A transaction must not count itself in its own velocity or history features."""
    factory.baseline(db_session)
    txn = factory.transaction(
        db_session, "TX-900013", "CUST-0001", amount=7000.0,
        when=factory.BASE - timedelta(hours=1), counterparty_id="BEN-00001",
    )
    assessment = pipeline.assess(db_session, txn)
    before = [t for t in assessment.history.transactions if t.timestamp < txn.timestamp]
    assert assessment.features.values["txn_count_30d"] <= len(before)
    assert assessment.features.context["prior_txn_count_90d"] == len(
        [t for t in before if t.timestamp >= txn.timestamp - timedelta(days=90)]
    )


def test_an_isolated_index_counts_only_customers_who_came_before():
    index = InMemoryNetworkIndex()
    base = factory.BASE
    for offset, customer in enumerate(["CUST-A", "CUST-B", "CUST-C"]):
        index.add("device", "DEV-shared", customer, base + timedelta(days=offset))
    assert index.device_customers("DEV-shared", base + timedelta(days=1), "CUST-A") == 0
    assert index.device_customers("DEV-shared", base + timedelta(days=5), "CUST-A") == 2
