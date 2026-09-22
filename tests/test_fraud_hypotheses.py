"""The discrimination the whole investigation layer exists for.

An account takeover and an authorised push payment scam look nearly identical to a risk score:
same customer, same amount, same brand-new payee, same jump above the normal range. They call for
opposite responses - lock the account versus phone the customer - so the tests below hold
everything else constant and change only the evidence that should decide it.
"""
from datetime import timedelta

import pytest

from app.fraud_investigation import agents, pipeline
from tests import fraud_factory as factory


def investigate(db, transaction):
    """Run the full agent pipeline over one transaction and return the context."""
    assessment = pipeline.assess(db, transaction)
    alert = pipeline.create_alert(db, assessment)
    db.commit()
    ctx = pipeline.build_context(db, alert, assessment)
    agents.run_agents(ctx)
    db.commit()
    return ctx


def support_for(ctx, hypothesis_id):
    ranked = ctx.section_data("hypothesis")["ranked"]
    return next(item["support"] for item in ranked if item["id"] == hypothesis_id)


def fired_rules(ctx) -> set:
    return {hit["id"] for hit in ctx.rule_hits}


@pytest.fixture()
def takeover(db_session):
    factory.baseline(db_session)
    return investigate(db_session, factory.takeover_transaction(db_session))


@pytest.fixture()
def scam(db_session):
    factory.baseline(db_session)
    return investigate(db_session, factory.scam_transaction(db_session))


def test_takeover_is_diagnosed_as_takeover(takeover):
    assert takeover.section_data("hypothesis")["fraud_type"] == "account_takeover"


def test_scam_is_not_diagnosed_as_takeover(scam):
    assert scam.section_data("hypothesis")["fraud_type"] == "authorised_push_payment_scam"


def test_own_device_and_location_rule_out_takeover(scam):
    assert support_for(scam, "account_takeover") == 0.0


def test_credential_change_rules_out_a_scam(takeover):
    assert support_for(takeover, "authorised_push_payment_scam") == 0.0


def test_takeover_is_caught_by_the_rules_alone(takeover):
    """Defence in depth: no trained model is loaded here, and it is still caught."""
    assert takeover.components["ml"] is None
    assert takeover.components["rules"] > 0
    assert takeover.scoring["risk_score"] >= 50
    assert takeover.alert.triage_decision == "investigate"


def test_scam_is_caught_by_the_rules_alone(scam):
    """R014 gives the scam typology a deterministic handle, so it no longer needs the model.

    Before R014 existed, every rule stayed silent on this transaction - the customer's own device,
    own city and untouched credentials are exactly what the other rules look for the absence of -
    and with no trained model it scored low enough to auto-close.
    """
    assert scam.components["ml"] is None
    assert fired_rules(scam) == {"R014"}
    assert scam.scoring["risk_score"] >= 30
    assert scam.alert.triage_decision == "investigate"


def test_the_scam_rule_asks_for_a_look_it_does_not_decide(scam):
    """R014 must surface a transaction for review, never escalate it to high risk on its own."""
    assert scam.scoring["risk_level"] == "medium"
    assert all(hit["floor"] == 0.0 for hit in scam.rule_hits)


def test_the_behaviour_detector_also_sees_the_scam(scam):
    """The rule is not carrying this alone; the deviation is measured and material."""
    assert scam.components["behavior"] >= 0.3
    assert scam.section_data("behavior")["deviation"]["level"] in ("medium", "high")


# --- R014: large first payment to a brand-new beneficiary --------------------------------------


def test_large_first_payment_to_a_new_payee_raises_the_scam_hypothesis(scam):
    """The rule and the hypothesis agree: this is what an APP scam looks like."""
    assert "R014" in fired_rules(scam)
    assert scam.section_data("hypothesis")["fraud_type"] == "authorised_push_payment_scam"


def test_a_normal_sized_first_payment_to_a_new_payee_does_not_fire_the_rule(db_session):
    """Most first payments to a new payee are somebody paying a new landlord."""
    factory.baseline(db_session)
    factory.beneficiary(db_session, "BEN-09010", "New Landlord")
    factory.event(db_session, "CUST-0001", "beneficiary_added", factory.BASE - timedelta(hours=4))
    modest = factory.transaction(
        db_session, "TX-900020", "CUST-0001", amount=6000.0,
        when=factory.BASE - timedelta(hours=3), counterparty_id="BEN-09010",
    )
    ctx = investigate(db_session, modest)

    assert "R014" not in fired_rules(ctx)
    assert ctx.section_data("hypothesis")["fraud_type"] is None
    assert ctx.alert.triage_decision == "auto_close"


def test_a_large_payment_to_a_known_payee_does_not_fire_the_rule(db_session):
    """Size alone is not the signal - the customer has paid this account before."""
    factory.baseline(db_session)
    known = factory.transaction(
        db_session, "TX-900021", "CUST-0001", amount=90000.0,
        when=factory.BASE - timedelta(hours=3), counterparty_id="BEN-00001",
    )
    ctx = investigate(db_session, known)

    assert "R014" not in fired_rules(ctx)
    assert support_for(ctx, "authorised_push_payment_scam") == 0.0


def test_takeover_recommends_locking_down_credentials(takeover):
    actions = {item["action"] for item in takeover.section_data("recommendation")["actions"]}
    assert {"force_credential_reset", "hold_transaction"} <= actions


def test_scam_does_not_recommend_a_credential_reset(scam):
    actions = {item["action"] for item in scam.section_data("recommendation")["actions"]}
    assert "force_credential_reset" not in actions
    assert "contact_customer" in actions


def test_hypothesis_explains_both_sides(takeover):
    top = takeover.section_data("hypothesis")["ranked"][0]
    assert top["matched"], "a diagnosis must say what supported it"
    assert "missing" in top, "and what it would have expected to see"


def test_weak_evidence_names_no_typology(db_session):
    """An ordinary payment slightly above normal is not given a fraud typology."""
    factory.baseline(db_session)
    ordinary = factory.transaction(
        db_session, "TX-900003", "CUST-0001", amount=9000.0,
        when=factory.BASE - timedelta(hours=3), counterparty_id="BEN-00001",
    )
    ctx = investigate(db_session, ordinary)
    assert ctx.section_data("hypothesis")["fraud_type"] is None


def test_scam_needs_its_distinguishing_core_not_just_an_absence_of_alarm(db_session):
    """A payment to a *known* payee is not a scam however normal everything else looks.

    Three of the scam indicators (own device, usual location, no credential change) are equally
    true of every ordinary payment, so without a required core they alone would clear the
    threshold and label routine traffic as fraud.
    """
    factory.baseline(db_session)
    known_payee = factory.transaction(
        db_session, "TX-900004", "CUST-0001", amount=90000.0,
        when=factory.BASE - timedelta(hours=3), counterparty_id="BEN-00001",
    )
    ctx = investigate(db_session, known_payee)
    ranked = {item["id"]: item for item in ctx.section_data("hypothesis")["ranked"]}
    assert ranked["authorised_push_payment_scam"]["support"] == 0.0
    assert ranked["authorised_push_payment_scam"]["unmet_requirements"] == ["new_beneficiary"]
