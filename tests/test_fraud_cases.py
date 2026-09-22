"""Case workflow, the feedback loop, and the tamper-evident audit trail."""
import pytest

from app.fraud_investigation import audit, cases, models, pipeline, training
from tests import fraud_factory as factory


@pytest.fixture()
def open_case(db_session):
    factory.baseline(db_session)
    _, case = pipeline.process_transaction(db_session, factory.takeover_transaction(db_session))
    return case


# --- Decisions ------------------------------------------------------------------------------------


def test_confirming_fraud_labels_the_transaction_for_retraining(db_session, open_case):
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya")
    assert db_session.get(models.Transaction, open_case.transaction_id).is_fraud is True
    assert training.feedback_labels(db_session) == {open_case.transaction_id: True}


def test_a_false_positive_is_labelled_too(db_session, open_case):
    cases.decide(db_session, open_case.id, "false_positive", "priya")
    assert db_session.get(models.Transaction, open_case.transaction_id).is_fraud is False
    assert training.feedback_labels(db_session) == {open_case.transaction_id: False}


def test_inconclusive_teaches_the_model_nothing(db_session, open_case):
    """"We could not tell" is not evidence the payment was fine."""
    cases.decide(db_session, open_case.id, "inconclusive", "priya")
    assert db_session.get(models.Transaction, open_case.transaction_id).is_fraud is None
    assert training.feedback_labels(db_session) == {}
    feedback = db_session.query(models.FraudFeedback).one()
    assert feedback.analyst_decision == "inconclusive"
    assert feedback.label is None


def test_only_the_actions_the_analyst_confirmed_are_applied(db_session, open_case):
    recommended = {item["action"] for item in open_case.case_file["recommended_actions"]}
    assert "block_beneficiary" in recommended, "the fixture should recommend more than we confirm"

    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya", actions_taken=["hold_transaction"])

    assert db_session.get(models.Transaction, open_case.transaction_id).status == "held"
    beneficiary = db_session.get(models.Counterparty, "BEN-09001")
    assert beneficiary.status == "active", "an action that was not confirmed must not be applied"


def test_actions_outside_this_system_are_recorded_but_not_claimed_as_done(db_session, open_case):
    case = cases.decide(
        db_session, open_case.id, "fraud_confirmed", "priya", actions_taken=["contact_customer", "hold_transaction"]
    )
    applied = {item["action"]: item for item in case.actions}
    assert applied["hold_transaction"]["executed_here"] is True
    assert applied["contact_customer"]["executed_here"] is False


def test_a_case_cannot_be_decided_twice(db_session, open_case):
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya")
    with pytest.raises(cases.InvalidTransition):
        cases.decide(db_session, open_case.id, "false_positive", "raj")


def test_an_unknown_decision_is_rejected(db_session, open_case):
    with pytest.raises(cases.InvalidTransition):
        cases.decide(db_session, open_case.id, "probably_fine", "priya")


def test_closing_a_case_closes_every_alert_folded_into_it(db_session, open_case):
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya")
    for alert_id in open_case.alert_ids:
        assert db_session.get(models.FraudAlert, alert_id).status == "case_closed"


def test_confirmed_fraud_is_counted_against_the_customer(db_session, open_case):
    before = db_session.get(models.Customer, open_case.customer_id).prior_fraud_cases or 0
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya")
    assert db_session.get(models.Customer, open_case.customer_id).prior_fraud_cases == before + 1


def test_escalation_raises_priority_and_leaves_a_note(db_session, open_case):
    case = cases.escalate(db_session, open_case.id, "priya", "Customer unreachable, funds still moving")
    assert case.status == "escalated"
    assert case.priority == "high"
    assert "Customer unreachable" in cases.notes(db_session, case.id)[-1].body


def test_feedback_summary_measures_precision(db_session, open_case):
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya")
    summary = cases.feedback_summary(db_session)
    assert summary["labelled"] == 1
    assert summary["confirmed_fraud"] == 1
    assert summary["precision"] == 1.0
    assert summary["by_predicted_level"]["high"]["confirmed"] == 1


# --- Audit trail ----------------------------------------------------------------------------------


def test_the_audit_trail_records_who_did_what(db_session, open_case):
    cases.assign(db_session, open_case.id, "priya")
    cases.decide(db_session, open_case.id, "fraud_confirmed", "priya", actions_taken=["hold_transaction"])

    actors = {row.actor for row in db_session.query(models.AuditLog)}
    actions = {row.action for row in db_session.query(models.AuditLog)}
    assert "system" in actors
    assert "analyst:priya" in actors
    assert "agent:hypothesis" in actors, "each agent's contribution must be attributable"
    assert {"alert_created", "case_opened", "case_assigned", "case_decided", "action_taken"} <= actions


def test_a_clean_chain_verifies(db_session, open_case):
    result = audit.verify(db_session)
    assert result["valid"] is True
    assert result["entries_checked"] > 5


def test_editing_a_past_entry_breaks_verification(db_session, open_case):
    """The point of the hash chain: history cannot be quietly rewritten."""
    entry = db_session.query(models.AuditLog).order_by(models.AuditLog.id).offset(2).first()
    entry.details = {"tampered": True}
    db_session.commit()

    result = audit.verify(db_session)
    assert result["valid"] is False
    assert result["first_invalid_id"] == entry.id


def test_deleting_an_entry_breaks_verification(db_session, open_case):
    entry = db_session.query(models.AuditLog).order_by(models.AuditLog.id).offset(2).first()
    following = entry.id + 1
    db_session.delete(entry)
    db_session.commit()

    result = audit.verify(db_session)
    assert result["valid"] is False
    assert result["first_invalid_id"] == following
