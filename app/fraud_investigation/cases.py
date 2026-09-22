"""Case workflow: assignment, notes, escalation, and the analyst decision that closes a case.

This is where the system's recommendations become actions and where the feedback loop closes. A
decision does three things at once:

1. Applies the actions the analyst confirmed (and only those - see `APPLICABLE_ACTIONS`).
2. Writes the ground-truth label back onto the transaction, which is what the next training run
   learns from.
3. Records an AI-recommendation-vs-human-decision row, which is how the model's precision is
   measured over time rather than asserted once at training.

`inconclusive` deliberately stores a NULL label: "we could not tell" is not evidence that the
transaction was legitimate, and training on it as if it were would quietly teach the model to
dismiss the hard cases.
"""
from typing import List, Optional

from sqlalchemy.orm import Session

from app.fraud_investigation import audit, models
from app.fraud_investigation.clock import now

DECISIONS = ("fraud_confirmed", "false_positive", "inconclusive")
# Decision -> the label written back to Transaction.is_fraud and FraudFeedback.label.
DECISION_LABELS = {"fraud_confirmed": True, "false_positive": False, "inconclusive": None}

# Actions that change state in this system. Anything else an analyst confirms (contacting the
# customer, filing a report, opening a network investigation) happens outside it and is recorded on
# the case as an instruction, not silently treated as done.
APPLICABLE_ACTIONS = {
    "hold_transaction": "Transaction put on hold",
    "block_beneficiary": "Beneficiary blocked",
    "restrict_account": "Account restricted",
    "freeze_account": "Account frozen",
}


class CaseNotFound(LookupError):
    pass


class InvalidTransition(ValueError):
    pass


def get_case(db: Session, case_id: str) -> models.FraudCase:
    case = db.get(models.FraudCase, case_id)
    if not case:
        raise CaseNotFound(f"Case {case_id} not found")
    return case


def list_cases(
    db: Session,
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = 100,
) -> List[models.FraudCase]:
    query = db.query(models.FraudCase)
    if status:
        query = query.filter(models.FraudCase.status == status)
    if priority:
        query = query.filter(models.FraudCase.priority == priority)
    if assigned_to:
        query = query.filter(models.FraudCase.assigned_to == assigned_to)
    # Highest risk first within the queue, then oldest - the order an analyst should work them in.
    return (
        query.order_by(models.FraudCase.risk_score.desc(), models.FraudCase.created_at).limit(limit).all()
    )


def notes(db: Session, case_id: str) -> List[models.CaseNote]:
    return (
        db.query(models.CaseNote)
        .filter(models.CaseNote.case_id == case_id)
        .order_by(models.CaseNote.created_at)
        .all()
    )


def add_note(db: Session, case_id: str, author: str, body: str) -> models.CaseNote:
    case = get_case(db, case_id)
    with audit.write_section(db):
        note = models.CaseNote(case_id=case.id, author=author, body=body)
        db.add(note)
        case.updated_at = now()
        audit.record(db, f"analyst:{author}", "note_added", "fraud_case", case.id, {"length": len(body)})
        db.flush()
    return note


def assign(db: Session, case_id: str, analyst: str) -> models.FraudCase:
    case = get_case(db, case_id)
    if case.status == "closed":
        raise InvalidTransition(f"Case {case_id} is closed")
    with audit.write_section(db):
        previous = case.assigned_to
        case.assigned_to = analyst
        case.updated_at = now()
        audit.record(
            db, f"analyst:{analyst}", "case_assigned", "fraud_case", case.id,
            {"assigned_to": analyst, "previously": previous},
        )
    return case


def escalate(db: Session, case_id: str, analyst: str, reason: str) -> models.FraudCase:
    case = get_case(db, case_id)
    if case.status == "closed":
        raise InvalidTransition(f"Case {case_id} is closed")
    with audit.write_section(db):
        case.status = "escalated"
        case.priority = "high"
        case.updated_at = now()
        db.add(models.CaseNote(case_id=case.id, author=analyst, body=f"Escalated: {reason}"))
        audit.record(db, f"analyst:{analyst}", "case_escalated", "fraud_case", case.id, {"reason": reason})
    return case


def _apply_actions(db: Session, case: models.FraudCase, chosen: List[str], analyst: str) -> List[dict]:
    """Apply the confirmed actions that this system can actually carry out."""
    applied: List[dict] = []
    transaction = db.get(models.Transaction, case.transaction_id)
    account = db.get(models.Account, case.account_id)

    for action in chosen:
        effect = None
        if action == "hold_transaction" and transaction and transaction.status == "completed":
            transaction.status = "held"
            effect = APPLICABLE_ACTIONS[action]
        elif action == "block_beneficiary" and transaction and transaction.counterparty_id:
            counterparty = db.get(models.Counterparty, transaction.counterparty_id)
            if counterparty:
                counterparty.status = "blocked"
                effect = f"{APPLICABLE_ACTIONS[action]}: {counterparty.name}"
        elif action in ("restrict_account", "freeze_account") and account:
            account.status = "restricted" if action == "restrict_account" else "frozen"
            effect = APPLICABLE_ACTIONS[action]

        applied.append(
            {
                "action": action,
                "applied_at": now().isoformat(),
                "by": analyst,
                "effect": effect,
                # False means the analyst has committed to doing it outside this system.
                "executed_here": effect is not None,
            }
        )
        audit.record(
            db, f"analyst:{analyst}", "action_taken", "fraud_case", case.id,
            {"action": action, "effect": effect, "executed_here": effect is not None},
        )
    return applied


def decide(
    db: Session,
    case_id: str,
    decision: str,
    analyst: str,
    notes_text: Optional[str] = None,
    actions_taken: Optional[List[str]] = None,
) -> models.FraudCase:
    """Close a case with an analyst's decision, apply the confirmed actions, and record feedback."""
    if decision not in DECISIONS:
        raise InvalidTransition(f"Decision must be one of {', '.join(DECISIONS)}")
    case = get_case(db, case_id)
    if case.status == "closed":
        raise InvalidTransition(f"Case {case_id} was already decided ({case.decision})")

    label = DECISION_LABELS[decision]
    alert = db.get(models.FraudAlert, case.alert_id)
    transaction = db.get(models.Transaction, case.transaction_id)

    with audit.write_section(db):
        applied = _apply_actions(db, case, actions_taken or [], analyst)

        case.status = "closed"
        case.decision = decision
        case.decided_by = analyst
        case.decided_at = now()
        case.decision_notes = notes_text
        case.updated_at = now()
        case.actions = list(case.actions or []) + applied

        if transaction is not None and label is not None:
            # Ground truth for the next training run.
            transaction.is_fraud = label
        if decision == "fraud_confirmed":
            customer = db.get(models.Customer, case.customer_id)
            if customer:
                customer.prior_fraud_cases = (customer.prior_fraud_cases or 0) + 1

        # Every alert folded into this case shares its outcome.
        for alert_id in case.alert_ids or [case.alert_id]:
            linked = db.get(models.FraudAlert, alert_id)
            if linked:
                linked.status = "case_closed"

        db.add(
            models.FraudFeedback(
                case_id=case.id,
                alert_id=case.alert_id,
                transaction_id=case.transaction_id,
                model_version=alert.model_version if alert else None,
                predicted_score=case.risk_score,
                predicted_level=case.risk_level,
                ai_primary_hypothesis=case.primary_hypothesis,
                analyst_decision=decision,
                label=label,
                analyst=analyst,
            )
        )
        if notes_text:
            db.add(models.CaseNote(case_id=case.id, author=analyst, body=notes_text))
        audit.record(
            db, f"analyst:{analyst}", "case_decided", "fraud_case", case.id,
            {
                "decision": decision,
                "predicted_score": case.risk_score,
                "predicted_hypothesis": case.primary_hypothesis,
                "actions": [item["action"] for item in applied],
            },
        )
    return case


def feedback_summary(db: Session) -> dict:
    """How the model's recommendations have held up against analyst decisions."""
    rows = db.query(models.FraudFeedback).all()
    decided = [row for row in rows if row.label is not None]
    confirmed = [row for row in decided if row.label]
    dismissed = [row for row in decided if not row.label]

    by_level: dict = {}
    for row in decided:
        bucket = by_level.setdefault(row.predicted_level, {"confirmed": 0, "dismissed": 0})
        bucket["confirmed" if row.label else "dismissed"] += 1
    for bucket in by_level.values():
        total = bucket["confirmed"] + bucket["dismissed"]
        bucket["precision"] = round(bucket["confirmed"] / total, 3) if total else None

    hypotheses: dict = {}
    for row in decided:
        key = row.ai_primary_hypothesis or "none"
        bucket = hypotheses.setdefault(key, {"confirmed": 0, "dismissed": 0})
        bucket["confirmed" if row.label else "dismissed"] += 1

    return {
        "total_decisions": len(rows),
        "labelled": len(decided),
        "inconclusive": len(rows) - len(decided),
        "confirmed_fraud": len(confirmed),
        "false_positives": len(dismissed),
        "precision": round(len(confirmed) / len(decided), 3) if decided else None,
        "by_predicted_level": by_level,
        "by_hypothesis": hypotheses,
        "average_score_confirmed": round(sum(r.predicted_score for r in confirmed) / len(confirmed), 1)
        if confirmed
        else None,
        "average_score_dismissed": round(sum(r.predicted_score for r in dismissed) / len(dismissed), 1)
        if dismissed
        else None,
    }
