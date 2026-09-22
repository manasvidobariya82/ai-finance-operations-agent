"""Portfolio-level view of the fraud system: volumes, queue state, and how the model is holding up."""
from typing import Dict

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.fraud_investigation import cases, models
from app.fraud_investigation.detection import ml


def _counts(db: Session, column) -> Dict[str, int]:
    return {value: count for value, count in db.query(column, func.count()).group_by(column).all() if value}


def dashboard(db: Session) -> dict:
    transactions = db.query(func.count(models.Transaction.id)).scalar() or 0
    scored = db.query(func.count(models.FraudAlert.id)).scalar() or 0
    open_statuses = ("open", "pending_verification", "escalated")

    open_cases = (
        db.query(func.count(models.FraudCase.id)).filter(models.FraudCase.status.in_(open_statuses)).scalar() or 0
    )
    closed_cases = (
        db.query(func.count(models.FraudCase.id)).filter(models.FraudCase.status == "closed").scalar() or 0
    )

    # What is actually exposed right now: the value of transactions behind cases nobody has decided
    # on yet. Closed cases are excluded whatever their outcome - they are no longer a decision the
    # bank owes anyone.
    at_risk = (
        db.query(func.coalesce(func.sum(models.Transaction.amount), 0.0))
        .join(models.FraudCase, models.FraudCase.transaction_id == models.Transaction.id)
        .filter(models.FraudCase.status.in_(open_statuses))
        .scalar()
        or 0.0
    )

    active = ml.active_model_record(db)
    return {
        "data_available": transactions > 0,
        "customers": db.query(func.count(models.Customer.id)).scalar() or 0,
        "transactions": transactions,
        "scored_transactions": scored,
        "unscored_transactions": max(0, transactions - scored),
        "alerts_by_level": _counts(db, models.FraudAlert.risk_level),
        "open_cases": open_cases,
        "closed_cases": closed_cases,
        "cases_by_priority": _counts(db, models.FraudCase.priority),
        "cases_by_hypothesis": _counts(db, models.FraudCase.primary_hypothesis),
        "amount_at_risk": round(float(at_risk), 2),
        "active_model": active.version if active else None,
        "model_metrics": active.metrics if active else None,
        "feedback": cases.feedback_summary(db),
        "audit_entries": db.query(func.count(models.AuditLog.id)).scalar() or 0,
    }
