from collections import Counter, defaultdict
from typing import Dict

from sqlalchemy.orm import Session

from app import models
from app.schemas import AnalyticsSummary, FraudLevelCounts


def build_summary(db: Session) -> AnalyticsSummary:
    invoices = db.query(models.Invoice).all()

    status_counts = Counter(inv.approval_status for inv in invoices)
    fraud_level_counts = Counter(inv.fraud_level for inv in invoices if inv.fraud_level)
    fraud_scores = [inv.fraud_score for inv in invoices if inv.fraud_score is not None]

    spend_by_currency: Dict[str, float] = defaultdict(float)
    pending_amount_by_currency: Dict[str, float] = defaultdict(float)
    rejected_amount_by_currency: Dict[str, float] = defaultdict(float)

    for inv in invoices:
        if inv.total_amount is None:
            continue
        currency = inv.currency or "UNKNOWN"
        if inv.approval_status in ("approved", "auto_approved"):
            spend_by_currency[currency] += inv.total_amount
        elif inv.approval_status == "pending":
            pending_amount_by_currency[currency] += inv.total_amount
        elif inv.approval_status == "rejected":
            rejected_amount_by_currency[currency] += inv.total_amount

    return AnalyticsSummary(
        total_invoices=len(invoices),
        pending_review=status_counts.get("pending", 0),
        auto_approved=status_counts.get("auto_approved", 0),
        approved=status_counts.get("approved", 0),
        rejected=status_counts.get("rejected", 0),
        duplicate_count=sum(1 for inv in invoices if inv.is_duplicate),
        average_fraud_score=(sum(fraud_scores) / len(fraud_scores)) if fraud_scores else None,
        fraud_level_counts=FraudLevelCounts(
            low=fraud_level_counts.get("low", 0),
            medium=fraud_level_counts.get("medium", 0),
            high=fraud_level_counts.get("high", 0),
        ),
        spend_by_currency=dict(spend_by_currency),
        pending_amount_by_currency=dict(pending_amount_by_currency),
        rejected_amount_by_currency=dict(rejected_amount_by_currency),
    )
