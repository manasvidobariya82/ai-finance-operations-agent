from app.config import settings


def decide_approval(
    has_validation_errors: bool,
    is_duplicate: bool,
    fraud_score: int,
    recommended_action: str,
    total_amount: float,
) -> str:
    """Route an invoice to one of: auto_approved, pending, rejected."""
    if recommended_action == "reject":
        return "rejected"

    if has_validation_errors or is_duplicate or fraud_score >= settings.mandatory_review_risk_score:
        return "pending"

    if fraud_score <= settings.auto_approve_max_risk_score and total_amount <= settings.auto_approve_max_amount:
        return "auto_approved"

    return "pending"
