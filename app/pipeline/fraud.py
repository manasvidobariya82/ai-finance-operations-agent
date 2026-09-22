from datetime import date
from typing import List, Literal, Optional, Tuple

from pydantic import BaseModel
from sqlalchemy.orm import Session

from app import models
from app.pipeline.extraction import InvoiceExtraction
from app.pipeline.gemini_client import generate_structured


class FraudAssessment(BaseModel):
    risk_score: int
    risk_level: Literal["low", "medium", "high"]
    reasons: List[str]
    recommended_action: Literal["auto_approve", "manual_review", "reject"]


FRAUD_PROMPT = """You are a fraud-detection analyst reviewing an invoice before it enters an
accounts-payable system. You are given the extracted invoice fields, rule-based flags already
raised, and summary statistics about this vendor's invoice history. Assess the overall
fraud/anomaly risk.

Score from 0 (no concern) to 100 (near-certain fraud). Consider: amount vs. vendor history,
altered or inconsistent bank details, suspiciously round numbers, mismatched dates, a missing
purchase order for a large amount, duplicate-adjacent invoices, and the rule flags provided.
Be conservative - only recommend "reject" for strong, specific evidence, not just an unfamiliar
vendor or a single soft flag."""


def _vendor_stats(db: Session, vendor_name: str) -> dict:
    # Filter in Python for a case-insensitive vendor match without relying on DB-specific functions.
    vendor_rows = [
        r
        for r in db.query(models.Invoice)
        .filter(models.Invoice.vendor_name.isnot(None))
        .filter(models.Invoice.total_amount.isnot(None))
        .order_by(models.Invoice.uploaded_at.desc())
        .all()
        if r.vendor_name.lower() == vendor_name.lower()
    ]

    amounts = [r.total_amount for r in vendor_rows]
    return {
        "count": len(amounts),
        "avg_amount": sum(amounts) / len(amounts) if amounts else 0,
        "last_bank_last4": vendor_rows[0].bank_account_last4 if vendor_rows else None,
    }


def _rule_flags(data: InvoiceExtraction, vendor_stats: dict) -> List[str]:
    flags: List[str] = []

    if data.invoice_date:
        try:
            if date.fromisoformat(data.invoice_date).weekday() >= 5:
                flags.append("Invoice dated on a weekend")
        except ValueError:
            pass

    if vendor_stats.get("count", 0) >= 3:
        avg = vendor_stats["avg_amount"]
        if avg > 0 and data.total_amount > avg * 3:
            flags.append(
                f"Amount ({data.total_amount:.2f}) is over 3x this vendor's historical average ({avg:.2f})"
            )

    if data.total_amount >= 10000 and not data.po_number:
        flags.append("Large invoice with no purchase order number")

    if data.total_amount >= 1000 and data.total_amount == round(data.total_amount):
        flags.append("Suspiciously round total amount")

    last_bank = vendor_stats.get("last_bank_last4")
    if last_bank and data.bank_account_last4 and last_bank != data.bank_account_last4:
        flags.append("Bank account details differ from this vendor's previous invoices")

    return flags


def assess_fraud(
    db: Session,
    data: InvoiceExtraction,
    is_duplicate: bool,
    duplicate_reason: Optional[str],
) -> Tuple[FraudAssessment, List[str]]:
    vendor_stats = _vendor_stats(db, data.vendor_name)
    rule_flags = _rule_flags(data, vendor_stats)
    if is_duplicate:
        rule_flags.append(f"Flagged as possible duplicate: {duplicate_reason}")

    prompt = (
        f"Extracted invoice:\n{data.model_dump_json(indent=2)}\n\n"
        f"Vendor history: {vendor_stats}\n\n"
        f"Rule-based flags already raised: {rule_flags or 'none'}\n\n"
        f"{FRAUD_PROMPT}"
    )
    return generate_structured(prompt, FraudAssessment), rule_flags
