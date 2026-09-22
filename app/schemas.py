from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel


class ApprovalRequest(BaseModel):
    approved_by: str


class RejectionRequest(BaseModel):
    reason: str
    rejected_by: Optional[str] = None


class JournalEntryOut(BaseModel):
    id: int
    invoice_id: int
    entry_date: str
    lines: List[dict]
    currency: str
    total_amount: float
    posted_at: datetime

    class Config:
        from_attributes = True


class FraudLevelCounts(BaseModel):
    low: int = 0
    medium: int = 0
    high: int = 0


class AnalyticsSummary(BaseModel):
    total_invoices: int
    pending_review: int
    auto_approved: int
    approved: int
    rejected: int
    duplicate_count: int

    average_fraud_score: Optional[float] = None
    fraud_level_counts: FraudLevelCounts

    spend_by_currency: Dict[str, float]
    pending_amount_by_currency: Dict[str, float]
    rejected_amount_by_currency: Dict[str, float]


class InvoiceOut(BaseModel):
    id: int
    filename: str
    status: str
    uploaded_at: datetime

    vendor_name: Optional[str] = None
    vendor_address: Optional[str] = None
    vendor_tax_id: Optional[str] = None
    invoice_number: Optional[str] = None
    invoice_date: Optional[str] = None
    due_date: Optional[str] = None
    po_number: Optional[str] = None
    currency: Optional[str] = None
    subtotal: Optional[float] = None
    tax_amount: Optional[float] = None
    total_amount: Optional[float] = None
    line_items: Optional[List[dict]] = None
    bank_account_last4: Optional[str] = None
    extraction_confidence: Optional[float] = None
    uncertain_fields: Optional[List[str]] = None

    validation_errors: Optional[List[str]] = None

    is_duplicate: bool = False
    duplicate_of_id: Optional[int] = None
    duplicate_reason: Optional[str] = None

    fraud_score: Optional[int] = None
    fraud_level: Optional[str] = None
    fraud_reasons: Optional[List[str]] = None
    fraud_rule_flags: Optional[List[str]] = None

    approval_status: str
    approved_by: Optional[str] = None
    approved_at: Optional[datetime] = None
    rejection_reason: Optional[str] = None

    class Config:
        from_attributes = True
