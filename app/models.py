from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, Float, ForeignKey, Integer, JSON, String
from sqlalchemy.orm import relationship

from app.db import Base


class Invoice(Base):
    __tablename__ = "invoices"

    id = Column(Integer, primary_key=True, index=True)
    filename = Column(String, nullable=False)
    file_path = Column(String, nullable=False)
    uploaded_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    # Pipeline stage: uploaded -> extracted -> validated -> duplicate_checked
    # -> fraud_checked -> pending_approval / auto_approved / rejected -> posted
    status = Column(String, default="uploaded", index=True)

    # OCR / field extraction
    vendor_name = Column(String, nullable=True)
    vendor_address = Column(String, nullable=True)
    vendor_tax_id = Column(String, nullable=True)
    invoice_number = Column(String, nullable=True, index=True)
    invoice_date = Column(String, nullable=True)
    due_date = Column(String, nullable=True)
    po_number = Column(String, nullable=True)
    currency = Column(String, nullable=True)
    subtotal = Column(Float, nullable=True)
    tax_amount = Column(Float, nullable=True)
    total_amount = Column(Float, nullable=True)
    line_items = Column(JSON, nullable=True)
    bank_account_last4 = Column(String, nullable=True)
    extraction_confidence = Column(Float, nullable=True)
    uncertain_fields = Column(JSON, nullable=True)

    # Validation
    validation_errors = Column(JSON, nullable=True)

    # Duplicate detection
    is_duplicate = Column(Boolean, default=False)
    duplicate_of_id = Column(Integer, ForeignKey("invoices.id"), nullable=True)
    duplicate_reason = Column(String, nullable=True)

    # Fraud checks
    fraud_score = Column(Integer, nullable=True)
    fraud_level = Column(String, nullable=True)
    fraud_reasons = Column(JSON, nullable=True)
    fraud_rule_flags = Column(JSON, nullable=True)

    # Approval
    approval_status = Column(String, default="pending", index=True)  # pending, auto_approved, approved, rejected
    approved_by = Column(String, nullable=True)
    approved_at = Column(DateTime, nullable=True)
    rejection_reason = Column(String, nullable=True)

    journal_entry = relationship("JournalEntry", back_populates="invoice", uselist=False)


class JournalEntry(Base):
    __tablename__ = "journal_entries"

    id = Column(Integer, primary_key=True, index=True)
    invoice_id = Column(Integer, ForeignKey("invoices.id"), unique=True, nullable=False)
    entry_date = Column(String, nullable=False)
    lines = Column(JSON, nullable=False)  # [{account, debit, credit, memo}, ...]
    currency = Column(String, nullable=False)
    total_amount = Column(Float, nullable=False)
    posted_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))

    invoice = relationship("Invoice", back_populates="journal_entry")
