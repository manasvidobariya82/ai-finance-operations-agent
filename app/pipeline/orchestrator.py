from sqlalchemy.orm import Session

from app import models
from app.pipeline.accounting import build_journal_entry
from app.pipeline.approval import decide_approval
from app.pipeline.duplicates import find_duplicate
from app.pipeline.extraction import extract_invoice
from app.pipeline.fraud import assess_fraud
from app.pipeline.validation import validate_invoice


def process_invoice(db: Session, file_path: str, filename: str) -> "models.Invoice":
    """Run the full pipeline for one uploaded invoice: OCR extraction, validation,
    duplicate detection, fraud checks, and approval routing. Auto-approved invoices
    are posted to the accounting ledger immediately."""
    invoice = models.Invoice(filename=filename, file_path=file_path, status="uploaded")
    db.add(invoice)
    db.commit()
    db.refresh(invoice)

    try:
        _run_pipeline(db, invoice, file_path)
    except Exception:
        # Don't leave a half-processed row stuck at "uploaded" (it would show up as pending
        # review with no data); the caller reports the error to the user instead.
        db.rollback()
        db.delete(invoice)
        db.commit()
        raise

    return invoice


def _run_pipeline(db: Session, invoice: "models.Invoice", file_path: str) -> None:
    extraction = extract_invoice(file_path)

    invoice.vendor_name = extraction.vendor_name
    invoice.vendor_address = extraction.vendor_address
    invoice.vendor_tax_id = extraction.vendor_tax_id
    invoice.invoice_number = extraction.invoice_number
    invoice.invoice_date = extraction.invoice_date
    invoice.due_date = extraction.due_date
    invoice.po_number = extraction.po_number
    invoice.currency = extraction.currency
    invoice.subtotal = extraction.subtotal
    invoice.tax_amount = extraction.tax_amount
    invoice.total_amount = extraction.total_amount
    invoice.line_items = [item.model_dump() for item in extraction.line_items]
    invoice.bank_account_last4 = extraction.bank_account_last4
    invoice.extraction_confidence = extraction.extraction_confidence
    invoice.uncertain_fields = extraction.uncertain_fields
    invoice.status = "extracted"

    validation_errors = validate_invoice(extraction)
    invoice.validation_errors = validation_errors
    invoice.status = "validated"

    duplicate, duplicate_reason = find_duplicate(
        db,
        extraction.vendor_name,
        extraction.invoice_number,
        extraction.total_amount,
        extraction.invoice_date,
        exclude_id=invoice.id,
    )
    invoice.is_duplicate = duplicate is not None
    invoice.duplicate_of_id = duplicate.id if duplicate else None
    invoice.duplicate_reason = duplicate_reason
    invoice.status = "duplicate_checked"

    fraud_assessment, rule_flags = assess_fraud(db, extraction, invoice.is_duplicate, duplicate_reason)
    invoice.fraud_score = fraud_assessment.risk_score
    invoice.fraud_level = fraud_assessment.risk_level
    invoice.fraud_reasons = fraud_assessment.reasons
    invoice.fraud_rule_flags = rule_flags
    invoice.status = "fraud_checked"

    approval_status = decide_approval(
        has_validation_errors=bool(validation_errors),
        is_duplicate=invoice.is_duplicate,
        fraud_score=fraud_assessment.risk_score,
        recommended_action=fraud_assessment.recommended_action,
        total_amount=extraction.total_amount,
    )
    invoice.approval_status = approval_status
    invoice.status = {
        "auto_approved": "auto_approved",
        "rejected": "rejected",
    }.get(approval_status, "pending_approval")

    db.commit()
    db.refresh(invoice)

    if approval_status == "auto_approved":
        entry = build_journal_entry(invoice)
        db.add(models.JournalEntry(invoice_id=invoice.id, **entry))
        invoice.status = "posted"
        db.commit()
        db.refresh(invoice)
