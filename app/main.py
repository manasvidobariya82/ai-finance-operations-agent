import logging
import mimetypes
import os
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import Depends, FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import Response
from google.genai import errors as genai_errors
from sqlalchemy.orm import Session

from app import models, schemas
from app.analytics import build_summary
from app.config import settings
from app.db import Base, engine, get_db
# Imported for the side effect of registering the fraud-investigation tables on Base before
# create_all runs below, as well as for the router itself.
from app.fraud_investigation.api import router as fraud_router
from app.pipeline import gemini_client
from app.pipeline.accounting import build_journal_entry, journal_entries_to_csv, journal_entry_to_csv
from app.pipeline.extraction import SUPPORTED_MIME_TYPES
from app.pipeline.orchestrator import process_invoice

logger = logging.getLogger("uvicorn.error")

Base.metadata.create_all(bind=engine)
os.makedirs(settings.upload_dir, exist_ok=True)
os.makedirs(settings.export_dir, exist_ok=True)

if not gemini_client.is_configured():
    logger.warning("GEMINI_API_KEY is not set - invoice uploads will fail until it is added to .env")

app = FastAPI(title="AI Finance Operations Agent", version="0.2.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_origin_regex=settings.cors_origin_regex,
    allow_methods=["*"],
    allow_headers=["*"],
)


app.include_router(fraud_router)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "gemini_configured": gemini_client.is_configured(),
        "gemini_model": settings.gemini_model,
    }


@app.post("/invoices/upload", response_model=schemas.InvoiceOut)
def upload_invoice(file: UploadFile = File(...), db: Session = Depends(get_db)):
    """Upload an invoice (PDF/PNG/JPEG/WEBP/GIF) and run it through the full pipeline:
    OCR extraction, validation, duplicate detection, fraud checks, and approval routing.

    Deliberately a sync endpoint: the Gemini calls block for several seconds, and FastAPI runs
    sync endpoints in a threadpool, so an upload no longer stalls every other request."""
    if not gemini_client.is_configured():
        raise HTTPException(
            status_code=503,
            detail="GEMINI_API_KEY is not set. Add it to the .env file in the project root and restart the backend.",
        )

    media_type, _ = mimetypes.guess_type(file.filename or "")
    if media_type not in SUPPORTED_MIME_TYPES:
        raise HTTPException(
            status_code=400,
            detail=f"Unsupported file type for '{file.filename}'. Upload a PDF, PNG, JPEG, WEBP or GIF invoice.",
        )

    contents = file.file.read()
    if not contents:
        raise HTTPException(status_code=400, detail="Uploaded file is empty")

    suffix = os.path.splitext(file.filename)[1].lower()
    stored_name = f"{uuid.uuid4().hex}{suffix}"
    file_path = os.path.join(settings.upload_dir, stored_name)
    with open(file_path, "wb") as f:
        f.write(contents)

    try:
        return process_invoice(db, file_path, file.filename)
    except Exception as exc:
        os.remove(file_path)
        logger.exception("Failed to process invoice %s", file.filename)
        if isinstance(exc, genai_errors.APIError):
            raise HTTPException(status_code=502, detail=f"Gemini API error: {exc}")
        raise HTTPException(status_code=422, detail=f"Failed to process invoice: {exc}")


@app.get("/analytics/summary", response_model=schemas.AnalyticsSummary)
def get_analytics_summary(db: Session = Depends(get_db)):
    return build_summary(db)


@app.get("/invoices", response_model=list[schemas.InvoiceOut])
def list_invoices(status: Optional[str] = Query(default=None), db: Session = Depends(get_db)):
    q = db.query(models.Invoice)
    if status:
        q = q.filter(models.Invoice.approval_status == status)
    return q.order_by(models.Invoice.uploaded_at.desc()).all()


@app.get("/invoices/{invoice_id}", response_model=schemas.InvoiceOut)
def get_invoice(invoice_id: int, db: Session = Depends(get_db)):
    invoice = db.get(models.Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    return invoice


@app.post("/invoices/{invoice_id}/approve", response_model=schemas.InvoiceOut)
def approve_invoice(invoice_id: int, body: schemas.ApprovalRequest, db: Session = Depends(get_db)):
    invoice = db.get(models.Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if invoice.approval_status in ("auto_approved", "approved"):
        raise HTTPException(status_code=400, detail="Invoice is already approved")
    if invoice.approval_status == "rejected":
        raise HTTPException(status_code=400, detail="Invoice was already rejected")
    if invoice.total_amount is None:
        raise HTTPException(
            status_code=400,
            detail="Invoice has no extracted total amount, so no journal entry can be posted",
        )

    invoice.approval_status = "approved"
    invoice.approved_by = body.approved_by
    invoice.approved_at = datetime.now(timezone.utc)
    invoice.status = "posted"

    entry = build_journal_entry(invoice)
    db.add(models.JournalEntry(invoice_id=invoice.id, **entry))
    db.commit()
    db.refresh(invoice)
    return invoice


@app.post("/invoices/{invoice_id}/reject", response_model=schemas.InvoiceOut)
def reject_invoice(invoice_id: int, body: schemas.RejectionRequest, db: Session = Depends(get_db)):
    invoice = db.get(models.Invoice, invoice_id)
    if not invoice:
        raise HTTPException(status_code=404, detail="Invoice not found")
    if invoice.approval_status in ("auto_approved", "approved"):
        raise HTTPException(status_code=400, detail="Invoice is already approved and cannot be rejected")

    invoice.approval_status = "rejected"
    invoice.rejection_reason = body.reason
    invoice.status = "rejected"
    db.commit()
    db.refresh(invoice)
    return invoice


@app.get("/invoices/{invoice_id}/journal-entry", response_model=schemas.JournalEntryOut)
def get_journal_entry(invoice_id: int, db: Session = Depends(get_db)):
    entry = db.query(models.JournalEntry).filter(models.JournalEntry.invoice_id == invoice_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="No journal entry for this invoice (not yet approved)")
    return entry


@app.get("/invoices/{invoice_id}/journal-entry/export")
def export_journal_entry(invoice_id: int, db: Session = Depends(get_db)):
    entry = db.query(models.JournalEntry).filter(models.JournalEntry.invoice_id == invoice_id).first()
    if not entry:
        raise HTTPException(status_code=404, detail="No journal entry for this invoice (not yet approved)")

    entry_dict = {
        "entry_date": entry.entry_date,
        "lines": entry.lines,
        "currency": entry.currency,
        "total_amount": entry.total_amount,
    }
    csv_text = journal_entry_to_csv(entry_dict, invoice_id)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename=journal_entry_{invoice_id}.csv"},
    )


@app.get("/journal-entries/export")
def export_all_journal_entries(db: Session = Depends(get_db)):
    entries = db.query(models.JournalEntry).all()
    rows = [
        (
            entry.invoice_id,
            {
                "entry_date": entry.entry_date,
                "lines": entry.lines,
                "currency": entry.currency,
                "total_amount": entry.total_amount,
            },
        )
        for entry in entries
    ]
    csv_text = journal_entries_to_csv(rows)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=journal_entries.csv"},
    )
