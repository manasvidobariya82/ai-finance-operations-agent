import mimetypes
from pathlib import Path
from typing import List, Optional

from google.genai import types
from pydantic import BaseModel

from app.pipeline.gemini_client import generate_structured


class LineItem(BaseModel):
    description: str
    quantity: float = 1
    unit_price: float = 0
    amount: float = 0


class InvoiceExtraction(BaseModel):
    vendor_name: str
    vendor_address: Optional[str] = None
    vendor_tax_id: Optional[str] = None
    invoice_number: str
    invoice_date: Optional[str] = None
    due_date: Optional[str] = None
    po_number: Optional[str] = None
    currency: str = "USD"
    subtotal: Optional[float] = None
    tax_amount: Optional[float] = None
    total_amount: float
    line_items: List[LineItem] = []
    bank_account_last4: Optional[str] = None
    extraction_confidence: float
    uncertain_fields: List[str] = []


EXTRACTION_PROMPT = """You are an invoice OCR and field-extraction system for an accounts-payable pipeline.
Read the attached invoice document/image carefully and extract every field in the schema.

Rules:
- Dates must be ISO format (YYYY-MM-DD). If a date is ambiguous or unreadable, leave it null and add
  the field name to uncertain_fields.
- total_amount must be the final amount due, not a subtotal.
- If subtotal or tax_amount are not printed on the invoice, compute them from line items when possible,
  otherwise leave them null.
- bank_account_last4 is the last 4 digits of any bank account/IBAN printed for payment, if present.
- extraction_confidence is your overall confidence (0.0-1.0) that every field was read correctly.
- List any field you are not fully confident about in uncertain_fields, even if you filled in a value.
- Do not invent data that is not present on the document."""


SUPPORTED_MIME_TYPES = {"application/pdf", "image/png", "image/jpeg", "image/webp", "image/gif"}


def _file_part(file_path: str) -> types.Part:
    path = Path(file_path)
    media_type, _ = mimetypes.guess_type(path.name)

    if media_type not in SUPPORTED_MIME_TYPES:
        raise ValueError(f"Unsupported invoice file type: {media_type or path.suffix}")

    return types.Part.from_bytes(data=path.read_bytes(), mime_type=media_type)


def extract_invoice(file_path: str) -> InvoiceExtraction:
    return generate_structured([_file_part(file_path), EXTRACTION_PROMPT], InvoiceExtraction)
