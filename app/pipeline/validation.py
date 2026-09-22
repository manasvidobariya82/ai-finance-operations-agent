from datetime import date
from typing import List

from app.pipeline.extraction import InvoiceExtraction

ALLOWED_CURRENCIES = {"USD", "EUR", "GBP", "INR", "CAD", "AUD", "JPY"}
AMOUNT_TOLERANCE = 0.02


def validate_invoice(data: InvoiceExtraction) -> List[str]:
    errors: List[str] = []

    if not data.vendor_name or not data.vendor_name.strip():
        errors.append("Missing vendor name")
    if not data.invoice_number or not data.invoice_number.strip():
        errors.append("Missing invoice number")
    if data.total_amount is None or data.total_amount <= 0:
        errors.append("Missing or non-positive total amount")
    if data.currency not in ALLOWED_CURRENCIES:
        errors.append(f"Unrecognized currency: {data.currency}")

    invoice_date_parsed = None
    if data.invoice_date:
        try:
            invoice_date_parsed = date.fromisoformat(data.invoice_date)
            if invoice_date_parsed > date.today():
                errors.append("Invoice date is in the future")
        except ValueError:
            errors.append(f"Invoice date is not a valid ISO date: {data.invoice_date}")

    if data.due_date and invoice_date_parsed:
        try:
            if date.fromisoformat(data.due_date) < invoice_date_parsed:
                errors.append("Due date is before invoice date")
        except ValueError:
            errors.append(f"Due date is not a valid ISO date: {data.due_date}")

    if data.line_items:
        items_total = sum(item.amount for item in data.line_items)
        reference = data.subtotal if data.subtotal is not None else data.total_amount
        if reference is not None and abs(items_total - reference) > max(AMOUNT_TOLERANCE, reference * 0.01):
            label = "subtotal" if data.subtotal is not None else "total"
            errors.append(f"Line items total ({items_total:.2f}) does not match {label} ({reference:.2f})")

    if data.subtotal is not None and data.tax_amount is not None and data.total_amount is not None:
        expected_total = data.subtotal + data.tax_amount
        if abs(expected_total - data.total_amount) > max(AMOUNT_TOLERANCE, data.total_amount * 0.01):
            errors.append(f"Subtotal + tax ({expected_total:.2f}) does not match total ({data.total_amount:.2f})")

    return errors
