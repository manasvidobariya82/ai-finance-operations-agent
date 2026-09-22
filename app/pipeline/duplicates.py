from difflib import SequenceMatcher
from datetime import date
from typing import Optional, Tuple

from sqlalchemy.orm import Session

from app import models
from app.config import settings


def _name_similarity(a: str, b: str) -> float:
    return SequenceMatcher(None, a.lower().strip(), b.lower().strip()).ratio()


def find_duplicate(
    db: Session,
    vendor_name: str,
    invoice_number: str,
    total_amount: float,
    invoice_date: Optional[str],
    exclude_id: Optional[int] = None,
) -> Tuple[Optional["models.Invoice"], Optional[str]]:
    query = db.query(models.Invoice)
    if exclude_id is not None:
        query = query.filter(models.Invoice.id != exclude_id)

    for other in query.all():
        if not other.vendor_name or not other.invoice_number:
            continue

        same_vendor = _name_similarity(vendor_name, other.vendor_name) >= settings.duplicate_name_similarity
        if not same_vendor:
            continue

        same_invoice_number = invoice_number.strip().lower() == other.invoice_number.strip().lower()
        if same_invoice_number:
            return other, f"Same vendor and invoice number as invoice #{other.id}"

        if other.total_amount is not None and abs(other.total_amount - total_amount) < 0.01:
            if invoice_date and other.invoice_date:
                try:
                    d1 = date.fromisoformat(invoice_date)
                    d2 = date.fromisoformat(other.invoice_date)
                except ValueError:
                    continue
                if abs((d1 - d2).days) <= settings.duplicate_date_window_days:
                    return (
                        other,
                        f"Same vendor and amount within {settings.duplicate_date_window_days} days as invoice #{other.id}",
                    )

    return None, None
