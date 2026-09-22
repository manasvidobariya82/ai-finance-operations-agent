import csv
import io
from datetime import date
from typing import List, Tuple

from app import models

DEFAULT_EXPENSE_ACCOUNT = "6000 - General Expenses"
ACCOUNTS_PAYABLE_ACCOUNT = "2000 - Accounts Payable"

CSV_HEADER = ["invoice_id", "entry_date", "account", "debit", "credit", "currency", "memo"]


def build_journal_entry(invoice: "models.Invoice") -> dict:
    """Build a balanced double-entry journal entry: debit expense, credit accounts payable."""
    entry_date = invoice.invoice_date or date.today().isoformat()
    memo = f"Invoice {invoice.invoice_number} from {invoice.vendor_name}"

    lines = [
        {"account": DEFAULT_EXPENSE_ACCOUNT, "debit": invoice.total_amount, "credit": 0.0, "memo": memo},
        {"account": ACCOUNTS_PAYABLE_ACCOUNT, "debit": 0.0, "credit": invoice.total_amount, "memo": memo},
    ]

    return {
        "entry_date": entry_date,
        "lines": lines,
        "currency": invoice.currency or "USD",
        "total_amount": invoice.total_amount,
    }


def journal_entry_to_csv(entry: dict, invoice_id: int) -> str:
    return journal_entries_to_csv([(invoice_id, entry)])


def journal_entries_to_csv(rows: List[Tuple[int, dict]]) -> str:
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(CSV_HEADER)
    for invoice_id, entry in rows:
        for line in entry["lines"]:
            writer.writerow(
                [
                    invoice_id,
                    entry["entry_date"],
                    line["account"],
                    line["debit"],
                    line["credit"],
                    entry["currency"],
                    line["memo"],
                ]
            )
    return buffer.getvalue()
