from app.pipeline.extraction import InvoiceExtraction, LineItem
from app.pipeline.validation import validate_invoice


def make_invoice(**overrides) -> InvoiceExtraction:
    defaults = dict(
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        invoice_date="2026-01-10",
        due_date="2026-02-10",
        currency="USD",
        subtotal=100.0,
        tax_amount=8.0,
        total_amount=108.0,
        line_items=[LineItem(description="Widgets", quantity=10, unit_price=10, amount=100.0)],
        extraction_confidence=0.95,
    )
    defaults.update(overrides)
    return InvoiceExtraction(**defaults)


def test_valid_invoice_has_no_errors():
    assert validate_invoice(make_invoice()) == []


def test_missing_vendor_name_flagged():
    errors = validate_invoice(make_invoice(vendor_name=""))
    assert "Missing vendor name" in errors


def test_future_invoice_date_flagged():
    errors = validate_invoice(make_invoice(invoice_date="2099-01-01"))
    assert "Invoice date is in the future" in errors


def test_due_date_before_invoice_date_flagged():
    errors = validate_invoice(make_invoice(invoice_date="2026-01-10", due_date="2026-01-01"))
    assert "Due date is before invoice date" in errors


def test_unrecognized_currency_flagged():
    errors = validate_invoice(make_invoice(currency="XYZ"))
    assert any("Unrecognized currency" in e for e in errors)


def test_line_items_mismatch_flagged():
    errors = validate_invoice(
        make_invoice(line_items=[LineItem(description="Widgets", quantity=1, unit_price=1, amount=50.0)])
    )
    assert any("Line items total" in e for e in errors)


def test_subtotal_plus_tax_mismatch_flagged():
    errors = validate_invoice(make_invoice(subtotal=100.0, tax_amount=8.0, total_amount=200.0))
    assert any("does not match total" in e for e in errors)
