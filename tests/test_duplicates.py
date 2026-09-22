from app import models
from app.pipeline.duplicates import find_duplicate


def add_invoice(db, **kwargs):
    invoice = models.Invoice(filename="f.pdf", file_path="/tmp/f.pdf", **kwargs)
    db.add(invoice)
    db.commit()
    db.refresh(invoice)
    return invoice


def test_same_vendor_and_invoice_number_is_duplicate(db_session):
    add_invoice(
        db_session,
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        total_amount=500.0,
        invoice_date="2026-01-10",
    )
    duplicate, reason = find_duplicate(db_session, "Acme Supplies", "INV-001", 500.0, "2026-01-10")
    assert duplicate is not None
    assert "invoice number" in reason


def test_same_vendor_and_amount_within_window_is_duplicate(db_session):
    add_invoice(
        db_session,
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        total_amount=500.0,
        invoice_date="2026-01-10",
    )
    duplicate, reason = find_duplicate(db_session, "Acme Supplies", "INV-002", 500.0, "2026-01-12")
    assert duplicate is not None
    assert "within" in reason


def test_different_vendor_is_not_duplicate(db_session):
    add_invoice(
        db_session,
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        total_amount=500.0,
        invoice_date="2026-01-10",
    )
    duplicate, reason = find_duplicate(db_session, "Globex Corp", "INV-001", 500.0, "2026-01-10")
    assert duplicate is None
    assert reason is None


def test_excludes_own_id(db_session):
    invoice = add_invoice(
        db_session,
        vendor_name="Acme Supplies",
        invoice_number="INV-001",
        total_amount=500.0,
        invoice_date="2026-01-10",
    )
    duplicate, _ = find_duplicate(
        db_session, "Acme Supplies", "INV-001", 500.0, "2026-01-10", exclude_id=invoice.id
    )
    assert duplicate is None
