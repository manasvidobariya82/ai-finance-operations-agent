from app import models
from app.analytics import build_summary


def add_invoice(db, **kwargs):
    invoice = models.Invoice(filename="f.pdf", file_path="/tmp/f.pdf", **kwargs)
    db.add(invoice)
    db.commit()
    return invoice


def test_empty_db_summary(db_session):
    summary = build_summary(db_session)
    assert summary.total_invoices == 0
    assert summary.average_fraud_score is None
    assert summary.spend_by_currency == {}


def test_counts_and_amounts_by_status(db_session):
    add_invoice(
        db_session,
        approval_status="auto_approved",
        total_amount=100.0,
        currency="USD",
        fraud_score=5,
        fraud_level="low",
    )
    add_invoice(
        db_session,
        approval_status="pending",
        total_amount=500.0,
        currency="USD",
        fraud_score=50,
        fraud_level="medium",
        is_duplicate=True,
    )
    add_invoice(
        db_session,
        approval_status="rejected",
        total_amount=1000.0,
        currency="INR",
        fraud_score=95,
        fraud_level="high",
    )

    summary = build_summary(db_session)

    assert summary.total_invoices == 3
    assert summary.auto_approved == 1
    assert summary.pending_review == 1
    assert summary.rejected == 1
    assert summary.duplicate_count == 1

    assert summary.spend_by_currency == {"USD": 100.0}
    assert summary.pending_amount_by_currency == {"USD": 500.0}
    assert summary.rejected_amount_by_currency == {"INR": 1000.0}

    assert summary.fraud_level_counts.low == 1
    assert summary.fraud_level_counts.medium == 1
    assert summary.fraud_level_counts.high == 1
    assert summary.average_fraud_score == (5 + 50 + 95) / 3


def test_invoices_without_amount_are_not_counted_as_spend(db_session):
    add_invoice(db_session, approval_status="pending", total_amount=None, currency=None)
    summary = build_summary(db_session)
    assert summary.total_invoices == 1
    assert summary.pending_amount_by_currency == {}
