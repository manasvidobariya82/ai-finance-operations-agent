import pytest
from fastapi.testclient import TestClient

from app import models
from app.config import settings
from app.db import get_db
from app.main import app
from app.pipeline import orchestrator
from app.pipeline.extraction import InvoiceExtraction, LineItem
from app.pipeline.fraud import FraudAssessment


@pytest.fixture()
def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


def add_invoice(db, **kwargs):
    invoice = models.Invoice(filename="f.pdf", file_path="/tmp/f.pdf", **kwargs)
    db.add(invoice)
    db.commit()
    return invoice


def test_approve_posts_balanced_journal_entry(client, db_session):
    invoice = add_invoice(
        db_session,
        vendor_name="Acme",
        invoice_number="INV-1",
        invoice_date="2026-09-01",
        currency="INR",
        total_amount=116820.0,
        status="pending_approval",
        approval_status="pending",
    )

    res = client.post(f"/invoices/{invoice.id}/approve", json={"approved_by": "tester"})
    assert res.status_code == 200
    assert res.json()["approval_status"] == "approved"
    assert res.json()["status"] == "posted"

    entry = client.get(f"/invoices/{invoice.id}/journal-entry").json()
    assert sum(line["debit"] for line in entry["lines"]) == 116820.0
    assert sum(line["credit"] for line in entry["lines"]) == 116820.0

    csv_lines = client.get("/journal-entries/export").text.strip().splitlines()
    assert len(csv_lines) == 3  # header + debit line + credit line


def test_approve_twice_is_rejected(client, db_session):
    invoice = add_invoice(db_session, total_amount=10.0, approval_status="pending")

    assert client.post(f"/invoices/{invoice.id}/approve", json={"approved_by": "a"}).status_code == 200
    assert client.post(f"/invoices/{invoice.id}/approve", json={"approved_by": "a"}).status_code == 400


def test_approve_without_extracted_total_returns_400(client, db_session):
    invoice = add_invoice(db_session, status="uploaded", approval_status="pending")

    res = client.post(f"/invoices/{invoice.id}/approve", json={"approved_by": "tester"})
    assert res.status_code == 400
    assert db_session.query(models.JournalEntry).count() == 0


@pytest.fixture()
def upload_env(monkeypatch, tmp_path):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    monkeypatch.setattr(settings, "upload_dir", str(tmp_path))
    return tmp_path


def fake_extraction(file_path):
    return InvoiceExtraction(
        vendor_name="Acme Supplies",
        invoice_number="INV-9",
        invoice_date="2026-09-01",
        currency="USD",
        subtotal=100.0,
        tax_amount=8.0,
        total_amount=108.0,
        line_items=[LineItem(description="Widgets", quantity=10, unit_price=10, amount=100.0)],
        extraction_confidence=0.95,
    )


def fake_fraud(db, data, is_duplicate, duplicate_reason):
    assessment = FraudAssessment(
        risk_score=5, risk_level="low", reasons=["Looks normal"], recommended_action="auto_approve"
    )
    return assessment, []


def test_health_reports_gemini_configuration(client, monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "test-key")
    assert client.get("/health").json()["gemini_configured"] is True


def test_upload_without_api_key_returns_503(client, upload_env, monkeypatch):
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GOOGLE_GENAI_USE_VERTEXAI"):
        monkeypatch.delenv(var, raising=False)

    res = client.post("/invoices/upload", files={"file": ("inv.pdf", b"%PDF-1.4", "application/pdf")})
    assert res.status_code == 503
    assert "GEMINI_API_KEY" in res.json()["detail"]


def test_upload_unsupported_file_type_returns_400(client, upload_env):
    res = client.post("/invoices/upload", files={"file": ("notes.txt", b"hello", "text/plain")})
    assert res.status_code == 400
    assert list(upload_env.iterdir()) == []


def test_upload_runs_pipeline_and_auto_approves(client, db_session, upload_env, monkeypatch):
    monkeypatch.setattr(orchestrator, "extract_invoice", fake_extraction)
    monkeypatch.setattr(orchestrator, "assess_fraud", fake_fraud)

    res = client.post("/invoices/upload", files={"file": ("inv.pdf", b"%PDF-1.4", "application/pdf")})
    assert res.status_code == 200
    body = res.json()
    assert body["vendor_name"] == "Acme Supplies"
    assert body["approval_status"] == "auto_approved"
    assert body["status"] == "posted"
    assert db_session.query(models.JournalEntry).count() == 1


def test_failed_pipeline_leaves_no_invoice_or_file(client, db_session, upload_env, monkeypatch):
    def broken_extraction(file_path):
        raise ValueError("model returned garbage")

    monkeypatch.setattr(orchestrator, "extract_invoice", broken_extraction)

    res = client.post("/invoices/upload", files={"file": ("inv.pdf", b"%PDF-1.4", "application/pdf")})
    assert res.status_code == 422
    assert "model returned garbage" in res.json()["detail"]
    assert db_session.query(models.Invoice).count() == 0
    assert list(upload_env.iterdir()) == []
