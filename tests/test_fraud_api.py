"""HTTP surface of the fraud investigation system."""
import pytest
from fastapi.testclient import TestClient

from app.db import get_db
from app.fraud_investigation import models, pipeline
from app.main import app
from tests import fraud_factory as factory


@pytest.fixture()
def client(db_session):
    app.dependency_overrides[get_db] = lambda: db_session
    try:
        yield TestClient(app)
    finally:
        app.dependency_overrides.clear()


@pytest.fixture()
def case(db_session):
    factory.baseline(db_session)
    _, opened = pipeline.process_transaction(db_session, factory.takeover_transaction(db_session))
    return opened


# --- Dashboard and listings -------------------------------------------------------------------------


def test_dashboard_on_an_empty_system(client):
    body = client.get("/fraud/dashboard").json()
    assert body["data_available"] is False
    assert body["transactions"] == 0
    assert body["active_model"] is None


def test_dashboard_reports_the_queue(client, case):
    body = client.get("/fraud/dashboard").json()
    assert body["data_available"] is True
    assert body["open_cases"] == 1
    assert body["alerts_by_level"]["high"] >= 1
    assert body["amount_at_risk"] == pytest.approx(90000.0)
    assert body["audit_entries"] > 0


def test_amount_at_risk_drops_once_a_case_is_decided(client, case):
    client.post(f"/fraud/cases/{case.id}/decide", json={"decision": "false_positive", "analyst": "priya"})
    body = client.get("/fraud/dashboard").json()
    assert body["open_cases"] == 0
    assert body["amount_at_risk"] == 0.0


def test_alerts_can_be_filtered(client, case):
    assert client.get("/fraud/alerts", params={"risk_level": "high"}).json()
    assert client.get("/fraud/alerts", params={"risk_level": "low"}).json() == []


def test_alert_detail_exposes_the_evidence(client, case):
    alert = client.get(f"/fraud/alerts/{case.alert_id}").json()
    assert alert["risk_level"] == "high"
    assert alert["reasons"]
    assert alert["rule_hits"]
    assert alert["components"]["method_explanation"]


def test_unknown_ids_are_404(client):
    assert client.get("/fraud/alerts/ALT-999999").status_code == 404
    assert client.get("/fraud/cases/CASE-99999").status_code == 404
    assert client.post("/fraud/transactions/TX-999999/score").status_code == 404


# --- Case workflow ----------------------------------------------------------------------------------


def test_case_detail_includes_the_case_file_and_notes(client, case):
    client.post(f"/fraud/cases/{case.id}/notes", json={"author": "priya", "body": "Left a voicemail."})
    body = client.get(f"/fraud/cases/{case.id}").json()

    assert body["case_file"]["sections"]
    assert body["case_file"]["primary_hypothesis"] == "Account takeover"
    assert [note["body"] for note in body["notes"]] == ["Left a voicemail."]


def test_a_case_can_be_assigned_escalated_and_decided(client, case):
    assert client.post(f"/fraud/cases/{case.id}/assign", json={"analyst": "priya"}).json()["assigned_to"] == "priya"

    escalated = client.post(
        f"/fraud/cases/{case.id}/escalate", json={"analyst": "priya", "reason": "funds still moving"}
    ).json()
    assert escalated["status"] == "escalated"

    decided = client.post(
        f"/fraud/cases/{case.id}/decide",
        json={
            "decision": "fraud_confirmed",
            "analyst": "priya",
            "notes": "Customer confirmed they did not authorise it.",
            "actions_taken": ["hold_transaction"],
        },
    ).json()
    assert decided["status"] == "closed"
    assert decided["decision"] == "fraud_confirmed"


def test_deciding_a_closed_case_is_a_conflict(client, case):
    payload = {"decision": "fraud_confirmed", "analyst": "priya"}
    assert client.post(f"/fraud/cases/{case.id}/decide", json=payload).status_code == 200
    assert client.post(f"/fraud/cases/{case.id}/decide", json=payload).status_code == 409


def test_an_invalid_decision_is_rejected(client, case):
    response = client.post(
        f"/fraud/cases/{case.id}/decide", json={"decision": "probably_fine", "analyst": "priya"}
    )
    assert response.status_code == 409


def test_cases_can_be_filtered_by_status(client, case):
    assert len(client.get("/fraud/cases", params={"status": "open"}).json()) == 1
    assert client.get("/fraud/cases", params={"status": "closed"}).json() == []


# --- Scoring ----------------------------------------------------------------------------------------


def test_scoring_a_single_transaction(client, db_session):
    factory.baseline(db_session)
    factory.takeover_transaction(db_session)
    alert = client.post("/fraud/transactions/TX-900001/score").json()
    assert alert["risk_level"] == "high"
    assert alert["case_id"]


def test_scoring_the_same_transaction_twice_is_a_conflict(client, case):
    assert client.post("/fraud/transactions/TX-900001/score").status_code == 409


def test_scoring_the_backlog(client, db_session):
    factory.baseline(db_session)
    factory.takeover_transaction(db_session)
    result = client.post("/fraud/score", json={}).json()

    assert result["scored"] == db_session.query(models.Transaction).count()
    assert result["alerts"] == result["scored"]
    assert result["cases"] >= 1
    assert result["auto_closed"] > 0


# --- Model registry and audit -------------------------------------------------------------------------


def test_training_without_data_is_a_conflict_not_a_crash(client):
    response = client.post("/fraud/model/train", json={})
    assert response.status_code == 409
    assert "labelled transactions" in response.json()["detail"]


def test_activating_an_unknown_version_is_404(client):
    assert client.post("/fraud/model/versions/nope/activate").status_code == 404


def test_the_drift_report_says_when_it_cannot_run(client):
    assert client.get("/fraud/model/drift").json()["available"] is False


def test_the_audit_trail_is_queryable_and_verifiable(client, case):
    verification = client.get("/fraud/audit/verify").json()
    assert verification["valid"] is True

    entries = client.get("/fraud/audit", params={"entity_id": case.id}).json()
    assert {entry["action"] for entry in entries} >= {"case_opened"}

    agent_entries = client.get("/fraud/audit", params={"actor": "agent:hypothesis"}).json()
    assert len(agent_entries) == 1


def test_generating_data_refuses_to_overwrite_without_reset(client, case):
    response = client.post("/fraud/data/generate", json={"customers": 10, "days": 30, "reset": False})
    assert response.status_code == 409
    assert "reset=true" in response.json()["detail"]


def test_feedback_summary_is_exposed(client, case):
    client.post(f"/fraud/cases/{case.id}/decide", json={"decision": "fraud_confirmed", "analyst": "priya"})
    body = client.get("/fraud/feedback/summary").json()
    assert body["confirmed_fraud"] == 1
    assert body["precision"] == 1.0
