"""REST API for the fraud investigation system.

Long-running operations (data generation, training, backlog scoring) are ordinary sync endpoints.
FastAPI runs those in a worker thread, so one of them does not stall the rest of the API; a
production deployment would move them onto a task queue and return a job id.
"""
import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.orm import Session

from app.db import get_db
from app.fraud_investigation import cases, models, overview, pipeline, schemas, synthetic, training
from app.fraud_investigation import audit as audit_log

logger = logging.getLogger("uvicorn.error")

router = APIRouter(prefix="/fraud", tags=["fraud investigation"])


# --- Data and dashboard --------------------------------------------------------------------------


@router.get("/dashboard", response_model=schemas.DashboardOut)
def get_dashboard(db: Session = Depends(get_db)):
    return overview.dashboard(db)


@router.post("/data/generate")
def generate_data(body: schemas.GenerateDataRequest, db: Session = Depends(get_db)):
    """Generate a synthetic bank: customers, 90 days of traffic, and injected fraud scenarios.

    Development and demo only. `reset=true` wipes the existing fraud data, including the audit log,
    which is why it is a separate, explicit flag rather than the default behaviour of every call.
    """
    if body.reset:
        synthetic.reset(db)
    elif synthetic.has_data(db):
        raise HTTPException(
            status_code=409,
            detail="Fraud data already exists. Pass reset=true to replace it.",
        )
    cfg = synthetic.SyntheticConfig(customers=body.customers, days=body.days, seed=body.seed)
    return synthetic.generate(db, cfg)


# --- Model registry ------------------------------------------------------------------------------


@router.post("/model/train", response_model=schemas.ModelVersionOut)
def train_model(body: schemas.TrainRequest, db: Session = Depends(get_db)):
    try:
        return training.train(db, notes=body.notes, activate=body.activate)
    except training.NotEnoughData as exc:
        raise HTTPException(status_code=409, detail=str(exc))


@router.get("/model/versions", response_model=List[schemas.ModelVersionOut])
def list_model_versions(db: Session = Depends(get_db)):
    return db.query(models.FraudModelVersion).order_by(models.FraudModelVersion.created_at.desc()).all()


@router.post("/model/versions/{version}/activate", response_model=schemas.ModelVersionOut)
def activate_model_version(version: str, db: Session = Depends(get_db)):
    try:
        return training.activate_version(db, version)
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.get("/model/drift")
def model_drift(days: int = Query(default=14, ge=1, le=180), db: Session = Depends(get_db)):
    return training.drift_report(db, days=days)


# --- Detection -----------------------------------------------------------------------------------


@router.post("/score", response_model=schemas.ScoreResult)
def score_backlog(body: schemas.ScoreRequest, db: Session = Depends(get_db)):
    """Score every transaction that has no alert yet, investigating the ones triage escalates."""
    return pipeline.score_backlog(db, limit=body.limit)


@router.post("/transactions/{transaction_id}/score", response_model=schemas.AlertOut)
def score_transaction(transaction_id: str, db: Session = Depends(get_db)):
    transaction = db.get(models.Transaction, transaction_id)
    if not transaction:
        raise HTTPException(status_code=404, detail=f"Transaction {transaction_id} not found")
    try:
        alert, _ = pipeline.process_transaction(db, transaction)
    except pipeline.AlreadyScored as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    return alert


@router.get("/transactions", response_model=List[schemas.TransactionOut])
def list_transactions(
    customer_id: Optional[str] = None,
    is_fraud: Optional[bool] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(models.Transaction)
    if customer_id:
        query = query.filter(models.Transaction.customer_id == customer_id)
    if is_fraud is not None:
        query = query.filter(models.Transaction.is_fraud.is_(is_fraud))
    return query.order_by(models.Transaction.timestamp.desc()).limit(limit).all()


# --- Alerts --------------------------------------------------------------------------------------


@router.get("/alerts", response_model=List[schemas.AlertSummaryOut])
def list_alerts(
    risk_level: Optional[str] = None,
    status: Optional[str] = None,
    customer_id: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(models.FraudAlert)
    if risk_level:
        query = query.filter(models.FraudAlert.risk_level == risk_level)
    if status:
        query = query.filter(models.FraudAlert.status == status)
    if customer_id:
        query = query.filter(models.FraudAlert.customer_id == customer_id)
    return query.order_by(models.FraudAlert.created_at.desc()).limit(limit).all()


@router.get("/alerts/{alert_id}", response_model=schemas.AlertOut)
def get_alert(alert_id: str, db: Session = Depends(get_db)):
    alert = db.get(models.FraudAlert, alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert {alert_id} not found")
    return alert


# --- Cases ---------------------------------------------------------------------------------------


@router.get("/cases", response_model=List[schemas.CaseSummaryOut])
def list_cases(
    status: Optional[str] = None,
    priority: Optional[str] = None,
    assigned_to: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    return cases.list_cases(db, status=status, priority=priority, assigned_to=assigned_to, limit=limit)


@router.get("/cases/{case_id}", response_model=schemas.CaseOut)
def get_case(case_id: str, db: Session = Depends(get_db)):
    try:
        case = cases.get_case(db, case_id)
    except cases.CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    payload = schemas.CaseOut.model_validate(case)
    payload.notes = [schemas.CaseNoteOut.model_validate(note) for note in cases.notes(db, case_id)]
    return payload


@router.post("/cases/{case_id}/assign", response_model=schemas.CaseSummaryOut)
def assign_case(case_id: str, body: schemas.AssignRequest, db: Session = Depends(get_db)):
    return _case_action(lambda: cases.assign(db, case_id, body.analyst))


@router.post("/cases/{case_id}/notes", response_model=schemas.CaseNoteOut)
def add_case_note(case_id: str, body: schemas.NoteRequest, db: Session = Depends(get_db)):
    return _case_action(lambda: cases.add_note(db, case_id, body.author, body.body))


@router.post("/cases/{case_id}/escalate", response_model=schemas.CaseSummaryOut)
def escalate_case(case_id: str, body: schemas.EscalateRequest, db: Session = Depends(get_db)):
    return _case_action(lambda: cases.escalate(db, case_id, body.analyst, body.reason))


@router.post("/cases/{case_id}/decide", response_model=schemas.CaseSummaryOut)
def decide_case(case_id: str, body: schemas.DecisionRequest, db: Session = Depends(get_db)):
    return _case_action(
        lambda: cases.decide(db, case_id, body.decision, body.analyst, body.notes, body.actions_taken)
    )


def _case_action(operation):
    try:
        return operation()
    except cases.CaseNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except cases.InvalidTransition as exc:
        raise HTTPException(status_code=409, detail=str(exc))


# --- Feedback and audit ---------------------------------------------------------------------------


@router.get("/feedback/summary")
def feedback_summary(db: Session = Depends(get_db)):
    return cases.feedback_summary(db)


@router.get("/audit", response_model=List[schemas.AuditEntryOut])
def list_audit(
    entity_id: Optional[str] = None,
    actor: Optional[str] = None,
    limit: int = Query(default=100, ge=1, le=1000),
    db: Session = Depends(get_db),
):
    query = db.query(models.AuditLog)
    if entity_id:
        query = query.filter(models.AuditLog.entity_id == entity_id)
    if actor:
        query = query.filter(models.AuditLog.actor == actor)
    return query.order_by(models.AuditLog.id.desc()).limit(limit).all()


@router.get("/audit/verify")
def verify_audit(db: Session = Depends(get_db)):
    """Recompute the audit hash chain. `valid: false` means a row was edited or deleted."""
    return audit_log.verify(db)
