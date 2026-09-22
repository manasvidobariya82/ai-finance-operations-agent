"""API schemas for the fraud investigation endpoints."""
from datetime import datetime
from typing import Dict, List, Optional

from pydantic import BaseModel, Field


class ORMModel(BaseModel):
    class Config:
        from_attributes = True


# --- Alerts ------------------------------------------------------------------------------------


class AlertOut(ORMModel):
    id: str
    transaction_id: str
    customer_id: str
    account_id: str
    created_at: Optional[datetime] = None
    risk_score: int
    risk_level: str
    components: dict
    reasons: List[str]
    signals: List[dict]
    rule_hits: List[dict]
    ml_explanation: Optional[List[dict]] = None
    model_version: Optional[str] = None
    triage_decision: str
    status: str
    case_id: Optional[str] = None


class AlertSummaryOut(ORMModel):
    """List view: everything a queue row needs, without the feature and signal payloads."""

    id: str
    transaction_id: str
    customer_id: str
    created_at: Optional[datetime] = None
    risk_score: int
    risk_level: str
    triage_decision: str
    status: str
    case_id: Optional[str] = None
    reasons: List[str]


# --- Cases -------------------------------------------------------------------------------------


class CaseSummaryOut(ORMModel):
    id: str
    alert_id: str
    customer_id: str
    account_id: str
    transaction_id: str
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    status: str
    priority: str
    risk_score: int
    risk_level: str
    primary_hypothesis: Optional[str] = None
    fraud_type: Optional[str] = None
    summary: Optional[str] = None
    assigned_to: Optional[str] = None
    decision: Optional[str] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    alert_ids: List[str] = Field(default_factory=list)


class CaseNoteOut(ORMModel):
    id: int
    case_id: str
    author: str
    body: str
    created_at: Optional[datetime] = None


class CaseOut(CaseSummaryOut):
    case_file: dict
    actions: List[dict] = Field(default_factory=list)
    decision_notes: Optional[str] = None
    notes: List[CaseNoteOut] = Field(default_factory=list)


class AssignRequest(BaseModel):
    analyst: str


class NoteRequest(BaseModel):
    author: str
    body: str


class EscalateRequest(BaseModel):
    analyst: str
    reason: str


class DecisionRequest(BaseModel):
    decision: str = Field(description="fraud_confirmed / false_positive / inconclusive")
    analyst: str
    notes: Optional[str] = None
    actions_taken: List[str] = Field(
        default_factory=list,
        description="Which recommended actions the analyst confirmed. Only these are applied.",
    )


# --- Detection runs, models, audit --------------------------------------------------------------


class ScoreRequest(BaseModel):
    limit: Optional[int] = Field(default=None, ge=1, description="Score at most this many unscored transactions")


class ScoreResult(BaseModel):
    scored: int
    alerts: int
    cases: int
    auto_closed: int
    by_level: Dict[str, int]
    model_version: Optional[str] = None


class TrainRequest(BaseModel):
    notes: Optional[str] = None
    activate: bool = True


class ModelVersionOut(ORMModel):
    id: int
    version: str
    created_at: Optional[datetime] = None
    algorithm: str
    feature_names: List[str]
    metrics: dict
    training_rows: int
    feedback_rows: int
    is_active: bool
    notes: Optional[str] = None


class GenerateDataRequest(BaseModel):
    customers: int = Field(default=200, ge=10, le=2000)
    days: int = Field(default=90, ge=14, le=365)
    seed: int = 7
    reset: bool = Field(default=True, description="Delete existing fraud data first")


class AuditEntryOut(ORMModel):
    id: int
    timestamp: datetime
    actor: str
    action: str
    entity_type: str
    entity_id: str
    details: Optional[dict] = None
    hash: str
    prev_hash: str


class TransactionOut(ORMModel):
    id: str
    account_id: str
    customer_id: str
    counterparty_id: Optional[str] = None
    amount: float
    currency: str
    timestamp: datetime
    txn_type: str
    payment_method: Optional[str] = None
    channel: Optional[str] = None
    device_id: Optional[str] = None
    ip_address: Optional[str] = None
    city: Optional[str] = None
    country: Optional[str] = None
    status: str
    is_fraud: Optional[bool] = None


class DashboardOut(BaseModel):
    data_available: bool
    customers: int
    transactions: int
    scored_transactions: int
    unscored_transactions: int
    alerts_by_level: Dict[str, int]
    open_cases: int
    closed_cases: int
    cases_by_priority: Dict[str, int]
    cases_by_hypothesis: Dict[str, int]
    amount_at_risk: float
    active_model: Optional[str] = None
    model_metrics: Optional[dict] = None
    feedback: dict
    audit_entries: int
