"""The investigation agent contract.

An investigation is a fixed sequence of small, single-purpose agents. Each one is handed the same
read-only `InvestigationContext` - the transaction, the customer's point-in-time history, the
features and signals, the external intelligence and the detector output - and returns one section
of the case file.

Agents are deliberately narrow and mostly deterministic. Only the narrative agent calls the LLM,
and only to phrase findings the other agents already established; scores, hypotheses, triage and
recommended actions are all computed in code, so a case can be re-derived and defended later.

Every agent that runs is written to the audit trail as `agent:<name>`.
"""
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Protocol

from sqlalchemy.orm import Session

from app.fraud_investigation import models
from app.fraud_investigation.detection.graph import EntityGraph
from app.fraud_investigation.features import FeatureVector, Signal
from app.fraud_investigation.history import CustomerHistory, TxnRecord
from app.fraud_investigation.intel import IntelContext


@dataclass
class InvestigationContext:
    """Everything the agents may look at. Built once per investigation and never mutated by them."""

    db: Session
    alert: models.FraudAlert
    transaction: models.Transaction
    record: TxnRecord
    customer: models.Customer
    history: CustomerHistory
    features: FeatureVector
    signals: List[Signal]
    intel: IntelContext
    scoring: dict
    rule_hits: List[dict]
    components: Dict[str, Optional[float]]
    counterparty: Optional[models.Counterparty] = None
    graph: Optional[EntityGraph] = None
    ml_explanation: Optional[List[dict]] = None
    model_version: Optional[str] = None
    # Filled in as the run proceeds, so later agents can build on earlier sections.
    sections: Dict[str, "AgentResult"] = field(default_factory=dict)

    @property
    def signal_codes(self) -> set:
        return {signal.code for signal in self.signals}

    @property
    def rule_ids(self) -> set:
        return {hit["id"] for hit in self.rule_hits}

    def feature(self, name: str) -> float:
        return float(self.features.values.get(name, 0.0))

    def section_data(self, name: str) -> dict:
        result = self.sections.get(name)
        return result.data if result else {}

    def describe_device(self, device_id: Optional[str]) -> str:
        if not device_id:
            return "none"
        device = self.db.get(models.Device, device_id)
        return f"{device.model} ({device_id})" if device and device.model else device_id


@dataclass
class AgentResult:
    """One section of the case file."""

    name: str
    title: str
    summary: str
    findings: List[str] = field(default_factory=list)
    data: dict = field(default_factory=dict)
    # How much this agent found to say, 0-1. Used to order the case file and to tell an analyst
    # which sections are worth reading first - never folded back into the risk score.
    confidence: float = 1.0

    def to_dict(self) -> dict:
        return {
            "agent": self.name,
            "title": self.title,
            "summary": self.summary,
            "findings": self.findings,
            "data": self.data,
            "confidence": round(self.confidence, 2),
        }


class Agent(Protocol):
    name: str
    title: str

    def run(self, ctx: InvestigationContext) -> AgentResult: ...
