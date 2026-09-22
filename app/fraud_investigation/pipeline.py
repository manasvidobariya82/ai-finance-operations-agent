"""End-to-end detection and investigation for one transaction.

    transaction
       -> point-in-time features + named signals
       -> five detectors (ML, rules, graph, behaviour, anomaly)
       -> deterministic score combination + triage
       -> alert
       -> [medium/high only] investigation agents -> case

Low-risk alerts are stored and auto-closed rather than discarded: they are the denominator for
every precision measurement later, and an auto-closed alert that turns out to be fraud is the only
way to find out what the detectors are missing.

Nothing in this module blocks, holds or freezes anything. It produces an assessment and, where
warranted, a case for a human to decide on.
"""
import logging
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from sqlalchemy import func
from sqlalchemy.orm import Session

from app.fraud_investigation import agents, audit, models
from app.fraud_investigation.agents.base import InvestigationContext
from app.fraud_investigation.clock import now
from app.fraud_investigation.detection import ml
from app.fraud_investigation.detection.behavior import assess_deviation, build_profile
from app.fraud_investigation.detection.graph import EntityGraph
from app.fraud_investigation.detection.ml import ModelBundle
from app.fraud_investigation.detection.rules import RULES_VERSION, evaluate_rules, rule_score
from app.fraud_investigation.features import FeatureVector, Signal, compute_features, extract_signals
from app.fraud_investigation.history import (
    CustomerHistory,
    NetworkLookup,
    SqlNetworkLookup,
    TxnRecord,
    load_all_histories,
    load_customer_history,
    txn_record,
)
from app.fraud_investigation.intel import IntelContext, transaction_intel
from app.fraud_investigation.scoring import combine, triage
from app.fraud_investigation.synthetic import next_id

logger = logging.getLogger("uvicorn.error")

CASE_ID_START = 10001
# A second alert on the same customer inside this window joins the open case instead of starting a
# new one - an attack in progress is one investigation, not five.
CASE_LINK_WINDOW = timedelta(hours=48)


class AlreadyScored(RuntimeError):
    """Raised when a transaction already has an alert."""


@dataclass
class Assessment:
    """Everything the detection layer produced for one transaction."""

    transaction: models.Transaction
    record: TxnRecord
    history: CustomerHistory
    features: FeatureVector
    signals: List[Signal]
    intel: IntelContext
    rule_hits: List[dict]
    components: Dict[str, Optional[float]]
    scoring: dict
    ml_explanation: Optional[List[dict]]
    model_version: Optional[str]
    graph: Optional[EntityGraph]

    @property
    def risk_score(self) -> int:
        return self.scoring["risk_score"]

    @property
    def risk_level(self) -> str:
        return self.scoring["risk_level"]


def next_case_id(db: Session) -> str:
    latest = db.query(func.max(models.FraudCase.id)).filter(models.FraudCase.id.like("CASE-%")).scalar()
    return f"CASE-{int(latest.split('-')[1]) + 1 if latest else CASE_ID_START}"


def assess(
    db: Session,
    transaction: models.Transaction,
    *,
    history: Optional[CustomerHistory] = None,
    network: Optional[NetworkLookup] = None,
    graph: Optional[EntityGraph] = None,
    bundle: Optional[ModelBundle] = None,
    model_version: Optional[str] = None,
    features: Optional[FeatureVector] = None,
    anomaly_score: Optional[float] = None,
) -> Assessment:
    """Run every detector over one transaction and combine the results.

    The optional arguments let a batch run share the expensive objects (all customer histories, the
    entity graph, the loaded model) across thousands of transactions instead of rebuilding them per
    row, and hand back work it has already done in bulk (`features`, `anomaly_score`). Passing none
    of them is the serving path: a handful of indexed queries for this one customer.
    """
    history = history or load_customer_history(db, transaction.customer_id)
    network = network or SqlNetworkLookup(db)
    record = txn_record(db, transaction)

    features = features if features is not None else compute_features(record, history, network)
    signals = extract_signals(record, features)
    intel = transaction_intel(db, transaction)

    rule_hits = evaluate_rules(features.values, intel)
    behaviour = assess_deviation(record, build_profile(history, record))

    if bundle is None:
        model_record = ml.active_model_record(db)
        if model_record:
            bundle = ml.load_bundle(model_record)
            model_version = model_record.version

    components: Dict[str, Optional[float]] = {
        # No trained model yet: the ML and anomaly components drop out and `combine` renormalises
        # the remaining weights, rather than scoring every transaction as if the model said zero.
        "ml": bundle.fraud_probability(features) if bundle else None,
        "rules": rule_score(rule_hits),
        "graph": graph.transaction_risk(
            transaction.customer_id, transaction.device_id, transaction.ip_address, transaction.counterparty_id
        )["score"]
        if graph
        else None,
        "behavior": behaviour["score"],
        "anomaly": anomaly_score if anomaly_score is not None else (bundle.anomaly_score(features) if bundle else None),
    }

    return Assessment(
        transaction=transaction,
        record=record,
        history=history,
        features=features,
        signals=signals,
        intel=intel,
        rule_hits=rule_hits,
        components=components,
        scoring=combine(components, rule_hits),
        ml_explanation=bundle.explain(features) if bundle else None,
        model_version=bundle.version if bundle else model_version,
        graph=graph,
    )


def create_alert(db: Session, assessment: Assessment) -> models.FraudAlert:
    """Persist the assessment as an alert. Caller owns the transaction boundary."""
    transaction = assessment.transaction
    decision = triage(assessment.risk_level)
    alert = models.FraudAlert(
        id=next_id(db, models.FraudAlert, "ALT"),
        transaction_id=transaction.id,
        customer_id=transaction.customer_id,
        account_id=transaction.account_id,
        created_at=now(),
        risk_score=assessment.risk_score,
        risk_level=assessment.risk_level,
        components={
            "scores": {name: value for name, value in assessment.components.items() if value is not None},
            "method": assessment.scoring["method"],
            "method_explanation": assessment.scoring["method_explanation"],
            "weighted_average": assessment.scoring["weighted_average"],
            "candidates": assessment.scoring["candidates"],
            "breakdown": assessment.scoring["breakdown"],
            "rules_version": RULES_VERSION,
        },
        reasons=[signal.description for signal in assessment.signals],
        signals=[signal.to_dict() for signal in assessment.signals],
        features=assessment.features.values,
        rule_hits=assessment.rule_hits,
        ml_explanation=assessment.ml_explanation,
        model_version=assessment.model_version,
        triage_decision=decision,
        status="auto_closed" if decision == "auto_close" else "case_open",
    )
    db.add(alert)
    db.flush()
    audit.record(
        db, "system", "alert_created", "fraud_alert", alert.id,
        {
            "transaction_id": transaction.id,
            "risk_score": alert.risk_score,
            "risk_level": alert.risk_level,
            "triage": decision,
            "rules": [hit["id"] for hit in assessment.rule_hits],
            "model_version": assessment.model_version,
        },
    )
    return alert


def build_context(db: Session, alert: models.FraudAlert, assessment: Assessment) -> InvestigationContext:
    return InvestigationContext(
        db=db,
        alert=alert,
        transaction=assessment.transaction,
        record=assessment.record,
        customer=db.get(models.Customer, assessment.transaction.customer_id),
        history=assessment.history,
        features=assessment.features,
        signals=assessment.signals,
        intel=assessment.intel,
        scoring=assessment.scoring,
        rule_hits=assessment.rule_hits,
        components=assessment.components,
        counterparty=db.get(models.Counterparty, assessment.transaction.counterparty_id)
        if assessment.transaction.counterparty_id
        else None,
        graph=assessment.graph,
        ml_explanation=assessment.ml_explanation,
        model_version=assessment.model_version,
    )


def _open_case_for(db: Session, alert: models.FraudAlert, when: datetime) -> Optional[models.FraudCase]:
    """An already-open case on the same customer that this alert belongs to.

    The window is measured between the *transactions*, not between the rows' `created_at`. Those
    two coincide when transactions are scored as they arrive, but a backfill stamps every alert
    with the same wall clock, which would fold a customer's whole history into a single case.
    """
    linked = models.Transaction.__table__.alias("linked_txn")
    return (
        db.query(models.FraudCase)
        .join(linked, linked.c.id == models.FraudCase.transaction_id)
        .filter(
            models.FraudCase.customer_id == alert.customer_id,
            models.FraudCase.status.in_(("open", "pending_verification", "escalated")),
            linked.c.timestamp >= when - CASE_LINK_WINDOW,
            linked.c.timestamp <= when,
        )
        .order_by(linked.c.timestamp.desc())
        .first()
    )


def investigate(db: Session, alert: models.FraudAlert, assessment: Assessment) -> models.FraudCase:
    """Run the agent pipeline and open (or extend) a case. Caller owns the transaction boundary."""
    existing = _open_case_for(db, alert, assessment.record.timestamp)
    if existing:
        existing.alert_ids = list(existing.alert_ids or []) + [alert.id]
        existing.updated_at = now()
        if alert.risk_score > existing.risk_score:
            existing.risk_score = alert.risk_score
            existing.risk_level = alert.risk_level
            existing.priority = "high" if alert.risk_level == "high" else "medium"
        alert.case_id = existing.id
        alert.status = "linked_to_case"
        audit.record(
            db, "system", "alert_linked_to_case", "fraud_case", existing.id,
            {"alert_id": alert.id, "risk_score": alert.risk_score},
        )
        return existing

    ctx = build_context(db, alert, assessment)
    agents.run_agents(ctx)
    case_file = agents.build_case_file(ctx)

    case = models.FraudCase(
        id=next_case_id(db),
        alert_id=alert.id,
        alert_ids=[alert.id],
        customer_id=alert.customer_id,
        account_id=alert.account_id,
        transaction_id=alert.transaction_id,
        created_at=now(),
        updated_at=now(),
        status="open",
        priority="high" if alert.risk_level == "high" else "medium",
        risk_score=alert.risk_score,
        risk_level=alert.risk_level,
        primary_hypothesis=case_file.get("primary_hypothesis"),
        fraud_type=case_file.get("fraud_type"),
        summary=case_file.get("summary"),
        case_file=case_file,
        actions=case_file.get("recommended_actions", []),
    )
    db.add(case)
    db.flush()

    alert.case_id = case.id
    alert.status = "case_open"
    audit.record(
        db, "system", "case_opened", "fraud_case", case.id,
        {
            "alert_id": alert.id,
            "risk_score": case.risk_score,
            "priority": case.priority,
            "hypothesis": case.primary_hypothesis,
            "narrative_source": case_file.get("narrative_source"),
        },
    )
    return case


def process_transaction(
    db: Session,
    transaction: models.Transaction,
    *,
    history: Optional[CustomerHistory] = None,
    network: Optional[NetworkLookup] = None,
    graph: Optional[EntityGraph] = None,
    bundle: Optional[ModelBundle] = None,
    model_version: Optional[str] = None,
    features: Optional[FeatureVector] = None,
    anomaly_score: Optional[float] = None,
) -> Tuple[models.FraudAlert, Optional[models.FraudCase]]:
    """Score one transaction, raise the alert, and investigate it if triage says so."""
    existing = (
        db.query(models.FraudAlert).filter(models.FraudAlert.transaction_id == transaction.id).first()
    )
    if existing:
        raise AlreadyScored(f"Transaction {transaction.id} already has alert {existing.id}")

    assessment = assess(
        db,
        transaction,
        history=history,
        network=network,
        graph=graph,
        bundle=bundle,
        model_version=model_version,
        features=features,
        anomaly_score=anomaly_score,
    )
    with audit.write_section(db):
        alert = create_alert(db, assessment)
        case = investigate(db, alert, assessment) if alert.triage_decision == "investigate" else None
    return alert, case


def unscored_transactions(db: Session, limit: Optional[int] = None) -> List[models.Transaction]:
    scored = db.query(models.FraudAlert.transaction_id)
    query = (
        db.query(models.Transaction)
        .filter(models.Transaction.id.notin_(scored))
        .order_by(models.Transaction.timestamp)
    )
    return query.limit(limit).all() if limit else query.all()


def score_backlog(db: Session, limit: Optional[int] = None) -> dict:
    """Score every transaction that has no alert yet.

    Two passes. The first computes point-in-time features for the whole batch and scores the
    anomaly model once over all of them, because a single-row Isolation Forest call spends most of
    its time in per-tree dispatch overhead rather than in the trees. The second runs the remaining
    detectors, raises the alerts and investigates whatever triage escalates.

    One entity graph, one loaded model and one bulk history load are shared across the whole run.
    The graph and the external intelligence reflect the database as it is now, rather than as it
    was at each transaction's timestamp - fine for backfilling a demo dataset, but a live
    deployment scores each transaction as it arrives, where "now" and "then" are the same moment.
    """
    pending = unscored_transactions(db, limit)
    if not pending:
        return {"scored": 0, "alerts": 0, "cases": 0, "auto_closed": 0, "by_level": {}}

    model_record = ml.active_model_record(db)
    bundle = ml.load_bundle(model_record) if model_record else None
    graph = EntityGraph.build(db)
    # Every customer's history and the whole network index in two queries, rather than a handful of
    # queries per transaction. Both stay point-in-time: `CustomerHistory` slices by timestamp and
    # `InMemoryNetworkIndex` bisects first-use times, so a row never sees its own future.
    histories, network = load_all_histories(db)

    scorable: List[models.Transaction] = []
    vectors: List[FeatureVector] = []
    for transaction in pending:
        history = histories.get(transaction.customer_id)
        if history is None:
            logger.warning("No history for customer %s; skipping %s", transaction.customer_id, transaction.id)
            continue
        scorable.append(transaction)
        vectors.append(compute_features(txn_record(db, transaction), history, network))

    anomalies = bundle.anomaly_scores(vectors) if bundle else [None] * len(vectors)

    counts = {"scored": 0, "alerts": 0, "cases": 0, "auto_closed": 0}
    by_level: Dict[str, int] = {"low": 0, "medium": 0, "high": 0}
    for transaction, features, anomaly in zip(scorable, vectors, anomalies):
        try:
            alert, case = process_transaction(
                db,
                transaction,
                history=histories[transaction.customer_id],
                network=network,
                graph=graph,
                bundle=bundle,
                model_version=model_record.version if model_record else None,
                features=features,
                anomaly_score=anomaly,
            )
        except AlreadyScored:
            continue
        except Exception:
            logger.exception("Failed to score transaction %s", transaction.id)
            db.rollback()
            continue

        counts["scored"] += 1
        counts["alerts"] += 1
        by_level[alert.risk_level] = by_level.get(alert.risk_level, 0) + 1
        if alert.triage_decision == "auto_close":
            counts["auto_closed"] += 1
        elif case is not None and case.alert_id == alert.id:
            counts["cases"] += 1

    return {**counts, "by_level": by_level, "model_version": model_record.version if model_record else None}
