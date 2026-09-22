"""Model training and the model registry.

Trains the two models `detection/ml.py` serves:

* XGBoost classifier - supervised, learns from labelled history (chargebacks, confirmed fraud,
  and analyst case decisions fed back through `FraudFeedback`).
* Isolation Forest - unsupervised, trained on legitimate rows only, so it flags "unlike anything
  normal" even for fraud patterns that never appear in the labels.

Both are fitted on point-in-time features (`features.compute_features` over `CustomerHistory`) -
the same code path that runs at serving time, so a feature can never be computed from data that
did not exist yet when the transaction happened.

The train/test split is chronological, not random: a random split would let the model learn from a
customer's future behaviour and report accuracy it cannot reproduce in production.
"""
import os
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sklearn.metrics import average_precision_score, confusion_matrix, precision_recall_fscore_support, roc_auc_score
from sqlalchemy.orm import Session

from app.config import settings
from app.fraud_investigation import audit, models
from app.fraud_investigation.clock import now
from app.fraud_investigation.detection import ml
from app.fraud_investigation.detection.ml import ANOMALY_FEATURES, ModelBundle
from app.fraud_investigation.features import FEATURE_NAMES, FeatureVector, compute_features
from app.fraud_investigation.history import load_all_histories

# Chronological split: the earliest 75% of transactions train, the latest 25% evaluate.
TRAIN_FRACTION = 0.75
PSI_BINS = 10
# Below these the labels cannot support a meaningful model; training refuses rather than register a
# version that would score nearly every transaction the same.
MIN_ROWS = 200
MIN_POSITIVES = 15
ANOMALY_CONTAMINATION = 0.02


class NotEnoughData(RuntimeError):
    """Raised when the labelled history is too small or too one-sided to train on."""


@dataclass
class TrainingData:
    vectors: List[FeatureVector]
    labels: np.ndarray
    timestamps: List[datetime]
    transaction_ids: List[str]

    def __len__(self) -> int:
        return len(self.vectors)

    def matrix(self) -> np.ndarray:
        return np.array([fv.as_list() for fv in self.vectors], dtype=float)


def feedback_labels(db: Session) -> Dict[str, bool]:
    """Analyst decisions from closed cases, as label overrides keyed by transaction.

    A later decision on the same transaction supersedes an earlier one, so the model always learns
    from the most recent human judgement. `inconclusive` decisions store a NULL label and are
    skipped - they are not evidence either way.
    """
    rows = (
        db.query(models.FraudFeedback)
        .filter(models.FraudFeedback.label.isnot(None))
        .order_by(models.FraudFeedback.id)
        .all()
    )
    return {row.transaction_id: bool(row.label) for row in rows}


def build_training_data(db: Session, overrides: Optional[Dict[str, bool]] = None) -> TrainingData:
    """Compute point-in-time features for every labelled transaction in the database."""
    overrides = overrides or {}
    histories, network = load_all_histories(db)

    rows: List[Tuple[datetime, str, FeatureVector, int]] = []
    for history in histories.values():
        for txn in history.transactions:
            label = overrides.get(txn.id, txn.is_fraud)
            if label is None:
                continue
            rows.append((txn.timestamp, txn.id, compute_features(txn, history, network), int(bool(label))))

    rows.sort(key=lambda row: (row[0], row[1]))
    return TrainingData(
        vectors=[row[2] for row in rows],
        labels=np.array([row[3] for row in rows], dtype=int),
        timestamps=[row[0] for row in rows],
        transaction_ids=[row[1] for row in rows],
    )


def _reference_stats(matrix: np.ndarray, names: List[str]) -> dict:
    """Per-feature bin edges and the training-time share of rows in each bin.

    Quantile edges (rather than equal width) keep the bins populated for the heavily skewed
    features - most of them are zero for the overwhelming majority of transactions.
    """
    stats = {}
    for i, name in enumerate(names):
        column = matrix[:, i]
        edges = np.unique(np.quantile(column, np.linspace(0, 1, PSI_BINS + 1)))
        if len(edges) < 2:  # constant feature - nothing to compare against later
            stats[name] = {"edges": [float(column[0])], "proportions": [1.0]}
            continue
        counts, _ = np.histogram(column, bins=edges)
        stats[name] = {
            "edges": [float(edge) for edge in edges],
            "proportions": [float(count) / len(column) for count in counts],
        }
    return stats


def population_stability_index(reference: dict, matrix: np.ndarray, names: List[str]) -> Dict[str, float]:
    """PSI per feature: how far the current distribution has moved from the training one.

    Convention: < 0.1 stable, 0.1-0.25 moderate shift, > 0.25 significant shift (retrain).
    """
    epsilon = 1e-6
    psi: Dict[str, float] = {}
    for i, name in enumerate(names):
        ref = reference.get(name)
        if not ref or len(ref["edges"]) < 2:
            continue
        counts, _ = np.histogram(matrix[:, i], bins=np.array(ref["edges"], dtype=float))
        current = np.clip(counts / max(len(matrix), 1), epsilon, None)
        expected = np.clip(np.array(ref["proportions"], dtype=float), epsilon, None)
        psi[name] = float(np.sum((current - expected) * np.log(current / expected)))
    return psi


def _metrics(y_true: np.ndarray, probabilities: np.ndarray, threshold: float = 0.5) -> dict:
    predicted = (probabilities >= threshold).astype(int)
    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true, predicted, average="binary", zero_division=0
    )
    both_classes = len(np.unique(y_true)) > 1
    tn, fp, fn, tp = confusion_matrix(y_true, predicted, labels=[0, 1]).ravel()
    return {
        "rows": int(len(y_true)),
        "positives": int(y_true.sum()),
        "threshold": threshold,
        "precision": round(float(precision), 4),
        "recall": round(float(recall), 4),
        "f1": round(float(f1), 4),
        "roc_auc": round(float(roc_auc_score(y_true, probabilities)), 4) if both_classes else None,
        "pr_auc": round(float(average_precision_score(y_true, probabilities)), 4) if both_classes else None,
        "true_positives": int(tp),
        "false_positives": int(fp),
        "true_negatives": int(tn),
        "false_negatives": int(fn),
        # What an operations team actually feels: the share of traffic the model would surface.
        "alert_rate": round(float(predicted.mean()), 4) if len(predicted) else 0.0,
    }


def _fit(data: TrainingData, matrix: np.ndarray, train_idx: np.ndarray):
    x_train, y_train = matrix[train_idx], data.labels[train_idx]
    positives = int(y_train.sum())
    negatives = len(y_train) - positives

    classifier = xgb.XGBClassifier(
        n_estimators=250,
        max_depth=5,
        learning_rate=0.08,
        subsample=0.9,
        colsample_bytree=0.8,
        min_child_weight=2,
        reg_lambda=1.5,
        # Fraud is a few percent of traffic; without this the model can call everything legitimate
        # and still look accurate.
        scale_pos_weight=max(1.0, negatives / max(positives, 1)),
        eval_metric="aucpr",
        tree_method="hist",
        random_state=7,
    )
    classifier.fit(x_train, y_train)

    anomaly_rows = [int(i) for i in train_idx if data.labels[i] == 0]
    anomaly_columns = [FEATURE_NAMES.index(name) for name in ANOMALY_FEATURES]
    legit = matrix[np.ix_(anomaly_rows, anomaly_columns)]
    anomaly_model = IsolationForest(
        n_estimators=200, contamination=ANOMALY_CONTAMINATION, random_state=7, n_jobs=-1
    )
    anomaly_model.fit(legit)
    # `ModelBundle.anomaly_score` reports "share of legitimate traffic less anomalous than this",
    # which needs the sorted training distribution to compare against.
    anomaly_reference = np.sort(-anomaly_model.score_samples(legit))
    return classifier, anomaly_model, anomaly_reference


def train(db: Session, notes: Optional[str] = None, activate: bool = True) -> models.FraudModelVersion:
    """Train both models on the current data, write the artifact, and register the version."""
    overrides = feedback_labels(db)
    data = build_training_data(db, overrides)

    if len(data) < MIN_ROWS:
        raise NotEnoughData(f"Need at least {MIN_ROWS} labelled transactions to train, found {len(data)}")
    positives = int(data.labels.sum())
    if positives < MIN_POSITIVES:
        raise NotEnoughData(
            f"Need at least {MIN_POSITIVES} confirmed-fraud transactions to train, found {positives}"
        )

    matrix = data.matrix()
    split = int(len(data) * TRAIN_FRACTION)
    train_idx, test_idx = np.arange(split), np.arange(split, len(data))
    holdout = "chronological"
    if data.labels[train_idx].sum() == 0 or data.labels[test_idx].sum() == 0:
        # All the fraud sits on one side of the time split. Evaluating there would report metrics
        # computed on a single class, so fall back to in-sample and label the metrics as such.
        train_idx = test_idx = np.arange(len(data))
        holdout = "in_sample"

    classifier, anomaly_model, anomaly_reference = _fit(data, matrix, train_idx)
    metrics = _metrics(data.labels[test_idx], classifier.predict_proba(matrix[test_idx])[:, 1])
    metrics.update(
        holdout=holdout,
        train_rows=int(len(train_idx)),
        train_positives=int(data.labels[train_idx].sum()),
        feedback_labels_applied=len(overrides),
    )

    version = f"fraud-{now():%Y%m%d-%H%M%S}"
    os.makedirs(settings.fraud_model_dir, exist_ok=True)
    artifact_path = os.path.join(settings.fraud_model_dir, f"{version}.joblib")
    joblib.dump(
        ModelBundle(
            version=version,
            classifier=classifier,
            anomaly_model=anomaly_model,
            anomaly_reference=anomaly_reference,
            feature_names=list(FEATURE_NAMES),
            anomaly_features=list(ANOMALY_FEATURES),
        ),
        artifact_path,
    )

    record = models.FraudModelVersion(
        version=version,
        algorithm="XGBClassifier + IsolationForest",
        feature_names=list(FEATURE_NAMES),
        metrics=metrics,
        reference_stats=_reference_stats(matrix[train_idx], list(FEATURE_NAMES)),
        training_rows=int(len(train_idx)),
        feedback_rows=len(overrides),
        artifact_path=artifact_path,
        is_active=False,
        notes=notes,
    )
    with audit.write_section(db):
        db.add(record)
        db.flush()
        audit.record(
            db, "system", "model_trained", "fraud_model", version,
            {"metrics": metrics, "training_rows": record.training_rows, "feedback_rows": len(overrides)},
        )
    if activate:
        activate_version(db, version)
    return record


def activate_version(db: Session, version: str) -> models.FraudModelVersion:
    record = db.query(models.FraudModelVersion).filter(models.FraudModelVersion.version == version).first()
    if not record:
        raise ValueError(f"Unknown model version {version}")
    with audit.write_section(db):
        db.query(models.FraudModelVersion).filter(models.FraudModelVersion.is_active.is_(True)).update(
            {"is_active": False}
        )
        record.is_active = True
        audit.record(db, "system", "model_activated", "fraud_model", version, {"metrics": record.metrics})
    # The bundle cache is keyed by version, so a rollback to a previously active version must
    # re-read the artifact from disk rather than serve a stale in-process copy.
    ml.clear_cache()
    return record


def drift_report(db: Session, days: int = 14) -> dict:
    """Compare recent traffic against the active model's training distribution (PSI)."""
    record = ml.active_model_record(db)
    if not record:
        return {"available": False, "reason": "No active model"}

    cutoff = now() - timedelta(days=days)
    histories, network = load_all_histories(db)
    vectors = [
        compute_features(txn, history, network)
        for history in histories.values()
        for txn in history.transactions
        if txn.timestamp >= cutoff
    ]
    if len(vectors) < 50:
        return {"available": False, "reason": f"Only {len(vectors)} transactions in the last {days} days"}

    matrix = np.array([fv.as_list() for fv in vectors], dtype=float)
    psi = population_stability_index(record.reference_stats, matrix, list(FEATURE_NAMES))
    worst = max(psi.values(), default=0.0)
    shifted = {name: round(value, 4) for name, value in psi.items() if value >= 0.1}
    return {
        "available": True,
        "model_version": record.version,
        "window_days": days,
        "rows_compared": len(vectors),
        "max_psi": round(float(worst), 4),
        "status": "significant_shift" if worst >= 0.25 else "moderate_shift" if worst >= 0.1 else "stable",
        "shifted_features": dict(sorted(shifted.items(), key=lambda item: -item[1])),
        "retrain_recommended": worst >= 0.25,
    }
