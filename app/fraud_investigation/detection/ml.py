"""Supervised fraud model (XGBoost) + unsupervised anomaly model (Isolation Forest), loaded from the
model registry. Per-prediction explanations are exact TreeSHAP contributions from XGBoost itself."""
import threading
from dataclasses import dataclass
from typing import Dict, List, Optional

import joblib
import numpy as np
import xgboost as xgb
from sklearn.ensemble import IsolationForest
from sqlalchemy.orm import Session

from app.fraud_investigation import models
from app.fraud_investigation.features import FEATURE_LABELS, FEATURE_NAMES, FeatureVector

# Behavioural features the anomaly model looks at. It is trained on legitimate traffic only, so it
# flags "unlike anything normal" regardless of whether that pattern was ever labelled as fraud.
ANOMALY_FEATURES = [
    "log_amount",
    "amount_vs_customer_avg",
    "amount_zscore",
    "device_age_hours",
    "new_device",
    "new_ip",
    "new_country",
    "distance_from_usual_km",
    "failed_logins_24h",
    "minutes_since_password_reset",
    "recipient_is_new",
    "is_night",
    "txn_count_1h",
    "small_txn_count_30m",
    "log_amount_24h",
    "device_shared_customers",
    "counterparty_sender_count",
]


@dataclass
class ModelBundle:
    version: str
    classifier: xgb.XGBClassifier
    anomaly_model: IsolationForest
    # Sorted anomaly scores of legitimate training rows, to turn a raw score into a percentile.
    anomaly_reference: np.ndarray
    feature_names: List[str]
    anomaly_features: List[str]

    def _row(self, values: Dict[str, float], names: List[str]) -> np.ndarray:
        return np.array([[float(values[n]) for n in names]], dtype=float)

    def fraud_probability(self, fv: FeatureVector) -> float:
        return float(self.classifier.predict_proba(self._row(fv.values, self.feature_names))[0, 1])

    def anomaly_score(self, fv: FeatureVector) -> float:
        """Share of legitimate training traffic that is less anomalous than this transaction."""
        raw = -self.anomaly_model.score_samples(self._row(fv.values, self.anomaly_features))[0]
        return float(np.searchsorted(self.anomaly_reference, raw) / len(self.anomaly_reference))

    def anomaly_scores(self, vectors: List[FeatureVector]) -> List[float]:
        """Batched `anomaly_score`.

        Scoring one row walks all 200 trees through scikit-learn's parallel dispatch machinery, and
        that per-tree overhead - not the tree traversal - dominates a single-row call. Passing the
        whole batch as one matrix pays it once instead of once per row, which is what makes
        backfilling a dataset practical.
        """
        if not vectors:
            return []
        matrix = np.array(
            [[float(fv.values[name]) for name in self.anomaly_features] for fv in vectors], dtype=float
        )
        raw = -self.anomaly_model.score_samples(matrix)
        return [float(np.searchsorted(self.anomaly_reference, value) / len(self.anomaly_reference)) for value in raw]

    def explain(self, fv: FeatureVector, top_n: int = 6) -> List[dict]:
        """Top features by |SHAP contribution| (log-odds), positive = pushed towards fraud."""
        matrix = xgb.DMatrix(self._row(fv.values, self.feature_names), feature_names=self.feature_names)
        contribs = self.classifier.get_booster().predict(matrix, pred_contribs=True)[0][:-1]  # last = bias
        order = np.argsort(-np.abs(contribs))[:top_n]
        return [
            {
                "feature": self.feature_names[i],
                "label": FEATURE_LABELS.get(self.feature_names[i], self.feature_names[i]),
                "value": round(float(fv.values[self.feature_names[i]]), 3),
                "contribution": round(float(contribs[i]), 3),
            }
            for i in order
            if abs(contribs[i]) >= 0.01
        ]


_cache: Dict[str, ModelBundle] = {}
_lock = threading.Lock()


def clear_cache() -> None:
    with _lock:
        _cache.clear()


def load_bundle(record: "models.FraudModelVersion") -> ModelBundle:
    with _lock:
        if record.version not in _cache:
            _cache[record.version] = joblib.load(record.artifact_path)
        return _cache[record.version]


def active_model_record(db: Session) -> Optional["models.FraudModelVersion"]:
    return db.query(models.FraudModelVersion).filter(models.FraudModelVersion.is_active.is_(True)).first()


def load_active_model(db: Session) -> Optional[ModelBundle]:
    record = active_model_record(db)
    return load_bundle(record) if record else None


def feature_matrix(vectors: List[FeatureVector], names: List[str] = FEATURE_NAMES) -> np.ndarray:
    return np.array([[float(fv.values[n]) for n in names] for fv in vectors], dtype=float)
