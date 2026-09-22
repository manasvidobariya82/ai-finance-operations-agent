"""Deterministic risk scoring: combines the detector outputs into one 0-100 score and level.

The LLM never touches this. The combination is a fixed, documented formula, so the same inputs
always give the same score and every point of it can be attributed to a component.
"""
from typing import Dict, List, Optional

from app.config import settings

COMPONENT_WEIGHTS = {"ml": 0.35, "rules": 0.2, "graph": 0.15, "behavior": 0.15, "anomaly": 0.15}
COMPONENT_LABELS = {
    "ml": "Supervised ML (XGBoost)",
    "rules": "Rule engine",
    "graph": "Graph / network risk",
    "behavior": "Behavioural deviation",
    "anomaly": "Anomaly detection (Isolation Forest)",
}
# A single very confident detector shouldn't be averaged away by quiet ones: the score is at least
# this fraction of the strongest of the ML model and the rule engine.
STRONG_DETECTOR_FACTOR = 0.85


def risk_level(score: int) -> str:
    if score < settings.fraud_low_risk_max:
        return "low"
    if score > settings.fraud_high_risk_min:
        return "high"
    return "medium"


def combine(components: Dict[str, Optional[float]], rule_hits: List[dict]) -> dict:
    available = {name: value for name, value in components.items() if value is not None}
    total_weight = sum(COMPONENT_WEIGHTS[name] for name in available)
    breakdown = [
        {
            "component": name,
            "label": COMPONENT_LABELS[name],
            "score": round(value, 3),
            "weight": round(COMPONENT_WEIGHTS[name] / total_weight, 3),
            "contribution": round(COMPONENT_WEIGHTS[name] * value / total_weight, 3),
        }
        for name, value in available.items()
    ]
    weighted = sum(item["contribution"] for item in breakdown)

    candidates = {"weighted_average": weighted}
    strongest = max((name for name in ("ml", "rules") if name in available), key=available.get, default=None)
    if strongest:
        candidates[f"strong_{strongest}"] = STRONG_DETECTOR_FACTOR * available[strongest]
    floor_hit = max(rule_hits, key=lambda h: h["floor"], default=None)
    if floor_hit and floor_hit["floor"] > 0:
        candidates[f"floor_{floor_hit['id']}"] = floor_hit["floor"]

    method = max(candidates, key=candidates.get)
    score = int(round(min(1.0, candidates[method]) * 100))
    explanations = {
        "weighted_average": "Weighted average of all detector scores",
        f"strong_{strongest}": f"{COMPONENT_LABELS.get(strongest, '')} is highly confident "
        f"({STRONG_DETECTOR_FACTOR:.0%} of its score is used as a minimum)",
    }
    if floor_hit:
        explanations[f"floor_{floor_hit['id']}"] = f"Critical rule {floor_hit['id']} ({floor_hit['name']}) sets a minimum score"

    return {
        "risk_score": score,
        "risk_level": risk_level(score),
        "breakdown": sorted(breakdown, key=lambda item: -item["contribution"]),
        "weighted_average": round(weighted, 3),
        "method": method,
        "method_explanation": explanations.get(method, method),
        "candidates": {name: round(value, 3) for name, value in candidates.items()},
    }


def triage(level: str) -> str:
    """Low risk is auto-closed (kept for monitoring); medium and high go to investigation.
    Detection never blocks anything by itself - actions only follow a human decision."""
    return "auto_close" if level == "low" else "investigate"
