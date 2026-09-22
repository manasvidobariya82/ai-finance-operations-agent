"""Behavioural profiling: what is normal for this customer, and how far the current transaction
deviates from it. Used as a detection component and by the behavioural intelligence agent."""
import math
from collections import Counter
from datetime import timedelta
from typing import Callable, Dict, Optional

from app.fraud_investigation.features import money
from app.fraud_investigation.history import CustomerHistory, TxnRecord

PROFILE_WINDOW = timedelta(days=90)

# Relative importance of each behavioural dimension in the deviation score (sums to 1).
DIMENSION_WEIGHTS = {
    "amount": 0.3,
    "device": 0.2,
    "location": 0.2,
    "beneficiary": 0.15,
    "time_of_day": 0.1,
    "payment_method": 0.05,
}


def _percentile(sorted_values, pct: float):
    if not sorted_values:
        return None
    k = (len(sorted_values) - 1) * pct
    lo, hi = math.floor(k), math.ceil(k)
    return sorted_values[lo] + (sorted_values[hi] - sorted_values[lo]) * (k - lo)


def build_profile(history: CustomerHistory, txn: TxnRecord) -> dict:
    txns = [t for t in history.transactions_before(txn.timestamp, PROFILE_WINDOW) if t.id != txn.id]
    events = history.events_before(txn.timestamp, PROFILE_WINDOW)
    amounts = sorted(t.amount for t in txns)
    hours = sorted(t.timestamp.hour for t in txns)

    countries = Counter(t.country for t in txns if t.country)
    countries.update(e.country for e in events if e.country and e.event_type == "login_success")
    cities = Counter(t.city for t in txns if t.city)
    devices = Counter(t.device_id for t in txns if t.device_id)
    devices.update(e.device_id for e in events if e.device_id and e.event_type == "login_success")

    return {
        "window_days": PROFILE_WINDOW.days,
        "transaction_count": len(txns),
        "amount_p10": _percentile(amounts, 0.1),
        "amount_p50": _percentile(amounts, 0.5),
        "amount_p90": _percentile(amounts, 0.9),
        "amount_max": amounts[-1] if amounts else None,
        "hour_from": int(_percentile(hours, 0.05)) if hours else None,
        "hour_to": int(_percentile(hours, 0.95)) if hours else None,
        "countries": dict(countries),
        "cities": dict(cities.most_common(3)),
        "devices": dict(devices),
        "beneficiaries": sorted({t.counterparty_id for t in txns if t.txn_type == "transfer" and t.counterparty_id}),
        "payment_methods": dict(Counter(t.payment_method for t in txns if t.payment_method)),
    }


def assess_deviation(
    txn: TxnRecord, profile: dict, describe_device: Callable[[Optional[str]], str] = lambda d: d or "none"
) -> dict:
    """Score 0-1 for how far `txn` departs from `profile`, with a per-dimension breakdown."""
    dims: Dict[str, dict] = {}

    p10, p90 = profile["amount_p10"], profile["amount_p90"]
    if p90:
        ratio = txn.amount / p90
        score = min(1.0, math.log10(ratio) / math.log10(8)) if ratio > 1 else 0.0
        normal = f"{money(p10)}–{money(p90)}"
    else:
        score, normal = 0.3, "no history"
    dims["amount"] = {"normal": normal, "current": money(txn.amount), "score": round(max(score, 0.0), 2)}

    if txn.device_id:
        known = txn.device_id in profile["devices"]
        usual = ", ".join(describe_device(d) for d in list(profile["devices"])[:2]) or "none"
        dims["device"] = {
            "normal": usual,
            "current": describe_device(txn.device_id) + ("" if known else " (new)"),
            "score": 0.0 if known else 0.8,
        }
    else:
        dims["device"] = {"normal": "-", "current": "card present (no device)", "score": 0.0}

    countries = profile["countries"]
    if txn.country and countries and txn.country not in countries:
        location_score = 1.0
    elif txn.city and profile["cities"] and txn.city not in profile["cities"]:
        location_score = 0.4
    else:
        location_score = 0.0
    dims["location"] = {
        "normal": ", ".join(profile["cities"]) or "unknown",
        "current": f"{txn.city}, {txn.country}" if txn.city else (txn.country or "unknown"),
        "score": location_score,
    }

    if txn.txn_type == "transfer":
        known_beneficiary = txn.counterparty_id in profile["beneficiaries"]
        dims["beneficiary"] = {
            "normal": f"{len(profile['beneficiaries'])} known beneficiaries",
            "current": "known beneficiary" if known_beneficiary else "new beneficiary",
            "score": 0.0 if known_beneficiary else 0.7,
        }
    else:
        dims["beneficiary"] = {"normal": "-", "current": txn.txn_type.replace("_", " "), "score": 0.0}

    hour_from, hour_to = profile["hour_from"], profile["hour_to"]
    hour = txn.timestamp.hour
    if hour_from is None:
        time_score, normal_time = 0.2, "no history"
    else:
        outside = hour < hour_from or hour > hour_to
        time_score = (0.9 if hour < 6 else 0.5) if outside else 0.0
        normal_time = f"{hour_from:02d}:00–{hour_to:02d}:59"
    dims["time_of_day"] = {"normal": normal_time, "current": f"{txn.timestamp:%H:%M}", "score": time_score}

    methods = profile["payment_methods"]
    new_method = bool(txn.payment_method and methods and txn.payment_method not in methods)
    dims["payment_method"] = {
        "normal": ", ".join(methods) or "-",
        "current": txn.payment_method or "-",
        "score": 0.8 if new_method else 0.0,
    }

    score = sum(DIMENSION_WEIGHTS[name] * d["score"] for name, d in dims.items())
    return {
        "score": round(score, 3),
        "level": "high" if score >= 0.55 else "medium" if score >= 0.3 else "low",
        "dimensions": dims,
    }
