"""Feature & signal engine: turns a raw transaction plus the customer's point-in-time history into
numeric model features and named, human-readable risk signals.

Nothing downstream (models, rules, agents, the LLM) looks at raw transaction rows directly - they
work from these features and signals.
"""
import math
import statistics
from collections import Counter
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Dict, List, Optional

from app.fraud_investigation.geo import distance_km
from app.fraud_investigation.history import CustomerHistory, NetworkLookup, TxnRecord

FEATURE_NAMES = [
    "log_amount",
    "amount_vs_customer_avg",
    "amount_zscore",
    "has_history",
    "txn_count_30d",
    "account_age_days",
    "device_age_hours",
    "new_device",
    "new_ip",
    "new_country",
    "foreign_country",
    "distance_from_usual_km",
    "failed_logins_24h",
    "password_reset_24h",
    "minutes_since_password_reset",
    "mfa_changed_24h",
    "device_added_24h",
    "beneficiary_added_24h",
    "profile_changed_7d",
    "recipient_is_new",
    "is_transfer",
    "is_card_purchase",
    "is_card_present",
    "hour_of_day",
    "is_night",
    "night_share_90d",
    "txn_count_1h",
    "small_txn_count_30m",
    "log_amount_24h",
    "device_shared_customers",
    "ip_shared_customers",
    "counterparty_sender_count",
    "kyc_verified",
]

FEATURE_LABELS = {
    "log_amount": "Transaction amount",
    "amount_vs_customer_avg": "Amount vs. customer average",
    "amount_zscore": "Amount z-score",
    "has_history": "Has transaction history",
    "txn_count_30d": "Transactions in last 30 days",
    "account_age_days": "Account age",
    "device_age_hours": "Device age for this customer",
    "new_device": "New device",
    "new_ip": "New IP address",
    "new_country": "New country",
    "foreign_country": "Foreign country",
    "distance_from_usual_km": "Distance from usual location",
    "failed_logins_24h": "Failed logins (24h)",
    "password_reset_24h": "Password reset (24h)",
    "minutes_since_password_reset": "Minutes since password reset",
    "mfa_changed_24h": "MFA method changed (24h)",
    "device_added_24h": "Device added (24h)",
    "beneficiary_added_24h": "Beneficiary added (24h)",
    "profile_changed_7d": "Profile changed (7d)",
    "recipient_is_new": "First payment to recipient",
    "is_transfer": "Is a transfer",
    "is_card_purchase": "Is a card purchase",
    "is_card_present": "Card-present (POS)",
    "hour_of_day": "Hour of day",
    "is_night": "Night-time (00:00-05:59)",
    "night_share_90d": "Customer's share of night-time activity",
    "txn_count_1h": "Transactions in previous hour",
    "small_txn_count_30m": "Small transactions in previous 30 min",
    "log_amount_24h": "Amount sent in previous 24h",
    "device_shared_customers": "Other customers on this device",
    "ip_shared_customers": "Other customers on this IP",
    "counterparty_sender_count": "Other customers paying this recipient",
    "kyc_verified": "KYC verified",
}

DEVICE_AGE_CAP_HOURS = 720.0
PASSWORD_RESET_CAP_MINUTES = 7 * 24 * 60.0
SMALL_AMOUNT = 500.0


@dataclass
class Signal:
    code: str
    severity: str  # low / medium / high
    description: str
    value: Optional[float] = None

    def to_dict(self) -> dict:
        return {"code": self.code, "severity": self.severity, "description": self.description, "value": self.value}


@dataclass
class FeatureVector:
    values: Dict[str, float]
    # Human-readable context behind the numbers (customer average, usual city, ...) for signal
    # descriptions and the evidence agent. Not model input.
    context: Dict[str, object] = field(default_factory=dict)

    def as_list(self) -> List[float]:
        return [float(self.values[name]) for name in FEATURE_NAMES]


def money(amount: float, currency: str = "INR") -> str:
    """Format an amount; INR uses Indian digit grouping (1,25,000)."""
    if currency != "INR":
        return f"{amount:,.2f} {currency}"
    whole = int(round(abs(amount)))
    digits = str(whole)
    if len(digits) > 3:
        head, tail = digits[:-3], digits[-3:]
        groups = []
        while len(head) > 2:
            groups.insert(0, head[-2:])
            head = head[:-2]
        if head:
            groups.insert(0, head)
        digits = ",".join(groups + [tail])
    return f"{'-' if amount < 0 else ''}₹{digits}"


def _first_seen(history: CustomerHistory, txn: TxnRecord, attr: str):
    """Earliest time this customer used `attr` (device_id / ip_address / country) before txn."""
    value = getattr(txn, attr)
    if not value:
        return None
    times = [t.timestamp for t in history.transactions_before(txn.timestamp) if getattr(t, attr) == value]
    times += [e.timestamp for e in history.events_before(txn.timestamp) if getattr(e, attr) == value]
    return min(times) if times else None


def compute_features(txn: TxnRecord, history: CustomerHistory, network: NetworkLookup) -> FeatureVector:
    ts = txn.timestamp
    profile = history.profile
    prior_all = [t for t in history.transactions_before(ts) if t.id != txn.id]
    prior_90d = [t for t in prior_all if t.timestamp >= ts - timedelta(days=90)]
    events_24h = history.events_before(ts, timedelta(hours=24))
    events_7d = history.events_before(ts, timedelta(days=7))

    amounts = [t.amount for t in prior_90d]
    has_history = len(amounts) >= 3
    avg = statistics.fmean(amounts) if amounts else txn.amount
    std = statistics.pstdev(amounts) if len(amounts) > 1 else 0.0
    ratio = txn.amount / avg if has_history and avg > 0 else 1.0
    zscore = (txn.amount - avg) / max(std, avg * 0.25, 1.0) if has_history else 0.0

    device_first = _first_seen(history, txn, "device_id")
    if txn.device_id:
        device_age = (ts - device_first).total_seconds() / 3600 if device_first else 0.0
    else:
        device_age = DEVICE_AGE_CAP_HOURS
    ip_first = _first_seen(history, txn, "ip_address")
    country_first = _first_seen(history, txn, "country")

    locations = Counter(t.city for t in prior_90d if t.city)
    locations.update(e.city for e in history.events_before(ts, timedelta(days=90)) if e.city)
    usual_city = locations.most_common(1)[0][0] if locations else profile.home_city
    distance = distance_km(usual_city, txn.city) or 0.0

    resets = [e.timestamp for e in events_7d if e.event_type == "password_reset"]
    minutes_since_reset = (ts - max(resets)).total_seconds() / 60 if resets else PASSWORD_RESET_CAP_MINUTES
    event_counts = Counter(e.event_type for e in events_24h)

    paid_before = {t.counterparty_id for t in prior_all if t.counterparty_id}
    night_share = sum(1 for t in prior_90d if t.timestamp.hour < 6) / len(prior_90d) if prior_90d else 0.0
    last_hour = [t for t in prior_all if t.timestamp >= ts - timedelta(hours=1)]
    last_30m_small = [
        t for t in prior_all if t.timestamp >= ts - timedelta(minutes=30) and t.amount < SMALL_AMOUNT
    ]
    sent_24h = sum(t.amount for t in prior_all if t.timestamp >= ts - timedelta(hours=24))

    counterparty_senders = (
        network.counterparty_senders(txn.counterparty_id, ts, txn.customer_id)
        if txn.counterparty_kind == "beneficiary"
        else 0
    )

    values = {
        "log_amount": math.log1p(txn.amount),
        "amount_vs_customer_avg": min(ratio, 100.0),
        "amount_zscore": max(-5.0, min(zscore, 50.0)),
        "has_history": float(has_history),
        "txn_count_30d": float(sum(1 for t in prior_90d if t.timestamp >= ts - timedelta(days=30))),
        "account_age_days": max(0.0, (ts - profile.account_opened_at).total_seconds() / 86400),
        "device_age_hours": min(device_age, DEVICE_AGE_CAP_HOURS),
        "new_device": float(bool(txn.device_id) and device_age < 24),
        "new_ip": float(bool(txn.ip_address) and (ip_first is None or ts - ip_first < timedelta(hours=24))),
        "new_country": float(
            bool(txn.country) and (country_first is None or ts - country_first < timedelta(hours=24))
        ),
        "foreign_country": float(bool(txn.country and profile.home_country) and txn.country != profile.home_country),
        "distance_from_usual_km": distance,
        "failed_logins_24h": float(event_counts["login_failed"]),
        "password_reset_24h": float(event_counts["password_reset"] > 0),
        "minutes_since_password_reset": min(minutes_since_reset, PASSWORD_RESET_CAP_MINUTES),
        "mfa_changed_24h": float(event_counts["mfa_method_changed"] > 0),
        "device_added_24h": float(event_counts["device_added"] > 0),
        "beneficiary_added_24h": float(event_counts["beneficiary_added"] > 0),
        "profile_changed_7d": float(any(e.event_type == "profile_updated" for e in events_7d)),
        "recipient_is_new": float(bool(txn.counterparty_id) and txn.counterparty_id not in paid_before),
        "is_transfer": float(txn.txn_type == "transfer"),
        "is_card_purchase": float(txn.txn_type == "card_purchase"),
        "is_card_present": float(txn.channel == "pos"),
        "hour_of_day": float(ts.hour),
        "is_night": float(ts.hour < 6),
        "night_share_90d": night_share,
        "txn_count_1h": float(len(last_hour)),
        "small_txn_count_30m": float(len(last_30m_small)),
        "log_amount_24h": math.log1p(sent_24h),
        "device_shared_customers": float(network.device_customers(txn.device_id, ts, txn.customer_id)),
        "ip_shared_customers": float(network.ip_customers(txn.ip_address, ts, txn.customer_id)),
        "counterparty_sender_count": float(counterparty_senders),
        "kyc_verified": float(profile.kyc_status == "verified"),
    }

    context = {
        "customer_avg_amount": round(avg, 2) if has_history else None,
        "customer_max_amount": max(amounts) if amounts else None,
        "prior_txn_count_90d": len(prior_90d),
        "usual_city": usual_city,
        "device_first_seen": device_first.isoformat() if device_first else None,
        "ip_first_seen": ip_first.isoformat() if ip_first else None,
        "last_password_reset": max(resets).isoformat() if resets else None,
    }
    return FeatureVector(values=values, context=context)


def extract_signals(txn: TxnRecord, fv: FeatureVector) -> List[Signal]:
    """Named risk signals - the vocabulary rules, agents and analysts share."""
    v, ctx = fv.values, fv.context
    signals: List[Signal] = []

    def add(code, severity, description, value=None):
        signals.append(Signal(code, severity, description, value))

    ratio = v["amount_vs_customer_avg"]
    if v["has_history"] and ratio >= 5:
        add(
            "unusually_high_amount",
            "high" if ratio >= 10 else "medium",
            f"{money(txn.amount)} is {ratio:.1f}x the customer's 90-day average of {money(ctx['customer_avg_amount'])}",
            round(ratio, 1),
        )
    if v["new_device"]:
        add("new_device", "medium", "Transaction made from a device this customer has never used before")
    if v["new_ip"] and txn.ip_address:
        add("new_ip", "low", f"First activity from IP {txn.ip_address}")
    if v["new_country"] and v["foreign_country"]:
        add("new_location", "high", f"First activity from {txn.city}, {txn.country}", v["distance_from_usual_km"])
    elif v["distance_from_usual_km"] >= 500:
        add(
            "unusual_location",
            "medium",
            f"{txn.city} is {v['distance_from_usual_km']:,.0f} km from the customer's usual location ({ctx['usual_city']})",
            round(v["distance_from_usual_km"]),
        )
    if v["recipient_is_new"] and v["is_transfer"]:
        added = " (added in the last 24h)" if v["beneficiary_added_24h"] else ""
        add("new_recipient", "medium", f"First transfer to this beneficiary{added}")
    if v["failed_logins_24h"] >= 3:
        add(
            "multiple_failed_logins",
            "high" if v["failed_logins_24h"] >= 5 else "medium",
            f"{int(v['failed_logins_24h'])} failed login attempts in the previous 24 hours",
            v["failed_logins_24h"],
        )
    if v["password_reset_24h"]:
        add(
            "recent_credential_change",
            "high" if v["minutes_since_password_reset"] <= 60 else "medium",
            f"Password reset {v['minutes_since_password_reset']:.0f} minutes before the transaction",
            round(v["minutes_since_password_reset"]),
        )
    if v["mfa_changed_24h"]:
        add("mfa_changed", "high", "MFA method changed in the previous 24 hours")
    if v["is_night"] and v["night_share_90d"] < 0.05:
        add(
            "unusual_transaction_time",
            "medium",
            f"Made at {txn.timestamp:%H:%M}; the customer rarely transacts between midnight and 6 AM",
        )
    if v["txn_count_1h"] >= 5:
        add("high_velocity", "medium", f"{int(v['txn_count_1h'])} transactions in the previous hour", v["txn_count_1h"])
    if v["small_txn_count_30m"] >= 4:
        add(
            "small_transaction_burst",
            "high",
            f"{int(v['small_txn_count_30m'])} small transactions (< {money(SMALL_AMOUNT)}) in the previous 30 minutes",
            v["small_txn_count_30m"],
        )
    if v["device_shared_customers"] >= 2:
        add(
            "shared_device",
            "high",
            f"Device has been used by {int(v['device_shared_customers'])} other customers",
            v["device_shared_customers"],
        )
    if v["counterparty_sender_count"] >= 3:
        add(
            "mule_recipient",
            "high",
            f"Beneficiary has received money from {int(v['counterparty_sender_count'])} other customers",
            v["counterparty_sender_count"],
        )
    if v["account_age_days"] < 30:
        add("new_account", "medium", f"Account opened {v['account_age_days']:.0f} days ago", round(v["account_age_days"]))
    if not v["kyc_verified"]:
        add("kyc_not_verified", "medium", "Customer KYC is not fully verified")
    if v["profile_changed_7d"]:
        add("recent_profile_change", "medium", "Contact details changed in the previous 7 days")
    return signals
