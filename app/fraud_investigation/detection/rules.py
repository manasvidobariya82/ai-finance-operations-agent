"""Deterministic rule engine. Each rule is an explicit, reviewable condition over features and
external intelligence; rule hits are combined with a noisy-OR so several weak rules add up without
any single one exceeding its own weight."""
from dataclasses import dataclass
from typing import Callable, Dict, List

from app.fraud_investigation.intel import IntelContext

RULES_VERSION = "rules-2026.09.2"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    severity: str  # low / medium / high / critical
    weight: float  # 0-1 contribution to the rule score
    condition: Callable[[Dict[str, float], IntelContext], bool]
    # Critical rules also put a floor under the combined risk score (see scoring.py).
    floor: float = 0.0


RULES: List[Rule] = [
    Rule(
        "R001", "High amount from a new device", "high", 0.55,
        lambda f, i: f["amount_vs_customer_avg"] >= 5 and f["new_device"] == 1,
    ),
    Rule(
        "R002", "New beneficiary paid shortly after a password reset", "high", 0.65,
        lambda f, i: f["is_transfer"] == 1 and f["recipient_is_new"] == 1 and f["minutes_since_password_reset"] <= 24 * 60,
    ),
    Rule(
        "R003", "Multiple failed logins before the transaction", "medium", 0.35,
        lambda f, i: f["failed_logins_24h"] >= 3,
    ),
    Rule(
        "R004", "Counterparty matches a sanctions list", "critical", 0.95,
        lambda f, i: bool(i.hits_on("sanctions")), floor=0.9,
    ),
    Rule(
        "R005", "Entity on the internal fraud blocklist", "critical", 0.9,
        lambda f, i: bool(i.hits_on("internal_blocklist")), floor=0.8,
    ),
    Rule(
        "R006", "High-risk IP (TOR / VPN / datacenter / poor reputation)", "high", 0.45,
        lambda f, i: i.ip_is_high_risk,
    ),
    Rule(
        "R007", "Transaction velocity spike", "medium", 0.4,
        lambda f, i: f["txn_count_1h"] >= 5,
    ),
    Rule(
        "R008", "Burst of small transactions (possible card testing)", "high", 0.55,
        lambda f, i: f["small_txn_count_30m"] >= 4,
    ),
    Rule(
        "R009", "Large night-time transfer, unusual for this customer", "medium", 0.35,
        lambda f, i: f["is_night"] == 1 and f["night_share_90d"] < 0.05 and f["is_transfer"] == 1 and f["amount_vs_customer_avg"] >= 3,
    ),
    Rule(
        "R010", "Device shared by multiple customers", "high", 0.45,
        lambda f, i: f["device_shared_customers"] >= 2,
    ),
    Rule(
        "R011", "Beneficiary receives funds from many customers (possible mule)", "high", 0.5,
        lambda f, i: f["counterparty_sender_count"] >= 3,
    ),
    Rule(
        "R012", "New account moving a large amount", "medium", 0.35,
        lambda f, i: f["account_age_days"] < 30 and f["log_amount"] >= 10.8,  # ~ ₹50,000
    ),
    Rule(
        "R013", "MFA method changed shortly before the transaction", "high", 0.45,
        lambda f, i: f["mfa_changed_24h"] == 1,
    ),
    # Authorised push payment scams: the customer sends the money themselves, from their own
    # device, in their own city, with their credentials untouched - so every rule above stays
    # silent and only the ML model has any chance of surfacing it. This is the one deterministic
    # handle on that typology.
    #
    # It is deliberately narrow, because most first payments to a new payee are somebody paying a
    # new landlord. The amount test is what separates the two: 4x the customer's own 90-day
    # average, the same threshold the scam hypothesis uses for its `amount_spike` indicator, so a
    # transaction this rule surfaces is one the hypothesis layer can actually diagnose. The ratio
    # is only meaningful against a real baseline, hence `has_history`; without one it is defined
    # as 1.0, so this cannot fire on a brand-new account.
    #
    # Weight and severity are set to move a transaction out of auto-close and into the review
    # queue, and no further: with no floor and at 0.4, this rule alone tops out in medium risk. It
    # asks for a look, it does not decide anything.
    Rule(
        "R014", "Large first payment to a brand-new beneficiary", "medium", 0.4,
        lambda f, i: (
            f["is_transfer"] == 1
            and f["recipient_is_new"] == 1
            and f["has_history"] == 1
            and f["amount_vs_customer_avg"] >= 4
        ),
    ),
]


def evaluate_rules(features: Dict[str, float], intel: IntelContext) -> List[dict]:
    hits = []
    for rule in RULES:
        if rule.condition(features, intel):
            hits.append(
                {"id": rule.id, "name": rule.name, "severity": rule.severity, "weight": rule.weight, "floor": rule.floor}
            )
    return hits


def rule_score(hits: List[dict]) -> float:
    remaining = 1.0
    for hit in hits:
        remaining *= 1 - hit["weight"]
    return 1 - remaining
