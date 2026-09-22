"""Hypothesis agent: which fraud typology, if any, explains the evidence.

A risk score says how worried to be; it does not say what is going on, and the answer changes what
should happen next. An account takeover means the customer is a victim whose credentials are
compromised - reset them and stop the payment. An authorised push payment scam means the customer
sent the money themselves after being deceived - the credentials are fine and the intervention is a
conversation, not a lockout. The two produce nearly identical risk scores and opposite actions.

Each typology is a fixed set of weighted indicators over the same features, signals and intel the
detectors used, plus detractors - evidence that argues against it. Support is the share of
indicator weight that matched, less any detractor weight, so every hypothesis can be shown to an
analyst as "these facts point here, these point away". No LLM is involved: the narrative agent
phrases this conclusion, it does not reach it.
"""
from dataclasses import dataclass, field
from typing import Callable, List, Tuple

from app.fraud_investigation.agents.base import AgentResult, InvestigationContext

# Below this, the evidence does not favour any typology strongly enough to name one.
MIN_SUPPORT = 0.35
# A second hypothesis this close to the first is reported as a genuine alternative to rule out.
CLOSE_ALTERNATIVE = 0.15


@dataclass(frozen=True)
class Indicator:
    code: str
    weight: float
    description: str
    test: Callable[[InvestigationContext], bool]


@dataclass(frozen=True)
class Hypothesis:
    id: str
    label: str
    description: str
    indicators: List[Indicator]
    detractors: List[Indicator] = field(default_factory=list)
    # Indicator codes without which this typology cannot apply at all. Some hypotheses are
    # partly built from the *absence* of contrary evidence - a scam payment is made from the
    # customer's own device, from their usual place, with no credential change - and those facts
    # are equally true of an ordinary payment. Without a required core, an unremarkable
    # transaction accumulates enough of them to be diagnosed as fraud.
    requires: Tuple[str, ...] = ()


def _credential_change(ctx: InvestigationContext) -> bool:
    return bool(ctx.feature("password_reset_24h") or ctx.feature("mfa_changed_24h"))


def _network(ctx: InvestigationContext) -> dict:
    return ctx.section_data("network")


def _tainted_beneficiary(ctx: InvestigationContext) -> bool:
    factors = _network(ctx).get("transaction_risk", {}).get("factors", [])
    return any("beneficiary" in factor["factor"] and "fraud" in factor["factor"] for factor in factors)


def _tainted_community(ctx: InvestigationContext) -> bool:
    return bool(_network(ctx).get("community", {}).get("tainted"))


def _shared_identity(ctx: InvestigationContext) -> bool:
    return any(
        shared["kind"] in ("phone", "email", "address") for shared in _network(ctx).get("shared_attributes", [])
    )


HYPOTHESES: List[Hypothesis] = [
    Hypothesis(
        "account_takeover",
        "Account takeover",
        "A third party has gained control of the customer's credentials and is moving money out.",
        [
            Indicator("credential_change", 0.25, "Password or MFA changed shortly before the payment", _credential_change),
            Indicator("new_device", 0.15, "Payment made from a device never used by this customer", lambda c: bool(c.feature("new_device"))),
            Indicator("failed_logins", 0.12, "Repeated failed logins before access succeeded", lambda c: c.feature("failed_logins_24h") >= 3),
            Indicator("new_location", 0.12, "First-ever activity from this country", lambda c: bool(c.feature("new_country") and c.feature("foreign_country"))),
            Indicator("high_risk_ip", 0.1, "Connection from TOR, VPN or a datacenter IP", lambda c: bool(c.section_data("intel").get("ip_is_high_risk"))),
            Indicator("new_beneficiary", 0.13, "Funds sent to a beneficiary added in the last 24 hours", lambda c: bool(c.feature("recipient_is_new") and c.feature("beneficiary_added_24h"))),
            Indicator("amount_spike", 0.13, "Amount far above this customer's normal range", lambda c: c.feature("amount_vs_customer_avg") >= 5),
        ],
        [
            Indicator("known_device", 0.2, "The device is one the customer regularly uses", lambda c: bool(c.record.device_id) and not c.feature("new_device")),
            Indicator("usual_location", 0.15, "The payment came from the customer's usual location", lambda c: c.feature("distance_from_usual_km") < 100 and not c.feature("foreign_country")),
        ],
    ),
    Hypothesis(
        "card_testing",
        "Card testing",
        "Stolen card details are being validated with a burst of small purchases before a large one.",
        [
            Indicator("small_burst", 0.35, "Several small transactions in a short window", lambda c: c.feature("small_txn_count_30m") >= 4),
            Indicator("velocity", 0.2, "Unusually high transaction velocity", lambda c: c.feature("txn_count_1h") >= 5),
            Indicator("card_channel", 0.15, "Card-not-present purchase", lambda c: bool(c.feature("is_card_purchase")) and not c.feature("is_card_present")),
            Indicator("new_device", 0.15, "Purchases from an unrecognised device", lambda c: bool(c.feature("new_device"))),
            Indicator("high_risk_ip", 0.15, "Connection from TOR, VPN or a datacenter IP", lambda c: bool(c.section_data("intel").get("ip_is_high_risk"))),
        ],
        requires=("small_burst",),
    ),
    Hypothesis(
        "money_mule_network",
        "Money mule network",
        "The receiving account is collecting funds from several customers, consistent with a laundering layer.",
        [
            Indicator("many_senders", 0.3, "Beneficiary receives money from several unrelated customers", lambda c: c.feature("counterparty_sender_count") >= 3),
            Indicator("tainted_beneficiary", 0.25, "Beneficiary is linked to confirmed fraud", _tainted_beneficiary),
            Indicator("tainted_community", 0.15, "Customer sits in a community containing known-fraud entities", _tainted_community),
            Indicator("shared_device", 0.15, "Device is shared with other customers", lambda c: c.feature("device_shared_customers") >= 2),
            Indicator("transfer", 0.15, "Funds moved by transfer rather than spent", lambda c: bool(c.feature("is_transfer"))),
        ],
    ),
    Hypothesis(
        "authorised_push_payment_scam",
        "Authorised push payment scam",
        "The customer authorised the payment themselves, most likely after being deceived by a third party.",
        [
            Indicator("own_device", 0.22, "Made from the customer's own, recognised device", lambda c: bool(c.record.device_id) and not c.feature("new_device")),
            Indicator("usual_location", 0.18, "Made from the customer's usual location", lambda c: c.feature("distance_from_usual_km") < 100 and not c.feature("foreign_country")),
            Indicator("new_beneficiary", 0.25, "First payment to a brand-new beneficiary", lambda c: bool(c.feature("recipient_is_new") and c.feature("is_transfer"))),
            Indicator("amount_spike", 0.2, "Amount far above this customer's normal range", lambda c: c.feature("amount_vs_customer_avg") >= 4),
            Indicator("no_credential_change", 0.15, "No password or MFA change before the payment", lambda c: not _credential_change(c)),
        ],
        [
            Indicator("credential_change", 0.3, "Credentials were changed shortly before the payment", _credential_change),
            Indicator("failed_logins", 0.15, "Repeated failed logins before the payment", lambda c: c.feature("failed_logins_24h") >= 3),
        ],
        requires=("new_beneficiary", "amount_spike"),
    ),
    Hypothesis(
        "sanctions_exposure",
        "Sanctions / blocklist exposure",
        "An entity in this payment matches a sanctions list or the internal fraud blocklist.",
        [
            Indicator("sanctions_hit", 0.6, "Counterparty matches a sanctions list", lambda c: bool(c.section_data("intel").get("sanctions_hit"))),
            Indicator("blocklist_hit", 0.4, "An entity matches the internal fraud blocklist", lambda c: bool(c.section_data("intel").get("blocklist_hit"))),
        ],
    ),
    Hypothesis(
        "synthetic_or_first_party",
        "Synthetic identity or first-party fraud",
        "The account itself looks fabricated or opened to be abused, rather than a genuine customer being attacked.",
        [
            Indicator("new_account", 0.25, "Account opened in the last 30 days", lambda c: c.feature("account_age_days") < 30),
            Indicator("kyc_incomplete", 0.25, "KYC is not fully verified", lambda c: not c.feature("kyc_verified")),
            Indicator("shared_identity", 0.2, "Contact details are shared with other customers", _shared_identity),
            Indicator("thin_history", 0.15, "Almost no genuine transaction history", lambda c: not c.feature("has_history")),
            Indicator("large_early_movement", 0.15, "A large amount moved very early in the account's life", lambda c: c.feature("account_age_days") < 60 and c.feature("log_amount") >= 10.8),
        ],
        requires=("new_account",),
    ),
]


class HypothesisAgent:
    name = "hypothesis"
    title = "Fraud hypotheses"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        assessed = [self._assess(hypothesis, ctx) for hypothesis in HYPOTHESES]
        assessed.sort(key=lambda item: -item["support"])
        top = assessed[0]

        if top["support"] < MIN_SUPPORT:
            primary, fraud_type = None, None
            summary = (
                "The evidence does not fit any known fraud typology strongly enough to name one; "
                "the alert rests on the risk score alone."
            )
        else:
            primary, fraud_type = top["label"], top["id"]
            summary = f"{top['label']} ({top['support']:.0%} of its indicators matched): {top['description']}"

        alternatives = [
            item for item in assessed[1:] if item["support"] >= MIN_SUPPORT and top["support"] - item["support"] <= CLOSE_ALTERNATIVE
        ]
        findings = [f"Supports {top['label']}: {reason}" for reason in top["matched"]] if primary else []
        findings += [f"Argues against {top['label']}: {reason}" for reason in top["against"]]
        for alternative in alternatives:
            findings.append(
                f"Alternative worth ruling out - {alternative['label']} ({alternative['support']:.0%}): "
                + "; ".join(alternative["matched"][:2])
            )

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings or ["No typology indicators matched."],
            data={
                "primary_hypothesis": primary,
                "fraud_type": fraud_type,
                "primary_support": top["support"],
                "alternatives": [item["id"] for item in alternatives],
                "ranked": assessed,
                "min_support": MIN_SUPPORT,
            },
            confidence=round(top["support"], 2),
        )

    def _assess(self, hypothesis: Hypothesis, ctx: InvestigationContext) -> dict:
        total = sum(indicator.weight for indicator in hypothesis.indicators)
        matched, missing, against = [], [], []
        earned = 0.0
        matched_codes = set()
        for indicator in hypothesis.indicators:
            if indicator.test(ctx):
                earned += indicator.weight
                matched.append(indicator.description)
                matched_codes.add(indicator.code)
            else:
                missing.append(indicator.description)

        penalty = 0.0
        for detractor in hypothesis.detractors:
            if detractor.test(ctx):
                penalty += detractor.weight
                against.append(detractor.description)

        unmet = [code for code in hypothesis.requires if code not in matched_codes]
        if unmet:
            support = 0.0
        else:
            support = max(0.0, (earned / total if total else 0.0) - penalty)
        return {
            "id": hypothesis.id,
            "label": hypothesis.label,
            "description": hypothesis.description,
            "support": round(min(1.0, support), 3),
            "matched": matched,
            "missing": missing,
            "against": against,
            "unmet_requirements": unmet,
        }
