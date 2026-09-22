"""Behavioural agent: what is normal for this customer, and what changed.

Builds the customer's 90-day behavioural profile, scores how far the transaction departs from it
per dimension, and lays out the digital events leading up to it. The session timeline is what
usually separates a takeover from an unusual-but-genuine payment: a genuine large transfer is not
normally preceded by a password reset from a new device in another country.
"""
from datetime import timedelta
from typing import List

from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.detection.behavior import assess_deviation, build_profile
from app.fraud_investigation.features import money

# How far back the pre-transaction session timeline reaches.
TIMELINE_WINDOW = timedelta(hours=72)
# Events that say something about control of the account, rather than routine browsing.
NOTABLE_EVENTS = {
    "login_failed": "Failed login",
    "password_reset": "Password reset",
    "mfa_method_changed": "MFA method changed",
    "device_added": "New device registered",
    "beneficiary_added": "New beneficiary added",
    "profile_updated": "Profile details changed",
}
DIMENSION_LABELS = {
    "amount": "Amount",
    "device": "Device",
    "location": "Location",
    "beneficiary": "Beneficiary",
    "time_of_day": "Time of day",
    "payment_method": "Payment method",
}


class BehaviorAgent:
    name = "behavior"
    title = "Behavioural analysis"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        profile = build_profile(ctx.history, ctx.record)
        deviation = assess_deviation(ctx.record, profile, ctx.describe_device)

        findings: List[str] = []
        for dimension, detail in sorted(deviation["dimensions"].items(), key=lambda item: -item[1]["score"]):
            if detail["score"] >= 0.3:
                findings.append(
                    f"{DIMENSION_LABELS.get(dimension, dimension)}: {detail['current']} "
                    f"(normally {detail['normal']})"
                )

        timeline = []
        for event in ctx.history.events_before(ctx.record.timestamp, TIMELINE_WINDOW):
            if event.event_type not in NOTABLE_EVENTS:
                continue
            minutes = (ctx.record.timestamp - event.timestamp).total_seconds() / 60
            timeline.append(
                {
                    "timestamp": event.timestamp.isoformat(),
                    "event_type": event.event_type,
                    "label": NOTABLE_EVENTS[event.event_type],
                    "minutes_before": round(minutes),
                    "device": ctx.describe_device(event.device_id),
                    "ip_address": event.ip_address,
                    "location": ", ".join(part for part in (event.city, event.country) if part) or None,
                    "details": event.details,
                }
            )
        timeline.append(
            {
                "timestamp": ctx.record.timestamp.isoformat(),
                "event_type": "transaction",
                "label": f"Transaction {money(ctx.record.amount)}",
                "minutes_before": 0,
                "device": ctx.describe_device(ctx.record.device_id),
                "ip_address": ctx.record.ip_address,
                "location": ", ".join(part for part in (ctx.record.city, ctx.record.country) if part) or None,
                "details": None,
            }
        )

        credential_events = [item for item in timeline if item["event_type"] in ("password_reset", "mfa_method_changed")]
        if credential_events:
            latest = credential_events[-1]
            findings.append(
                f"{latest['label']} {latest['minutes_before']} minutes before the transaction, "
                f"from {latest['location'] or 'an unknown location'}."
            )

        if profile["transaction_count"] == 0:
            summary = "No prior transaction history in the last 90 days, so there is no behavioural baseline to compare against."
            confidence = 0.3
        else:
            summary = (
                f"Deviation from this customer's 90-day baseline is {deviation['level']} "
                f"({deviation['score']:.2f}), across {profile['transaction_count']} prior transactions."
            )
            confidence = min(1.0, 0.4 + profile["transaction_count"] / 40)

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings or ["The transaction is consistent with the customer's usual behaviour."],
            data={
                "profile": profile,
                "deviation": deviation,
                "session_timeline": timeline,
                "baseline_transactions": profile["transaction_count"],
            },
            confidence=confidence,
        )
