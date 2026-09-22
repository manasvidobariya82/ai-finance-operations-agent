"""Evidence agent: the facts of the transaction itself.

The first section of every case file. It states what happened in plain terms, lists the named risk
signals the feature engine raised, and shows which features actually moved the ML score (exact
TreeSHAP contributions, not a post-hoc guess).
"""
from typing import List

from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.features import money
from app.fraud_investigation.scoring import COMPONENT_LABELS

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}


class EvidenceAgent:
    name = "evidence"
    title = "Transaction evidence"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        txn, record = ctx.transaction, ctx.record
        counterparty = ctx.counterparty

        recipient = "unknown recipient"
        if counterparty:
            kind = "merchant" if counterparty.kind == "merchant" else "beneficiary"
            account = f" ••{counterparty.account_number[-4:]}" if counterparty.account_number else ""
            recipient = f"{counterparty.name}{account} ({kind})"

        location = ", ".join(part for part in (txn.city, txn.country) if part) or "unknown location"
        summary = (
            f"{money(txn.amount, txn.currency)} {record.txn_type.replace('_', ' ')} to {recipient} "
            f"on {txn.timestamp:%d %b %Y at %H:%M} from {location}."
        )

        signals = sorted(ctx.signals, key=lambda s: (SEVERITY_ORDER.get(s.severity, 3), s.code))
        findings: List[str] = [signal.description for signal in signals]
        if not findings:
            findings.append("No named risk signals were raised for this transaction.")

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings,
            data={
                "transaction": {
                    "id": txn.id,
                    "amount": txn.amount,
                    "amount_display": money(txn.amount, txn.currency),
                    "currency": txn.currency,
                    "timestamp": txn.timestamp.isoformat(),
                    "type": txn.txn_type,
                    "payment_method": txn.payment_method,
                    "channel": txn.channel,
                    "status": txn.status,
                    "city": txn.city,
                    "country": txn.country,
                    "device": ctx.describe_device(txn.device_id),
                    "device_id": txn.device_id,
                    "ip_address": txn.ip_address,
                },
                "customer": {
                    "id": ctx.customer.id,
                    "name": ctx.customer.full_name,
                    "segment": ctx.customer.segment,
                    "kyc_status": ctx.customer.kyc_status,
                    "home_city": ctx.customer.home_city,
                    "account_id": txn.account_id,
                    "account_age_days": round(ctx.feature("account_age_days")),
                    "prior_fraud_cases": ctx.customer.prior_fraud_cases or 0,
                },
                "counterparty": {
                    "id": counterparty.id,
                    "name": counterparty.name,
                    "kind": counterparty.kind,
                    "bank": counterparty.bank,
                    "country": counterparty.country,
                    "category": counterparty.category,
                    "status": counterparty.status,
                    "first_payment": bool(ctx.feature("recipient_is_new")),
                }
                if counterparty
                else None,
                "signals": [signal.to_dict() for signal in signals],
                "feature_context": ctx.features.context,
                "ml_explanation": ctx.ml_explanation or [],
                "detector_breakdown": ctx.scoring["breakdown"],
                "scoring_method": {
                    "method": ctx.scoring["method"],
                    "explanation": ctx.scoring["method_explanation"],
                    "weighted_average": ctx.scoring["weighted_average"],
                    "candidates": ctx.scoring["candidates"],
                },
                "components": {
                    name: {"label": COMPONENT_LABELS[name], "score": round(value, 3)}
                    for name, value in ctx.components.items()
                    if value is not None
                },
                "model_version": ctx.model_version,
            },
            confidence=1.0,
        )
