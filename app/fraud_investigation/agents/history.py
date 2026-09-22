"""Case-history agent: what happened the last time this looked like this.

Two questions an analyst asks before anything else, and which a per-transaction score cannot
answer: has this customer been here before, and when alerts with these same signals were worked in
the past, how often did they turn out to be real? A signal combination with a poor historical
precision is worth knowing about before someone freezes an account over it.
"""
from typing import Dict, List

from app.fraud_investigation import models
from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.features import money

# An earlier alert counts as a precedent when it shares at least this many signal codes.
SIMILARITY_MIN_SHARED = 2
MAX_PRECEDENTS = 8
DECISION_LABELS = {
    "fraud_confirmed": "confirmed fraud",
    "false_positive": "false positive",
    "inconclusive": "inconclusive",
}


class HistoryAgent:
    name = "history"
    title = "Customer and alert history"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        db, customer_id = ctx.db, ctx.customer.id

        prior_alerts = (
            db.query(models.FraudAlert)
            .filter(models.FraudAlert.customer_id == customer_id, models.FraudAlert.id != ctx.alert.id)
            .order_by(models.FraudAlert.created_at.desc())
            .all()
        )
        prior_cases = (
            db.query(models.FraudCase)
            .filter(models.FraudCase.customer_id == customer_id, models.FraudCase.id != ctx.alert.case_id)
            .order_by(models.FraudCase.created_at.desc())
            .all()
        )
        confirmed = [case for case in prior_cases if case.decision == "fraud_confirmed"]
        dismissed = [case for case in prior_cases if case.decision == "false_positive"]

        findings: List[str] = []
        if ctx.customer.prior_fraud_cases:
            findings.append(
                f"{ctx.customer.prior_fraud_cases} fraud case(s) recorded against this customer before "
                "the current data window."
            )
        if confirmed:
            latest = confirmed[0]
            findings.append(
                f"{len(confirmed)} previously confirmed fraud case(s); the most recent "
                f"({latest.id}, {latest.created_at:%d %b %Y}) was {latest.fraud_type or 'unclassified'}."
            )
        if dismissed:
            findings.append(f"{len(dismissed)} previous alert(s) on this customer were closed as false positives.")

        precedents, outcomes = self._precedents(db, ctx)
        for precedent in precedents[:3]:
            findings.append(
                f"Precedent {precedent['case_id'] or precedent['alert_id']}: "
                f"{precedent['shared_signals']} shared signal(s), scored {precedent['risk_score']}, "
                f"{DECISION_LABELS.get(precedent['decision'], 'still open')}."
            )

        decided = outcomes["fraud_confirmed"] + outcomes["false_positive"]
        precision = outcomes["fraud_confirmed"] / decided if decided else None
        if precision is not None:
            findings.append(
                f"Alerts sharing these signals have been confirmed as fraud "
                f"{outcomes['fraud_confirmed']}/{decided} times ({precision:.0%})."
            )

        prior_total = sum(t.amount for t in ctx.history.transactions_before(ctx.record.timestamp))
        summary = (
            f"{len(prior_alerts)} earlier alert(s) and {len(prior_cases)} earlier case(s) for this customer, "
            f"over {len(ctx.history.transactions) - 1} prior transactions totalling {money(prior_total)}."
        )

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings or ["No prior alerts or cases for this customer."],
            data={
                "prior_alert_count": len(prior_alerts),
                "prior_case_count": len(prior_cases),
                "confirmed_fraud_cases": len(confirmed),
                "false_positive_cases": len(dismissed),
                "prior_fraud_cases_on_record": ctx.customer.prior_fraud_cases or 0,
                "recent_alerts": [
                    {
                        "alert_id": alert.id,
                        "created_at": alert.created_at.isoformat() if alert.created_at else None,
                        "risk_score": alert.risk_score,
                        "risk_level": alert.risk_level,
                        "status": alert.status,
                        "case_id": alert.case_id,
                    }
                    for alert in prior_alerts[:10]
                ],
                "precedents": precedents,
                "precedent_outcomes": outcomes,
                "precedent_precision": round(precision, 3) if precision is not None else None,
            },
            confidence=0.9 if precedents or prior_cases else 0.4,
        )

    def _precedents(self, db, ctx: InvestigationContext):
        """Earlier alerts across all customers that shared this alert's signal vocabulary."""
        codes = ctx.signal_codes
        outcomes: Dict[str, int] = {"fraud_confirmed": 0, "false_positive": 0, "inconclusive": 0, "open": 0}
        precedents: List[dict] = []
        if not codes:
            return precedents, outcomes

        earlier = (
            db.query(models.FraudAlert)
            .filter(models.FraudAlert.id != ctx.alert.id)
            .order_by(models.FraudAlert.created_at.desc())
            .limit(500)
            .all()
        )
        cases = {
            case.id: case
            for case in db.query(models.FraudCase).filter(
                models.FraudCase.id.in_([alert.case_id for alert in earlier if alert.case_id] or [""])
            )
        }

        for alert in earlier:
            shared = codes & {signal.get("code") for signal in (alert.signals or [])}
            if len(shared) < SIMILARITY_MIN_SHARED:
                continue
            case = cases.get(alert.case_id) if alert.case_id else None
            decision = case.decision if case and case.decision else None
            outcomes[decision or "open"] += 1
            if len(precedents) < MAX_PRECEDENTS:
                precedents.append(
                    {
                        "alert_id": alert.id,
                        "case_id": case.id if case else None,
                        "customer_id": alert.customer_id,
                        "same_customer": alert.customer_id == ctx.customer.id,
                        "created_at": alert.created_at.isoformat() if alert.created_at else None,
                        "risk_score": alert.risk_score,
                        "shared_signals": len(shared),
                        "signals": sorted(shared),
                        "decision": decision,
                        "fraud_type": case.fraud_type if case else None,
                    }
                )

        precedents.sort(key=lambda p: (-p["shared_signals"], p["created_at"] or ""))
        return precedents, outcomes
