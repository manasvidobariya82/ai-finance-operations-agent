"""External intelligence agent: watchlists, IP reputation and counterparty standing.

Screening results carry regulatory weight - a sanctions hit changes what the bank is obliged to do,
not just how suspicious the payment looks - so this section reports matches literally, including
the list, the source and how close a fuzzy name match actually was.
"""
from typing import List

from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.intel import screen_email_domain, screen_exact

LIST_LABELS = {
    "sanctions": "Sanctions list",
    "internal_blocklist": "Internal fraud blocklist",
    "disposable_email": "Disposable email provider",
}


class IntelAgent:
    name = "intel"
    title = "External intelligence"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        hits = list(ctx.intel.watchlist_hits)
        # The detection path screens the transaction's own entities; an investigation also screens
        # the customer, whose details may have been changed during a takeover.
        customer_hits = screen_email_domain(ctx.db, ctx.customer.email) + screen_exact(
            ctx.db, "phone", ctx.customer.phone
        )
        hits += customer_hits

        findings: List[str] = []
        for hit in hits:
            match = "exact match" if hit.match_score >= 1.0 else f"{hit.match_score:.0%} name match"
            findings.append(
                f"{LIST_LABELS.get(hit.list_name, hit.list_name)}: '{hit.matched_value}' matches "
                f"'{hit.listed_value}' ({match}, source {hit.source})"
                + (f" - {hit.reason}" if hit.reason else "")
            )

        ip = ctx.intel.ip
        if ip:
            if ctx.intel.ip_is_high_risk:
                findings.append(
                    f"IP {ip['ip_address']} is {ip['usage_type']} with reputation score "
                    f"{ip['risk_score']}/100 ({ip['isp']}, {ip['city']}, {ip['country']})."
                )
            elif ip["country"] and ctx.customer.home_country and ip["country"] != ctx.customer.home_country:
                findings.append(
                    f"IP {ip['ip_address']} geolocates to {ip['city']}, {ip['country']}, "
                    f"outside the customer's home country ({ctx.customer.home_country})."
                )

        counterparty = ctx.counterparty
        if counterparty and counterparty.status == "blocked":
            findings.append(f"Counterparty {counterparty.name} is already blocked in the system.")

        sanctions = [hit for hit in hits if hit.list_name == "sanctions"]
        blocklist = [hit for hit in hits if hit.list_name == "internal_blocklist"]
        if sanctions:
            summary = f"Sanctions screening hit on {sanctions[0].matched_value} - escalation is mandatory."
        elif blocklist:
            summary = f"{len(blocklist)} internal blocklist hit(s) on entities in this transaction."
        elif findings:
            summary = "No watchlist match, but the connection intelligence is adverse."
        else:
            summary = "No adverse external intelligence found."

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings,
            data={
                "watchlist_hits": [hit.to_dict() for hit in hits],
                "ip_reputation": ip,
                "ip_is_high_risk": ctx.intel.ip_is_high_risk,
                "sanctions_hit": bool(sanctions),
                "blocklist_hit": bool(blocklist),
                "counterparty_status": counterparty.status if counterparty else None,
            },
            confidence=1.0 if hits or ip else 0.6,
        )
