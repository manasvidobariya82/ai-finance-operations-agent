"""Network agent: who else is connected to this customer, device, IP and beneficiary.

Per-transaction models see one payment at a time, so they cannot see a mule ring. This agent walks
the entity graph out from the customer, reports the links that matter (entities used in confirmed
fraud, attributes shared with other customers, the community the customer sits in) and hands the
case UI a laid-out subgraph to draw.
"""
from typing import List

from app.config import settings
from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.detection.graph import node_id


class NetworkAgent:
    name = "network"
    title = "Network analysis"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        if ctx.graph is None:
            return AgentResult(
                name=self.name,
                title=self.title,
                summary="Network analysis was not available for this investigation.",
                findings=[],
                data={"available": False},
                confidence=0.0,
            )

        txn = ctx.transaction
        focus = [
            txn.device_id and node_id("device", txn.device_id),
            txn.ip_address and node_id("ip", txn.ip_address),
            txn.counterparty_id and node_id("beneficiary", txn.counterparty_id),
        ]
        report = ctx.graph.investigate(ctx.customer.id, settings.fraud_graph_max_hops, focus=focus)
        risk = ctx.graph.transaction_risk(ctx.customer.id, txn.device_id, txn.ip_address, txn.counterparty_id)

        if not report.get("available"):
            return AgentResult(
                name=self.name,
                title=self.title,
                summary="This customer has no links to other entities in the graph.",
                findings=[],
                data={"available": False, "transaction_risk": risk},
                confidence=0.2,
            )

        findings: List[str] = [factor["factor"].capitalize() for factor in risk["factors"]]
        tainted = report["tainted_entities"]
        for entity in tainted[:5]:
            findings.append(
                f"{entity['kind'].capitalize()} {entity['label']} ({entity['hops']} hop(s) away) {entity['reason']}."
            )
        for shared in report["shared_attributes"][:5]:
            findings.append(
                f"{shared['kind'].capitalize()} {shared['label']} is shared with "
                f"{len(shared['shared_with'])} other customer(s): {', '.join(shared['shared_with'][:4])}."
            )

        community = report["community"]
        if community.get("tainted"):
            findings.append(
                f"The customer sits in a community of {community['size']} entities "
                f"({community['customers']} customers) containing {community['tainted']} entity/entities "
                "linked to confirmed fraud."
            )

        related = report["related_customers"]
        fraud_linked = [c for c in related if c["touches_known_fraud"]]
        if not findings:
            summary = f"No risky links found within {report['max_hops']} hops."
        elif fraud_linked:
            summary = (
                f"{len(related)} customer(s) are reachable within {report['max_hops']} hops; "
                f"{len(fraud_linked)} of them touch entities used in confirmed fraud."
            )
        else:
            summary = f"{len(related)} customer(s) are reachable within {report['max_hops']} hops via shared entities."

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=findings,
            data={**report, "transaction_risk": risk},
            confidence=0.9 if findings else 0.5,
        )
