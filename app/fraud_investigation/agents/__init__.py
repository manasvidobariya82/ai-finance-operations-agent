"""The investigation agent pipeline.

Agents run in a fixed order because later ones read what earlier ones established: the hypothesis
agent weighs the external intelligence and network findings, the recommendation agent follows the
hypothesis, and the narrative agent writes up all of it. Each agent's contribution is written to
the audit trail under its own actor name, so a finished case can be traced back to which agent
produced which claim.

One failing agent does not fail the investigation. Its section is replaced with an explicit error
placeholder and the rest of the case is still assembled - an analyst is better served by a case
file missing its network section than by no case at all.
"""
import logging
from typing import Dict, List

from app.fraud_investigation import audit
from app.fraud_investigation.agents.base import Agent, AgentResult, InvestigationContext
from app.fraud_investigation.agents.behavior import BehaviorAgent
from app.fraud_investigation.agents.evidence import EvidenceAgent
from app.fraud_investigation.agents.history import HistoryAgent
from app.fraud_investigation.agents.hypothesis import HypothesisAgent
from app.fraud_investigation.agents.intel import IntelAgent
from app.fraud_investigation.agents.narrative import NarrativeAgent
from app.fraud_investigation.agents.network import NetworkAgent
from app.fraud_investigation.agents.recommendation import RecommendationAgent
from app.fraud_investigation.clock import now

logger = logging.getLogger("uvicorn.error")

# Order matters - see the module docstring.
PIPELINE: List[Agent] = [
    EvidenceAgent(),
    BehaviorAgent(),
    IntelAgent(),
    NetworkAgent(),
    HistoryAgent(),
    HypothesisAgent(),
    RecommendationAgent(),
    NarrativeAgent(),
]

__all__ = ["AgentResult", "InvestigationContext", "PIPELINE", "run_agents", "build_case_file"]


def run_agents(ctx: InvestigationContext) -> Dict[str, AgentResult]:
    """Run every agent against `ctx`, recording each one in the audit trail."""
    for agent in PIPELINE:
        try:
            result = agent.run(ctx)
        except Exception as exc:  # one agent's failure must not lose the whole case
            logger.exception("Investigation agent %s failed for alert %s", agent.name, ctx.alert.id)
            result = AgentResult(
                name=agent.name,
                title=agent.title,
                summary=f"This section could not be produced ({type(exc).__name__}).",
                findings=[],
                data={"error": str(exc)},
                confidence=0.0,
            )
        ctx.sections[agent.name] = result
        audit.record(
            ctx.db,
            f"agent:{agent.name}",
            "agent_completed",
            "fraud_alert",
            ctx.alert.id,
            {"summary": result.summary, "findings": len(result.findings), "confidence": result.confidence},
        )
    return ctx.sections


def build_case_file(ctx: InvestigationContext) -> dict:
    """Assemble the agent sections into the stored case file."""
    hypothesis = ctx.section_data("hypothesis")
    narrative = ctx.section_data("narrative")
    recommendation = ctx.section_data("recommendation")

    return {
        "alert_id": ctx.alert.id,
        "transaction_id": ctx.transaction.id,
        "customer_id": ctx.customer.id,
        "generated_at": now().isoformat(),
        "model_version": ctx.model_version,
        "risk": {
            "score": ctx.scoring["risk_score"],
            "level": ctx.scoring["risk_level"],
            "method": ctx.scoring["method"],
            "method_explanation": ctx.scoring["method_explanation"],
            "breakdown": ctx.scoring["breakdown"],
        },
        "headline": narrative.get("headline"),
        "summary": narrative.get("summary"),
        "key_points": narrative.get("key_points", []),
        "verification_steps": narrative.get("verification_steps", []),
        "narrative_source": narrative.get("source"),
        "primary_hypothesis": hypothesis.get("primary_hypothesis"),
        "fraud_type": hypothesis.get("fraud_type"),
        "hypotheses": hypothesis.get("ranked", []),
        "recommended_actions": recommendation.get("actions", []),
        "sections": [ctx.sections[agent.name].to_dict() for agent in PIPELINE if agent.name in ctx.sections],
        "agents_run": [agent.name for agent in PIPELINE if agent.name in ctx.sections],
    }
