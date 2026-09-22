"""Narrative agent: the written case summary.

The only agent that calls the LLM, and the only thing it is trusted with. The score, the
hypothesis, the triage decision and the recommended actions are all fixed before this runs; the
model is handed those conclusions plus the evidence behind them and asked to write them up for a
human. It is explicitly told not to re-score, re-diagnose or add facts, because anything it
invented here would end up in a case file that a regulator can ask about.

If the LLM is disabled, unconfigured or failing, the investigation still completes - the narrative
falls back to a deterministic write-up assembled from the same sections. A fraud queue that stops
working when an external API is down is worse than one that writes plainer English.
"""
import logging
from typing import List, Optional

from google.genai import errors as genai_errors
from pydantic import BaseModel

from app.config import settings
from app.fraud_investigation.agents.base import AgentResult, InvestigationContext
from app.fraud_investigation.features import money
from app.pipeline.gemini_client import GeminiNotConfiguredError, generate_structured, is_configured

logger = logging.getLogger("uvicorn.error")

SECTION_ORDER = ["evidence", "behavior", "intel", "network", "history", "hypothesis"]

PROMPT = """You are a senior fraud analyst writing the case summary that a colleague will read
before they decide what to do about this alert.

Everything below has already been established by the detection system: the risk score, the leading
hypothesis and the recommended actions are given to you as facts. Your job is to write them up
clearly, not to re-assess them.

Rules:
- Use only the evidence provided. Never introduce a fact, name, amount, time or location that does
  not appear below.
- Do not give your own risk score, and do not contradict the stated hypothesis. If the evidence
  looks weak, say what is missing rather than changing the conclusion.
- Write for someone who will act on this in the next few minutes: what happened, why it was
  flagged, and what would confirm or dismiss it.
- The customer is presumed to be a victim or to be innocent until an analyst decides otherwise.
  Describe the behaviour, not the person.
- headline: one sentence, under 120 characters.
- summary: 3-5 sentences of plain prose, no bullet points, no markdown.
- key_points: the 3-5 facts that matter most, each a short phrase.
- verification_steps: concrete checks that would confirm or rule out the hypothesis."""


class CaseNarrative(BaseModel):
    headline: str
    summary: str
    key_points: List[str]
    verification_steps: List[str]


class NarrativeAgent:
    name = "narrative"
    title = "Case summary"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        brief = self._brief(ctx)
        narrative, source, error = self._generate(brief)
        return AgentResult(
            name=self.name,
            title=self.title,
            summary=narrative.headline,
            findings=narrative.key_points,
            data={
                "headline": narrative.headline,
                "summary": narrative.summary,
                "key_points": narrative.key_points,
                "verification_steps": narrative.verification_steps,
                "source": source,
                "model": settings.gemini_model if source == "llm" else None,
                "error": error,
            },
            confidence=0.8 if source == "llm" else 0.6,
        )

    def _generate(self, brief: dict):
        if not settings.fraud_use_llm:
            return self._fallback(brief), "deterministic", None
        if not is_configured():
            return self._fallback(brief), "deterministic", "Gemini is not configured"
        try:
            return generate_structured(f"{PROMPT}\n\nCase evidence:\n{brief}", CaseNarrative), "llm", None
        except (genai_errors.APIError, GeminiNotConfiguredError, ValueError) as exc:
            # The case must still be investigable; degrade to the deterministic write-up and record
            # why, so a queue full of plain summaries is traceable to the outage that caused it.
            logger.warning("Case narrative fell back to the deterministic writer: %s", exc)
            return self._fallback(brief), "deterministic", str(exc)

    def _brief(self, ctx: InvestigationContext) -> dict:
        hypothesis = ctx.section_data("hypothesis")
        ranked = hypothesis.get("ranked", [])
        return {
            "alert_id": ctx.alert.id,
            "risk_score": ctx.scoring["risk_score"],
            "risk_level": ctx.scoring["risk_level"],
            "scoring_method": ctx.scoring["method_explanation"],
            "transaction": ctx.section_data("evidence").get("transaction"),
            "customer": ctx.section_data("evidence").get("customer"),
            "counterparty": ctx.section_data("evidence").get("counterparty"),
            "signals": [signal.description for signal in ctx.signals],
            "rules_triggered": [f"{hit['id']} {hit['name']}" for hit in ctx.rule_hits],
            "top_model_features": [
                f"{item['label']} = {item['value']} ({'increases' if item['contribution'] > 0 else 'reduces'} risk)"
                for item in (ctx.ml_explanation or [])
            ],
            "leading_hypothesis": hypothesis.get("primary_hypothesis"),
            "hypothesis_support": [
                {"hypothesis": item["label"], "support": item["support"], "for": item["matched"], "against": item["against"]}
                for item in ranked[:3]
            ],
            "sections": {
                name: {"summary": ctx.sections[name].summary, "findings": ctx.sections[name].findings}
                for name in SECTION_ORDER
                if name in ctx.sections
            },
            "recommended_actions": [
                item["label"] for item in ctx.section_data("recommendation").get("actions", [])
            ],
        }

    def _fallback(self, brief: dict) -> CaseNarrative:
        transaction = brief.get("transaction") or {}
        customer = brief.get("customer") or {}
        counterparty = brief.get("counterparty") or {}
        amount = transaction.get("amount_display") or money(transaction.get("amount") or 0)
        recipient = counterparty.get("name") or "an unspecified recipient"
        hypothesis: Optional[str] = brief.get("leading_hypothesis")

        headline = (
            f"{brief['risk_level'].title()} risk ({brief['risk_score']}/100): {amount} to {recipient}"
            + (f" - {hypothesis.lower()} suspected" if hypothesis else "")
        )
        signals = brief.get("signals") or []
        sentences = [
            f"{customer.get('name', 'The customer')} sent {amount} to {recipient} "
            f"on {transaction.get('timestamp', 'an unrecorded date')} from "
            f"{transaction.get('city') or 'an unknown location'}.",
            f"The transaction scored {brief['risk_score']}/100 ({brief['risk_level']} risk); "
            f"{brief['scoring_method'].lower()}.",
        ]
        if signals:
            sentences.append("The alert was driven by: " + "; ".join(signals[:3]) + ".")
        if hypothesis:
            support = brief.get("hypothesis_support") or [{}]
            reasons = support[0].get("for") or []
            sentences.append(
                f"The evidence is most consistent with {hypothesis.lower()}"
                + (f", supported by {reasons[0].lower()}." if reasons else ".")
            )
        else:
            sentences.append("No single fraud typology fits the evidence, so the alert rests on the risk score alone.")

        return CaseNarrative(
            headline=headline[:200],
            summary=" ".join(sentences),
            key_points=signals[:5] or ["No named risk signals were raised."],
            verification_steps=[
                "Confirm with the customer, on a channel not used in the flagged session, that they made this payment.",
                "Check whether the receiving account has been reported by other customers.",
                "Review the logins and credential changes in the 72 hours before the transaction.",
            ],
        )
