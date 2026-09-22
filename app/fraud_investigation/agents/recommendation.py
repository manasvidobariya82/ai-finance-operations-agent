"""Recommendation agent: what an analyst should consider doing, and why.

Nothing here executes. Every action is a proposal attached to the case and recorded in the audit
trail; it only takes effect when a human decides on the case (see `cases.decide`). That split is
deliberate - an automated freeze on a false positive locks a customer out of their own money, so
the system is built to recommend and explain rather than to act.

Which actions are proposed follows the hypothesis, not just the score, because the typologies call
for opposite responses: a takeover victim needs their credentials reset and the payment stopped, a
scam victim needs a phone call before they send the next one, and freezing the latter's account
helps nobody.
"""
from typing import List

from app.fraud_investigation.agents.base import AgentResult, InvestigationContext

IMMEDIATE = "immediate"
STANDARD = "standard"


def _action(action: str, label: str, rationale: str, urgency: str = STANDARD) -> dict:
    return {
        "action": action,
        "label": label,
        "rationale": rationale,
        "urgency": urgency,
        # Detection never acts on its own; see the module docstring.
        "requires_analyst_approval": True,
    }


class RecommendationAgent:
    name = "recommendation"
    title = "Recommended actions"

    def run(self, ctx: InvestigationContext) -> AgentResult:
        hypothesis = ctx.section_data("hypothesis")
        intel = ctx.section_data("intel")
        fraud_type = hypothesis.get("fraud_type")
        level = ctx.scoring["risk_level"]
        actions: List[dict] = []

        if intel.get("sanctions_hit"):
            actions += [
                _action("hold_transaction", "Hold the transaction", "A sanctions match must be cleared before funds move.", IMMEDIATE),
                _action("escalate_compliance", "Escalate to financial crime compliance", "Sanctions exposure is a regulatory matter, not a fraud-team decision.", IMMEDIATE),
                _action("file_sar", "Prepare a suspicious activity report", "A confirmed sanctions match is reportable."),
            ]

        if fraud_type == "account_takeover":
            actions += [
                _action("hold_transaction", "Hold the transaction pending verification", "The payment is the likely cash-out of a compromised account.", IMMEDIATE),
                _action("force_credential_reset", "Force a credential reset and revoke sessions", "Control of the account appears to rest with a third party.", IMMEDIATE),
                _action("contact_customer", "Contact the customer out of band", "Verify on a channel the attacker does not control - not the registered device or email."),
                _action("block_beneficiary", "Block the receiving beneficiary", "Stops further payments to the same destination while the case is open."),
            ]
        elif fraud_type == "authorised_push_payment_scam":
            actions += [
                _action("hold_transaction", "Hold the transaction pending a customer conversation", "The customer authorised this themselves; the question is whether they were deceived.", IMMEDIATE),
                _action("contact_customer", "Call the customer and confirm the payment's purpose", "Scam victims usually reveal the pretext when asked directly about it.", IMMEDIATE),
                _action("warn_customer", "Deliver a scam warning before releasing funds", "Documented warnings matter for the reimbursement position later."),
            ]
        elif fraud_type == "card_testing":
            actions += [
                _action("block_card", "Block the card and reissue", "The card details are being validated for use elsewhere.", IMMEDIATE),
                _action("hold_transaction", "Reverse or hold the test transactions", "Small authorisations are the rehearsal, not the loss."),
                _action("contact_customer", "Notify the customer of the card compromise", "The card must be treated as compromised wherever else it is stored."),
            ]
        elif fraud_type == "money_mule_network":
            actions += [
                _action("block_beneficiary", "Block the receiving beneficiary", "The account is collecting funds from multiple unrelated customers.", IMMEDIATE),
                _action("report_network", "Refer the connected entities for network investigation", "The linked accounts are likely part of the same laundering layer."),
                _action("file_sar", "Prepare a suspicious activity report", "Layering through mule accounts is reportable."),
            ]
        elif fraud_type == "synthetic_or_first_party":
            actions += [
                _action("restrict_account", "Restrict outbound payments on the account", "The account itself, not the customer, is the likely problem.", IMMEDIATE),
                _action("escalate_kyc", "Re-run KYC and request identity re-verification", "Identity evidence is incomplete or shared with other accounts."),
            ]

        if not actions:
            if level == "high":
                actions.append(_action("hold_transaction", "Hold the transaction pending review", "Risk is high even though no single typology fits the evidence.", IMMEDIATE))
            actions.append(_action("contact_customer", "Verify the transaction with the customer", "The fastest way to resolve an alert with no clear typology."))

        actions.append(
            _action("monitor", "Keep the account under enhanced monitoring", "Applies whatever the outcome, until the case is closed.")
        )

        seen, deduped = set(), []
        for item in actions:
            if item["action"] not in seen:
                seen.add(item["action"])
                deduped.append(item)

        immediate = [item for item in deduped if item["urgency"] == IMMEDIATE]
        summary = (
            f"{len(immediate)} action(s) recommended before funds move, {len(deduped) - len(immediate)} for the case workflow."
            if immediate
            else f"{len(deduped)} action(s) recommended; nothing needs to happen before funds move."
        )

        return AgentResult(
            name=self.name,
            title=self.title,
            summary=summary,
            findings=[f"{item['label']} - {item['rationale']}" for item in deduped],
            data={"actions": deduped, "immediate_actions": [item["action"] for item in immediate]},
            confidence=0.9 if fraud_type else 0.5,
        )
