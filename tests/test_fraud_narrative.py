"""The narrative agent: the only LLM in the investigation, and what happens when it is not there."""
import pytest
from google.genai import errors as genai_errors

from app.config import settings
from app.fraud_investigation import agents, pipeline
from app.fraud_investigation.agents import narrative as narrative_module
from app.fraud_investigation.agents.narrative import CaseNarrative
from tests import fraud_factory as factory


@pytest.fixture()
def context(db_session):
    factory.baseline(db_session)
    transaction = factory.takeover_transaction(db_session)
    assessment = pipeline.assess(db_session, transaction)
    alert = pipeline.create_alert(db_session, assessment)
    db_session.commit()
    return pipeline.build_context(db_session, alert, assessment)


def run(ctx):
    agents.run_agents(ctx)
    return ctx.section_data("narrative")


def test_the_deterministic_writer_produces_a_usable_summary(context):
    """With the LLM off, a case is still readable - the queue does not stop."""
    result = run(context)
    assert result["source"] == "deterministic"
    assert result["headline"] and result["summary"]
    assert result["key_points"]
    assert result["verification_steps"]


def test_the_deterministic_summary_states_the_score_and_hypothesis(context):
    result = run(context)
    assert str(context.scoring["risk_score"]) in result["headline"]
    assert "takeover" in result["headline"].lower()


def test_the_llm_writes_the_summary_when_it_is_available(context, monkeypatch):
    monkeypatch.setattr(settings, "fraud_use_llm", True)
    monkeypatch.setattr(narrative_module, "is_configured", lambda: True)
    captured = {}

    def fake_generate(prompt, schema):
        captured["prompt"] = prompt
        return CaseNarrative(
            headline="Funds moved out after a credential reset",
            summary="A large transfer followed a password reset from a new device abroad.",
            key_points=["Password reset 45 minutes earlier"],
            verification_steps=["Call the customer on their registered number"],
        )

    monkeypatch.setattr(narrative_module, "generate_structured", fake_generate)
    result = run(context)

    assert result["source"] == "llm"
    assert result["headline"] == "Funds moved out after a credential reset"
    # The conclusions are handed to the model, not asked of it.
    assert "leading_hypothesis" in captured["prompt"]
    assert "risk_score" in captured["prompt"]


def test_an_llm_outage_degrades_instead_of_losing_the_case(context, monkeypatch):
    monkeypatch.setattr(settings, "fraud_use_llm", True)
    monkeypatch.setattr(narrative_module, "is_configured", lambda: True)

    def boom(prompt, schema):
        raise genai_errors.APIError(503, {"message": "model overloaded"})

    monkeypatch.setattr(narrative_module, "generate_structured", boom)
    result = run(context)

    assert result["source"] == "deterministic"
    assert result["error"], "the outage must be recorded on the case, not hidden"
    assert result["summary"]


def test_a_malformed_llm_response_also_degrades(context, monkeypatch):
    monkeypatch.setattr(settings, "fraud_use_llm", True)
    monkeypatch.setattr(narrative_module, "is_configured", lambda: True)

    def bad_json(prompt, schema):
        raise ValueError("Gemini returned an empty response for CaseNarrative")

    monkeypatch.setattr(narrative_module, "generate_structured", bad_json)
    assert run(context)["source"] == "deterministic"


def test_the_case_file_records_which_writer_was_used(db_session):
    factory.baseline(db_session)
    _, case = pipeline.process_transaction(db_session, factory.takeover_transaction(db_session))
    assert case.case_file["narrative_source"] == "deterministic"


def test_one_failing_agent_does_not_lose_the_whole_case(context, monkeypatch):
    """A case missing its network section beats no case at all."""
    def explode(self, ctx):
        raise RuntimeError("graph backend unavailable")

    monkeypatch.setattr("app.fraud_investigation.agents.network.NetworkAgent.run", explode)
    agents.run_agents(context)
    case_file = agents.build_case_file(context)

    network = next(s for s in case_file["sections"] if s["agent"] == "network")
    assert network["confidence"] == 0.0
    assert "graph backend unavailable" in network["data"]["error"]
    assert case_file["primary_hypothesis"], "the rest of the investigation still ran"
