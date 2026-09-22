from types import SimpleNamespace

import pytest
from google.genai import errors
from pydantic import BaseModel

from app.config import settings
from app.pipeline import gemini_client


class Answer(BaseModel):
    value: int


class FakeModels:
    def __init__(self, outcomes):
        self.outcomes = outcomes
        self.called_models = []

    def generate_content(self, model, contents, config):
        self.called_models.append(model)
        outcome = self.outcomes.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        return outcome


@pytest.fixture()
def fake_models(monkeypatch):
    def install(*outcomes):
        models = FakeModels(list(outcomes))
        monkeypatch.setattr(gemini_client, "get_client", lambda: SimpleNamespace(models=models))
        return models

    monkeypatch.setattr(settings, "gemini_model", "primary-model")
    monkeypatch.setattr(settings, "gemini_fallback_model", "fallback-model")
    return install


def overloaded():
    return errors.ServerError(503, {"error": {"code": 503, "message": "high demand", "status": "UNAVAILABLE"}})


def test_returns_parsed_response(fake_models):
    fake_models(SimpleNamespace(parsed=Answer(value=1), text='{"value": 1}'))
    assert gemini_client.generate_structured("q", Answer) == Answer(value=1)


def test_falls_back_when_primary_model_is_overloaded(fake_models):
    models = fake_models(overloaded(), SimpleNamespace(parsed=Answer(value=2), text='{"value": 2}'))
    assert gemini_client.generate_structured("q", Answer).value == 2
    assert models.called_models == ["primary-model", "fallback-model"]


def test_does_not_fall_back_on_client_errors(fake_models):
    bad_request = errors.ClientError(400, {"error": {"code": 400, "message": "bad", "status": "INVALID_ARGUMENT"}})
    models = fake_models(bad_request)
    with pytest.raises(errors.ClientError):
        gemini_client.generate_structured("q", Answer)
    assert models.called_models == ["primary-model"]


def test_validates_raw_text_when_sdk_did_not_parse(fake_models):
    fake_models(SimpleNamespace(parsed=None, text='{"value": 3}'))
    assert gemini_client.generate_structured("q", Answer).value == 3


def test_empty_response_raises_clear_error(fake_models):
    fake_models(SimpleNamespace(parsed=None, text=None))
    with pytest.raises(ValueError, match="empty response"):
        gemini_client.generate_structured("q", Answer)
