import logging
import os
from functools import lru_cache
from typing import Type, TypeVar

from google import genai
from google.genai import errors, types
from pydantic import BaseModel

from app.config import settings

logger = logging.getLogger("uvicorn.error")

T = TypeVar("T", bound=BaseModel)

# Overloaded / rate-limited / transient server errors - worth trying the fallback model for.
FALLBACK_STATUS_CODES = {429, 500, 503, 504}


class GeminiNotConfiguredError(RuntimeError):
    """Raised when no Gemini credentials are present in the environment."""


def is_configured() -> bool:
    return bool(
        os.getenv("GEMINI_API_KEY") or os.getenv("GOOGLE_API_KEY") or os.getenv("GOOGLE_GENAI_USE_VERTEXAI")
    )


@lru_cache(maxsize=1)
def get_client() -> genai.Client:
    """Lazily construct the Gemini client. google-genai validates the API key
    eagerly at construction time, so this must not run at import time - it
    would break importing the extraction/fraud modules (and anything that
    imports them, including pure-logic unit tests) whenever no key is set."""
    if not is_configured():
        raise GeminiNotConfiguredError(
            "GEMINI_API_KEY is not set. Add it to the .env file in the project root and restart the backend."
        )
    # The SDK doesn't retry at all unless retry options are given; retry transient errors
    # (429/5xx) a couple of times with backoff before giving up.
    return genai.Client(
        http_options=types.HttpOptions(retry_options=types.HttpRetryOptions(attempts=3, max_delay=8))
    )


def generate_structured(contents, schema: Type[T]) -> T:
    """Call Gemini with a JSON response schema and return the result as a `schema` instance.
    Falls back to settings.gemini_fallback_model if the primary model is unavailable."""
    config = types.GenerateContentConfig(
        response_mime_type="application/json",
        response_schema=schema,
        automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
    )
    try:
        response = get_client().models.generate_content(
            model=settings.gemini_model, contents=contents, config=config
        )
    except errors.APIError as exc:
        fallback = settings.gemini_fallback_model
        if exc.code not in FALLBACK_STATUS_CODES or not fallback or fallback == settings.gemini_model:
            raise
        logger.warning(
            "Gemini model %s unavailable (%s %s), retrying with %s",
            settings.gemini_model, exc.code, exc.status, fallback,
        )
        response = get_client().models.generate_content(model=fallback, contents=contents, config=config)

    if isinstance(response.parsed, schema):
        return response.parsed

    # The SDK leaves `parsed` as None when the JSON doesn't validate (e.g. truncated output or a
    # missing required field). Validate it ourselves so the error says what actually went wrong
    # instead of a later AttributeError on None.
    if not response.text:
        raise ValueError(f"Gemini returned an empty response for {schema.__name__}")
    return schema.model_validate_json(response.text)
