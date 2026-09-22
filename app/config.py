import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent.parent

# Settings below (and the Gemini SDK's GEMINI_API_KEY lookup) read os.environ, so .env has to be
# loaded before either runs. Variables already set in the real environment take precedence.
load_dotenv(PROJECT_ROOT / ".env")


def _default_cors_origins() -> list:
    raw = os.getenv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
    return [origin.strip() for origin in raw.split(",") if origin.strip()]


@dataclass
class Settings:
    gemini_model: str = os.getenv("GEMINI_MODEL", "gemini-3-flash-preview")
    # Used when gemini_model is overloaded or rate-limited (preview models often return 503
    # "high demand"). Set to an empty string to disable the fallback.
    gemini_fallback_model: str = os.getenv("GEMINI_FALLBACK_MODEL", "gemini-2.5-flash")
    database_url: str = os.getenv("DATABASE_URL", "sqlite:///./finance_agent.db")
    upload_dir: str = os.getenv("UPLOAD_DIR", "storage/uploads")
    export_dir: str = os.getenv("EXPORT_DIR", "storage/exports")

    # Approval routing thresholds
    auto_approve_max_amount: float = float(os.getenv("AUTO_APPROVE_MAX_AMOUNT", "1000"))
    auto_approve_max_risk_score: int = int(os.getenv("AUTO_APPROVE_MAX_RISK_SCORE", "20"))
    mandatory_review_risk_score: int = int(os.getenv("MANDATORY_REVIEW_RISK_SCORE", "80"))

    # Duplicate detection
    duplicate_date_window_days: int = int(os.getenv("DUPLICATE_DATE_WINDOW_DAYS", "3"))
    duplicate_name_similarity: float = float(os.getenv("DUPLICATE_NAME_SIMILARITY", "0.9"))

    # Fraud investigation: triage thresholds on the 0-100 combined risk score
    # (< low_max -> low / auto-close, > high_min -> high / full investigation, else medium).
    fraud_low_risk_max: int = int(os.getenv("FRAUD_LOW_RISK_MAX", "30"))
    fraud_high_risk_min: int = int(os.getenv("FRAUD_HIGH_RISK_MIN", "70"))
    fraud_model_dir: str = os.getenv("FRAUD_MODEL_DIR", "storage/models")
    fraud_graph_max_hops: int = int(os.getenv("FRAUD_GRAPH_MAX_HOPS", "3"))
    # The LLM only writes the case narrative; scores, hypotheses and triage stay deterministic.
    fraud_use_llm: bool = os.getenv("FRAUD_USE_LLM", "true").lower() in ("1", "true", "yes")

    # Frontend origins allowed to call this API (comma-separated)
    cors_origins: list = field(default_factory=_default_cors_origins)
    # Vite picks the next free port (5173, 5174, ...) when one is taken, so match any
    # localhost/127.0.0.1 port in dev rather than hardcoding one - override for production.
    cors_origin_regex: str = os.getenv("CORS_ORIGIN_REGEX", r"http://(localhost|127\.0\.0\.1):\d+")


settings = Settings()
