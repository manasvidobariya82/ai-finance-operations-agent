import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.db import Base

# Imported for the side effect of registering the fraud-investigation tables on Base, so
# create_all below builds them for every test database.
from app.fraud_investigation import models as fraud_models  # noqa: F401


@pytest.fixture()
def db_session():
    # StaticPool shares one connection, so API tests (endpoints run in a worker thread)
    # see the same in-memory database as the test itself.
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(bind=engine)
    session = sessionmaker(autocommit=False, autoflush=False, bind=engine)()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture(autouse=True)
def no_llm_calls(monkeypatch):
    """Keep the whole suite offline.

    A developer's .env is loaded at import time, so a real GEMINI_API_KEY would otherwise be
    picked up and the narrative agent would make live API calls during tests. The deterministic
    writer is exercised instead; the LLM path is tested by faking the client.
    """
    monkeypatch.setattr(settings, "fraud_use_llm", False)
