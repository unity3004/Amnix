"""Shared pytest fixtures.

Integration tests (marked with @pytest.mark.integration) need a reachable
PostgreSQL instance. They run against a dedicated `<postgres_db>_test`
database on the same server as backend/.env points at, so they never touch
real development data. That database's schema is bootstrapped directly via
Base.metadata.create_all() for test isolation/speed — this is a testing
convenience only; the actual application schema is owned exclusively by
Alembic migrations (see alembic/versions/).

Each test runs inside a transaction that is rolled back afterwards, so
tests never leak state into one another and the test database stays empty
between runs.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

import app.models  # noqa: F401  (registers models on Base.metadata)
from app.core.config import get_settings
from app.core.database import Base
from app.models.security_event import SecurityEvent


def _build_test_database_url() -> str | None:
    settings = get_settings()
    test_db_name = f"{settings.postgres_db}_test"
    admin_url = (
        f"postgresql+psycopg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/postgres"
    )
    try:
        admin_engine = create_engine(admin_url, isolation_level="AUTOCOMMIT")
        with admin_engine.connect() as conn:
            exists = conn.execute(
                text("SELECT 1 FROM pg_database WHERE datname = :name"),
                {"name": test_db_name},
            ).scalar()
            if not exists:
                conn.execute(text(f'CREATE DATABASE "{test_db_name}"'))
        admin_engine.dispose()
    except Exception:
        return None

    return (
        f"postgresql+psycopg://{settings.postgres_user}:{settings.postgres_password}"
        f"@{settings.postgres_host}:{settings.postgres_port}/{test_db_name}"
    )


@pytest.fixture(scope="session")
def _pg_engine():
    url = _build_test_database_url()
    if url is None:
        pytest.skip("PostgreSQL is not reachable; skipping integration tests")

    engine = create_engine(url)
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture
def db_session(_pg_engine):
    connection = _pg_engine.connect()
    transaction = connection.begin()
    session_local = sessionmaker(bind=connection)
    session = session_local()

    yield session

    session.close()
    transaction.rollback()
    connection.close()


@pytest.fixture
def event_factory():
    """Build transient (unpersisted) SecurityEvent instances for detection
    rule unit tests, which operate purely in memory and need no database.

    `id` is set explicitly since the real gen_random_uuid() default is
    computed server-side on insert — these objects are never inserted.
    """

    def _make(**overrides) -> SecurityEvent:
        defaults = {
            "id": uuid.uuid4(),
            "event_timestamp": datetime.now(timezone.utc),
            "event_type": "process_creation",
            "source": "test",
            "raw_data": {},
        }
        defaults.update(overrides)
        return SecurityEvent(**defaults)

    return _make
