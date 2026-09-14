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
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.mitre.registry import MAPPING_SOURCE, MITRE_ATTACK_VERSION
from app.schemas.ai import AIContext, AIEntities, MITREContext


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


@pytest.fixture(autouse=True)
def _disable_login_rate_limiting():
    """Step 11H: app.api.dependencies.enforce_login_rate_limit keys its
    Redis counter on the request's client IP. Starlette's TestClient
    always reports the same fixed pseudo-IP ("testclient") regardless of
    which test or test file is running, so without this override every
    test across the entire suite that calls POST /auth/login (most of
    them, via each file's own `_authenticate()` helper) would share one
    global budget and start tripping 429s on each other well before any
    single test intended to exercise rate limiting.

    Disabled by default for every test, autouse so no individual test
    file has to remember to do this. Function-scoped autouse fixtures
    run before other function-scoped fixtures a test explicitly requests
    (pytest's documented ordering), so this override is already in place
    before any test's own `client`/TestClient fixture runs.
    tests/test_rate_limit.py, which exists specifically to exercise the
    real behavior, pops this override back out in its own `client`
    fixture before yielding.
    """
    from app.api.dependencies import enforce_login_rate_limit
    from app.main import app

    app.dependency_overrides[enforce_login_rate_limit] = lambda: None
    yield
    app.dependency_overrides.pop(enforce_login_rate_limit, None)


@pytest.fixture
def db_session(_pg_engine):
    """Step 12R discovery: a plain `sessionmaker(bind=connection)` joined
    to an already-`begin()`'d Connection does NOT keep this fixture's own
    "everything rolls back" contract for a test that calls
    `session.commit()` more than once (every repository in this codebase
    that calls `.commit()` internally -- AlertRepository, UserRepository,
    CopilotAuditRepository, etc. -- does exactly that whenever a test
    builds more than one row). Each `session.commit()` was actually
    ending the real, cross-connection-visible transaction rather than
    staying nested inside it, so only the LAST pending change before
    teardown was ever rolled back -- everything committed earlier in the
    same test permanently persisted into the `_test` database. This was
    silently accumulating garbage in that database across every prior
    test invocation this session (confirmed directly: `amnix_test` held
    163 leftover User rows and 74 leftover AdminAudit rows from
    unmodified, pre-existing test files at the time this was found),
    eventually surfacing as failures in unrelated tests that scan a
    whole table expecting an exact/empty count (test_alert_list_api.py,
    test_security_event_list_api.py). `join_transaction_mode=
    "create_savepoint"` is SQLAlchemy 2.0's built-in fix for precisely
    this scenario: a Session joining an externally-managed transaction
    now transparently uses a SAVEPOINT for its own commit/rollback
    calls, so `session.commit()` releases (and immediately reopens) a
    SAVEPOINT instead of ending the real transaction -- the outer
    `transaction` this fixture began stays open, and its own
    `rollback()` below now genuinely undoes everything, no matter how
    many times a test (or the repositories it calls) committed.
    """
    connection = _pg_engine.connect()
    transaction = connection.begin()
    session_local = sessionmaker(bind=connection, join_transaction_mode="create_savepoint")
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


@pytest.fixture
def alert_factory():
    """Build transient (unpersisted) Alert instances for investigation
    engine unit tests, which operate purely in memory and need no
    database. `security_events` may be passed a list of (also transient)
    SecurityEvent instances directly — SQLAlchemy relationship
    collections work as plain Python lists on unpersisted objects.
    """

    def _make(**overrides) -> Alert:
        now = datetime.now(timezone.utc)
        defaults = {
            "id": uuid.uuid4(),
            "rule_id": "brute_force_authentication",
            "title": "Test alert",
            "description": "Test alert description.",
            "severity": "high",
            "confidence": "high",
            "status": "new",
            "first_seen": now,
            "last_seen": now,
            "created_at": now,
            "updated_at": now,
            "evidence": {},
            "security_events": [],
        }
        defaults.update(overrides)
        return Alert(**defaults)

    return _make


@pytest.fixture
def ai_context_factory():
    """Build minimal, valid AIContext instances directly (no DB, no
    InvestigationContext round-trip needed) for provider/prompt-layer
    unit tests that don't care how the context was derived.
    """

    def _make(**overrides) -> AIContext:
        defaults = {
            "alert_id": uuid.uuid4(),
            "rule_id": "brute_force_authentication",
            "title": "Test alert",
            "description": "Test alert description.",
            "severity": "high",
            "confidence": "high",
            "status": "new",
            "evidence": {},
            "timeline": [],
            "entities": AIEntities(),
            "investigation_summary": "Alert generated by rule 'brute_force_authentication'.",
            "mitre": MITREContext(candidate_techniques=[], mapping_source=MAPPING_SOURCE, mapping_version=MITRE_ATTACK_VERSION),
        }
        defaults.update(overrides)
        return AIContext(**defaults)

    return _make
