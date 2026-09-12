"""Integration tests for Step 11H: POST /auth/login rate limiting.
Require PostgreSQL AND a reachable Redis (see conftest.py's db_session
fixture and this file's own _redis_client fixture, which skips if Redis
is unreachable, mirroring the Postgres skip pattern).

Every other test file in this suite disables the real rate limiter by
default (see tests/conftest.py's `_disable_login_rate_limiting` autouse
fixture) because Starlette's TestClient always reports the same fixed
pseudo-IP ("testclient") regardless of which test is running -- without
that, every test across the whole suite that logs in would share one
global Redis-backed budget. This file explicitly re-enables the real
dependency and is careful to isolate its own Redis key(s) between tests.

Two layers are tested: app.core.rate_limit.check_and_increment directly
(fast, deterministic window/identity-isolation behavior, no HTTP), and
the full route through POST /auth/login (status codes, headers, scope,
fail-open behavior).
"""

import time
import uuid

import pytest
import redis as redis_lib
from fastapi.testclient import TestClient

from app.api.dependencies import enforce_login_rate_limit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import check_and_increment
from app.core.redis import get_redis_client
from app.main import app

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"
RATE_LIMIT_KEY = "ratelimit:login:testclient"


@pytest.fixture(scope="session")
def _redis_client():
    client = get_redis_client()
    try:
        client.ping()
    except redis_lib.RedisError:
        pytest.skip("Redis is not reachable; skipping rate limit tests")
    return client


@pytest.fixture
def clean_rate_limit_key(_redis_client):
    _redis_client.delete(RATE_LIMIT_KEY)
    yield
    _redis_client.delete(RATE_LIMIT_KEY)


@pytest.fixture
def client(db_session, clean_rate_limit_key):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    # Undo conftest's blanket override for this file only -- the real
    # dependency (and therefore real Redis) is exactly what these tests
    # need to exercise.
    app.dependency_overrides.pop(enforce_login_rate_limit, None)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def low_limit():
    """Temporarily lowers the real, cached Settings instance's rate-limit
    threshold so tests can exceed it in a handful of requests rather than
    the production default of 10. get_settings() is @lru_cache'd, so
    mutating the one cached instance's attributes affects every
    subsequent call the running app makes -- restored afterward.
    """
    settings = get_settings()
    original_max = settings.login_rate_limit_max_attempts
    original_window = settings.login_rate_limit_window_seconds
    settings.login_rate_limit_max_attempts = 3
    settings.login_rate_limit_window_seconds = 60
    yield settings.login_rate_limit_max_attempts
    settings.login_rate_limit_max_attempts = original_max
    settings.login_rate_limit_window_seconds = original_window


def _unique_email(prefix: str = "ratelimit") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register(client, email: str, password: str = VALID_PASSWORD) -> None:
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201, response.text


# =============================================================================
# Core primitive: app.core.rate_limit.check_and_increment
# =============================================================================


def test_check_and_increment_allows_requests_below_the_limit(_redis_client):
    key = f"ratelimit:test:{uuid.uuid4().hex}"
    try:
        result = check_and_increment(_redis_client, key=key, max_attempts=3, window_seconds=60)
        assert result.allowed is True
        assert result.remaining == 2
    finally:
        _redis_client.delete(key)


def test_check_and_increment_denies_once_the_limit_is_exceeded(_redis_client):
    key = f"ratelimit:test:{uuid.uuid4().hex}"
    try:
        for _ in range(3):
            check_and_increment(_redis_client, key=key, max_attempts=3, window_seconds=60)
        result = check_and_increment(_redis_client, key=key, max_attempts=3, window_seconds=60)
        assert result.allowed is False
        assert result.remaining == 0
    finally:
        _redis_client.delete(key)


def test_check_and_increment_independent_keys_have_independent_budgets(_redis_client):
    key_a = f"ratelimit:test:{uuid.uuid4().hex}"
    key_b = f"ratelimit:test:{uuid.uuid4().hex}"
    try:
        for _ in range(3):
            check_and_increment(_redis_client, key=key_a, max_attempts=3, window_seconds=60)
        result_a = check_and_increment(_redis_client, key=key_a, max_attempts=3, window_seconds=60)
        result_b = check_and_increment(_redis_client, key=key_b, max_attempts=3, window_seconds=60)

        assert result_a.allowed is False
        assert result_b.allowed is True
    finally:
        _redis_client.delete(key_a)
        _redis_client.delete(key_b)


def test_check_and_increment_window_expiry_resets_the_counter(_redis_client):
    key = f"ratelimit:test:{uuid.uuid4().hex}"
    try:
        first = check_and_increment(_redis_client, key=key, max_attempts=1, window_seconds=1)
        blocked = check_and_increment(_redis_client, key=key, max_attempts=1, window_seconds=1)
        time.sleep(1.5)
        reset = check_and_increment(_redis_client, key=key, max_attempts=1, window_seconds=1)

        assert first.allowed is True
        assert blocked.allowed is False
        assert reset.allowed is True
    finally:
        _redis_client.delete(key)


# =============================================================================
# Route: POST /auth/login
# =============================================================================


def test_requests_below_the_limit_all_succeed(client, low_limit):
    email = _unique_email()
    _register(client, email)

    for _ in range(low_limit):
        response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
        assert response.status_code == 200


def test_exceeding_the_limit_returns_429_with_generic_body(client, low_limit):
    email = _unique_email()
    _register(client, email)
    for _ in range(low_limit):
        client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 429
    assert response.json() == {"detail": "Too many login attempts. Please try again later."}


def test_429_response_includes_a_sane_retry_after_header(client, low_limit):
    email = _unique_email()
    _register(client, email)
    for _ in range(low_limit):
        client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 429
    retry_after = int(response.headers["retry-after"])
    assert 0 < retry_after <= 60


def test_limit_is_shared_across_different_emails_from_the_same_client(client, low_limit):
    """The limiter is keyed on client IP, not email -- a script rotating
    through many different email addresses from the same source is still
    bounded by one shared budget (see enforce_login_rate_limit's own
    docstring for why email is deliberately not part of the key).
    """
    for _ in range(low_limit):
        email = _unique_email()
        _register(client, email)
        response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
        assert response.status_code == 200

    another_email = _unique_email()
    _register(client, another_email)
    response = client.post("/auth/login", json={"email": another_email, "password": VALID_PASSWORD})

    assert response.status_code == 429


def test_failed_login_attempts_also_count_toward_the_limit(client, low_limit):
    """Counting only successful logins would let an attacker brute-force
    passwords for free as long as they never guess correctly -- exactly
    the scenario this control exists to blunt. Failures must count too.
    """
    email = _unique_email()
    _register(client, email)

    for _ in range(low_limit):
        response = client.post("/auth/login", json={"email": email, "password": "wrong password"})
        assert response.status_code == 401

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 429


def test_rate_limiting_does_not_apply_to_register(client, low_limit):
    """Scope check: Step 11H intentionally limits only POST /auth/login
    (see enforce_login_rate_limit's own docstring) -- registration is
    unaffected even well past what would exhaust the login budget.
    """
    for _ in range(low_limit + 2):
        response = client.post("/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD})
        assert response.status_code == 201


def test_rate_limiting_does_not_apply_to_refresh(client, low_limit):
    """Scope check, same reasoning -- /auth/refresh (already protected by
    Step 11D's reuse-detection) is unaffected by the login limiter.
    """
    for _ in range(low_limit + 2):
        response = client.post("/auth/refresh", json={"refresh_token": "garbage-not-a-real-token"})
        assert response.status_code == 401


def test_fails_open_when_redis_is_unreachable(client, monkeypatch):
    """If the rate limiter's own backend is down, login must still work
    -- see enforce_login_rate_limit's own docstring for why fail-open was
    chosen over fail-closed for this specific control.
    """
    import app.api.dependencies as dependencies_module

    broken_client = redis_lib.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2, socket_timeout=0.2)
    monkeypatch.setattr(dependencies_module, "get_redis_client", lambda: broken_client)

    email = _unique_email()
    _register(client, email)

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200
