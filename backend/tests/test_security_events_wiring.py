"""Integration tests for Step 11J: security events actually wired into
AMNIX's real security boundaries (app.api.dependencies, app.api.auth,
app.api.admin, app.middleware.request_size_limit). Require PostgreSQL
and Redis.

Every test here exercises the REAL code path (a real HTTP request
through app.main:app) and captures the "amnix.security" logger via
pytest's caplog, then parses each captured record as JSON -- this
proves an event was actually emitted by the wired-in call site, not
merely that the standalone SecurityEvent/log_security_event primitives
work in isolation (that is tests/test_security_events.py's job).
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

import redis as redis_lib

from app.api.dependencies import enforce_login_rate_limit
from app.core.config import get_settings
from app.core.database import get_db
from app.core.redis import get_redis_client
from app.core.security import hash_password
from app.main import app
from app.models.user import User
from app.repositories.user import UserRepository

RATE_LIMIT_KEY = "ratelimit:login:testclient"

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"

VALID_EVENT_PAYLOAD = {
    "event_timestamp": "2026-09-09T10:00:00Z",
    "event_type": "process_creation",
    "source": "test",
    "raw_data": {},
}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture(scope="session")
def _redis_client():
    redis_client = get_redis_client()
    try:
        redis_client.ping()
    except redis_lib.RedisError:
        pytest.skip("Redis is not reachable; skipping rate-limit-dependent tests")
    return redis_client


@pytest.fixture
def rate_limited_client(db_session, _redis_client):
    """Like `client`, but also pops conftest's blanket
    _disable_login_rate_limiting override so the real Redis-backed
    limiter runs -- see tests/test_rate_limit.py for the same pattern
    and why it's necessary (TestClient shares one fixed pseudo-IP across
    the whole suite). Also clears the shared Redis rate-limit key before
    and after, so this file's own tests don't pollute each other (every
    test in this file shares the same "testclient" pseudo-IP, and
    therefore the same Redis key, unlike Postgres's per-test rolled-back
    transaction).
    """
    _redis_client.delete(RATE_LIMIT_KEY)

    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    app.dependency_overrides.pop(enforce_login_rate_limit, None)
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
    _redis_client.delete(RATE_LIMIT_KEY)


@pytest.fixture
def low_login_limit():
    settings = get_settings()
    original_max = settings.login_rate_limit_max_attempts
    original_window = settings.login_rate_limit_window_seconds
    settings.login_rate_limit_max_attempts = 2
    settings.login_rate_limit_window_seconds = 60
    yield settings.login_rate_limit_max_attempts
    settings.login_rate_limit_max_attempts = original_max
    settings.login_rate_limit_window_seconds = original_window


def _unique_email(prefix: str = "secevt") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client, *, password: str = VALID_PASSWORD) -> tuple[str, str, dict]:
    email = _unique_email()
    register_response = client.post("/auth/register", json={"email": email, "password": password})
    assert register_response.status_code == 201, register_response.text
    login_response = client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200, login_response.text
    body = login_response.json()
    return email, body["access_token"], body["user"]


def _create_admin_and_login(client, db_session) -> tuple[str, str, dict]:
    email = _unique_email("admin")
    admin_user = User(email=email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(admin_user)
    db_session.commit()
    login_response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    assert login_response.status_code == 200, login_response.text
    body = login_response.json()
    return email, body["access_token"], body["user"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _security_events(caplog) -> list[dict]:
    return [json.loads(r.message) for r in caplog.records if r.name == "amnix.security"]


def _settings_max_bytes() -> int:
    return get_settings().max_request_body_bytes


# =============================================================================
# Auth events (12-15)
# =============================================================================


def test_login_success_emits_correct_event(client, caplog):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200
    events = _security_events(caplog)
    login_events = [e for e in events if e["event_type"] == "AUTH_LOGIN_SUCCESS"]
    assert len(login_events) == 1
    assert login_events[0]["outcome"] == "success"
    assert login_events[0]["actor_user_id"] == response.json()["user"]["id"]
    assert "login_identifier_fingerprint" in login_events[0]
    assert email not in json.dumps(login_events[0])


def test_login_failure_emits_correct_event(client, caplog):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post("/auth/login", json={"email": email, "password": "totally wrong password"})

    assert response.status_code == 401
    events = _security_events(caplog)
    failure_events = [e for e in events if e["event_type"] == "AUTH_LOGIN_FAILURE"]
    assert len(failure_events) == 1
    assert failure_events[0]["outcome"] == "failure"
    assert "actor_user_id" not in failure_events[0]
    assert "login_identifier_fingerprint" in failure_events[0]
    assert email not in json.dumps(failure_events[0])
    assert "wrong password" not in json.dumps(failure_events[0])


def test_invalid_jwt_emits_correct_event(client, caplog):
    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer("garbage-not-a-jwt"))

    assert response.status_code == 401
    events = _security_events(caplog)
    token_events = [e for e in events if e["event_type"] == "AUTH_TOKEN_INVALID"]
    assert len(token_events) == 1
    assert "actor_user_id" not in token_events[0]


def test_inactive_user_emits_correct_event(client, db_session, caplog):
    _, token, user_body = _register_and_login(client)
    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    user.is_active = False
    db_session.commit()

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401
    events = _security_events(caplog)
    inactive_events = [e for e in events if e["event_type"] == "AUTH_USER_INACTIVE"]
    assert len(inactive_events) == 1
    assert inactive_events[0]["actor_user_id"] == user_body["id"]


# =============================================================================
# Authorization events (16-17)
# =============================================================================


def test_analyst_hitting_admin_endpoint_emits_authorization_denied(client, caplog):
    _, analyst_token, analyst_body = _register_and_login(client)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.patch(
            f"/admin/users/{analyst_body['id']}/status", json={"is_active": False}, headers=_bearer(analyst_token)
        )

    assert response.status_code == 403
    events = _security_events(caplog)
    denied_events = [e for e in events if e["event_type"] == "AUTHORIZATION_DENIED"]
    assert len(denied_events) == 1
    assert denied_events[0]["actor_user_id"] == analyst_body["id"]
    assert denied_events[0]["status_code"] == 403


def test_admin_success_does_not_emit_a_false_authorization_denial(client, db_session, caplog):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.patch(
            f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
        )

    assert response.status_code == 200
    events = _security_events(caplog)
    assert not [e for e in events if e["event_type"] == "AUTHORIZATION_DENIED"]


# =============================================================================
# Rate-limit events (18-19)
# =============================================================================


def test_rate_limit_rejection_emits_correct_event(rate_limited_client, low_login_limit, caplog):
    email = _unique_email()
    rate_limited_client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    for _ in range(low_login_limit):
        rate_limited_client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    with caplog.at_level("INFO", logger="amnix.security"):
        response = rate_limited_client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 429
    events = _security_events(caplog)
    rate_limit_events = [e for e in events if e["event_type"] == "AUTH_RATE_LIMITED"]
    assert len(rate_limit_events) == 1
    assert rate_limit_events[0]["status_code"] == 429


def test_ordinary_login_does_not_emit_a_rate_limit_event(rate_limited_client, caplog):
    email = _unique_email()
    rate_limited_client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    with caplog.at_level("INFO", logger="amnix.security"):
        response = rate_limited_client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200
    events = _security_events(caplog)
    assert not [e for e in events if e["event_type"] == "AUTH_RATE_LIMITED"]


# =============================================================================
# Admin events (20-21)
# =============================================================================


def test_successful_status_change_emits_admin_user_status_changed(client, db_session, caplog):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.patch(
            f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
        )

    assert response.status_code == 200
    events = _security_events(caplog)
    changed_events = [e for e in events if e["event_type"] == "ADMIN_USER_STATUS_CHANGED"]
    assert len(changed_events) == 1
    assert changed_events[0]["actor_user_id"] == admin_body["id"]
    assert changed_events[0]["target_user_id"] == target_body["id"]
    assert changed_events[0]["target_is_active"] is False


def test_self_target_conflict_does_not_emit_a_false_success(client, db_session, caplog):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.patch(
            f"/admin/users/{admin_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
        )

    assert response.status_code == 409
    events = _security_events(caplog)
    assert not [e for e in events if e["event_type"] == "ADMIN_USER_STATUS_CHANGED"]


def test_nonexistent_target_does_not_emit_a_false_success(client, db_session, caplog):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.patch(
            f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False}, headers=_bearer(admin_token)
        )

    assert response.status_code == 404
    events = _security_events(caplog)
    assert not [e for e in events if e["event_type"] == "ADMIN_USER_STATUS_CHANGED"]


# =============================================================================
# Request-size events (22-23)
# =============================================================================


def test_oversized_request_emits_request_body_too_large(client, caplog):
    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post(
            "/events",
            content=b"x" * 10,
            headers={"content-length": str(_settings_max_bytes() + 1)},
        )

    assert response.status_code == 413
    events = _security_events(caplog)
    size_events = [e for e in events if e["event_type"] == "REQUEST_BODY_TOO_LARGE"]
    assert len(size_events) == 1
    assert size_events[0]["status_code"] == 413


def test_normal_request_does_not_emit_a_size_event(client, caplog):
    _, token, _ = _register_and_login(client)

    with caplog.at_level("INFO", logger="amnix.security"):
        response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 201
    events = _security_events(caplog)
    assert not [e for e in events if e["event_type"] == "REQUEST_BODY_TOO_LARGE"]


# =============================================================================
# Failure isolation (24-29): the security logger is deliberately broken
# for each of these, and the real security behavior must be unaffected.
# =============================================================================


@pytest.fixture
def broken_security_logger(monkeypatch):
    import app.core.security_events as security_events_module

    def _broken_log(*args, **kwargs):
        raise RuntimeError("security logging backend is completely broken")

    monkeypatch.setattr(security_events_module._logger, "log", _broken_log)


def test_logger_failure_does_not_break_login(client, broken_security_logger):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200


def test_logger_failure_does_not_break_authentication(client, broken_security_logger):
    _, token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 201

    unauth_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer("garbage"))
    assert unauth_response.status_code == 401


def test_logger_failure_does_not_break_authorization(client, db_session, broken_security_logger):
    _, analyst_token, analyst_body = _register_and_login(client)

    denied_response = client.patch(
        f"/admin/users/{analyst_body['id']}/status", json={"is_active": False}, headers=_bearer(analyst_token)
    )
    assert denied_response.status_code == 403


def test_logger_failure_does_not_break_admin_operation(client, db_session, broken_security_logger):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200


def test_logger_failure_does_not_break_413_handling(client, broken_security_logger):
    response = client.post(
        "/events",
        content=b"x" * 10,
        headers={"content-length": str(_settings_max_bytes() + 1)},
    )

    assert response.status_code == 413


def test_logger_failure_does_not_break_rate_limit_behavior(
    rate_limited_client, low_login_limit, broken_security_logger
):
    email = _unique_email()
    rate_limited_client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    for _ in range(low_login_limit):
        response = rate_limited_client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
        assert response.status_code == 200

    over_limit_response = rate_limited_client.post(
        "/auth/login", json={"email": email, "password": VALID_PASSWORD}
    )
    assert over_limit_response.status_code == 429
