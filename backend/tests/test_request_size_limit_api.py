"""Integration tests for Step 11I's request-size limit as wired into the
real AMNIX app (app.main:app, real 1 MiB default via
settings.max_request_body_bytes). Require PostgreSQL.

Covers: legitimate AMNIX payloads across every relevant endpoint,
interaction with authentication (which check wins, and why), the health
endpoint, and response-leakage checks. Exact-boundary mechanics (at the
limit / one byte over / missing Content-Length) are covered separately
in tests/test_request_size_limit_boundary.py against a throwaway app
with a small, deterministic limit -- see that file's own docstring for
why the real app's fixed-at-startup limit isn't practical for precise
boundary testing.
"""

import json
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.database import get_db
from app.main import app

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


def _unique_email(prefix: str = "sizelimit") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client, *, password: str = VALID_PASSWORD) -> tuple[str, str, dict]:
    email = _unique_email()
    register_response = client.post("/auth/register", json={"email": email, "password": password})
    assert register_response.status_code == 201, register_response.text
    login_response = client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200, login_response.text
    body = login_response.json()
    return email, body["access_token"], body["user"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _setup_alert(db_session):
    from datetime import datetime, timezone

    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="size-limit-test",
        raw_data={},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    alert = Alert(
        rule_id="brute_force_authentication",
        title="Size limit test alert",
        description="Size limit test alert.",
        severity="high",
        confidence="high",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


# =============================================================================
# Legitimate AMNIX payloads all succeed, well within the real limit
# =============================================================================


def test_legitimate_events_payload_succeeds(client):
    _, token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 201


def test_legitimate_alerts_payload_succeeds(client, db_session):
    from datetime import datetime, timezone

    from app.models.security_event import SecurityEvent

    _, token, _ = _register_and_login(client)
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="t", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    response = client.post(
        "/alerts",
        json={
            "rule_id": "brute_force_authentication",
            "title": "Legit alert",
            "description": "Legit alert.",
            "severity": "high",
            "confidence": "high",
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "evidence": {},
            "source_event_ids": [str(event.id)],
        },
        headers=_bearer(token),
    )

    assert response.status_code == 201


def test_legitimate_copilot_payload_succeeds(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot", json={"question": "Why was this flagged?"}, headers=_bearer(token)
    )

    assert response.status_code == 200


def test_legitimate_copilot_follow_up_payload_succeeds(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot/follow-up",
        json={"question": "What should I check next?", "history": []},
        headers=_bearer(token),
    )

    assert response.status_code == 200


def test_legitimate_login_succeeds(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200


def test_legitimate_register_succeeds(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD})

    assert response.status_code == 201


def test_legitimate_refresh_preserves_existing_behavior(client):
    """Not the happy path (a garbage token) -- just confirms the size
    middleware does not alter /auth/refresh's ordinary 401 behavior for
    a normal-sized request, exactly as before Step 11I.
    """
    response = client.post("/auth/refresh", json={"refresh_token": "garbage-not-a-real-token"})

    assert response.status_code == 401


def test_legitimate_admin_status_update_payload_reaches_business_logic(client, db_session):
    from app.core.security import hash_password
    from app.models.user import User

    _, _, target_body = _register_and_login(client)
    admin_email = _unique_email("admin")
    admin_user = User(email=admin_email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(admin_user)
    db_session.commit()
    admin_login = client.post("/auth/login", json={"email": admin_email, "password": VALID_PASSWORD})
    admin_token = admin_login.json()["access_token"]

    response = client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200


# =============================================================================
# Authentication interaction
# =============================================================================


def test_normal_unauthenticated_request_still_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD)

    assert response.status_code == 401


def test_oversized_unauthenticated_request_returns_413_not_401(client):
    """The size-limit middleware wraps the entire ASGI app, including
    FastAPI's own routing and dependency resolution -- so it runs before
    the authentication dependency ever gets a chance to reject a missing
    token. An oversized request with NO Authorization header must still
    be rejected for its size, not its missing credentials.
    """
    response = client.post(
        "/events",
        content=b"x" * 10,
        headers={"content-length": str(settings_max_bytes() + 1)},
    )

    assert response.status_code == 413
    assert response.status_code != 401


def settings_max_bytes() -> int:
    return get_settings().max_request_body_bytes


def test_normal_authenticated_request_succeeds(client):
    _, token, _ = _register_and_login(client)

    response = client.get("/health")

    assert response.status_code == 200


# =============================================================================
# Size check vs. schema validation: independent concerns
# =============================================================================


def test_body_within_size_limit_but_invalid_schema_reaches_422_not_413(client):
    """A body well under the 1 MiB size limit but with raw_data exceeding
    its own 256 KB schema bound must be rejected by Pydantic (422), not
    by the size middleware (413) -- proof the two checks are independent
    layers, not a duplicate of the same concern.
    """
    _, token, _ = _register_and_login(client)
    oversized_raw_data_payload = dict(VALID_EVENT_PAYLOAD)
    oversized_raw_data_payload["raw_data"] = {"k": "x" * (300 * 1024)}  # over the 256 KB schema bound

    response = client.post("/events", json=oversized_raw_data_payload, headers=_bearer(token))

    assert response.status_code == 422


# =============================================================================
# Health endpoint stays lightweight and unaffected
# =============================================================================


def test_health_endpoint_unaffected(client):
    response = client.get("/health")

    assert response.status_code == 200


# =============================================================================
# 413 response leakage and server stability
# =============================================================================


def test_413_response_does_not_leak_internal_details(client):
    response = client.post(
        "/events",
        content=b"x" * 10,
        headers={"content-length": str(settings_max_bytes() + 1)},
    )

    assert response.status_code == 413
    body_text = response.text.lower()
    for forbidden_term in ("traceback", "middleware", "asgi", "starlette", "fastapi", "secret"):
        assert forbidden_term not in body_text
    assert response.json() == {"detail": "Request body too large."}


def test_server_remains_healthy_after_an_oversized_request(client):
    client.post("/events", content=b"x" * 10, headers={"content-length": str(settings_max_bytes() + 1)})

    response = client.get("/health")

    assert response.status_code == 200
