"""Integration tests for Step 11L's HTTP security boundary as wired into
the real AMNIX app (app.main:app, real default config: empty
CORS_ALLOWED_ORIGINS, TRUSTED_HOSTS including "testserver"). Require
PostgreSQL.

Covers: security headers present/absent on the exact response paths
verified during discovery (200/401/403/404/422 carry them; the fast-path
413 and TrustedHost rejection do not -- see the Step 11L final report
for why, verified empirically, not assumed), CORS/auth/RBAC
independence, invalid-Host business-logic isolation, and a full
regression sweep across every route category.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"

VALID_EVENT_PAYLOAD = {
    "event_timestamp": "2026-09-09T10:00:00Z",
    "event_type": "process_creation",
    "source": "test",
    "raw_data": {},
}

EXPECTED_SECURITY_HEADERS = {
    "x-content-type-options": "nosniff",
    "x-frame-options": "DENY",
    "referrer-policy": "no-referrer",
}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "httpsec") -> str:
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


def _setup_alert(db_session):
    from datetime import datetime, timezone

    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="httpsec-test",
        raw_data={},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    alert = Alert(
        rule_id="brute_force_authentication",
        title="HTTP security test alert",
        description="HTTP security test alert.",
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


def _assert_security_headers_present(response):
    for name, value in EXPECTED_SECURITY_HEADERS.items():
        assert response.headers.get(name) == value, f"missing/wrong {name} on {response.status_code} response"


# =============================================================================
# Security headers: present on normal responses and most error paths
# =============================================================================


def test_security_headers_present_on_successful_response(client):
    response = client.get("/health")

    assert response.status_code == 200
    _assert_security_headers_present(response)


def test_security_headers_present_on_authentication_error(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD)

    assert response.status_code == 401
    _assert_security_headers_present(response)


def test_security_headers_present_on_authorization_error(client):
    _, analyst_token, analyst_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{analyst_body['id']}/status", json={"is_active": False}, headers=_bearer(analyst_token)
    )

    assert response.status_code == 403
    _assert_security_headers_present(response)


def test_security_headers_present_on_404(client):
    _, token, _ = _register_and_login(client)

    response = client.get(f"/alerts/{uuid.uuid4()}", headers=_bearer(token))

    assert response.status_code == 404
    _assert_security_headers_present(response)


def test_security_headers_present_on_422_validation_error(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": "x" * 129})

    assert response.status_code == 422
    _assert_security_headers_present(response)


def test_security_headers_present_on_incremental_path_413(client):
    """The chunked/missing-Content-Length 413 path is handled by
    Starlette's own ExceptionMiddleware, which sits INSIDE
    SecurityHeadersMiddleware in the stack -- verified during discovery
    that this path DOES carry the headers, unlike the fast
    Content-Length path below.
    """
    response = client.post("/events", content=(b"z" * 200_000 for _ in range(10)))

    assert response.status_code == 413
    _assert_security_headers_present(response)


def test_security_headers_absent_on_fast_content_length_413(client):
    """The Content-Length fast-reject path short-circuits inside
    RequestBodySizeLimitMiddleware, which sits OUTSIDE (above)
    SecurityHeadersMiddleware in the stack -- it never calls into the
    inner layers at all, so no security headers are added. Verified
    empirically during Step 11L discovery, documented here rather than
    silently assumed to be covered.
    """
    response = client.post("/events", content=b"x" * 10, headers={"content-length": "2097152"})

    assert response.status_code == 413
    assert response.headers.get("x-content-type-options") is None


def test_security_headers_absent_on_invalid_host_rejection(client):
    """TrustedHostMiddleware is the outermost layer -- an invalid Host
    is rejected before SecurityHeadersMiddleware (or anything else) ever
    runs. Documented, not silently assumed.
    """
    response = client.get("/health", headers={"Host": "evil.example.com"})

    assert response.status_code == 400
    assert response.headers.get("x-content-type-options") is None


# =============================================================================
# CORS does not bypass authentication or authorization
# =============================================================================


def test_cors_origin_header_does_not_bypass_authentication(client):
    """The real app's default CORS config allows no origins, but even
    the ORIGIN HEADER'S PRESENCE must never influence the authentication
    decision -- CORS is a browser-enforced, response-header-based
    mechanism, not a server-side authorization check.
    """
    response = client.post(
        "/events", json=VALID_EVENT_PAYLOAD, headers={"Origin": "http://localhost:5173"}
    )

    assert response.status_code == 401


def test_cors_origin_header_does_not_bypass_rbac(client):
    _, analyst_token, analyst_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{analyst_body['id']}/status",
        json={"is_active": False},
        headers={**_bearer(analyst_token), "Origin": "http://localhost:5173"},
    )

    assert response.status_code == 403


def test_normal_non_cors_request_is_unaffected_by_cors_middleware(client):
    """A same-origin/non-browser request (no Origin header at all, as
    every existing AMNIX test and any real backend-to-backend caller
    sends) must behave completely unchanged -- CORSMiddleware is a
    no-op when there's no Origin header to react to.
    """
    _, token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 201
    assert "access-control-allow-origin" not in response.headers


# =============================================================================
# Invalid Host: rejected before reaching any protected route logic or state
# =============================================================================


def test_invalid_host_does_not_authenticate(client):
    _, token, _ = _register_and_login(client)

    response = client.post(
        "/events", json=VALID_EVENT_PAYLOAD, headers={**_bearer(token), "Host": "evil.example.com"}
    )

    assert response.status_code == 400


def test_invalid_host_does_not_create_an_event(client, db_session):
    from sqlalchemy import func, select

    from app.models.security_event import SecurityEvent

    _, token, _ = _register_and_login(client)
    before = db_session.scalar(select(func.count()).select_from(SecurityEvent))

    response = client.post(
        "/events", json=VALID_EVENT_PAYLOAD, headers={**_bearer(token), "Host": "evil.example.com"}
    )

    assert response.status_code == 400
    after = db_session.scalar(select(func.count()).select_from(SecurityEvent))
    assert after == before


def test_invalid_host_does_not_create_an_alert(client, db_session):
    from sqlalchemy import func, select

    from app.models.alert import Alert

    _, token, _ = _register_and_login(client)
    before = db_session.scalar(select(func.count()).select_from(Alert))

    response = client.post(
        "/alerts",
        json={
            "rule_id": "brute_force_authentication",
            "title": "t",
            "description": "d",
            "severity": "high",
            "confidence": "high",
            "first_seen": "2026-09-09T10:00:00Z",
            "evidence": {},
            "source_event_ids": [str(uuid.uuid4())],
        },
        headers={**_bearer(token), "Host": "evil.example.com"},
    )

    assert response.status_code == 400
    after = db_session.scalar(select(func.count()).select_from(Alert))
    assert after == before


def test_invalid_host_does_not_invoke_copilot(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot",
        json={"question": "Why?"},
        headers={**_bearer(token), "Host": "evil.example.com"},
    )

    assert response.status_code == 400


def test_invalid_host_does_not_mutate_admin_state(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status",
        json={"is_active": False},
        headers={**_bearer(admin_token), "Host": "evil.example.com"},
    )

    assert response.status_code == 400
    from app.repositories.user import UserRepository

    target = UserRepository(db_session).get_by_id(uuid.UUID(target_body["id"]))
    assert target.is_active is True


def test_invalid_host_response_does_not_leak_configuration(client):
    response = client.get("/health", headers={"Host": "evil.example.com"})

    body_lower = response.text.lower()
    for forbidden in ("testserver", "localhost", "127.0.0.1", "trusted_hosts", "traceback"):
        assert forbidden not in body_lower


# =============================================================================
# Full regression sweep across every route category
# =============================================================================


def test_health_still_works(client):
    assert client.get("/health").status_code == 200


def test_register_still_works(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD})
    assert response.status_code == 201


def test_login_still_works(client):
    email, _, _ = _register_and_login(client)
    assert email  # login already asserted 200 inside the helper


def test_refresh_still_works(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    assert response.status_code == 200


def test_protected_endpoint_still_works(client):
    _, token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 201


def test_admin_endpoint_still_works(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200


def test_events_still_works(client):
    _, token, _ = _register_and_login(client)

    create_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))
    event_id = create_response.json()["id"]

    get_response = client.get(f"/events/{event_id}", headers=_bearer(token))

    assert get_response.status_code == 200


def test_alerts_still_works(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.get(f"/alerts/{alert.id}", headers=_bearer(token))

    assert response.status_code == 200


def test_investigation_still_works(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.get(f"/alerts/{alert.id}/investigation", headers=_bearer(token))

    assert response.status_code == 200


def test_copilot_still_works(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "Why?"}, headers=_bearer(token))

    assert response.status_code == 200


def test_copilot_follow_up_still_works(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot/follow-up",
        json={"question": "What next?", "history": []},
        headers=_bearer(token),
    )

    assert response.status_code == 200


def test_copilot_audit_retrieval_still_works(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)
    client.post(f"/alerts/{alert.id}/copilot", json={"question": "Why?"}, headers=_bearer(token))

    response = client.get(f"/alerts/{alert.id}/copilot/audits", headers=_bearer(token))

    assert response.status_code == 200


# =============================================================================
# Security logging still works (Step 11J interaction)
# =============================================================================


def test_security_logging_still_emits_events(client, caplog):
    import json

    with caplog.at_level("INFO", logger="amnix.security"):
        _, token, _ = _register_and_login(client)

    events = [
        json.loads(r.message)
        for r in caplog.records
        if r.name == "amnix.security"
    ]
    assert any(e["event_type"] == "AUTH_LOGIN_SUCCESS" for e in events)
