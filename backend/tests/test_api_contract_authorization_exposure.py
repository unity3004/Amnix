"""Step 11O: authorization error surface, resource-not-found safety,
mass-assignment prevention, and response-schema exposure boundaries.
Require PostgreSQL.

Covers brief items 19-35: AUTHORIZATION (19-21), RESOURCE ERRORS
(22-25), MASS ASSIGNMENT (26-30), RESPONSE EXPOSURE (31-35).
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "expose") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client, *, password: str = VALID_PASSWORD) -> tuple[str, dict]:
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": password})
    login = client.post("/auth/login", json={"email": email, "password": password})
    body = login.json()
    return body["access_token"], body["user"]


def _create_admin_and_login(client, db_session) -> tuple[str, dict]:
    email = _unique_email("admin")
    admin_user = User(email=email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(admin_user)
    db_session.commit()
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    body = login.json()
    return body["access_token"], body["user"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_event(db_session, **overrides):
    from app.models.security_event import SecurityEvent

    defaults = {
        "event_timestamp": datetime.now(timezone.utc),
        "event_type": "authentication_failure",
        "source": "contract-test",
        "raw_data": {},
    }
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _make_alert(db_session, event_ids=None, **overrides):
    from app.models.alert import Alert
    from app.repositories.alert import AlertRepository

    now = datetime.now(timezone.utc)
    events = AlertRepository(db_session).get_security_events_by_ids(event_ids or [_make_event(db_session).id])
    defaults = {
        "rule_id": "brute_force_authentication",
        "title": "Contract test alert",
        "description": "d",
        "severity": "high",
        "confidence": "high",
        "first_seen": now,
        "last_seen": now,
        "evidence": {},
        "security_events": events,
    }
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


# =============================================================================
# 19-21. Authorization error surface
# =============================================================================


def test_analyst_hitting_admin_route_is_safe_minimal_403(client):
    token, _ = _register_and_login(client)
    response = client.get("/admin/audits", headers=_bearer(token))
    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions."}


def test_admin_403_body_never_names_required_role_or_actual_role(client):
    token, _ = _register_and_login(client)
    response = client.patch(f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False}, headers=_bearer(token))
    assert response.status_code == 403
    assert "admin" not in response.text.lower()
    assert "analyst" not in response.text.lower()


def test_unknown_role_claim_fails_closed_403_not_privileged(client, db_session):
    """A JWT with a role outside {analyst, admin} must never be treated
    as implicitly privileged -- see require_roles()'s own fail-closed
    design.
    """
    from app.core.tokens import create_access_token

    user = User(email=_unique_email(), password_hash=hash_password(VALID_PASSWORD), role="analyst")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    # Directly mint a token claiming an unrecognized role -- decode_access_token()
    # itself would reject this (role must be in _VALID_ROLES), which is the
    # correct outcome; confirm it surfaces as safe 401, not a crash.
    import jwt as pyjwt

    from app.core.config import get_settings

    settings = get_settings()
    import time

    now = int(time.time())
    token = pyjwt.encode(
        {"sub": str(user.id), "role": "superadmin", "iat": now, "exp": now + 900, "jti": str(uuid.uuid4()),
         "iss": settings.jwt_issuer, "aud": settings.jwt_audience},
        settings.jwt_secret_key, algorithm="HS256",
    )
    response = client.get("/admin/audits", headers=_bearer(token))
    assert response.status_code == 401


def test_inactive_user_protected_route_is_401(client, db_session):
    from app.core.tokens import create_access_token

    user = User(email=_unique_email(), password_hash=hash_password(VALID_PASSWORD), role="analyst", is_active=False)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token(user_id=user.id, role=user.role)

    response = client.get(f"/events/{uuid.uuid4()}", headers=_bearer(token))
    assert response.status_code == 401


# =============================================================================
# 22-25. Resource errors
# =============================================================================


def test_nonexistent_event_is_safe_404(client):
    token, _ = _register_and_login(client)
    response = client.get(f"/events/{uuid.uuid4()}", headers=_bearer(token))
    assert response.status_code == 404
    assert response.json() == {"detail": "Security event not found"}


def test_nonexistent_alert_is_safe_404(client):
    token, _ = _register_and_login(client)
    response = client.get(f"/alerts/{uuid.uuid4()}", headers=_bearer(token))
    assert response.status_code == 404
    assert response.json() == {"detail": "Alert not found"}


def test_nonexistent_admin_target_user_is_safe_404(client, db_session):
    admin_token, _ = _create_admin_and_login(client, db_session)
    response = client.patch(
        f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )
    assert response.status_code == 404
    assert response.json() == {"detail": "User not found"}


def test_malformed_resource_uuid_is_safe_validation_response(client):
    token, _ = _register_and_login(client)
    response = client.get("/alerts/definitely-not-a-uuid", headers=_bearer(token))
    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


# =============================================================================
# 26-30. Mass assignment
# =============================================================================


def test_client_cannot_set_admin_audit_actor(client, db_session):
    """AdminAudit rows have no client-facing write schema at all -- the
    actor is always the authenticated admin's own id, sourced from
    current_user, never request input. Prove this by checking the
    persisted audit's actor matches the CALLER, not anything supplied.
    """
    admin_token, admin_body = _create_admin_and_login(client, db_session)
    target_token, target_body = _register_and_login(client)

    client.patch(f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token))

    audits = client.get(f"/admin/audits?target_user_id={target_body['id']}", headers=_bearer(admin_token)).json()
    assert audits["items"][0]["actor_user_id"] == admin_body["id"]


def test_client_cannot_set_admin_audit_action(client, db_session):
    """UserStatusUpdate has no `action` field at all -- confirm the
    schema rejects it outright.
    """
    admin_token, _ = _create_admin_and_login(client, db_session)
    _, target_body = _register_and_login(client)
    response = client.patch(
        f"/admin/users/{target_body['id']}/status",
        json={"is_active": False, "action": "DELETE_EVERYTHING"},
        headers=_bearer(admin_token),
    )
    assert response.status_code == 422


def test_client_cannot_modify_role_through_status_endpoint(client, db_session):
    admin_token, _ = _create_admin_and_login(client, db_session)
    _, target_body = _register_and_login(client)
    response = client.patch(
        f"/admin/users/{target_body['id']}/status",
        json={"is_active": False, "role": "admin"},
        headers=_bearer(admin_token),
    )
    assert response.status_code == 422


def test_client_cannot_modify_password_hash_through_status_endpoint(client, db_session):
    admin_token, _ = _create_admin_and_login(client, db_session)
    _, target_body = _register_and_login(client)
    response = client.patch(
        f"/admin/users/{target_body['id']}/status",
        json={"is_active": False, "password_hash": "$argon2id$forged"},
        headers=_bearer(admin_token),
    )
    assert response.status_code == 422


def test_client_cannot_override_server_generated_alert_id(client):
    token, _ = _register_and_login(client)
    event_id = None
    ev = client.post(
        "/events",
        json={
            "event_timestamp": "2026-01-01T00:00:00Z",
            "event_type": "x",
            "source": "x",
            "raw_data": {},
        },
        headers=_bearer(token),
    )
    event_id = ev.json()["id"]
    forged_id = str(uuid.uuid4())
    response = client.post(
        "/alerts",
        json={
            "id": forged_id,
            "rule_id": "x",
            "title": "x",
            "description": "x",
            "severity": "high",
            "confidence": "high",
            "first_seen": "2026-01-01T00:00:00Z",
            "evidence": {},
            "source_event_ids": [event_id],
        },
        headers=_bearer(token),
    )
    assert response.status_code == 422


def test_client_cannot_set_alert_status_directly_at_creation(client):
    """AlertCreate has no `status` field -- every alert is created NEW,
    only PATCH .../status can transition it, through the lifecycle
    state machine.
    """
    token, _ = _register_and_login(client)
    ev = client.post(
        "/events",
        json={"event_timestamp": "2026-01-01T00:00:00Z", "event_type": "x", "source": "x", "raw_data": {}},
        headers=_bearer(token),
    )
    response = client.post(
        "/alerts",
        json={
            "rule_id": "x", "title": "x", "description": "x", "severity": "high", "confidence": "high",
            "first_seen": "2026-01-01T00:00:00Z", "evidence": {}, "status": "resolved",
            "source_event_ids": [ev.json()["id"]],
        },
        headers=_bearer(token),
    )
    assert response.status_code == 422


# =============================================================================
# 31-35. Response-schema exposure
# =============================================================================


def test_user_read_excludes_password_hash(client):
    token, user_body = _register_and_login(client)
    assert "password_hash" not in user_body
    assert "password" not in user_body
    response = client.get(f"/events/{uuid.uuid4()}", headers=_bearer(token))
    assert "password_hash" not in response.text


def test_login_response_excludes_password_hash(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    assert "password_hash" not in response.text
    assert "$argon2" not in response.text


def test_admin_audit_response_excludes_credentials(client, db_session):
    admin_token, _ = _create_admin_and_login(client, db_session)
    _, target_body = _register_and_login(client)
    client.patch(f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token))

    response = client.get("/admin/audits", headers=_bearer(admin_token))
    body = response.json()
    assert set(body["items"][0].keys()) == {
        "id", "actor_user_id", "target_user_id", "action", "previous_is_active", "new_is_active", "created_at"
    }
    assert "password_hash" not in response.text
    assert "$argon2" not in response.text


def test_copilot_audit_response_excludes_raw_prompt_context_history(client, db_session):
    alert = _make_alert(db_session)
    token, _ = _register_and_login(client)
    client.post(f"/alerts/{alert.id}/copilot", json={"question": "What happened here?"}, headers=_bearer(token))

    response = client.get(f"/alerts/{alert.id}/copilot/audits", headers=_bearer(token))
    body = response.json()
    assert body["items"]
    assert set(body["items"][0].keys()) == {
        "id", "alert_id", "request_type", "provider_name", "model_name", "outcome", "validation_status",
        "http_status", "question_fingerprint", "question_length", "history_turn_count", "duration_ms", "created_at",
    }
    for forbidden in ("system_instructions", "conversation_history", "raw_response", "prompt", "answer", "assessment"):
        assert forbidden not in response.text


def test_copilot_response_excludes_internal_ai_context(client, db_session):
    alert = _make_alert(db_session)
    token, _ = _register_and_login(client)
    response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "What happened here?"}, headers=_bearer(token))
    body = response.json()
    assert set(body.keys()) == {"alert_id", "provider", "model", "assessment", "generated_at", "usage"}
    assert "system_instructions" not in response.text
    assert "mapping_source" not in response.text


def test_admin_audit_pagination_bounds_reject_invalid_values(client, db_session):
    admin_token, _ = _create_admin_and_login(client, db_session)
    assert client.get("/admin/audits?limit=0", headers=_bearer(admin_token)).status_code == 422
    assert client.get("/admin/audits?limit=201", headers=_bearer(admin_token)).status_code == 422
    assert client.get("/admin/audits?offset=-1", headers=_bearer(admin_token)).status_code == 422


def test_copilot_audit_pagination_bounds_reject_invalid_values(client, db_session):
    alert = _make_alert(db_session)
    token, _ = _register_and_login(client)
    assert client.get(f"/alerts/{alert.id}/copilot/audits?limit=0", headers=_bearer(token)).status_code == 422
    assert client.get(f"/alerts/{alert.id}/copilot/audits?limit=201", headers=_bearer(token)).status_code == 422
    assert client.get(f"/alerts/{alert.id}/copilot/audits?offset=-1", headers=_bearer(token)).status_code == 422
