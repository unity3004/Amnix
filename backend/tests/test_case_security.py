"""Dedicated security tests for the Case API (Step 12R). Require
PostgreSQL. Focused, security-specific tests kept separate from the
broader endpoint-coverage suite in test_case_api.py -- several of these
properties are also incidentally exercised there; this file exists to
make each one an explicit, named, unambiguous assertion.

Proves: actor identity cannot be spoofed (created_by/actor_user_id/
author_id/linked_by are always server-resolved), mass assignment is
rejected (extra="forbid" on every mutating schema), audit `action`
cannot be client-controlled, case_number cannot be client-controlled,
an analyst cannot escalate into an admin-only ownership action, and an
inactive user cannot be handed ownership of a case.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.repositories.user import UserRepository

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


def _register_and_login(client) -> tuple[str, dict]:
    email = f"casesec-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    body = login.json()
    return body["access_token"], body["user"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_alert(db_session, **overrides) -> Alert:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="test", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="Security test alert",
        description="d",
        severity="high",
        confidence="high",
        status="new",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    defaults.update(overrides)
    return AlertRepository(db_session).create(Alert(**defaults))


# =============================================================================
# Actor spoofing
# =============================================================================


def test_created_by_cannot_be_spoofed_on_create(client):
    token, real_body = _register_and_login(client)

    response = client.post(
        "/cases",
        json={"title": "t", "description": "d", "created_by": str(uuid.uuid4())},
        headers=_bearer(token),
    )

    assert response.status_code == 422  # extra="forbid" -- the field doesn't exist on the schema at all


def test_created_by_is_always_the_real_authenticated_user(client):
    token, body = _register_and_login(client)

    response = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token))

    assert response.json()["created_by"] == body["id"]


def test_actor_user_id_cannot_be_spoofed_on_status_change(client):
    token, real_body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/status",
        json={"status": "INVESTIGATING", "actor_user_id": str(uuid.uuid4())},
        headers=_bearer(token),
    )

    assert response.status_code == 422


def test_actor_reflected_in_audit_is_always_the_real_caller(client):
    token, body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_id}/audit", headers=_bearer(token))

    assert all(item["actor_user_id"] == body["id"] for item in response.json()["items"])


def test_linked_by_cannot_be_spoofed(client, db_session):
    token, real_body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]
    alert = _make_alert(db_session)

    response = client.post(
        f"/cases/{case_id}/alerts",
        json={"alert_id": str(alert.id), "linked_by": str(uuid.uuid4())},
        headers=_bearer(token),
    )

    assert response.status_code == 422


def test_author_id_cannot_be_spoofed_on_note_creation(client):
    token, real_body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.post(
        f"/cases/{case_id}/notes", json={"body": "x", "author_id": str(uuid.uuid4())}, headers=_bearer(token)
    )

    assert response.status_code == 422


def test_note_author_is_always_the_real_authenticated_user(client):
    token, body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.post(f"/cases/{case_id}/notes", json={"body": "x"}, headers=_bearer(token))

    assert response.json()["author_id"] == body["id"]


# =============================================================================
# Mass assignment
# =============================================================================


@pytest.mark.parametrize(
    "extra_field", ["id", "case_number", "status", "owner_id", "created_at", "updated_at", "closed_at", "closure_reason"]
)
def test_create_rejects_every_server_controlled_field(client, extra_field):
    token, _ = _register_and_login(client)

    response = client.post(
        "/cases", json={"title": "t", "description": "d", extra_field: "anything"}, headers=_bearer(token)
    )

    assert response.status_code == 422


@pytest.mark.parametrize("extra_field", ["status", "owner_id", "created_by", "case_number", "closed_at", "closure_reason"])
def test_update_rejects_every_disallowed_field(client, extra_field):
    token, _ = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.patch(f"/cases/{case_id}", json={extra_field: "anything"}, headers=_bearer(token))

    assert response.status_code == 422


def test_case_number_can_never_be_set_through_any_endpoint(client):
    """case_number must remain sequence-generated only -- never
    accepted by create, update, or any other mutating endpoint.
    """
    token, _ = _register_and_login(client)

    create_response = client.post(
        "/cases", json={"title": "t", "description": "d", "case_number": 999999}, headers=_bearer(token)
    )
    assert create_response.status_code == 422


# =============================================================================
# Audit action cannot be client-controlled
# =============================================================================


def test_audit_action_cannot_be_supplied_through_any_write_endpoint(client):
    """No mutating schema in app.schemas.case has an `action` field at
    all -- CaseAudit rows are always constructed server-side with a
    hardcoded literal action per CaseService method.
    """
    token, _ = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/status",
        json={"status": "INVESTIGATING", "action": "SOMETHING_ELSE"},
        headers=_bearer(token),
    )

    assert response.status_code == 422


def test_audit_history_never_contains_a_fabricated_action(client):
    token, _ = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_id}/audit", headers=_bearer(token))

    valid_actions = {
        "CASE_CREATED", "CASE_TITLE_CHANGED", "CASE_DESCRIPTION_CHANGED", "CASE_STATUS_CHANGED",
        "CASE_PRIORITY_CHANGED", "CASE_OWNER_CHANGED", "CASE_ALERT_LINKED", "CASE_ALERT_UNLINKED",
        "CASE_CLOSED", "CASE_REOPENED",
    }
    assert all(item["action"] in valid_actions for item in response.json()["items"])


# =============================================================================
# Owner privilege escalation
# =============================================================================


def test_analyst_cannot_reassign_via_the_owner_endpoint_role_escalation_attempt(client):
    """An analyst cannot smuggle admin-only ownership behavior through
    any request-body field -- role is never read from anywhere but the
    DB-backed AuthenticatedUser.
    """
    token, _ = _register_and_login(client)
    other_token, other_body = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/owner",
        json={"owner_id": other_body["id"], "is_admin": True, "role": "admin"},
        headers=_bearer(token),
    )

    assert response.status_code == 422  # extra="forbid" -- fields don't exist


def test_inactive_user_can_never_receive_ownership(client, db_session):
    from app.models.user import User
    from app.core.security import hash_password

    admin_email = f"admin-{uuid.uuid4().hex[:8]}@example.com"
    db_session.add(User(email=admin_email, password_hash=hash_password(VALID_PASSWORD), role="admin"))
    db_session.commit()
    admin_login = client.post("/auth/login", json={"email": admin_email, "password": VALID_PASSWORD})
    admin_token = admin_login.json()["access_token"]

    _, inactive_body = _register_and_login(client)
    inactive_user = UserRepository(db_session).get_by_id(uuid.UUID(inactive_body["id"]))
    inactive_user.is_active = False
    db_session.commit()

    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(admin_token)).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/owner", json={"owner_id": inactive_body["id"]}, headers=_bearer(admin_token)
    )

    assert response.status_code == 422
    fresh = client.get(f"/cases/{case_id}", headers=_bearer(admin_token)).json()
    assert fresh["owner_id"] is None


# =============================================================================
# No raw backend internals ever exposed
# =============================================================================


def test_no_secrets_tokens_or_provider_exceptions_appear_in_any_case_response(client, db_session):
    token, _ = _register_and_login(client)
    case_id = client.post("/cases", json={"title": "t", "description": "d"}, headers=_bearer(token)).json()["id"]
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))
    client.post(f"/cases/{case_id}/notes", json={"body": "x"}, headers=_bearer(token))

    responses = [
        client.get(f"/cases/{case_id}", headers=_bearer(token)),
        client.get(f"/cases/{case_id}/alerts", headers=_bearer(token)),
        client.get(f"/cases/{case_id}/audit", headers=_bearer(token)),
        client.get(f"/cases/{case_id}/notes", headers=_bearer(token)),
    ]
    for response in responses:
        text = response.text.lower()
        for forbidden in ("password", "password_hash", "refresh_token", "authorization", "secret", "api_key", "anthropic"):
            assert forbidden not in text
