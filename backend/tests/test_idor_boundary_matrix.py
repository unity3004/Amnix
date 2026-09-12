"""Step 11N: IDOR/BOLA authorization boundary matrix. Require PostgreSQL.

Covers the core authentication/RBAC/resource-identifier/mutation matrix
(brief items 1-22, 36-39) across every reviewed resource: events,
alerts, investigations, Copilot, Copilot audits, admin audits, and admin
user management. Cross-resource confusion and Copilot follow-up
isolation are covered separately in
tests/test_idor_cross_resource_and_copilot.py; admin-audit filter
security in tests/test_idor_admin_audit_filters.py; route-level security
properties in tests/test_idor_security_properties.py.

AMNIX's authorization model (confirmed by discovery, not assumed):
  PUBLIC: /health, /auth/register, /auth/login, /auth/refresh
  AUTHENTICATED SHARED SOC (any active analyst or admin): events,
    alerts, alert status, investigations, Copilot, Copilot follow-up,
    Copilot audits
  ADMIN ONLY: PATCH /admin/users/{id}/status, GET /admin/audits
There is no resource-ownership, tenant, or per-user-queue model anywhere
in AMNIX -- an authenticated analyst legitimately reading/operating on
ANY alert/event/investigation by UUID is the intended shared-SOC
behavior, not an authorization defect.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import AuthenticatedUser, get_current_user
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"

VALID_EVENT_PAYLOAD = {
    "event_timestamp": "2026-09-10T10:00:00Z",
    "event_type": "authentication_failure",
    "source": "idor-test",
    "raw_data": {},
}

MALFORMED_UUID = "not-a-uuid-at-all"


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "idor") -> str:
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


def _make_event(db_session, **overrides):
    from app.models.security_event import SecurityEvent

    defaults = dict(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="idor-test",
        raw_data={},
    )
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _make_alert(db_session, event_ids=None, **overrides):
    from app.models.alert import Alert

    if event_ids is None:
        event_ids = [_make_event(db_session).id]
    from app.repositories.alert import AlertRepository

    events = AlertRepository(db_session).get_security_events_by_ids(event_ids)
    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="IDOR test alert",
        description="IDOR test alert.",
        severity="high",
        confidence="high",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=events,
    )
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


# =============================================================================
# 1-7. Authentication: unauthenticated -> 401 across every reviewed resource
# =============================================================================


def test_unauthenticated_event_request_returns_401(client, db_session):
    event = _make_event(db_session)

    response = client.get(f"/events/{event.id}")

    assert response.status_code == 401


def test_unauthenticated_alert_request_returns_401(client, db_session):
    alert = _make_alert(db_session)

    response = client.get(f"/alerts/{alert.id}")

    assert response.status_code == 401


def test_unauthenticated_investigation_request_returns_401(client, db_session):
    alert = _make_alert(db_session)

    response = client.get(f"/alerts/{alert.id}/investigation")

    assert response.status_code == 401


def test_unauthenticated_copilot_request_returns_401(client, db_session):
    alert = _make_alert(db_session)

    response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "Why?"})

    assert response.status_code == 401


def test_unauthenticated_copilot_audit_request_returns_401(client, db_session):
    alert = _make_alert(db_session)

    response = client.get(f"/alerts/{alert.id}/copilot/audits")

    assert response.status_code == 401


def test_unauthenticated_admin_audit_request_returns_401(client):
    response = client.get("/admin/audits")

    assert response.status_code == 401


def test_unauthenticated_admin_user_mutation_returns_401(client, db_session):
    target = _make_event(db_session)  # any real UUID works, endpoint rejects before lookup

    response = client.patch(f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False})

    assert response.status_code == 401


# =============================================================================
# 8-13. RBAC: shared SOC access vs. admin-only boundary
# =============================================================================


def test_analyst_can_access_shared_soc_resources(client, db_session):
    _, analyst_token, _ = _register_and_login(client)
    event = _make_event(db_session)
    alert = _make_alert(db_session)

    assert client.get(f"/events/{event.id}", headers=_bearer(analyst_token)).status_code == 200
    assert client.get(f"/alerts/{alert.id}", headers=_bearer(analyst_token)).status_code == 200
    assert client.get(f"/alerts/{alert.id}/investigation", headers=_bearer(analyst_token)).status_code == 200
    assert (
        client.post(
            f"/alerts/{alert.id}/copilot", json={"question": "Why?"}, headers=_bearer(analyst_token)
        ).status_code
        == 200
    )
    assert client.get(f"/alerts/{alert.id}/copilot/audits", headers=_bearer(analyst_token)).status_code == 200


def test_admin_can_access_shared_soc_resources(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    event = _make_event(db_session)
    alert = _make_alert(db_session)

    assert client.get(f"/events/{event.id}", headers=_bearer(admin_token)).status_code == 200
    assert client.get(f"/alerts/{alert.id}", headers=_bearer(admin_token)).status_code == 200
    assert client.get(f"/alerts/{alert.id}/investigation", headers=_bearer(admin_token)).status_code == 200


def test_analyst_accessing_admin_audit_returns_403(client):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get("/admin/audits", headers=_bearer(analyst_token))

    assert response.status_code == 403


def test_analyst_accessing_admin_user_mutation_returns_403(client, db_session):
    _, analyst_token, _ = _register_and_login(client)
    _, _, other_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{other_body['id']}/status", json={"is_active": False}, headers=_bearer(analyst_token)
    )

    assert response.status_code == 403


def test_unknown_role_accessing_admin_resource_returns_403(client):
    fabricated_user = AuthenticatedUser(id=uuid.uuid4(), email="ghost@example.com", role="superadmin", is_active=True)
    app.dependency_overrides[get_current_user] = lambda: fabricated_user
    try:
        response = client.get("/admin/audits")
    finally:
        del app.dependency_overrides[get_current_user]

    assert response.status_code == 403


def test_inactive_user_accessing_protected_resource_returns_401(client, db_session):
    _, token, body = _register_and_login(client)
    user = UserRepository(db_session).get_by_id(uuid.UUID(body["id"]))
    user.is_active = False
    db_session.commit()

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


# =============================================================================
# 14-22. Resource identifiers: valid / nonexistent / malformed
# =============================================================================


def test_valid_event_uuid_succeeds(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)

    response = client.get(f"/events/{event.id}", headers=_bearer(token))

    assert response.status_code == 200


def test_nonexistent_event_uuid_returns_404(client):
    _, token, _ = _register_and_login(client)

    response = client.get(f"/events/{uuid.uuid4()}", headers=_bearer(token))

    assert response.status_code == 404


def test_malformed_event_uuid_returns_422(client):
    _, token, _ = _register_and_login(client)

    response = client.get(f"/events/{MALFORMED_UUID}", headers=_bearer(token))

    assert response.status_code == 422


def test_valid_alert_uuid_succeeds(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)

    response = client.get(f"/alerts/{alert.id}", headers=_bearer(token))

    assert response.status_code == 200


def test_nonexistent_alert_uuid_returns_404(client):
    _, token, _ = _register_and_login(client)

    response = client.get(f"/alerts/{uuid.uuid4()}", headers=_bearer(token))

    assert response.status_code == 404


def test_malformed_alert_uuid_returns_422(client):
    _, token, _ = _register_and_login(client)

    response = client.get(f"/alerts/{MALFORMED_UUID}", headers=_bearer(token))

    assert response.status_code == 422


def test_valid_user_uuid_succeeds_for_admin_mutation(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200


def test_nonexistent_user_uuid_returns_404_for_admin_mutation(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.patch(
        f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 404


def test_malformed_user_uuid_returns_422_for_admin_mutation(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.patch(
        f"/admin/users/{MALFORMED_UUID}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 422


# =============================================================================
# 36-39. Mutation authorization
# =============================================================================


def test_alert_status_mutation_allowed_for_analyst_per_shared_soc_model(client, db_session):
    """The existing product intentionally allows analysts to change
    alert status (verified during discovery: no role check exists on
    this route beyond authentication) -- this is not a defect to fix.
    """
    _, analyst_token, _ = _register_and_login(client)
    alert = _make_alert(db_session)

    response = client.patch(
        f"/alerts/{alert.id}/status", json={"status": "acknowledged"}, headers=_bearer(analyst_token)
    )

    assert response.status_code == 200


def test_unauthenticated_alert_mutation_denied(client, db_session):
    alert = _make_alert(db_session)

    response = client.patch(f"/alerts/{alert.id}/status", json={"status": "acknowledged"})

    assert response.status_code == 401


def test_unauthorized_admin_user_mutation_denied(client, db_session):
    _, analyst_token, _ = _register_and_login(client)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(analyst_token)
    )

    assert response.status_code == 403


def test_self_target_admin_mutation_remains_409(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)

    response = client.patch(
        f"/admin/users/{admin_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 409


def test_nonexistent_target_admin_mutation_remains_404(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.patch(
        f"/admin/users/{uuid.uuid4()}/status", json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 404
