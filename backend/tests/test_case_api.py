"""Integration tests for the Case API (Step 12R). Require PostgreSQL.

Covers the full stack (FastAPI -> service -> repository -> DB) for
every /cases route: authentication, both-roles-allowed access (matching
GET /alerts' own shared-SOC model), validation, pagination, and safe
error responses. Mirrors tests/test_alert_api.py's own fixture/helper
shape exactly.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository

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


def _unique_email(prefix: str = "caseapi") -> str:
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
        title="API test alert",
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


def _create_case(client, token, **overrides):
    payload = {"title": "Test case", "description": "A test case description."}
    payload.update(overrides)
    return client.post("/cases", json=payload, headers=_bearer(token))


# =============================================================================
# Authentication
# =============================================================================


@pytest.mark.parametrize(
    "method,path",
    [
        ("POST", "/cases"),
        ("GET", "/cases"),
        ("GET", "/cases/00000000-0000-0000-0000-000000000000"),
        ("PATCH", "/cases/00000000-0000-0000-0000-000000000000"),
        ("PATCH", "/cases/00000000-0000-0000-0000-000000000000/status"),
        ("PATCH", "/cases/00000000-0000-0000-0000-000000000000/owner"),
        ("GET", "/cases/00000000-0000-0000-0000-000000000000/alerts"),
        ("POST", "/cases/00000000-0000-0000-0000-000000000000/alerts"),
        ("DELETE", "/cases/00000000-0000-0000-0000-000000000000/alerts/00000000-0000-0000-0000-000000000000"),
        ("GET", "/cases/00000000-0000-0000-0000-000000000000/audit"),
        ("GET", "/cases/00000000-0000-0000-0000-000000000000/notes"),
        ("POST", "/cases/00000000-0000-0000-0000-000000000000/notes"),
    ],
)
def test_every_route_requires_authentication(client, method, path):
    response = client.request(method, path, json={} if method in ("POST", "PATCH") else None)
    assert response.status_code == 401


def test_invalid_token_returns_401(client):
    response = client.get("/cases", headers=_bearer("garbage-not-a-jwt"))
    assert response.status_code == 401


# =============================================================================
# Create
# =============================================================================


def test_analyst_can_create_case(client):
    _, token, _ = _register_and_login(client)

    response = _create_case(client, token)

    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "OPEN"
    assert body["priority"] == "medium"
    assert body["severity"] is None
    assert isinstance(body["case_number"], int)
    assert body["owner_id"] is None
    assert body["closed_at"] is None
    assert body["closure_reason"] is None


def test_admin_can_create_case(client, db_session):
    _, token, _ = _create_admin_and_login(client, db_session)

    response = _create_case(client, token)

    assert response.status_code == 201, response.text


def test_created_by_is_the_authenticated_user_not_client_supplied(client, db_session):
    _, token, body = _register_and_login(client)

    response = _create_case(client, token, created_by=str(uuid.uuid4()))

    assert response.status_code == 422  # extra="forbid" rejects the field entirely


def test_create_rejects_blank_title(client):
    _, token, _ = _register_and_login(client)
    response = _create_case(client, token, title="   ")
    assert response.status_code == 422


def test_create_rejects_blank_description(client):
    _, token, _ = _register_and_login(client)
    response = _create_case(client, token, description="   ")
    assert response.status_code == 422


def test_create_rejects_invalid_priority(client):
    _, token, _ = _register_and_login(client)
    response = _create_case(client, token, priority="urgent")
    assert response.status_code == 422


# =============================================================================
# List / pagination / filters
# =============================================================================


def test_list_cases_returns_created_case(client):
    _, token, _ = _register_and_login(client)
    create_response = _create_case(client, token, title="Listed case")

    response = client.get("/cases", headers=_bearer(token))

    assert response.status_code == 200
    body = response.json()
    assert set(body.keys()) == {"items", "limit", "offset"}
    assert any(item["id"] == create_response.json()["id"] for item in body["items"])


def test_list_never_returns_a_total(client):
    _, token, _ = _register_and_login(client)
    response = client.get("/cases", headers=_bearer(token))
    assert "total" not in response.json()


@pytest.mark.parametrize("query", ["limit=0", "limit=201", "offset=-1"])
def test_list_pagination_bounds_are_enforced(client, query):
    _, token, _ = _register_and_login(client)
    response = client.get(f"/cases?{query}", headers=_bearer(token))
    assert response.status_code == 422


def test_list_filters_by_status(client):
    _, token, _ = _register_and_login(client)
    create_response = _create_case(client, token, title="Status-filtered case")
    case_id = create_response.json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    response = client.get("/cases?status=INVESTIGATING", headers=_bearer(token))

    assert response.status_code == 200
    assert any(item["id"] == case_id for item in response.json()["items"])


def test_list_rejects_unknown_status_value(client):
    _, token, _ = _register_and_login(client)
    response = client.get("/cases?status=NOT_REAL", headers=_bearer(token))
    assert response.status_code == 422


def test_list_filters_by_priority(client):
    _, token, _ = _register_and_login(client)
    create_response = _create_case(client, token, title="High priority case", priority="high")
    case_id = create_response.json()["id"]

    response = client.get("/cases?priority=high", headers=_bearer(token))

    assert any(item["id"] == case_id for item in response.json()["items"])


def test_list_filters_by_owner_id(client):
    _, token, body = _register_and_login(client)
    create_response = _create_case(client, token, title="Owned case")
    case_id = create_response.json()["id"]
    client.patch(f"/cases/{case_id}/owner", json={"owner_id": body["id"]}, headers=_bearer(token))

    response = client.get(f"/cases?owner_id={body['id']}", headers=_bearer(token))

    assert any(item["id"] == case_id for item in response.json()["items"])


# =============================================================================
# Get
# =============================================================================


def test_get_returns_created_case(client):
    _, token, _ = _register_and_login(client)
    create_response = _create_case(client, token)
    case_id = create_response.json()["id"]

    response = client.get(f"/cases/{case_id}", headers=_bearer(token))

    assert response.status_code == 200
    assert response.json()["id"] == case_id


def test_get_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.get(f"/cases/{uuid.uuid4()}", headers=_bearer(token))
    assert response.status_code == 404


def test_get_malformed_uuid_returns_422(client):
    _, token, _ = _register_and_login(client)
    response = client.get("/cases/not-a-uuid", headers=_bearer(token))
    assert response.status_code == 422


def test_severity_reflects_the_max_linked_alert_severity(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session, severity="critical")

    client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))
    response = client.get(f"/cases/{case_id}", headers=_bearer(token))

    assert response.json()["severity"] == "critical"


# =============================================================================
# Update
# =============================================================================


def test_update_case_title_and_priority(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(
        f"/cases/{case_id}", json={"title": "Renamed", "priority": "critical"}, headers=_bearer(token)
    )

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["title"] == "Renamed"
    assert body["priority"] == "critical"


def test_update_cannot_set_status(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}", json={"status": "CLOSED"}, headers=_bearer(token))

    assert response.status_code == 422


def test_update_cannot_set_owner_id(client, db_session):
    _, token, body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}", json={"owner_id": body["id"]}, headers=_bearer(token))

    assert response.status_code == 422


def test_update_cannot_set_case_number(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}", json={"case_number": 999999}, headers=_bearer(token))

    assert response.status_code == 422


def test_update_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.patch(f"/cases/{uuid.uuid4()}", json={"title": "x"}, headers=_bearer(token))
    assert response.status_code == 404


# =============================================================================
# Status
# =============================================================================


def test_status_transition_success(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    assert response.status_code == 200
    assert response.json()["status"] == "INVESTIGATING"


def test_invalid_status_transition_returns_409(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}/status", json={"status": "CLOSED"}, headers=_bearer(token))

    assert response.status_code == 409


def test_unknown_status_value_returns_422(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}/status", json={"status": "CONTAINMENT"}, headers=_bearer(token))

    assert response.status_code == 422


def test_closing_without_closure_reason_returns_422(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))
    client.patch(f"/cases/{case_id}/status", json={"status": "RESOLVED"}, headers=_bearer(token))

    response = client.patch(f"/cases/{case_id}/status", json={"status": "CLOSED"}, headers=_bearer(token))

    assert response.status_code == 422


def test_closing_with_closure_reason_succeeds(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))
    client.patch(f"/cases/{case_id}/status", json={"status": "RESOLVED"}, headers=_bearer(token))

    response = client.patch(
        f"/cases/{case_id}/status", json={"status": "CLOSED", "closure_reason": "Done."}, headers=_bearer(token)
    )

    assert response.status_code == 200
    assert response.json()["closure_reason"] == "Done."


def test_status_endpoint_rejects_client_supplied_previous_status(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/status",
        json={"status": "INVESTIGATING", "previous_status": "OPEN"},
        headers=_bearer(token),
    )

    assert response.status_code == 422


def test_status_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.patch(f"/cases/{uuid.uuid4()}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))
    assert response.status_code == 404


# =============================================================================
# Owner
# =============================================================================


def test_analyst_self_assign_succeeds(client):
    _, token, body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}/owner", json={"owner_id": body["id"]}, headers=_bearer(token))

    assert response.status_code == 200
    assert response.json()["owner_id"] == body["id"]


def test_analyst_cannot_assign_case_to_another_analyst(client):
    _, token, _ = _register_and_login(client)
    _, _, other_body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(f"/cases/{case_id}/owner", json={"owner_id": other_body["id"]}, headers=_bearer(token))

    assert response.status_code == 403


def test_admin_can_reassign_case(client, db_session):
    _, analyst_token, analyst_body = _register_and_login(client)
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    case_id = _create_case(client, analyst_token).json()["id"]
    client.patch(f"/cases/{case_id}/owner", json={"owner_id": analyst_body["id"]}, headers=_bearer(analyst_token))

    response = client.patch(f"/cases/{case_id}/owner", json={"owner_id": target_body["id"]}, headers=_bearer(admin_token))

    assert response.status_code == 200
    assert response.json()["owner_id"] == target_body["id"]


def test_assigning_nonexistent_user_returns_404(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    case_id = _create_case(client, admin_token).json()["id"]

    response = client.patch(f"/cases/{case_id}/owner", json={"owner_id": str(uuid.uuid4())}, headers=_bearer(admin_token))

    assert response.status_code == 404


def test_assigning_inactive_user_returns_422(client, db_session):
    from app.repositories.user import UserRepository

    _, admin_token, _ = _create_admin_and_login(client, db_session)
    case_id = _create_case(client, admin_token).json()["id"]
    _, _, inactive_body = _register_and_login(client)
    inactive_user = UserRepository(db_session).get_by_id(uuid.UUID(inactive_body["id"]))
    inactive_user.is_active = False
    db_session.commit()

    response = client.patch(
        f"/cases/{case_id}/owner", json={"owner_id": inactive_body["id"]}, headers=_bearer(admin_token)
    )

    assert response.status_code == 422


def test_owner_endpoint_rejects_client_role_field(client):
    _, token, body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.patch(
        f"/cases/{case_id}/owner", json={"owner_id": body["id"], "role": "admin"}, headers=_bearer(token)
    )

    assert response.status_code == 422


def test_owner_unknown_case_returns_404(client):
    _, token, body = _register_and_login(client)
    response = client.patch(f"/cases/{uuid.uuid4()}/owner", json={"owner_id": body["id"]}, headers=_bearer(token))
    assert response.status_code == 404


# =============================================================================
# Alerts
# =============================================================================


def test_link_alert_returns_alert_read(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session)

    response = client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    assert response.status_code == 201, response.text
    assert response.json()["id"] == str(alert.id)


def test_link_nonexistent_alert_returns_404(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(uuid.uuid4())}, headers=_bearer(token))

    assert response.status_code == 404


def test_link_alert_to_nonexistent_case_returns_404(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)

    response = client.post(f"/cases/{uuid.uuid4()}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    assert response.status_code == 404


def test_duplicate_link_returns_409(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    response = client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    assert response.status_code == 409


def test_link_endpoint_rejects_client_supplied_linked_by(client, db_session):
    _, token, body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session)

    response = client.post(
        f"/cases/{case_id}/alerts",
        json={"alert_id": str(alert.id), "linked_by": body["id"]},
        headers=_bearer(token),
    )

    assert response.status_code == 422


def test_list_case_alerts_returns_linked_alerts(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    response = client.get(f"/cases/{case_id}/alerts", headers=_bearer(token))

    assert response.status_code == 200
    ids = [item["id"] for item in response.json()["items"]]
    assert str(alert.id) in ids


def test_list_case_alerts_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.get(f"/cases/{uuid.uuid4()}/alerts", headers=_bearer(token))
    assert response.status_code == 404


def test_unlink_alert_succeeds(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_id}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    response = client.delete(f"/cases/{case_id}/alerts/{alert.id}", headers=_bearer(token))

    assert response.status_code == 204
    assert client.get(f"/cases/{case_id}/alerts", headers=_bearer(token)).json()["items"] == []


def test_unlink_unrelated_alert_returns_404(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    unrelated_alert = _make_alert(db_session)

    response = client.delete(f"/cases/{case_id}/alerts/{unrelated_alert.id}", headers=_bearer(token))

    assert response.status_code == 404


def test_unlink_from_nonexistent_case_returns_404(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)

    response = client.delete(f"/cases/{uuid.uuid4()}/alerts/{alert.id}", headers=_bearer(token))

    assert response.status_code == 404


# =============================================================================
# Audit
# =============================================================================


def test_audit_history_reflects_real_actions(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    client.patch(f"/cases/{case_id}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_id}/audit", headers=_bearer(token))

    assert response.status_code == 200
    actions = [item["action"] for item in response.json()["items"]]
    assert "CASE_CREATED" in actions
    assert "CASE_STATUS_CHANGED" in actions


def test_audit_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.get(f"/cases/{uuid.uuid4()}/audit", headers=_bearer(token))
    assert response.status_code == 404


def test_audit_response_contains_only_expected_fields(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.get(f"/cases/{case_id}/audit", headers=_bearer(token))

    item = response.json()["items"][0]
    assert set(item.keys()) == {
        "id",
        "case_id",
        "actor_user_id",
        "action",
        "related_alert_id",
        "previous_value",
        "new_value",
        "created_at",
    }


@pytest.mark.parametrize("query", ["limit=0", "limit=201", "offset=-1"])
def test_audit_pagination_bounds_are_enforced(client, query):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    response = client.get(f"/cases/{case_id}/audit?{query}", headers=_bearer(token))
    assert response.status_code == 422


# =============================================================================
# Notes
# =============================================================================


def test_create_note_succeeds(client):
    _, token, body = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.post(f"/cases/{case_id}/notes", json={"body": "Observed C2 beaconing."}, headers=_bearer(token))

    assert response.status_code == 201, response.text
    note = response.json()
    assert note["body"] == "Observed C2 beaconing."
    assert note["author_id"] == body["id"]


def test_note_rejects_client_supplied_author_id(client, db_session):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.post(
        f"/cases/{case_id}/notes", json={"body": "x", "author_id": str(uuid.uuid4())}, headers=_bearer(token)
    )

    assert response.status_code == 422


def test_note_rejects_blank_body(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]

    response = client.post(f"/cases/{case_id}/notes", json={"body": "   "}, headers=_bearer(token))

    assert response.status_code == 422


def test_note_creation_does_not_produce_an_audit_row(client):
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    before_count = len(client.get(f"/cases/{case_id}/audit", headers=_bearer(token)).json()["items"])

    client.post(f"/cases/{case_id}/notes", json={"body": "A note."}, headers=_bearer(token))

    after_count = len(client.get(f"/cases/{case_id}/audit", headers=_bearer(token)).json()["items"])
    assert after_count == before_count


def test_list_notes_returns_both_created_notes(client):
    """Chronological ORDERING itself is proven at the repository layer
    (test_case_repository.py::test_case_note_list_is_chronological_
    oldest_first, which sets created_at explicitly): PostgreSQL's now()
    returns the enclosing TRANSACTION's start time, not wall-clock time,
    so two notes created via two real API calls inside one test's single
    database transaction always share an identical created_at -- no
    amount of real elapsed time changes that, so ordering between them
    is not something this API-level test can observe. This test proves
    both notes are correctly persisted and returned instead.
    """
    _, token, _ = _register_and_login(client)
    case_id = _create_case(client, token).json()["id"]
    client.post(f"/cases/{case_id}/notes", json={"body": "first"}, headers=_bearer(token))
    client.post(f"/cases/{case_id}/notes", json={"body": "second"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_id}/notes", headers=_bearer(token))

    bodies = {item["body"] for item in response.json()["items"]}
    assert bodies == {"first", "second"}


def test_notes_unknown_case_returns_404(client):
    _, token, _ = _register_and_login(client)
    response = client.get(f"/cases/{uuid.uuid4()}/notes", headers=_bearer(token))
    assert response.status_code == 404


def test_no_note_edit_or_delete_route_exists():
    """v1 CaseNote is fully immutable (Step 12Q/12R decision) -- verified
    against the real, generated OpenAPI schema.
    """
    spec = app.openapi()
    note_paths = {path: set(methods) for path, methods in spec["paths"].items() if "/notes" in path}
    assert note_paths
    for path, methods in note_paths.items():
        assert "patch" not in methods
        assert "delete" not in methods
        assert "put" not in methods


# =============================================================================
# Safe error responses
# =============================================================================


def test_no_raw_exception_or_sql_leaks_in_any_error_response(client):
    _, token, _ = _register_and_login(client)

    responses = [
        client.get(f"/cases/{uuid.uuid4()}", headers=_bearer(token)),
        client.patch(f"/cases/{uuid.uuid4()}", json={"title": "x"}, headers=_bearer(token)),
        client.post(f"/cases/{uuid.uuid4()}/alerts", json={"alert_id": str(uuid.uuid4())}, headers=_bearer(token)),
    ]
    for response in responses:
        text = response.text.lower()
        for forbidden in ("traceback", "sqlalchemy", "integrityerror", "psycopg", "select ", "insert into"):
            assert forbidden not in text
