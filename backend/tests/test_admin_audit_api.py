"""Integration tests for GET /admin/audits (Step 11M). Require
PostgreSQL.

Covers the full authorization boundary (mirroring the same matrix
already established for PATCH /admin/users/{id}/status in
tests/test_admin_api.py — no token, invalid token, inactive admin,
analyst, unknown role, valid admin), pagination, filters, and response
schema safety (no credential/secret fields ever reachable). The
underlying atomic write is tested separately in
tests/test_admin_audit_transaction.py.
"""

import uuid

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


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "auditapi") -> str:
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


def _change_status(client, admin_token: str, target_id: str, is_active: bool):
    return client.patch(
        f"/admin/users/{target_id}/status", json={"is_active": is_active}, headers=_bearer(admin_token)
    )


# =============================================================================
# 27-31. Authorization/IDOR matrix
# =============================================================================


def test_no_token_returns_401(client):
    response = client.get("/admin/audits")

    assert response.status_code == 401


def test_invalid_token_returns_401(client):
    response = client.get("/admin/audits", headers=_bearer("garbage-not-a-jwt"))

    assert response.status_code == 401


def test_inactive_admin_returns_401(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    admin_user = UserRepository(db_session).get_by_id(uuid.UUID(admin_body["id"]))
    admin_user.is_active = False
    db_session.commit()

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    assert response.status_code == 401


def test_analyst_returns_403(client):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get("/admin/audits", headers=_bearer(analyst_token))

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions."}


def test_unknown_role_fails_closed_with_403(client):
    fabricated_user = AuthenticatedUser(id=uuid.uuid4(), email="ghost@example.com", role="superadmin", is_active=True)
    app.dependency_overrides[get_current_user] = lambda: fabricated_user
    try:
        response = client.get("/admin/audits")
    finally:
        del app.dependency_overrides[get_current_user]

    assert response.status_code == 403


def test_valid_admin_returns_200(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    assert response.status_code == 200


# =============================================================================
# 32-33. Pagination / filters
# =============================================================================


def test_pagination_defaults(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    _change_status(client, admin_token, target_body["id"], False)

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    assert response.status_code == 200
    body = response.json()
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_pagination_bounds_are_enforced(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    too_high = client.get("/admin/audits?limit=201", headers=_bearer(admin_token))
    too_low = client.get("/admin/audits?limit=0", headers=_bearer(admin_token))
    negative_offset = client.get("/admin/audits?offset=-1", headers=_bearer(admin_token))

    assert too_high.status_code == 422
    assert too_low.status_code == 422
    assert negative_offset.status_code == 422


def test_pagination_limit_and_offset_slice_correctly(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    for is_active in (False, True, False):
        assert _change_status(client, admin_token, target_body["id"], is_active).status_code == 200

    page_one = client.get(
        f"/admin/audits?limit=1&offset=0&target_user_id={target_body['id']}", headers=_bearer(admin_token)
    ).json()
    page_two = client.get(
        f"/admin/audits?limit=1&offset=1&target_user_id={target_body['id']}", headers=_bearer(admin_token)
    ).json()

    assert len(page_one["items"]) == 1
    assert len(page_two["items"]) == 1
    assert page_one["items"][0]["id"] != page_two["items"][0]["id"]


def test_actor_filter_works(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, other_admin_token, other_admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    _change_status(client, admin_token, target_body["id"], False)

    response = client.get(f"/admin/audits?actor_user_id={admin_body['id']}", headers=_bearer(admin_token))

    assert response.status_code == 200
    items = response.json()["items"]
    assert items
    assert all(item["actor_user_id"] == admin_body["id"] for item in items)


def test_target_filter_works(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_a = _register_and_login(client)
    _, _, target_b = _register_and_login(client)
    _change_status(client, admin_token, target_a["id"], False)
    _change_status(client, admin_token, target_b["id"], False)

    response = client.get(f"/admin/audits?target_user_id={target_a['id']}", headers=_bearer(admin_token))

    items = response.json()["items"]
    assert items
    assert all(item["target_user_id"] == target_a["id"] for item in items)


def test_action_filter_rejects_unknown_action_value(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits?action=NOT_A_REAL_ACTION", headers=_bearer(admin_token))

    assert response.status_code == 422


def test_action_filter_accepts_the_real_value(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    _change_status(client, admin_token, target_body["id"], False)

    response = client.get("/admin/audits?action=USER_STATUS_CHANGED", headers=_bearer(admin_token))

    assert response.status_code == 200
    assert all(item["action"] == "USER_STATUS_CHANGED" for item in response.json()["items"])


# =============================================================================
# 34-36. Response schema safety
# =============================================================================


def test_response_schema_contains_only_expected_fields(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    _change_status(client, admin_token, target_body["id"], False)

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    body = response.json()
    assert set(body.keys()) == {"items", "limit", "offset"}
    assert body["items"]
    item = body["items"][0]
    assert set(item.keys()) == {
        "id",
        "actor_user_id",
        "target_user_id",
        "action",
        "previous_is_active",
        "new_is_active",
        "created_at",
    }


def test_no_password_hash_token_or_secret_fields_appear(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    _change_status(client, admin_token, target_body["id"], False)

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    body_text = response.text.lower()
    for forbidden in ("password", "password_hash", "refresh_token", "token_hash", "authorization", "secret"):
        assert forbidden not in body_text


def test_correct_audit_appears_after_a_real_status_change(client, db_session):
    """End-to-end: the record GET /admin/audits returns for a real
    status change matches exactly what was performed.
    """
    admin_email, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    change_response = _change_status(client, admin_token, target_body["id"], False)
    assert change_response.status_code == 200

    response = client.get(f"/admin/audits?target_user_id={target_body['id']}", headers=_bearer(admin_token))

    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["actor_user_id"] == admin_body["id"]
    assert items[0]["target_user_id"] == target_body["id"]
    assert items[0]["action"] == "USER_STATUS_CHANGED"
    assert items[0]["previous_is_active"] is True
    assert items[0]["new_is_active"] is False


def test_cannot_supply_arbitrary_action_via_the_write_endpoint(client, db_session):
    """No arbitrary action can be supplied through the write path (Step
    11M requirement #36) -- UserStatusUpdate (the write endpoint's own
    schema) has no `action` field at all, so submitting one is a 422
    before anything runs.
    """
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        f"/admin/users/{target_body['id']}/status",
        json={"is_active": False, "action": "SOMETHING_ELSE"},
        headers=_bearer(admin_token),
    )

    assert response.status_code == 422
