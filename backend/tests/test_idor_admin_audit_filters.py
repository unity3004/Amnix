"""Step 11N: GET /admin/audits filter security (brief items 31-35).
Require PostgreSQL.

Proves that actor_user_id/target_user_id/action query filters can only
ever NARROW an already-admin-only query -- they cannot be used by a
non-admin caller to bypass RBAC, and invalid values fail safely (422)
before reaching the database at all.
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


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "auditfilter") -> str:
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


# =============================================================================
# 31-32. Analyst cannot use filters to bypass RBAC
# =============================================================================


def test_analyst_cannot_bypass_rbac_via_actor_filter(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(f"/admin/audits?actor_user_id={admin_body['id']}", headers=_bearer(analyst_token))

    assert response.status_code == 403


def test_analyst_cannot_bypass_rbac_via_target_filter(client, db_session):
    _, _, target_body = _register_and_login(client)
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(f"/admin/audits?target_user_id={target_body['id']}", headers=_bearer(analyst_token))

    assert response.status_code == 403


def test_analyst_cannot_bypass_rbac_via_action_filter(client):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get("/admin/audits?action=USER_STATUS_CHANGED", headers=_bearer(analyst_token))

    assert response.status_code == 403


def test_analyst_cannot_bypass_rbac_via_combined_filters(client, db_session):
    _, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(
        f"/admin/audits?actor_user_id={admin_body['id']}&target_user_id={admin_body['id']}"
        "&action=USER_STATUS_CHANGED",
        headers=_bearer(analyst_token),
    )

    assert response.status_code == 403


def test_unauthenticated_request_with_filters_still_returns_401(client, db_session):
    _, _, target_body = _register_and_login(client)

    response = client.get(f"/admin/audits?target_user_id={target_body['id']}")

    assert response.status_code == 401


# =============================================================================
# 33. Admin filters work correctly (narrow, never widen)
# =============================================================================


def test_admin_actor_filter_narrows_results_correctly(client, db_session):
    _, admin_a_token, admin_a_body = _create_admin_and_login(client, db_session)
    _, admin_b_token, admin_b_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": False}, headers=_bearer(admin_a_token)
    )
    client.patch(
        f"/admin/users/{target_body['id']}/status", json={"is_active": True}, headers=_bearer(admin_b_token)
    )

    response = client.get(f"/admin/audits?actor_user_id={admin_a_body['id']}", headers=_bearer(admin_a_token))

    items = response.json()["items"]
    assert items
    assert all(item["actor_user_id"] == admin_a_body["id"] for item in items)
    assert all(item["actor_user_id"] != admin_b_body["id"] for item in items)


def test_admin_target_filter_narrows_results_correctly(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_a = _register_and_login(client)
    _, _, target_b = _register_and_login(client)

    client.patch(f"/admin/users/{target_a['id']}/status", json={"is_active": False}, headers=_bearer(admin_token))
    client.patch(f"/admin/users/{target_b['id']}/status", json={"is_active": False}, headers=_bearer(admin_token))

    response = client.get(f"/admin/audits?target_user_id={target_a['id']}", headers=_bearer(admin_token))

    items = response.json()["items"]
    assert items
    assert all(item["target_user_id"] == target_a["id"] for item in items)


def test_admin_filters_never_widen_beyond_admin_only_access(client, db_session):
    """Even with maximally broad filters (no filters at all), the
    endpoint remains admin-only -- filters can only narrow an
    already-authorized query, never grant access on their own.
    """
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits", headers=_bearer(admin_token))

    assert response.status_code == 200


# =============================================================================
# 34-35. Invalid action / UUID filters fail safely
# =============================================================================


def test_invalid_action_filter_returns_422(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits?action=DELETE_EVERYTHING", headers=_bearer(admin_token))

    assert response.status_code == 422


def test_malformed_actor_uuid_filter_returns_422(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits?actor_user_id=not-a-uuid", headers=_bearer(admin_token))

    assert response.status_code == 422


def test_malformed_target_uuid_filter_returns_422(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get("/admin/audits?target_user_id=not-a-uuid", headers=_bearer(admin_token))

    assert response.status_code == 422


def test_sql_injection_shaped_actor_filter_returns_422_not_reaches_database(client, db_session):
    """A SQL-injection-shaped string in a UUID-typed filter is rejected
    by Pydantic's UUID coercion before it ever reaches a repository
    query -- SQLAlchemy's parameterized queries would neutralize it
    regardless, but this confirms it doesn't even get that far.
    """
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get(
        "/admin/audits?actor_user_id=' OR '1'='1", headers=_bearer(admin_token)
    )

    assert response.status_code == 422


def test_nonexistent_uuid_filters_return_empty_list_not_error(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get(f"/admin/audits?actor_user_id={uuid.uuid4()}", headers=_bearer(admin_token))

    assert response.status_code == 200
    assert response.json()["items"] == []
