"""Integration tests for Step 11G: PATCH /admin/users/{user_id}/status —
AMNIX's first real admin-only route. Require PostgreSQL.

Covers the full authorization boundary (authentication via
get_current_user, authorization via require_admin — see
app.api.dependencies and app.api.admin) plus the operation's own
business invariants (self-target rejection, not-found handling,
idempotency, field isolation). Mirrors the structure and helpers
already established in tests/test_auth_middleware.py and
tests/test_rbac.py rather than reinventing them.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from app.api.dependencies import AuthenticatedUser, get_current_user
from app.core.config import get_settings
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


def _unique_email(prefix: str = "admin-api") -> str:
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


def _status_path(user_id) -> str:
    return f"/admin/users/{user_id}/status"


# =============================================================================
# Authentication (1-4)
# =============================================================================


def test_no_token_returns_401(client, db_session):
    _, _, target_body = _register_and_login(client)

    response = client.patch(_status_path(target_body["id"]), json={"is_active": False})

    assert response.status_code == 401


def test_invalid_token_returns_401(client, db_session):
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer("garbage-not-a-jwt")
    )

    assert response.status_code == 401


def test_expired_token_returns_401(client, db_session):
    _, _, target_body = _register_and_login(client)
    settings = get_settings()
    now = datetime.now(timezone.utc)
    expired_token = pyjwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "role": "admin",
            "iat": now - timedelta(minutes=30),
            "exp": now - timedelta(minutes=15),
            "jti": str(uuid.uuid4()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(expired_token)
    )

    assert response.status_code == 401


def test_inactive_admin_caller_returns_401(client, db_session):
    admin_email, admin_token, admin_body = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    admin_user = UserRepository(db_session).get_by_id(uuid.UUID(admin_body["id"]))
    admin_user.is_active = False
    db_session.commit()

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 401


# =============================================================================
# Authorization (5-7)
# =============================================================================


def test_analyst_caller_returns_403(client, db_session):
    _, analyst_token, _ = _register_and_login(client)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(analyst_token)
    )

    assert response.status_code == 403
    assert response.json() == {"detail": "Insufficient permissions."}


def test_admin_caller_succeeds(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is False


def test_unknown_role_fails_closed(client, db_session):
    _, _, target_body = _register_and_login(client)
    fabricated_user = AuthenticatedUser(id=uuid.uuid4(), email="ghost@example.com", role="superadmin", is_active=True)
    app.dependency_overrides[get_current_user] = lambda: fabricated_user
    try:
        response = client.patch(_status_path(target_body["id"]), json={"is_active": False})
    finally:
        del app.dependency_overrides[get_current_user]

    assert response.status_code == 403


# =============================================================================
# Operation (8-15)
# =============================================================================


def test_valid_admin_operation_succeeds_and_persists(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    target_id = uuid.UUID(target_body["id"])

    response = client.patch(_status_path(target_id), json={"is_active": False}, headers=_bearer(admin_token))

    assert response.status_code == 200
    db_session.expire_all()
    target = UserRepository(db_session).get_by_id(target_id)
    assert target.is_active is False


def test_nonexistent_target_returns_404(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.patch(
        _status_path(uuid.uuid4()), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 404


def test_repeated_disable_is_idempotent(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    first = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )
    second = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert first.status_code == 200
    assert second.status_code == 200
    assert first.json()["is_active"] is False
    assert second.json()["is_active"] is False


def test_re_enabling_a_disabled_user_succeeds(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    client.patch(_status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token))

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": True}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200
    assert response.json()["is_active"] is True


def test_response_schema_contains_only_expected_fields(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 200
    assert set(response.json().keys()) == {"id", "email", "role", "is_active", "created_at", "updated_at"}


def test_password_hash_never_appears_in_response(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    body_text = response.text.lower()
    assert "password_hash" not in body_text
    assert "argon2" not in body_text


def test_cannot_supply_role_in_request_body(client, db_session):
    """UserStatusUpdate is extra='forbid' with only `is_active` -- a
    client attempting to smuggle a role change through this endpoint
    gets a 422 (schema rejection) before UserService ever runs, not a
    silently-ignored field and not a privilege escalation.
    """
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]),
        json={"is_active": False, "role": "admin"},
        headers=_bearer(admin_token),
    )

    assert response.status_code == 422


def test_analyst_cannot_escalate_self_via_body_role_field(client, db_session):
    _, analyst_token, analyst_body = _register_and_login(client)

    response = client.patch(
        _status_path(analyst_body["id"]),
        json={"is_active": True, "role": "admin"},
        headers=_bearer(analyst_token),
    )

    # Authorization (403) is evaluated via require_admin before the
    # analyst's request body is even parsed against UserStatusUpdate --
    # either way, no path here can ever change `role`.
    assert response.status_code == 403


# =============================================================================
# Self-target behavior
# =============================================================================


def test_admin_cannot_disable_own_account(client, db_session):
    admin_email, admin_token, admin_body = _create_admin_and_login(client, db_session)

    response = client.patch(
        _status_path(admin_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.status_code == 409
    assert response.json() == {"detail": "Admins cannot change their own account status."}
    db_session.expire_all()
    admin_user = UserRepository(db_session).get_by_id(uuid.UUID(admin_body["id"]))
    assert admin_user.is_active is True


def test_admin_can_disable_another_admin(client, db_session):
    _, acting_admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, other_admin_body = _create_admin_and_login(client, db_session)

    response = client.patch(
        _status_path(other_admin_body["id"]), json={"is_active": False}, headers=_bearer(acting_admin_token)
    )

    assert response.status_code == 200
    assert response.json()["role"] == "admin"
    assert response.json()["is_active"] is False


# =============================================================================
# Business invariants preserved
# =============================================================================


def test_target_role_is_unchanged_by_the_operation(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)

    response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )

    assert response.json()["role"] == "analyst"


def test_target_password_hash_is_unchanged_by_the_operation(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, _, target_body = _register_and_login(client)
    target_id = uuid.UUID(target_body["id"])
    original_hash = UserRepository(db_session).get_by_id(target_id).password_hash

    client.patch(_status_path(target_id), json={"is_active": False}, headers=_bearer(admin_token))

    db_session.expire_all()
    assert UserRepository(db_session).get_by_id(target_id).password_hash == original_hash


# =============================================================================
# Authentication reflects the new active state (ties back to Step 11E)
# =============================================================================


def test_disabling_a_user_invalidates_their_existing_access_token(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    _, target_token, target_body = _register_and_login(client)

    # The target's own token works on an ordinary protected route before
    # being disabled.
    pre_response = client.post(
        "/events",
        json={
            "event_timestamp": "2026-09-09T10:00:00Z",
            "event_type": "process_creation",
            "source": "test",
            "raw_data": {},
        },
        headers=_bearer(target_token),
    )
    assert pre_response.status_code == 201

    disable_response = client.patch(
        _status_path(target_body["id"]), json={"is_active": False}, headers=_bearer(admin_token)
    )
    assert disable_response.status_code == 200

    post_response = client.post(
        "/events",
        json={
            "event_timestamp": "2026-09-09T10:00:05Z",
            "event_type": "process_creation",
            "source": "test",
            "raw_data": {},
        },
        headers=_bearer(target_token),
    )
    assert post_response.status_code == 401


# =============================================================================
# Existing SOC functionality remains intact
# =============================================================================


def test_existing_analyst_functionality_is_unaffected_by_admin_route(client):
    _, analyst_token, _ = _register_and_login(client)

    response = client.post(
        "/events",
        json={
            "event_timestamp": "2026-09-09T10:00:10Z",
            "event_type": "process_creation",
            "source": "test",
            "raw_data": {},
        },
        headers=_bearer(analyst_token),
    )

    assert response.status_code == 201


# =============================================================================
# OpenAPI
# =============================================================================


def test_openapi_marks_admin_route_as_requiring_bearer():
    spec = app.openapi()

    security = spec["paths"]["/admin/users/{user_id}/status"]["patch"].get("security")
    assert security == [{"HTTPBearer": []}]


def test_openapi_bearer_scheme_unaffected():
    spec = app.openapi()

    assert spec["components"]["securitySchemes"] == {"HTTPBearer": {"type": "http", "scheme": "bearer"}}
