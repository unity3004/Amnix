"""Integration tests for Step 11F: the authorization (RBAC) layer —
app.api.dependencies.require_roles() / require_admin. Require PostgreSQL.

No production route in AMNIX is admin-only yet (see the Step 11F brief:
"Do NOT manufacture an admin-only endpoint merely to make RBAC appear
useful"). To exercise require_admin/require_roles() through the real
FastAPI dependency-injection pipeline (not a bare Python function call),
this file temporarily mounts two test-only routes onto the live `app`
instance for the duration of each test that needs them, and removes them
immediately afterward (see the `rbac_test_routes` fixture) — nothing is
added to app/api/*.py.

Every existing production route (POST /events, /alerts, ...) keeps using
only Depends(get_current_user), unchanged from Step 11E: per the current
RBAC policy, admin has all analyst capabilities and no operation is
admin-only, so no production route's dependency changes in this step.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi import APIRouter, Depends
from fastapi.testclient import TestClient

from app.api.dependencies import AuthenticatedUser, get_current_user, require_admin, require_roles
from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"

ADMIN_ONLY_PATH = "/__test_only__/admin-only"
ANALYST_OR_ADMIN_PATH = "/__test_only__/analyst-or-admin"


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def rbac_test_routes():
    """Temporarily mounts two test-only routes exercising require_admin
    and require_roles("analyst", "admin") through the real HTTP/DI
    stack, then removes them — see this file's module docstring for why
    this exists instead of a production admin-only endpoint.
    """
    original_routes = list(app.router.routes)
    router = APIRouter()

    @router.get(ADMIN_ONLY_PATH, include_in_schema=False)
    def _admin_only(current_user: AuthenticatedUser = Depends(require_admin)):
        return {"role": current_user.role}

    @router.get(ANALYST_OR_ADMIN_PATH, include_in_schema=False)
    def _analyst_or_admin(current_user: AuthenticatedUser = Depends(require_roles("analyst", "admin"))):
        return {"role": current_user.role}

    app.include_router(router)
    app.openapi_schema = None
    try:
        yield
    finally:
        app.router.routes = original_routes
        app.openapi_schema = None


def _unique_email(prefix: str = "rbac") -> str:
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
# 1-4: role recognition / allow paths
# =============================================================================


def test_analyst_role_is_recognized_and_allowed_where_analyst_required(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(ANALYST_OR_ADMIN_PATH, headers=_bearer(analyst_token))

    assert response.status_code == 200
    assert response.json()["role"] == "analyst"


def test_admin_role_is_recognized_and_allowed_where_analyst_required(client, db_session, rbac_test_routes):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get(ANALYST_OR_ADMIN_PATH, headers=_bearer(admin_token))

    assert response.status_code == 200
    assert response.json()["role"] == "admin"


def test_admin_role_is_allowed_where_admin_required(client, db_session, rbac_test_routes):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.get(ADMIN_ONLY_PATH, headers=_bearer(admin_token))

    assert response.status_code == 200
    assert response.json()["role"] == "admin"


# =============================================================================
# 5-8: denial semantics
# =============================================================================


def test_analyst_is_denied_where_admin_required_with_403(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(ADMIN_ONLY_PATH, headers=_bearer(analyst_token))

    assert response.status_code == 403
    assert response.status_code != 401


def test_denial_body_contains_only_generic_safe_information(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(ADMIN_ONLY_PATH, headers=_bearer(analyst_token))

    assert response.json() == {"detail": "Insufficient permissions."}
    body_text = response.text.lower()
    for leaked_term in ("admin", "analyst", "role"):
        assert leaked_term not in body_text


# =============================================================================
# 9-11: authentication failures still take priority and stay 401
# =============================================================================


def test_no_token_against_admin_only_route_still_returns_401(client, rbac_test_routes):
    response = client.get(ADMIN_ONLY_PATH)

    assert response.status_code == 401


def test_invalid_token_against_admin_only_route_still_returns_401(client, rbac_test_routes):
    response = client.get(ADMIN_ONLY_PATH, headers=_bearer("garbage-not-a-jwt"))

    assert response.status_code == 401


def test_inactive_admin_user_against_admin_only_route_returns_401_not_403(client, db_session, rbac_test_routes):
    email, admin_token, admin_body = _create_admin_and_login(client, db_session)
    user = UserRepository(db_session).get_by_id(uuid.UUID(admin_body["id"]))
    user.is_active = False
    db_session.commit()

    response = client.get(ADMIN_ONLY_PATH, headers=_bearer(admin_token))

    assert response.status_code == 401


# =============================================================================
# 12: unknown role fails closed
# =============================================================================


def test_unknown_role_fails_closed_on_admin_only_route(client, rbac_test_routes):
    """A role value outside the fixed 'analyst'/'admin' vocabulary can
    never occur through the real database (User.role is CHECK-
    constrained), so this simulates it the only legitimate way
    available: overriding get_current_user() to hand authorization a
    fabricated AuthenticatedUser, exactly as if some future defect
    upstream let an unrecognized role slip through. require_roles() must
    still deny it -- an unknown role is never implicitly privileged.
    """
    fabricated_user = AuthenticatedUser(id=uuid.uuid4(), email="ghost@example.com", role="superadmin", is_active=True)
    app.dependency_overrides[get_current_user] = lambda: fabricated_user
    try:
        admin_response = client.get(ADMIN_ONLY_PATH)
        analyst_response = client.get(ANALYST_OR_ADMIN_PATH)
    finally:
        del app.dependency_overrides[get_current_user]

    assert admin_response.status_code == 403
    assert analyst_response.status_code == 403


# =============================================================================
# 13-15: role cannot be supplied by the client through any channel
# =============================================================================


def test_role_in_request_body_does_not_grant_admin_access(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)

    response = client.request(
        "GET", ADMIN_ONLY_PATH, headers=_bearer(analyst_token), json={"role": "admin"}
    )

    assert response.status_code == 403


def test_role_in_query_parameter_does_not_grant_admin_access(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)

    response = client.get(f"{ADMIN_ONLY_PATH}?role=admin", headers=_bearer(analyst_token))

    assert response.status_code == 403


def test_role_in_arbitrary_client_header_does_not_grant_admin_access(client, rbac_test_routes):
    _, analyst_token, _ = _register_and_login(client)
    headers = _bearer(analyst_token)
    headers["X-Role"] = "admin"
    headers["X-User-Role"] = "admin"

    response = client.get(ADMIN_ONLY_PATH, headers=headers)

    assert response.status_code == 403


# =============================================================================
# Trust boundary: authorization uses the DB-backed role, not the JWT claim
# =============================================================================


def test_forged_admin_role_claim_does_not_grant_admin_access(client, db_session, rbac_test_routes):
    """A structurally valid, correctly-signed access token belonging to a
    real analyst account, whose `role` claim has been altered to
    "admin". Authentication still succeeds (Step 11E: the claim is only
    checked for shape) and hands authorization an AuthenticatedUser --
    but that AuthenticatedUser's role comes from the database row
    (get_current_user() never returns the claim's role), so this must
    still be denied by require_admin.
    """
    _, analyst_token, user_body = _register_and_login(client)
    settings = get_settings()
    real_claims = pyjwt.decode(
        analyst_token, settings.jwt_secret_key, algorithms=["HS256"], issuer="amnix", audience="amnix-api"
    )
    forged_claims = dict(real_claims, role="admin")
    forged_token = pyjwt.encode(forged_claims, settings.jwt_secret_key, algorithm="HS256")

    response = client.get(ADMIN_ONLY_PATH, headers=_bearer(forged_token))

    assert response.status_code == 403
    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    assert user.role == "analyst"  # unchanged by the forged claim


# =============================================================================
# Existing production routes: no accidental restriction, no accidental bypass
# =============================================================================


VALID_EVENT_PAYLOAD = {
    "event_timestamp": "2026-09-06T10:00:00Z",
    "event_type": "process_creation",
    "source": "test",
    "raw_data": {},
}


def test_existing_analyst_functionality_is_unaffected_by_rbac(client):
    """POST /events keeps using only Depends(get_current_user) -- no
    role restriction was added to any existing production route in
    Step 11F. An analyst token must still succeed exactly as in Step
    11E.
    """
    _, analyst_token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(analyst_token))

    assert response.status_code == 201


def test_existing_admin_functionality_is_unaffected_by_rbac(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(admin_token))

    assert response.status_code == 201


def test_existing_unauthenticated_request_still_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD)

    assert response.status_code == 401


# =============================================================================
# require_roles() factory misuse fails at definition time, not at request time
# =============================================================================


def test_require_roles_rejects_unknown_role_at_definition_time():
    with pytest.raises(ValueError):
        require_roles("superadmin")


def test_require_roles_rejects_empty_call_at_definition_time():
    with pytest.raises(ValueError):
        require_roles()


# =============================================================================
# OpenAPI: existing Bearer security metadata is untouched by this step
# =============================================================================


def test_openapi_bearer_scheme_unaffected_by_rbac_layer():
    spec = app.openapi()

    assert spec["components"]["securitySchemes"] == {"HTTPBearer": {"type": "http", "scheme": "bearer"}}
    assert spec["paths"]["/events"]["post"].get("security") == [{"HTTPBearer": []}]
    assert not spec["paths"]["/health"]["get"].get("security")


def test_test_only_admin_route_is_excluded_from_openapi_schema(rbac_test_routes):
    spec = app.openapi()

    assert ADMIN_ONLY_PATH not in spec["paths"]
    assert ANALYST_OR_ADMIN_PATH not in spec["paths"]
