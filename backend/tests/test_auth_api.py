"""Integration tests for POST /auth/register and POST /auth/login
(Step 11C). Require PostgreSQL.

Mirrors test_copilot_api.py's fixture conventions (self-contained per
file, real MockAIProvider/db_session wiring via the same `client`
fixture pattern already established throughout this test suite).
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app

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


def _unique_email(prefix: str = "analyst") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


# =============================================================================
# Registration
# =============================================================================


def test_register_returns_201_and_safe_user(client):
    email = _unique_email()

    response = client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 201
    body = response.json()
    assert body["email"] == email
    assert body["role"] == "analyst"
    assert body["is_active"] is True
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body


def test_register_normalizes_email_in_response(client):
    raw_email = f"  Analyst-{uuid.uuid4().hex[:8]}@Example.COM  "

    response = client.post("/auth/register", json={"email": raw_email, "password": VALID_PASSWORD})

    assert response.status_code == 201
    assert response.json()["email"] == raw_email.strip().lower()


def test_register_response_never_contains_password_or_hash(client):
    email = _unique_email()

    response = client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    body_text = response.text
    assert VALID_PASSWORD not in body_text
    assert "password_hash" not in body_text
    assert "password" not in response.json()


def test_register_rejects_client_supplied_role(client):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD, "role": "admin"}
    )

    assert response.status_code == 422


def test_register_rejects_client_supplied_is_active(client):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD, "is_active": False}
    )

    assert response.status_code == 422


def test_register_rejects_client_supplied_password_hash(client):
    response = client.post(
        "/auth/register",
        json={"email": _unique_email(), "password": VALID_PASSWORD, "password_hash": "$argon2id$fake"},
    )

    assert response.status_code == 422


def test_register_rejects_client_supplied_id(client):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD, "id": str(uuid.uuid4())}
    )

    assert response.status_code == 422


def test_register_short_password_returns_422(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": "short11ch"})

    assert response.status_code == 422
    assert VALID_PASSWORD not in response.text
    assert "short11ch" not in response.text


def test_register_duplicate_email_returns_409(client):
    email = _unique_email()
    first = client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    assert first.status_code == 201

    second = client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    assert second.status_code == 409
    assert "already registered" in second.json()["detail"].lower()


def test_register_duplicate_email_case_insensitive_returns_409(client):
    base = f"dup-{uuid.uuid4().hex[:8]}@example.com"
    first = client.post("/auth/register", json={"email": base, "password": VALID_PASSWORD})
    assert first.status_code == 201

    second = client.post("/auth/register", json={"email": f"  {base.upper()}  ", "password": VALID_PASSWORD})

    assert second.status_code == 409


def test_register_conflict_response_does_not_leak_db_details(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    body_text = response.text.lower()
    for leaky_term in ("integrityerror", "psycopg", "sqlalchemy", "constraint", "duplicate key"):
        assert leaky_term not in body_text


# =============================================================================
# Login
# =============================================================================


def test_login_with_valid_credentials_returns_200_and_safe_user(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200
    body = response.json()
    assert body["user"]["email"] == email
    assert "password" not in body["user"]
    assert "password_hash" not in body["user"]
    assert "password" not in body
    assert "password_hash" not in body


def test_login_response_contains_token_pair(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    body = response.json()
    assert isinstance(body["access_token"], str) and body["access_token"]
    assert isinstance(body["refresh_token"], str) and body["refresh_token"]
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900


def test_login_access_token_is_a_valid_jwt_with_expected_claims(client):
    import jwt as pyjwt

    from app.core.config import get_settings

    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    body = response.json()

    settings = get_settings()
    claims = pyjwt.decode(
        body["access_token"],
        settings.jwt_secret_key,
        algorithms=["HS256"],
        issuer="amnix",
        audience="amnix-api",
    )
    assert claims["sub"] == body["user"]["id"]
    assert claims["role"] == "analyst"
    assert "jti" in claims
    assert "password" not in claims
    assert "password_hash" not in claims


def test_login_response_never_contains_token_hash_or_family_id(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    body_text = response.text.lower()
    for forbidden in ("token_hash", "family_id", "password_hash"):
        assert forbidden not in body_text


def test_login_wrong_password_returns_401(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": "totally wrong password"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_nonexistent_email_returns_401_with_same_message(client):
    response = client.post("/auth/login", json={"email": "nobody-registered@example.com", "password": VALID_PASSWORD})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid email or password."


def test_login_wrong_password_and_nonexistent_email_are_identical_responses(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    wrong_password_response = client.post("/auth/login", json={"email": email, "password": "wrong password"})
    nonexistent_response = client.post(
        "/auth/login", json={"email": "still-nobody@example.com", "password": VALID_PASSWORD}
    )

    assert wrong_password_response.status_code == nonexistent_response.status_code == 401
    assert wrong_password_response.json() == nonexistent_response.json()


def test_login_normalizes_email(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": f"  {email.upper()}  ", "password": VALID_PASSWORD})

    assert response.status_code == 200
    assert response.json()["user"]["email"] == email


def test_login_response_never_contains_raw_db_error_text(client):
    response = client.post("/auth/login", json={"email": "nobody-at-all@example.com", "password": VALID_PASSWORD})

    body_text = response.text.lower()
    for leaky_term in ("traceback", "sqlalchemy", "psycopg", "internal server error"):
        assert leaky_term not in body_text


def test_login_user_object_has_no_token_shaped_field(client):
    """The nested `user` object is exactly UserRead -- no token/session
    field leaks into it (tokens live only at the top level of the login
    response, see TokenResponse/LoginResponse in app.schemas.auth).
    """
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    user_body = response.json()["user"]
    for forbidden_field in ("access_token", "refresh_token", "token", "session_id", "jwt"):
        assert forbidden_field not in user_body


# =============================================================================
# Refresh
# =============================================================================


def test_refresh_with_valid_token_returns_200_and_new_pair(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    assert response.status_code == 200
    body = response.json()
    assert body["access_token"] != login_body["access_token"]
    assert body["refresh_token"] != login_body["refresh_token"]
    assert body["token_type"] == "Bearer"
    assert body["expires_in"] == 900
    assert "user" not in body


def test_refresh_response_never_contains_db_internals(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    body_text = response.text.lower()
    for forbidden in ("token_hash", "family_id", "password", "password_hash"):
        assert forbidden not in body_text


def test_refresh_with_unknown_token_returns_401(client):
    response = client.post("/auth/refresh", json={"refresh_token": "not-a-real-token-at-all"})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."


def test_refresh_old_token_is_rejected_after_rotation(client):
    """Using an already-rotated (old) refresh token a second time must
    fail -- the classic reuse-detection guarantee.
    """
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()
    old_refresh_token = login_body["refresh_token"]

    first_refresh = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    assert first_refresh.status_code == 200

    reuse_attempt = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})

    assert reuse_attempt.status_code == 401
    assert reuse_attempt.json()["detail"] == "Invalid or expired refresh token."


def test_refresh_reuse_revokes_the_entire_family(client, db_session):
    """Reuse of an old token must revoke the WHOLE family -- including
    the newest, otherwise-still-valid token -- not just reject the
    single reuse attempt.
    """
    from sqlalchemy import select

    from app.models.refresh_token import RefreshToken

    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()
    old_refresh_token = login_body["refresh_token"]

    refreshed = client.post("/auth/refresh", json={"refresh_token": old_refresh_token})
    newest_refresh_token = refreshed.json()["refresh_token"]

    # Reuse the OLD (already-rotated) token to trigger family revocation.
    client.post("/auth/refresh", json={"refresh_token": old_refresh_token})

    # The newest token, though never itself reused, must now be revoked too.
    second_attempt_with_newest = client.post("/auth/refresh", json={"refresh_token": newest_refresh_token})
    assert second_attempt_with_newest.status_code == 401

    rows = list(db_session.scalars(select(RefreshToken)))
    assert all(r.revoked_at is not None for r in rows if r.user_id == rows[0].user_id)


def test_refresh_chain_can_rotate_multiple_times(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    token = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()["refresh_token"]

    for _ in range(3):
        response = client.post("/auth/refresh", json={"refresh_token": token})
        assert response.status_code == 200
        token = response.json()["refresh_token"]


def test_refresh_for_inactive_account_fails(client, db_session):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    from app.repositories.user import UserRepository

    user = UserRepository(db_session).get_by_email(email)
    user.is_active = False
    db_session.commit()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."


def test_refresh_does_not_return_password_or_hash(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    body_text = response.text
    assert VALID_PASSWORD not in body_text


# =============================================================================
# Backward compatibility / no accidental route protection
# =============================================================================


def test_existing_health_endpoint_still_unauthenticated(client):
    response = client.get("/health")

    assert response.status_code == 200


def test_events_endpoint_now_requires_authentication(client):
    """Step 11E's own intended contract change: POST /events was
    publicly accessible through Step 11D and is now protected -- see
    app.api.dependencies.get_current_user and the full route-protection
    coverage in test_auth_middleware.py. This test documents the
    change at exactly the place the old (now-incorrect) "still
    unauthenticated" assumption used to live, rather than silently
    deleting it.
    """
    response = client.post(
        "/events",
        json={
            "event_timestamp": "2026-09-05T10:00:00Z",
            "event_type": "process_creation",
            "source": "test",
            "raw_data": {},
        },
    )

    assert response.status_code == 401


def test_registration_does_not_affect_alert_or_event_tables(client, db_session):
    from sqlalchemy import select

    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent

    before_alerts = len(list(db_session.scalars(select(Alert))))
    before_events = len(list(db_session.scalars(select(SecurityEvent))))

    client.post("/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD})

    after_alerts = len(list(db_session.scalars(select(Alert))))
    after_events = len(list(db_session.scalars(select(SecurityEvent))))

    assert after_alerts == before_alerts
    assert after_events == before_events
