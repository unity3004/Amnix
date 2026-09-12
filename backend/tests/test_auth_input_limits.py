"""Integration tests for Step 11K: authentication input-size hardening.
Require PostgreSQL.

Covers the central invariant this step establishes: an oversized
password or refresh token must never reach Argon2 hashing/verification
or refresh-token hashing/database operations at all — Pydantic schema
validation (app.schemas.auth) must reject it first, every time. Proven
two ways: (a) black-box HTTP status/body assertions, and (b) monkeypatch
proofs that the underlying cryptographic/DB functions are never called
for an over-limit value — status codes alone can't distinguish "rejected
before Argon2" from "rejected after Argon2 happened to also fail", so
the monkeypatch proofs are the real evidence for the objective's core
claim, not just a nice-to-have.
"""

import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.repositories.refresh_token import RefreshTokenRepository

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


def _unique_email(prefix: str = "sizelimit") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _user_count(db_session) -> int:
    from sqlalchemy import func, select

    from app.models.user import User

    return db_session.scalar(select(func.count()).select_from(User))


def _refresh_token_count(db_session) -> int:
    from sqlalchemy import func, select

    from app.models.refresh_token import RefreshToken

    return db_session.scalar(select(func.count()).select_from(RefreshToken))


def _never_called(name: str):
    def _boom(*args, **kwargs):
        raise AssertionError(f"{name} must never be called for an over-limit credential")

    return _boom


# =============================================================================
# Registration: boundary (1-5)
# =============================================================================


@pytest.mark.parametrize(
    "length,expected_status",
    [(11, 422), (12, 201), (127, 201), (128, 201), (129, 422)],
)
def test_registration_password_length_boundary(client, length, expected_status):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": "a" * length}
    )

    assert response.status_code == expected_status


# =============================================================================
# Registration: Argon2/DB non-invocation proofs (6-7)
# =============================================================================


def test_oversized_registration_password_never_invokes_argon2_hashing(client, monkeypatch):
    import app.services.auth_service as auth_service_module

    monkeypatch.setattr(auth_service_module, "hash_password", _never_called("hash_password"))

    response = client.post("/auth/register", json={"email": _unique_email(), "password": "a" * 129})

    assert response.status_code == 422


def test_oversized_registration_password_does_not_create_a_user(client, db_session):
    before = _user_count(db_session)

    response = client.post("/auth/register", json={"email": _unique_email(), "password": "a" * 129})

    assert response.status_code == 422
    assert _user_count(db_session) == before


# =============================================================================
# Registration: extra-field rejection unaffected (8)
# =============================================================================


def test_registration_still_rejects_unknown_fields(client):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD, "role": "admin"}
    )

    assert response.status_code == 422


# =============================================================================
# Login: boundary and behavior (9-13)
# =============================================================================


def test_login_with_128_character_password_follows_normal_authentication_behavior(client):
    email = _unique_email()
    password_128 = "b" * 128
    register_response = client.post("/auth/register", json={"email": email, "password": password_128})
    assert register_response.status_code == 201

    login_response = client.post("/auth/login", json={"email": email, "password": password_128})

    assert login_response.status_code == 200
    body = login_response.json()
    assert body["user"]["email"] == email
    assert "access_token" in body


def test_login_with_129_character_password_is_rejected(client):
    response = client.post("/auth/login", json={"email": _unique_email(), "password": "c" * 129})

    assert response.status_code == 422


def test_oversized_login_password_never_invokes_password_verification(client, monkeypatch):
    import app.services.auth_service as auth_service_module

    monkeypatch.setattr(auth_service_module, "verify_password", _never_called("verify_password"))

    response = client.post("/auth/login", json={"email": _unique_email(), "password": "d" * 129})

    assert response.status_code == 422


def test_oversized_login_password_cannot_produce_successful_authentication(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": "e" * 129})

    assert response.status_code == 422
    assert "access_token" not in response.text
    assert "refresh_token" not in response.text


def test_oversized_login_validation_response_does_not_contain_the_password(client):
    oversized_password = "UNIQUE_MARKER_9f21_" + "f" * 200

    response = client.post("/auth/login", json={"email": _unique_email(), "password": oversized_password})

    assert response.status_code == 422
    assert oversized_password not in response.text
    assert "UNIQUE_MARKER_9f21" not in response.text
    assert "[redacted]" in response.text


# =============================================================================
# Refresh: boundary (14-17)
# =============================================================================


def test_refresh_with_existing_valid_token_still_works(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    assert response.status_code == 200
    assert response.json()["refresh_token"] != login_body["refresh_token"]


@pytest.mark.parametrize("length", [511, 512])
def test_refresh_token_within_the_size_limit_passes_schema_validation(client, length):
    """511/512-char tokens are not real, so they still fail authentication
    -- but with 401 (normal token-validation failure), never 422. This is
    what "subject to normal validation behavior" means: the SCHEMA layer
    lets them through; TokenService.refresh()'s own logic is what then
    rejects them for not existing.
    """
    response = client.post("/auth/refresh", json={"refresh_token": "g" * length})

    assert response.status_code == 401
    assert response.json()["detail"] == "Invalid or expired refresh token."


def test_refresh_token_over_513_characters_is_rejected_by_schema(client):
    response = client.post("/auth/refresh", json={"refresh_token": "h" * 513})

    assert response.status_code == 422


# =============================================================================
# Refresh: hashing/DB/rotation/revocation non-invocation proofs (18-21)
# =============================================================================


def test_oversized_refresh_token_never_invokes_token_hashing(client, monkeypatch):
    import app.services.token_service as token_service_module

    monkeypatch.setattr(token_service_module, "hash_refresh_token", _never_called("hash_refresh_token"))

    response = client.post("/auth/refresh", json={"refresh_token": "i" * 513})

    assert response.status_code == 422


def test_oversized_refresh_token_never_accesses_the_refresh_token_table(client, monkeypatch):
    monkeypatch.setattr(
        RefreshTokenRepository,
        "get_by_token_hash_for_update",
        lambda self, token_hash: (_ for _ in ()).throw(
            AssertionError("get_by_token_hash_for_update must never be called for an over-limit token")
        ),
    )

    response = client.post("/auth/refresh", json={"refresh_token": "j" * 513})

    assert response.status_code == 422


def test_oversized_refresh_token_never_rotates_a_token(client, monkeypatch, db_session):
    monkeypatch.setattr(
        RefreshTokenRepository,
        "rotate",
        lambda self, old_token, new_token: (_ for _ in ()).throw(
            AssertionError("rotate() must never be called for an over-limit token")
        ),
    )
    before = _refresh_token_count(db_session)

    response = client.post("/auth/refresh", json={"refresh_token": "k" * 513})

    assert response.status_code == 422
    assert _refresh_token_count(db_session) == before


def test_oversized_refresh_token_never_revokes_a_family(client, monkeypatch):
    monkeypatch.setattr(
        RefreshTokenRepository,
        "revoke_family",
        lambda self, family_id: (_ for _ in ()).throw(
            AssertionError("revoke_family() must never be called for an over-limit token")
        ),
    )

    response = client.post("/auth/refresh", json={"refresh_token": "l" * 513})

    assert response.status_code == 422


# =============================================================================
# Interaction with Step 11I: normal-sized HTTP request, oversized field
# =============================================================================


def test_normal_sized_request_with_oversized_field_reaches_schema_validation_not_413(client):
    """The overall HTTP request body here is a few hundred bytes -- far
    under Step 11I's 1 MiB global limit -- so it must pass THAT layer
    untouched and be rejected by Pydantic (422) instead, never 413. This
    is the concrete demonstration of the documented flow: HTTP request ->
    11I body-size limit -> Pydantic validation -> auth processing.
    """
    response = client.post("/auth/register", json={"email": _unique_email(), "password": "m" * 129})

    assert response.status_code == 422
    assert response.status_code != 413


# =============================================================================
# Redaction: mixed-error case (a different field also fails validation)
# =============================================================================


def test_oversized_password_is_redacted_even_when_another_field_also_fails(client):
    """A missing `email` alongside an oversized `password` produces TWO
    validation errors in one response -- Pydantic's "missing" error for
    `email` carries the *entire request body* (including the password)
    as its own `input`, not just the email-shaped part. Both this error
    AND the password field's own error must have the password redacted.
    """
    oversized_password = "UNIQUE_MARKER_7c3a_" + "n" * 150

    response = client.post("/auth/register", json={"password": oversized_password})

    assert response.status_code == 422
    assert oversized_password not in response.text
    assert "UNIQUE_MARKER_7c3a" not in response.text
