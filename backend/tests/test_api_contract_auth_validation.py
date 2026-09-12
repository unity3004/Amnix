"""Step 11O: authentication error surface, JWT error surface, and
Pydantic/FastAPI validation-error leakage. Require PostgreSQL.

Covers brief items 1-18 plus the property-style redaction checks from
section 31, focused specifically on the auth endpoints and the global
RequestValidationError handler (app.api.auth.redact_sensitive_
validation_errors).

Central regression this file exists to lock in: Step 11O discovery
found that a wrong Content-Type on an otherwise-valid JSON body
produces a THIRD Pydantic error shape (`input` is the raw body as
`bytes`, under `loc == ("body",)`) that Step 11K's original redaction
logic did not cover -- a real submitted password/refresh_token was
echoed back verbatim in the 422 response. Fixed narrowly in
app.api.auth._redact_error_input (see that function's own docstring).
test_content_type_mismatch_does_not_leak_password_or_refresh_token
below is the direct regression test for that fix.
"""

import time
import uuid

import jwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
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


def _unique_email(prefix: str = "contract") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register(client, email: str, password: str = VALID_PASSWORD) -> None:
    response = client.post("/auth/register", json={"email": email, "password": password})
    assert response.status_code == 201, response.text


# =============================================================================
# 1-2, 7. Authentication error surface: login never reveals account state
# =============================================================================


def test_invalid_password_login_response_is_generic(client):
    email = _unique_email()
    _register(client, email)

    response = client.post("/auth/login", json={"email": email, "password": "wrong-password-entirely"})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}


def test_nonexistent_user_login_response_is_identical_to_wrong_password(client):
    nonexistent_response = client.post(
        "/auth/login", json={"email": _unique_email("ghost"), "password": "irrelevant-password"}
    )

    email = _unique_email()
    _register(client, email)
    wrong_password_response = client.post("/auth/login", json={"email": email, "password": "wrong-password"})

    assert nonexistent_response.status_code == wrong_password_response.status_code == 401
    assert nonexistent_response.json() == wrong_password_response.json()


def test_inactive_user_login_response_is_identical_to_wrong_password(client, db_session):
    from app.core.security import hash_password
    from app.models.user import User

    email = _unique_email("inactive")
    user = User(email=email, password_hash=hash_password(VALID_PASSWORD), role="analyst", is_active=False)
    db_session.add(user)
    db_session.commit()

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 401
    assert response.json() == {"detail": "Invalid email or password."}


def test_login_failure_response_never_contains_password_hash_field(client):
    response = client.post("/auth/login", json={"email": _unique_email(), "password": "x" * 20})

    assert "password_hash" not in response.text
    assert "password" not in response.json()["detail"].lower() or response.json()["detail"] == "Invalid email or password."


# =============================================================================
# 3-7. JWT error surface
# =============================================================================


def _protected_get(client, token: str | None, headers_override: dict | None = None):
    headers = headers_override if headers_override is not None else ({"Authorization": f"Bearer {token}"} if token else {})
    return client.get(f"/events/{uuid.uuid4()}", headers=headers)


def test_missing_authorization_header_is_safe_401(client):
    response = _protected_get(client, None)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_malformed_jwt_response_is_safe(client):
    response = _protected_get(client, "not-a-jwt-at-all")
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}
    assert "jwt" not in response.text.lower().replace("could not validate credentials.", "")


def test_expired_jwt_response_is_safe(client):
    settings = get_settings()
    now = int(time.time())
    expired_token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "role": "analyst",
            "iat": now - 3600,
            "exp": now - 1800,
            "jti": str(uuid.uuid4()),
            "iss": settings.jwt_issuer,
            "aud": settings.jwt_audience,
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = _protected_get(client, expired_token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_wrong_issuer_jwt_response_is_safe(client):
    settings = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "role": "analyst",
            "iat": now,
            "exp": now + 900,
            "jti": str(uuid.uuid4()),
            "iss": "not-amnix",
            "aud": settings.jwt_audience,
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = _protected_get(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_wrong_audience_jwt_response_is_safe(client):
    settings = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {
            "sub": str(uuid.uuid4()),
            "role": "analyst",
            "iat": now,
            "exp": now + 900,
            "jti": str(uuid.uuid4()),
            "iss": settings.jwt_issuer,
            "aud": "not-amnix-api",
        },
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = _protected_get(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_missing_claims_jwt_response_is_safe(client):
    settings = get_settings()
    now = int(time.time())
    # missing "role" entirely
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "iat": now, "exp": now + 900, "jti": str(uuid.uuid4()),
         "iss": settings.jwt_issuer, "aud": settings.jwt_audience},
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = _protected_get(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_invalid_role_claim_jwt_response_is_safe(client):
    settings = get_settings()
    now = int(time.time())
    token = jwt.encode(
        {"sub": str(uuid.uuid4()), "role": "superuser", "iat": now, "exp": now + 900, "jti": str(uuid.uuid4()),
         "iss": settings.jwt_issuer, "aud": settings.jwt_audience},
        settings.jwt_secret_key,
        algorithm="HS256",
    )
    response = _protected_get(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


def test_alg_none_jwt_is_rejected_not_accepted(client):
    """Algorithm-confusion defense-in-depth: decode_access_token() always
    pins algorithms=["HS256"] explicitly, so a client-forged `alg: none`
    token (unsigned) must never be treated as valid.
    """
    header = {"alg": "none", "typ": "JWT"}
    import base64
    import json as jsonlib

    def _b64(d: dict) -> str:
        return base64.urlsafe_b64encode(jsonlib.dumps(d).encode()).decode().rstrip("=")

    now = int(time.time())
    payload = {"sub": str(uuid.uuid4()), "role": "admin", "iat": now, "exp": now + 900, "jti": str(uuid.uuid4())}
    forged_token = f"{_b64(header)}.{_b64(payload)}."

    response = _protected_get(client, forged_token)
    assert response.status_code == 401


def test_basic_auth_header_is_rejected_as_401_not_accepted(client):
    response = _protected_get(client, None, headers_override={"Authorization": "Basic dXNlcjpwYXNz"})
    assert response.status_code == 401


def test_empty_authorization_header_is_safe_401(client):
    response = _protected_get(client, None, headers_override={"Authorization": ""})
    assert response.status_code == 401


def test_inactive_user_valid_jwt_response_is_safe_401(client, db_session):
    from app.core.security import hash_password
    from app.core.tokens import create_access_token
    from app.models.user import User

    user = User(email=_unique_email("deactivated"), password_hash=hash_password(VALID_PASSWORD), role="analyst", is_active=False)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    token = create_access_token(user_id=user.id, role=user.role)
    response = _protected_get(client, token)
    assert response.status_code == 401
    assert response.json() == {"detail": "Could not validate credentials."}


# =============================================================================
# 8-13. Pydantic/FastAPI validation leakage
# =============================================================================


def test_malformed_uuid_path_param_is_safe_422(client, db_session):
    from app.core.tokens import create_access_token
    from app.core.security import hash_password
    from app.models.user import User

    user = User(email=_unique_email(), password_hash=hash_password(VALID_PASSWORD), role="analyst")
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    token = create_access_token(user_id=user.id, role=user.role)

    response = client.get("/events/not-a-real-uuid", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


def test_malformed_enum_is_safe_422(client):
    response = client.post(
        "/events",
        json={
            "event_timestamp": "2026-01-01T00:00:00Z",
            "event_type": "x",
            "source": "x",
            "raw_data": {},
            "severity": "not-a-real-severity",
        },
        headers=_auth_headers(client),
    )
    assert response.status_code == 422


def test_malformed_boolean_is_safe_422(client, db_session):
    admin_token = _create_admin(client, db_session)
    response = client.patch(
        f"/admin/users/{uuid.uuid4()}/status",
        json={"is_active": "not-a-boolean"},
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 422


def test_malformed_integer_query_param_is_safe_422(client):
    response = client.get("/admin/audits?limit=not-an-integer", headers=_auth_headers(client))
    # analyst is forbidden (403) before query validation in some frameworks,
    # or 422 if validated first -- either is safe; only a 500/leak is not.
    assert response.status_code in (403, 422)
    assert "traceback" not in response.text.lower()


def test_malformed_nested_object_is_safe_422(client):
    response = client.post(
        "/alerts",
        json={
            "rule_id": "x",
            "title": "x",
            "description": "x",
            "severity": "high",
            "confidence": "high",
            "first_seen": "2026-01-01T00:00:00Z",
            "evidence": "this-should-be-a-dict-not-a-string",
            "source_event_ids": [str(uuid.uuid4())],
        },
        headers=_auth_headers(client),
    )
    assert response.status_code == 422


def test_malformed_json_body_is_safe_422(client):
    response = client.post(
        "/auth/login", content=b'{"email": "a@example.com", "password":', headers={"Content-Type": "application/json"}
    )
    assert response.status_code == 422
    assert "traceback" not in response.text.lower()


def test_unexpected_body_field_is_rejected_422(client):
    response = client.post(
        "/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD, "role": "admin"}
    )
    assert response.status_code == 422


def test_oversized_password_is_rejected_before_hashing(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": "x" * 200})
    assert response.status_code == 422


def test_oversized_refresh_token_is_rejected_before_hash_lookup(client):
    response = client.post("/auth/refresh", json={"refresh_token": "x" * 600})
    assert response.status_code == 422


def test_validation_error_does_not_echo_password(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": "x" * 200})
    assert "x" * 200 not in response.text


def test_validation_error_does_not_echo_refresh_token(client):
    secret_value = "REFRESH-" + "y" * 600
    response = client.post("/auth/refresh", json={"refresh_token": secret_value})
    assert secret_value not in response.text


def test_model_level_error_with_sensitive_sibling_field_is_redacted(client):
    """Step 11K's own original regression case: a missing `email` on the
    same request as an oversized `password` must not leak the password
    through the *other* field's model-level error `input` dict.
    """
    secret_password = "SIBLING-FIELD-SECRET-" + "z" * 150
    response = client.post("/auth/register", json={"password": secret_password})
    assert secret_password not in response.text


def test_content_type_mismatch_does_not_leak_password_or_refresh_token(client):
    """Step 11O regression test for the defect found and fixed in this
    step -- see this module's own docstring for the full story.
    """
    secret_password = "CONTENT-TYPE-BYPASS-SECRET-PW-12345"
    response = client.post(
        "/auth/login",
        content=('{"email":"victim@example.com","password":"%s"}' % secret_password).encode(),
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 422
    assert secret_password not in response.text
    assert response.json()["detail"][0]["input"] == "[redacted]"


def test_content_type_mismatch_does_not_leak_refresh_token(client):
    secret_token = "CONTENT-TYPE-BYPASS-SECRET-REFRESH-98765"
    response = client.post(
        "/auth/refresh",
        content=('{"refresh_token":"%s"}' % secret_token).encode(),
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code == 422
    assert secret_token not in response.text


def test_content_type_mismatch_without_sensitive_field_is_not_over_redacted(client):
    """The fix must not blanket-redact every content-type-mismatch error
    -- only ones that actually contain a sensitive field name.
    """
    response = client.post(
        "/auth/login", content=b"totally unrelated garbage body", headers={"Content-Type": "text/plain"}
    )
    assert response.status_code == 422
    assert response.json()["detail"][0]["input"] == "totally unrelated garbage body"


# =============================================================================
# Mass assignment: registration cannot set role/is_active/id/password_hash
# =============================================================================


@pytest.mark.parametrize("forbidden_field,value", [("role", "admin"), ("is_active", False), ("id", str(uuid.uuid4())), ("password_hash", "$argon2id$fake")])
def test_register_rejects_privileged_fields(client, forbidden_field, value):
    payload = {"email": _unique_email(), "password": VALID_PASSWORD, forbidden_field: value}
    response = client.post("/auth/register", json=payload)
    assert response.status_code == 422


def test_registered_user_is_always_analyst_role(client, db_session):
    from app.models.user import User

    email = _unique_email()
    _register(client, email)
    user = db_session.query(User).filter(User.email == email).one()
    assert user.role == "analyst"
    assert user.is_active is True


def _auth_headers(client) -> dict:
    email = _unique_email()
    _register(client, email)
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    return {"Authorization": f"Bearer {login.json()['access_token']}"}


def _create_admin(client, db_session) -> str:
    from app.core.security import hash_password
    from app.models.user import User

    email = _unique_email("admin")
    user = User(email=email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(user)
    db_session.commit()
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    return login.json()["access_token"]
