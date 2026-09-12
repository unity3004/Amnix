"""Integration tests for Step 11E: the authentication dependency
(app.api.dependencies.get_current_user) and route protection across
every existing AMNIX route. Require PostgreSQL.

Section 1: fine-grained Bearer/JWT validation behavior, exercised
against one representative protected route (POST /events) so every
scenario goes through the real FastAPI dependency-injection pipeline
(header parsing via HTTPBearer, not a hand-called Python function).

Section 2: the full route-protection matrix -- every protected route
discovered in app/api/alerts.py and app/api/events.py, plus the four
routes that must remain public.
"""

import uuid
from datetime import datetime, timedelta, timezone

import jwt as pyjwt
import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration

VALID_PASSWORD = "correct horse battery staple"

VALID_EVENT_PAYLOAD = {
    "event_timestamp": "2026-09-06T10:00:00Z",
    "event_type": "process_creation",
    "source": "test",
    "raw_data": {},
}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _unique_email(prefix: str = "mw") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client, *, password: str = VALID_PASSWORD) -> tuple[str, str, dict]:
    """Returns (email, access_token, user_body)."""
    email = _unique_email()
    register_response = client.post("/auth/register", json={"email": email, "password": password})
    assert register_response.status_code == 201, register_response.text
    login_response = client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200, login_response.text
    body = login_response.json()
    return email, body["access_token"], body["user"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _sign(payload: dict, *, secret: str | None = None, algorithm: str = "HS256") -> str:
    settings = get_settings()
    return pyjwt.encode(payload, secret if secret is not None else settings.jwt_secret_key, algorithm=algorithm)


def _base_claims(**overrides) -> dict:
    now = datetime.now(timezone.utc)
    claims = {
        "sub": str(uuid.uuid4()),
        "role": "analyst",
        "iat": now,
        "exp": now + timedelta(minutes=15),
        "jti": str(uuid.uuid4()),
        "iss": "amnix",
        "aud": "amnix-api",
    }
    claims.update(overrides)
    return claims


# =============================================================================
# Section 1: fine-grained dependency behavior (POST /events as the probe)
# =============================================================================


def test_valid_bearer_token_is_accepted(client):
    _, access_token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))

    assert response.status_code == 201


def test_missing_authorization_header_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD)

    assert response.status_code == 401
    assert response.headers.get("www-authenticate") == "Bearer"


def test_empty_authorization_header_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers={"Authorization": ""})

    assert response.status_code == 401


def test_basic_auth_scheme_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers={"Authorization": "Basic abc"})

    assert response.status_code == 401


def test_malformed_bearer_header_with_no_token_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers={"Authorization": "Bearer"})

    assert response.status_code == 401


def test_garbage_jwt_returns_401(client):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer("garbage-not-a-jwt"))

    assert response.status_code == 401


def test_expired_jwt_returns_401(client):
    now = datetime.now(timezone.utc)
    token = _sign(_base_claims(iat=now - timedelta(minutes=30), exp=now - timedelta(minutes=15)))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_tampered_jwt_returns_401(client):
    _, access_token, _ = _register_and_login(client)
    tampered = access_token[:-4] + ("AAAA" if access_token[-4:] != "AAAA" else "BBBB")

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(tampered))

    assert response.status_code == 401


def test_wrong_issuer_returns_401(client):
    token = _sign(_base_claims(iss="not-amnix"))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_wrong_audience_returns_401(client):
    token = _sign(_base_claims(aud="not-amnix-api"))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_alg_none_returns_401(client):
    token = pyjwt.encode(_base_claims(), "", algorithm="none")

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_alternate_algorithm_returns_401(client):
    token = _sign(_base_claims(), algorithm="HS384")

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_missing_sub_returns_401(client):
    claims = _base_claims()
    del claims["sub"]
    token = _sign(claims)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_invalid_uuid_sub_returns_401(client):
    token = _sign(_base_claims(sub="not-a-uuid"))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_missing_role_returns_401(client):
    claims = _base_claims()
    del claims["role"]
    token = _sign(claims)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_invalid_role_returns_401(client):
    token = _sign(_base_claims(role="superadmin"))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_missing_jti_returns_401(client):
    claims = _base_claims()
    del claims["jti"]
    token = _sign(claims)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_nonexistent_user_returns_401(client):
    """A structurally perfect, correctly-signed token for a user id that
    simply does not exist in the database.
    """
    token = _sign(_base_claims(sub=str(uuid.uuid4())))

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(token))

    assert response.status_code == 401


def test_inactive_user_returns_401(client, db_session):
    email, access_token, user_body = _register_and_login(client)
    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    user.is_active = False
    db_session.commit()

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))

    assert response.status_code == 401


def test_valid_active_user_is_authenticated(client):
    _, access_token, user_body = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))

    assert response.status_code == 201


# =============================================================================
# Token claim vs. database (Section 23 of the brief)
# =============================================================================


def test_forged_role_claim_does_not_override_database_role(client, db_session):
    """A structurally valid, correctly-signed token whose role claim has
    been altered to a DIFFERENT valid role than the account's real,
    current role in the database. Authentication must still succeed
    (the JWT role claim only needs to be structurally valid at this
    step -- see app.api.dependencies' own docstring), but the
    authoritative identity must come from the current database row, not
    the token. This is not an RBAC test -- both roles are allowed to
    call this route equally in Step 11E (see test_admin_and_analyst_
    tokens_are_both_authenticated below); the point here is proving
    WHERE the authoritative role comes from.
    """
    email, access_token, user_body = _register_and_login(client)  # real role: analyst
    settings = get_settings()
    real_claims = pyjwt.decode(
        access_token, settings.jwt_secret_key, algorithms=["HS256"], issuer="amnix", audience="amnix-api"
    )
    forged_claims = dict(real_claims, role="admin")
    forged_token = pyjwt.encode(forged_claims, settings.jwt_secret_key, algorithm="HS256")

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(forged_token))

    # Still authenticates (the account is real and active) -- Step 11E
    # does not reject a role mismatch, it just never trusts the claim.
    assert response.status_code == 201

    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    assert user.role == "analyst"  # unchanged by the forged claim


# =============================================================================
# Role structure only, no RBAC (Section 21)
# =============================================================================


def test_admin_and_analyst_tokens_are_both_authenticated(client, db_session):
    analyst_email, analyst_token, _ = _register_and_login(client)
    admin_email = _unique_email("admin")
    admin_user = User(email=admin_email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(admin_user)
    db_session.commit()
    admin_login = client.post("/auth/login", json={"email": admin_email, "password": VALID_PASSWORD})
    admin_token = admin_login.json()["access_token"]

    analyst_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(analyst_token))
    admin_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(admin_token))

    assert analyst_response.status_code == 201
    assert admin_response.status_code == 201


# =============================================================================
# Error leakage (Section 22)
# =============================================================================


@pytest.mark.parametrize(
    "make_headers",
    [
        lambda: {},
        lambda: _bearer("garbage"),
        lambda: _bearer(_sign(_base_claims(role="bad-role"))),
    ],
)
def test_auth_failure_responses_never_leak_internal_details(client, make_headers):
    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=make_headers())

    assert response.status_code == 401
    body_text = response.text.lower()
    forbidden_terms = (
        "pyjwt",
        "jwt.exceptions",
        "sqlalchemy",
        "psycopg",
        "traceback",
        "uuid(",
        "valueerror",
        "keyerror",
        "secret",
        "connection",
    )
    for term in forbidden_terms:
        assert term not in body_text


def test_inactive_user_401_does_not_reveal_account_existed(client, db_session):
    email, access_token, user_body = _register_and_login(client)
    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    user.is_active = False
    db_session.commit()

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))

    body_text = response.text.lower()
    assert email.lower() not in body_text
    assert "inactive" not in body_text
    assert "disabled" not in body_text
    assert response.json()["detail"] == "Could not validate credentials."


def test_nonexistent_user_and_inactive_user_produce_identical_responses(client, db_session):
    inactive_email, inactive_token, inactive_body = _register_and_login(client)
    inactive_user = UserRepository(db_session).get_by_id(uuid.UUID(inactive_body["id"]))
    inactive_user.is_active = False
    db_session.commit()

    nonexistent_token = _sign(_base_claims(sub=str(uuid.uuid4())))

    inactive_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(inactive_token))
    nonexistent_response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(nonexistent_token))

    assert inactive_response.status_code == nonexistent_response.status_code == 401
    assert inactive_response.json() == nonexistent_response.json()


# =============================================================================
# User state: disable / delete after token issuance (Section 20)
# =============================================================================


def test_disabling_user_after_login_invalidates_existing_access_token(client, db_session):
    email, access_token, user_body = _register_and_login(client)
    assert client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token)).status_code == 201

    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    user.is_active = False
    db_session.commit()

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))
    assert response.status_code == 401


def test_deleting_user_after_login_invalidates_existing_access_token(client, db_session):
    email, access_token, user_body = _register_and_login(client)
    assert client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token)).status_code == 201

    user = UserRepository(db_session).get_by_id(uuid.UUID(user_body["id"]))
    db_session.delete(user)
    db_session.commit()

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))
    assert response.status_code == 401


# =============================================================================
# Section 2: full route-protection matrix
# =============================================================================
#
# Every route discovered in app/api/events.py and app/api/alerts.py
# (see this file's own module docstring), plus the four routes that
# must remain public. Each protected entry is verified with (a) no
# Authorization header -> 401, (b) an invalid token -> 401, and (c) a
# valid active-user token -> the request reaches real endpoint logic
# (asserted via a status code business logic could plausibly produce --
# never 401/403).


def _setup_alert(db_session):
    """A minimal real Alert + its source SecurityEvent, built directly
    against the ORM (not through the now-authenticated API) so route-
    matrix tests can target a real alert_id without depending on
    another protected endpoint succeeding first.
    """
    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="route-matrix-test",
        raw_data={},
        username="jdoe",
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    alert = Alert(
        rule_id="brute_force_authentication",
        title="Route matrix test alert",
        description="Route matrix test alert.",
        severity="high",
        confidence="high",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


@pytest.mark.parametrize(
    "method,path_template,json_body",
    [
        ("POST", "/events", VALID_EVENT_PAYLOAD),
        ("GET", "/events/{event_id}", None),
        ("POST", "/alerts", None),  # body filled in per-test below (needs a real event id)
        ("GET", "/alerts/{alert_id}", None),
        ("PATCH", "/alerts/{alert_id}/status", {"status": "acknowledged"}),
        ("GET", "/alerts/{alert_id}/investigation", None),
        ("POST", "/alerts/{alert_id}/copilot", {"question": "Why?"}),
        ("POST", "/alerts/{alert_id}/copilot/follow-up", {"question": "What next?", "history": []}),
        ("GET", "/alerts/{alert_id}/copilot/audits", None),
    ],
)
def test_protected_route_rejects_missing_and_invalid_tokens(client, db_session, method, path_template, json_body):
    alert = _setup_alert(db_session)
    path = path_template.format(alert_id=alert.id, event_id=uuid.uuid4())

    no_header_response = client.request(method, path, json=json_body)
    assert no_header_response.status_code == 401, f"{method} {path} without a token"

    invalid_token_response = client.request(method, path, json=json_body, headers=_bearer("garbage"))
    assert invalid_token_response.status_code == 401, f"{method} {path} with an invalid token"


def test_events_post_with_valid_token_reaches_business_logic(client):
    _, access_token, _ = _register_and_login(client)

    response = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token))

    assert response.status_code == 201


def test_events_get_with_valid_token_reaches_business_logic(client):
    _, access_token, _ = _register_and_login(client)
    created = client.post("/events", json=VALID_EVENT_PAYLOAD, headers=_bearer(access_token)).json()

    response = client.get(f"/events/{created['id']}", headers=_bearer(access_token))

    assert response.status_code == 200


def test_alerts_post_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    from app.models.security_event import SecurityEvent

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="t", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    response = client.post(
        "/alerts",
        json={
            "rule_id": "brute_force_authentication",
            "title": "Matrix test",
            "description": "Matrix test.",
            "severity": "high",
            "confidence": "high",
            "first_seen": datetime.now(timezone.utc).isoformat(),
            "evidence": {},
            "source_event_ids": [str(event.id)],
        },
        headers=_bearer(access_token),
    )

    assert response.status_code == 201


def test_alerts_get_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.get(f"/alerts/{alert.id}", headers=_bearer(access_token))

    assert response.status_code == 200


def test_alerts_status_patch_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.patch(
        f"/alerts/{alert.id}/status", json={"status": "acknowledged"}, headers=_bearer(access_token)
    )

    assert response.status_code == 200


def test_investigation_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.get(f"/alerts/{alert.id}/investigation", headers=_bearer(access_token))

    assert response.status_code == 200


def test_copilot_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot", json={"question": "Why?"}, headers=_bearer(access_token)
    )

    assert response.status_code == 200


def test_copilot_follow_up_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.post(
        f"/alerts/{alert.id}/copilot/follow-up",
        json={"question": "What next?", "history": []},
        headers=_bearer(access_token),
    )

    assert response.status_code == 200


def test_copilot_audits_with_valid_token_reaches_business_logic(client, db_session):
    _, access_token, _ = _register_and_login(client)
    alert = _setup_alert(db_session)

    response = client.get(f"/alerts/{alert.id}/copilot/audits", headers=_bearer(access_token))

    assert response.status_code == 200


# --- public routes remain public --------------------------------------------


def test_health_remains_public(client):
    response = client.get("/health")

    assert response.status_code == 200


def test_register_remains_public(client):
    response = client.post("/auth/register", json={"email": _unique_email(), "password": VALID_PASSWORD})

    assert response.status_code == 201


def test_login_remains_public(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    assert response.status_code == 200


def test_refresh_remains_public(client):
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login_body = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD}).json()

    # No Authorization header at all -- the refresh token itself is the
    # credential, per Step 11D/11E's design.
    response = client.post("/auth/refresh", json={"refresh_token": login_body["refresh_token"]})

    assert response.status_code == 200


# =============================================================================
# OpenAPI security metadata
# =============================================================================


def test_openapi_declares_bearer_security_scheme():
    spec = app.openapi()

    assert spec["components"]["securitySchemes"] == {"HTTPBearer": {"type": "http", "scheme": "bearer"}}


@pytest.mark.parametrize(
    "path,method",
    [
        ("/events", "post"),
        ("/events/{event_id}", "get"),
        ("/alerts", "post"),
        ("/alerts/{alert_id}", "get"),
        ("/alerts/{alert_id}/status", "patch"),
        ("/alerts/{alert_id}/investigation", "get"),
        ("/alerts/{alert_id}/copilot", "post"),
        ("/alerts/{alert_id}/copilot/follow-up", "post"),
        ("/alerts/{alert_id}/copilot/audits", "get"),
    ],
)
def test_openapi_marks_protected_routes_as_requiring_bearer(path, method):
    spec = app.openapi()

    security = spec["paths"][path][method].get("security")
    assert security == [{"HTTPBearer": []}]


@pytest.mark.parametrize(
    "path,method",
    [
        ("/health", "get"),
        ("/auth/register", "post"),
        ("/auth/login", "post"),
        ("/auth/refresh", "post"),
    ],
)
def test_openapi_does_not_mark_public_routes_as_requiring_bearer(path, method):
    spec = app.openapi()

    assert not spec["paths"][path][method].get("security")
