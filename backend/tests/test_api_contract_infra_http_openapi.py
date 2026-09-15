"""Step 11O: provider/database/Redis failure surfaces, HTTP method and
Content-Type behavior, request-body-limit regression, rate-limit
response safety, OpenAPI contract checks, security-header regression,
and property-style leakage scans. Require PostgreSQL.

Covers brief items 36-55 plus section 31's property-style tests.
"""

import uuid
from datetime import datetime, timezone

import pytest
import redis as redis_lib
from fastapi.testclient import TestClient
from sqlalchemy.exc import OperationalError

from app.ai.factory import get_ai_provider
from app.ai.provider import AIProvider
from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.user import User
from app.schemas.ai import AIRequest, AIResponse

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


def _unique_email(prefix: str = "infra") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client) -> str:
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    return login.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def _make_alert(db_session, **overrides):
    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent
    from app.repositories.alert import AlertRepository

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="t", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    events = AlertRepository(db_session).get_security_events_by_ids([event.id])
    now = datetime.now(timezone.utc)
    defaults = {
        "rule_id": "brute_force_authentication", "title": "t", "description": "d", "severity": "high",
        "confidence": "high", "first_seen": now, "last_seen": now, "evidence": {}, "security_events": events,
    }
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


# =============================================================================
# 36-38. Provider failure surface
# =============================================================================


class _TransportFailingProvider(AIProvider):
    @property
    def name(self) -> str:
        return "transport-failing-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        raise RuntimeError("simulated connection reset to 10.0.5.9:443 with api_key=sk-ant-FAKE-SECRET-VALUE")


class _MalformedOutputProvider(AIProvider):
    @property
    def name(self) -> str:
        return "malformed-output-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        return AIResponse(content="not valid json at all", provider=self.name, model="test-model", usage=None)


def test_provider_transport_failure_is_safe_502(client, db_session):
    alert = _make_alert(db_session)
    token = _register_and_login(client)
    app.dependency_overrides[get_ai_provider] = lambda: _TransportFailingProvider()
    try:
        response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "What happened?"}, headers=_bearer(token))
    finally:
        del app.dependency_overrides[get_ai_provider]

    assert response.status_code == 502
    assert "sk-ant-FAKE-SECRET-VALUE" not in response.text
    assert "10.0.5.9" not in response.text
    assert "RuntimeError" not in response.text
    assert response.json() == {"detail": "The AI provider failed to generate a response."}


def test_provider_validation_failure_is_safe_502(client, db_session):
    alert = _make_alert(db_session)
    token = _register_and_login(client)
    app.dependency_overrides[get_ai_provider] = lambda: _MalformedOutputProvider()
    try:
        response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "What happened?"}, headers=_bearer(token))
    finally:
        del app.dependency_overrides[get_ai_provider]

    assert response.status_code == 502
    assert "not valid json at all" not in response.text
    assert response.json() == {"detail": "The AI provider returned a response that did not match the expected schema."}


def test_malformed_provider_output_on_follow_up_is_safe(client, db_session):
    alert = _make_alert(db_session)
    token = _register_and_login(client)
    app.dependency_overrides[get_ai_provider] = lambda: _MalformedOutputProvider()
    try:
        response = client.post(
            f"/alerts/{alert.id}/copilot/follow-up", json={"question": "And then?", "history": []}, headers=_bearer(token)
        )
    finally:
        del app.dependency_overrides[get_ai_provider]

    assert response.status_code == 502
    assert "not valid json at all" not in response.text


# =============================================================================
# 39. Database exception leakage
# =============================================================================


class _BrokenSession:
    """A session double whose every read operation raises a realistic
    SQLAlchemy OperationalError carrying fake-but-realistic sensitive
    connection/SQL detail -- proves that detail never reaches the HTTP
    response, regardless of whether it would ever really appear in a
    genuine Postgres outage.
    """

    def get(self, *args, **kwargs):
        raise OperationalError(
            "SELECT * FROM security_events WHERE id = %(id)s",
            {"id": "..."},
            Exception('connection to server at "10.0.0.55", port 5432 failed: FATAL: password authentication failed for user "amnix_prod"'),
        )

    def __getattr__(self, name):
        def _raise(*args, **kwargs):
            raise OperationalError("<simulated>", {}, Exception("simulated database outage"))
        return _raise


def test_simulated_db_exception_does_not_leak_sql_or_connection_details(client, db_session):
    """A genuinely unhandled DB exception must degrade to a safe generic
    500, never a raw SQL/connection-detail response -- see this file's
    module docstring. Uses raise_server_exceptions=False (matching how
    a real ASGI server behaves) since the default TestClient re-raises
    server-side exceptions into the test process rather than converting
    them to a response, which would defeat the point of this test.
    """
    token = _register_and_login(client)

    def _broken_get_db():
        yield _BrokenSession()

    app.dependency_overrides[get_db] = _broken_get_db
    try:
        with TestClient(app, raise_server_exceptions=False) as unsafe_client:
            response = unsafe_client.get(f"/events/{uuid.uuid4()}", headers=_bearer(token))
    finally:
        app.dependency_overrides[get_db] = lambda: (yield db_session)

    assert response.status_code == 500
    assert "10.0.0.55" not in response.text
    assert "password authentication failed" not in response.text
    assert "SELECT" not in response.text
    assert "amnix_prod" not in response.text
    assert "Traceback" not in response.text


# =============================================================================
# 40. Redis exception leakage (login rate limiter)
# =============================================================================


def test_simulated_redis_failure_does_not_leak_redis_details(client, monkeypatch):
    import app.api.dependencies as dependencies_module

    broken_client = redis_lib.Redis(host="127.0.0.1", port=1, socket_connect_timeout=0.2, socket_timeout=0.2)
    monkeypatch.setattr(dependencies_module, "get_redis_client", lambda: broken_client)

    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})

    # Fails open -- login still succeeds, and nothing about Redis leaks
    assert response.status_code == 200
    assert "127.0.0.1:1" not in response.text
    assert "redis" not in response.text.lower()
    assert "ConnectionError" not in response.text


# =============================================================================
# 41-43. HTTP method / Content-Type / malformed JSON
# =============================================================================


def test_unsupported_method_does_not_execute_endpoint(client, db_session):
    alert = _make_alert(db_session)
    token = _register_and_login(client)
    before = client.get(f"/alerts/{alert.id}", headers=_bearer(token)).json()

    response = client.delete(f"/alerts/{alert.id}", headers=_bearer(token))
    assert response.status_code == 405

    after = client.get(f"/alerts/{alert.id}", headers=_bearer(token)).json()
    assert before == after


def test_put_on_get_only_health_is_405(client):
    response = client.put("/health")
    assert response.status_code == 405


def test_wrong_content_type_fails_safely_not_500(client):
    response = client.post(
        "/events", content=b'{"event_type":"x"}', headers={"Content-Type": "text/plain", **_auth_or_empty(client)}
    )
    assert response.status_code in (401, 422)


def test_malformed_json_fails_safely_not_500(client):
    response = client.post("/auth/login", content=b"{bad json", headers={"Content-Type": "application/json"})
    assert response.status_code == 422


def _auth_or_empty(client) -> dict:
    return _bearer(_register_and_login(client))


# =============================================================================
# 44-46. Rate limit response
# =============================================================================


def test_login_rate_limit_returns_429_with_retry_after(client, monkeypatch):
    from app.api.dependencies import enforce_login_rate_limit
    from app.core.config import get_settings

    # Remove the autouse global bypass for this one test, matching
    # tests/test_rate_limit.py's own established pattern.
    app.dependency_overrides.pop(enforce_login_rate_limit, None)
    settings = get_settings()
    email = _unique_email()
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})

    last_response = None
    for _ in range(settings.login_rate_limit_max_attempts + 2):
        last_response = client.post("/auth/login", json={"email": email, "password": "wrong"})
        if last_response.status_code == 429:
            break

    assert last_response.status_code == 429
    assert "Retry-After" in last_response.headers
    assert int(last_response.headers["Retry-After"]) > 0
    assert last_response.json() == {"detail": "Too many login attempts. Please try again later."}
    assert "redis" not in last_response.text.lower()


# =============================================================================
# 47-49. Body-size limit regression (Step 11I)
# =============================================================================


def test_oversized_content_length_request_is_413(client):
    from app.core.config import get_settings

    settings = get_settings()
    oversized = b"x" * (settings.max_request_body_bytes + 1)
    response = client.post(
        "/events", content=oversized, headers={"Content-Type": "application/json", "Content-Length": str(len(oversized))}
    )
    assert response.status_code == 413


def test_413_response_does_not_echo_body(client):
    from app.core.config import get_settings

    settings = get_settings()
    oversized = b'{"secret_marker": "' + b"A" * settings.max_request_body_bytes + b'"}'
    response = client.post("/events", content=oversized)
    assert response.status_code == 413
    assert b"A" * 100 not in response.content
    assert response.json() == {"detail": "Request body too large."}


# =============================================================================
# 50-53. OpenAPI contract
# =============================================================================


def test_all_protected_routes_carry_bearer_security_metadata():
    spec = app.openapi()
    public = {("/health", "get"), ("/auth/register", "post"), ("/auth/login", "post"), ("/auth/refresh", "post")}
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            if method not in ("get", "post", "patch", "put", "delete"):
                continue
            if (path, method) in public:
                continue
            assert operation.get("security") == [{"HTTPBearer": []}], f"{method} {path} missing bearer security"


def test_admin_routes_documented_and_protected():
    spec = app.openapi()
    for path in ("/admin/users/{user_id}/status", "/admin/audits"):
        assert path in spec["paths"]


def test_public_routes_remain_public_in_openapi():
    spec = app.openapi()
    for path, method in [("/health", "get"), ("/auth/register", "post"), ("/auth/login", "post"), ("/auth/refresh", "post")]:
        assert not spec["paths"][path][method].get("security")


def test_user_read_response_schema_has_no_password_field():
    spec = app.openapi()
    user_read_schema = spec["components"]["schemas"]["UserRead"]
    assert "password" not in user_read_schema["properties"]
    assert "password_hash" not in user_read_schema["properties"]


def test_copilot_audit_response_schema_matches_intended_public_fields():
    spec = app.openapi()
    schema = spec["components"]["schemas"]["CopilotAuditResponse"]
    assert set(schema["properties"].keys()) == {
        "id", "alert_id", "case_id", "request_type", "provider_name", "model_name", "outcome", "validation_status",
        "http_status", "question_fingerprint", "question_length", "history_turn_count", "duration_ms", "created_at",
    }


# =============================================================================
# 54-55. Security header regression
# =============================================================================


def _assert_security_headers_present(response):
    assert response.headers.get("x-content-type-options") == "nosniff"
    assert response.headers.get("x-frame-options") == "DENY"
    assert response.headers.get("referrer-policy") == "no-referrer"


def test_normal_response_has_security_headers(client):
    response = client.get("/health")
    assert response.status_code == 200
    _assert_security_headers_present(response)


def test_401_response_has_security_headers(client):
    response = client.get(f"/events/{uuid.uuid4()}")
    assert response.status_code == 401
    _assert_security_headers_present(response)


def test_403_response_has_security_headers(client):
    token = _register_and_login(client)
    response = client.get("/admin/audits", headers=_bearer(token))
    assert response.status_code == 403
    _assert_security_headers_present(response)


def test_404_response_has_security_headers(client):
    token = _register_and_login(client)
    response = client.get(f"/alerts/{uuid.uuid4()}", headers=_bearer(token))
    assert response.status_code == 404
    _assert_security_headers_present(response)


def test_422_response_has_security_headers(client):
    response = client.post("/auth/login", json={"email": "a@example.com"})
    assert response.status_code == 422
    _assert_security_headers_present(response)


def test_502_response_has_security_headers(client, db_session):
    alert = _make_alert(db_session)
    token = _register_and_login(client)
    app.dependency_overrides[get_ai_provider] = lambda: _TransportFailingProvider()
    try:
        response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "?"}, headers=_bearer(token))
    finally:
        del app.dependency_overrides[get_ai_provider]
    assert response.status_code == 502
    _assert_security_headers_present(response)


# =============================================================================
# Section 31: property-style leakage checks across a battery of responses
# =============================================================================


_FORBIDDEN_SUBSTRINGS = [
    "password_hash",
    "$argon2",
    "JWT_SECRET",
    "sk-ant-",
    "Traceback (most recent call last)",
    "postgresql+psycopg://",
    "redis://",
]


@pytest.mark.parametrize(
    "make_response",
    [
        lambda c, db: c.post("/auth/login", json={"email": "nonexistent@example.com", "password": "wrong"}),
        lambda c, db: c.get(f"/events/{uuid.uuid4()}"),
        lambda c, db: c.get("/admin/audits"),
        lambda c, db: c.post("/auth/register", json={"email": "bad", "password": "x" * 200}),
    ],
)
def test_no_forbidden_secret_material_in_response_body(client, db_session, make_response):
    response = make_response(client, db_session)
    for forbidden in _FORBIDDEN_SUBSTRINGS:
        assert forbidden not in response.text
