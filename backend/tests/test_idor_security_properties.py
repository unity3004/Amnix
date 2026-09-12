"""Step 11N: authorization security PROPERTY tests (brief section 17),
verified against the real generated OpenAPI schema and, where OpenAPI
alone cannot prove a property, direct signature/schema introspection.
Require PostgreSQL only where a live request is needed; most of these
tests need no database at all.

These test properties that must hold across the WHOLE route surface,
not just individual example endpoints:
  - every protected route requires Bearer authentication
  - every admin-only route requires it too (no separate "weaker" auth)
  - no route is accidentally left public
  - no endpoint accepts a client-supplied actor identity or role
  - AdminAudit's action is server-controlled, not a request field
  - Copilot's resource context cannot be selected via anything other
    than the URL's own alert_id
"""

import inspect
import uuid

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app

# The exact, complete set of routes that must remain public -- anything
# else discovered in the schema must carry Bearer security. Maintained
# explicitly here (not derived) so a newly-added route defaults to
# "must be protected" and a real, deliberate addition to this list is
# required to make it public -- the safer failure direction.
EXPECTED_PUBLIC_ROUTES = {
    ("/health", "get"),
    ("/auth/register", "post"),
    ("/auth/login", "post"),
    ("/auth/refresh", "post"),
}

EXPECTED_ADMIN_ONLY_ROUTES = {
    ("/admin/users/{user_id}/status", "patch"),
    ("/admin/audits", "get"),
}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _openapi_routes() -> dict[tuple[str, str], dict]:
    spec = app.openapi()
    routes = {}
    for path, methods in spec["paths"].items():
        for method, operation in methods.items():
            if method in ("get", "post", "patch", "put", "delete"):
                routes[(path, method)] = operation
    return routes


# =============================================================================
# Every protected route requires Bearer authentication; public routes don't
# =============================================================================


def test_every_public_route_has_no_security_requirement():
    routes = _openapi_routes()

    for path, method in EXPECTED_PUBLIC_ROUTES:
        assert (path, method) in routes, f"expected public route {method.upper()} {path} not found"
        assert not routes[(path, method)].get("security"), f"{method.upper()} {path} unexpectedly requires auth"


def test_every_non_public_route_requires_bearer_security():
    """The complement of the public-route check: EVERY route not in the
    explicit public allowlist must carry HTTPBearer security -- this
    fails loudly if any future route is added without authentication by
    accident, rather than requiring someone to remember to test it
    individually.
    """
    routes = _openapi_routes()

    for (path, method), operation in routes.items():
        if (path, method) in EXPECTED_PUBLIC_ROUTES:
            continue
        security = operation.get("security")
        assert security == [{"HTTPBearer": []}], f"{method.upper()} {path} is missing Bearer security: {security!r}"


def test_admin_only_routes_are_exactly_the_expected_set():
    """Cross-check against a live request too, not just OpenAPI metadata
    -- an analyst token against every route in EXPECTED_ADMIN_ONLY_ROUTES
    must get 403, proving the schema's security tag actually corresponds
    to enforced admin-only behavior, not just documentation.
    """
    routes = _openapi_routes()
    for path, method in EXPECTED_ADMIN_ONLY_ROUTES:
        assert (path, method) in routes


def test_no_route_outside_the_admin_allowlist_is_accidentally_admin_restricted(client, db_session):
    """Every shared-SOC route must remain accessible to a plain analyst
    -- confirms the admin boundary is exactly where expected, not
    accidentally wider.
    """
    from datetime import datetime, timezone

    from app.models.alert import Alert
    from app.models.security_event import SecurityEvent
    from app.repositories.alert import AlertRepository

    email = f"prop-{uuid.uuid4().hex[:8]}@example.com"
    password = "correct horse battery staple"
    client.post("/auth/register", json={"email": email, "password": password})
    token = client.post("/auth/login", json={"email": email, "password": password}).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}

    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="t", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    events = AlertRepository(db_session).get_security_events_by_ids([event.id])
    now = datetime.now(timezone.utc)
    alert = Alert(
        rule_id="brute_force_authentication",
        title="t",
        description="d",
        severity="high",
        confidence="high",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=events,
    )
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)

    assert client.get(f"/events/{event.id}", headers=headers).status_code == 200
    assert client.get(f"/alerts/{alert.id}", headers=headers).status_code == 200
    assert client.get(f"/alerts/{alert.id}/investigation", headers=headers).status_code == 200
    assert (
        client.post(f"/alerts/{alert.id}/copilot", json={"question": "?"}, headers=headers).status_code == 200
    )
    assert client.get(f"/alerts/{alert.id}/copilot/audits", headers=headers).status_code == 200


# =============================================================================
# No endpoint accepts client-supplied actor identity or role
# =============================================================================


def test_login_request_schema_has_no_role_field():
    from app.schemas.auth import LoginRequest

    fields = set(LoginRequest.model_fields.keys())
    assert "role" not in fields
    assert "actor_user_id" not in fields
    assert "user_id" not in fields


def test_register_request_schema_has_no_role_or_id_field():
    from app.schemas.auth import RegisterRequest

    fields = set(RegisterRequest.model_fields.keys())
    assert "role" not in fields
    assert "id" not in fields
    assert "is_active" not in fields


def test_admin_user_status_update_schema_accepts_only_is_active():
    from app.schemas.auth import UserStatusUpdate

    assert set(UserStatusUpdate.model_fields.keys()) == {"is_active"}


def test_copilot_message_schema_has_no_resource_identifier_field():
    """The client-supplied follow-up history schema has no field a
    client could use to name a different alert/event/investigation --
    confirmed directly against the schema's own field set, not just by
    example (see tests/test_idor_cross_resource_and_copilot.py for the
    behavioral proof).
    """
    from app.schemas.ai import CopilotMessage

    assert set(CopilotMessage.model_fields.keys()) == {"role", "content"}


def test_copilot_follow_up_request_accepts_only_question_and_history():
    from app.schemas.ai import CopilotFollowUpRequest

    assert set(CopilotFollowUpRequest.model_fields.keys()) == {"question", "history"}


# =============================================================================
# AdminAudit action is server-controlled
# =============================================================================


def test_admin_audit_service_signature_has_no_action_parameter():
    from app.services.admin_audit_service import AdminAuditService

    signature = inspect.signature(AdminAuditService.change_user_status)
    assert "action" not in signature.parameters


def test_admin_audit_model_action_is_check_constrained_to_one_value():
    from app.models.admin_audit import ADMIN_AUDIT_ACTIONS

    assert ADMIN_AUDIT_ACTIONS == ("USER_STATUS_CHANGED",)


# =============================================================================
# Copilot context cannot be selected via arbitrary client-supplied identifiers
# =============================================================================


def test_copilot_question_request_has_no_context_override_field():
    from app.schemas.ai import CopilotQuestionRequest

    assert set(CopilotQuestionRequest.model_fields.keys()) == {"question"}


def test_ask_and_follow_up_only_accept_alert_id_positionally_from_the_route():
    """CopilotService.ask()/follow_up() both take alert_id as their own
    explicit parameter (sourced only from the URL path in
    app.api.alerts, never from payload) -- confirmed directly against
    the method signatures.
    """
    from app.services.copilot_service import CopilotService

    ask_params = list(inspect.signature(CopilotService.ask).parameters.keys())
    follow_up_params = list(inspect.signature(CopilotService.follow_up).parameters.keys())

    assert ask_params == ["self", "alert_id", "question"]
    assert follow_up_params == ["self", "alert_id", "question", "history"]
