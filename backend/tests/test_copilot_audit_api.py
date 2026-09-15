"""Integration tests for GET /alerts/{alert_id}/copilot/audits (Step
10F.5). Require PostgreSQL. Mirrors test_copilot_api.py's fixture/helper
conventions (self-contained per file, per this codebase's existing
pattern).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.models.copilot_audit import CopilotAudit
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.repositories.copilot_audit import MAX_LIST_LIMIT, CopilotAuditRepository
from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService

pytestmark = pytest.mark.integration

START = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        _authenticate(test_client)
        yield test_client
    app.dependency_overrides.clear()


def _authenticate(test_client: TestClient) -> None:
    """Step 11E: every route this file exercises now requires a Bearer
    access token. Registers + logs in one throwaway test user per test
    client and attaches the resulting access token to every subsequent
    request that client makes, so existing tests keep exercising
    business logic without each one individually managing
    authentication -- see app.api.dependencies.get_current_user.
    """
    email = f"test-client-{uuid.uuid4().hex[:8]}@example.com"
    password = "correct horse battery staple"
    register_response = test_client.post("/auth/register", json={"email": email, "password": password})
    assert register_response.status_code == 201, register_response.text
    login_response = test_client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200, login_response.text
    test_client.headers["Authorization"] = f"Bearer {login_response.json()['access_token']}"


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": START,
        "event_type": "authentication_failure",
        "source": "test",
        "hostname": "WKS-01",
        "username": "jdoe",
        "raw_data": {},
    }
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _create_alert(db_session, event_ids, **overrides):
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Brute force authentication detected for jdoe",
        "description": "5 authentication failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": START.isoformat(),
        "evidence": {"failure_count": 5, "username": "jdoe"},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    service = AlertService(AlertRepository(db_session))
    return service.create(AlertCreate(**payload))


def _seed_audit(db_session, alert_id: uuid.UUID, created_at: datetime, **overrides) -> CopilotAudit:
    defaults = dict(
        alert_id=alert_id,
        request_type="ask",
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome="success",
        validation_status="passed",
        http_status=200,
        question_fingerprint="a" * 64,
        question_length=10,
        history_turn_count=None,
        duration_ms=5,
    )
    defaults.update(overrides)
    audit = CopilotAudit(**defaults)
    audit.created_at = created_at
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)
    return audit


# =============================================================================
# Basic retrieval
# =============================================================================


def test_get_audits_for_alert_with_audits_returns_200(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START)

    response = client.get(f"/alerts/{alert.id}/copilot/audits")

    assert response.status_code == 200
    body = response.json()
    assert len(body["items"]) == 1
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_get_audits_for_alert_with_zero_audits_returns_200_and_empty_items(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.get(f"/alerts/{alert.id}/copilot/audits")

    assert response.status_code == 200
    assert response.json()["items"] == []


def test_get_audits_newest_first_ordering(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    first = _seed_audit(db_session, alert.id, START)
    second = _seed_audit(db_session, alert.id, START + timedelta(milliseconds=1))
    third = _seed_audit(db_session, alert.id, START + timedelta(milliseconds=2))

    response = client.get(f"/alerts/{alert.id}/copilot/audits")

    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [str(third.id), str(second.id), str(first.id)]


# =============================================================================
# Pagination
# =============================================================================


def test_get_audits_limit_bounds_results(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    for i in range(5):
        _seed_audit(db_session, alert.id, START + timedelta(milliseconds=i))

    response = client.get(f"/alerts/{alert.id}/copilot/audits", params={"limit": 2})

    assert len(response.json()["items"]) == 2
    assert response.json()["limit"] == 2


def test_get_audits_offset_skips_results(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    audits = [_seed_audit(db_session, alert.id, START + timedelta(milliseconds=i)) for i in range(3)]
    newest_first_ids = [str(a.id) for a in reversed(audits)]

    response = client.get(f"/alerts/{alert.id}/copilot/audits", params={"limit": 1, "offset": 1})

    assert [item["id"] for item in response.json()["items"]] == newest_first_ids[1:2]
    assert response.json()["offset"] == 1


def test_get_audits_limit_zero_returns_422(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.get(f"/alerts/{alert.id}/copilot/audits", params={"limit": 0})

    assert response.status_code == 422


def test_get_audits_limit_above_max_returns_422(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.get(f"/alerts/{alert.id}/copilot/audits", params={"limit": MAX_LIST_LIMIT + 1})

    assert response.status_code == 422


def test_get_audits_negative_offset_returns_422(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.get(f"/alerts/{alert.id}/copilot/audits", params={"offset": -1})

    assert response.status_code == 422


def test_get_audits_pagination_does_not_cross_alert_boundaries(client, db_session):
    event = _make_event(db_session)
    alert_a = _create_alert(db_session, [event.id])
    alert_b = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert_a.id, START)
    for i in range(3):
        _seed_audit(db_session, alert_b.id, START + timedelta(milliseconds=i))

    response = client.get(f"/alerts/{alert_a.id}/copilot/audits", params={"limit": 200, "offset": 0})

    assert len(response.json()["items"]) == 1
    assert response.json()["items"][0]["alert_id"] == str(alert_a.id)


# =============================================================================
# Alert existence / malformed input
# =============================================================================


def test_get_audits_unknown_alert_returns_404(client):
    response = client.get(f"/alerts/{uuid.uuid4()}/copilot/audits")

    assert response.status_code == 404


def test_get_audits_malformed_uuid_returns_422(client):
    response = client.get("/alerts/not-a-uuid/copilot/audits")

    assert response.status_code == 422


# =============================================================================
# Alert isolation (critical security regression)
# =============================================================================


def test_alert_a_never_sees_alert_bs_audits(client, db_session):
    event = _make_event(db_session)
    alert_a = _create_alert(db_session, [event.id])
    alert_b = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert_b.id, START)
    _seed_audit(db_session, alert_b.id, START + timedelta(milliseconds=1))

    response_a = client.get(f"/alerts/{alert_a.id}/copilot/audits")
    response_b = client.get(f"/alerts/{alert_b.id}/copilot/audits")

    assert response_a.json()["items"] == []
    assert len(response_b.json()["items"]) == 2
    assert all(item["alert_id"] == str(alert_b.id) for item in response_b.json()["items"])


def test_alert_with_zero_audits_returns_empty_even_when_another_alert_has_many(client, db_session):
    event = _make_event(db_session)
    alert_a = _create_alert(db_session, [event.id])
    alert_b = _create_alert(db_session, [event.id])
    for i in range(4):
        _seed_audit(db_session, alert_b.id, START + timedelta(milliseconds=i))

    response = client.get(f"/alerts/{alert_a.id}/copilot/audits")

    assert response.json()["items"] == []


# =============================================================================
# Enum / field integrity, null handling, fingerprint format
# =============================================================================


def test_get_audits_preserves_exact_enum_values(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(
        db_session,
        alert.id,
        START,
        request_type="follow_up",
        outcome="failure",
        validation_status="not_applicable",
        http_status=502,
        history_turn_count=2,
        model_name=None,
    )

    item = client.get(f"/alerts/{alert.id}/copilot/audits").json()["items"][0]

    assert item["request_type"] == "follow_up"
    assert item["outcome"] == "failure"
    assert item["validation_status"] == "not_applicable"
    assert item["http_status"] == 502
    assert item["history_turn_count"] == 2


def test_get_audits_null_model_name_is_preserved_as_json_null(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(
        db_session, alert.id, START, model_name=None, outcome="failure", validation_status="not_applicable", http_status=502
    )

    item = client.get(f"/alerts/{alert.id}/copilot/audits").json()["items"][0]

    assert item["model_name"] is None
    assert item["model_name"] != ""
    assert item["model_name"] != "unknown"
    assert item["model_name"] != "N/A"


def test_get_audits_null_history_turn_count_is_preserved(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START, request_type="ask", history_turn_count=None)

    item = client.get(f"/alerts/{alert.id}/copilot/audits").json()["items"][0]

    assert item["history_turn_count"] is None


def test_get_audits_fingerprint_is_64_char_lowercase_hex(client, db_session):
    import hashlib

    fingerprint = hashlib.sha256(b"deterministic-content").hexdigest()
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START, question_fingerprint=fingerprint)

    item = client.get(f"/alerts/{alert.id}/copilot/audits").json()["items"][0]

    assert item["question_fingerprint"] == fingerprint
    assert len(item["question_fingerprint"]) == 64
    assert item["question_fingerprint"] == item["question_fingerprint"].lower()
    int(item["question_fingerprint"], 16)


def test_get_audits_id_and_alert_id_and_created_at_are_typed_correctly(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    seeded = _seed_audit(db_session, alert.id, START)

    item = client.get(f"/alerts/{alert.id}/copilot/audits").json()["items"][0]

    assert uuid.UUID(item["id"]) == seeded.id
    assert uuid.UUID(item["alert_id"]) == alert.id
    # ISO-8601 with an explicit UTC offset -- not a manually formatted string.
    assert item["created_at"].endswith("Z") or "+00:00" in item["created_at"]


# =============================================================================
# Content-minimization / security regression
# =============================================================================


def test_response_schema_has_only_the_approved_fields():
    from app.schemas.copilot_audit import CopilotAuditResponse

    assert set(CopilotAuditResponse.model_fields) == {
        "id",
        "alert_id",
        "case_id",
        "request_type",
        "provider_name",
        "model_name",
        "outcome",
        "validation_status",
        "http_status",
        "question_fingerprint",
        "question_length",
        "history_turn_count",
        "duration_ms",
        "created_at",
    }


def test_response_schema_forbids_content_fields():
    from app.schemas.copilot_audit import CopilotAuditListResponse, CopilotAuditResponse

    forbidden = {
        "question",
        "history",
        "conversation",
        "answer",
        "response",
        "context",
        "system_instructions",
        "raw_data",
        "event_metadata",
        "alert_metadata",
        "exception",
        "error_detail",
        "secret",
        "api_key",
        "rationale",
    }
    fields = set(CopilotAuditResponse.model_fields) | set(CopilotAuditListResponse.model_fields)
    assert not (fields & forbidden)


def test_get_audits_response_body_never_contains_forbidden_substrings(client, db_session):
    event = _make_event(db_session, command_line="powershell -enc SECRET_MARKER_PAYLOAD")
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START)

    response = client.get(f"/alerts/{alert.id}/copilot/audits")

    body_text = response.text
    for forbidden in ("SECRET_MARKER_PAYLOAD", "system_instructions", "raw_data", "traceback", "api_key"):
        assert forbidden not in body_text


def test_get_does_not_create_audit_rows(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START)
    before = len(CopilotAuditRepository(db_session).list_for_alert(alert.id, limit=MAX_LIST_LIMIT))

    client.get(f"/alerts/{alert.id}/copilot/audits")
    client.get(f"/alerts/{alert.id}/copilot/audits")

    after = len(CopilotAuditRepository(db_session).list_for_alert(alert.id, limit=MAX_LIST_LIMIT))
    assert after == before == 1


def test_get_does_not_mutate_alert(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    _seed_audit(db_session, alert.id, START)
    original_status = alert.status
    original_title = alert.title
    original_updated_at = alert.updated_at

    client.get(f"/alerts/{alert.id}/copilot/audits")

    db_session.refresh(alert)
    assert alert.status == original_status
    assert alert.title == original_title
    assert alert.updated_at == original_updated_at


def test_get_does_not_mutate_audit_rows(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    seeded = _seed_audit(db_session, alert.id, START)

    client.get(f"/alerts/{alert.id}/copilot/audits")

    reloaded = CopilotAuditRepository(db_session).get_by_id(seeded.id)
    assert reloaded.outcome == seeded.outcome
    assert reloaded.created_at == seeded.created_at
    assert reloaded.question_fingerprint == seeded.question_fingerprint


def test_route_handler_does_not_reference_ai_mitre_or_action_internals():
    """Section 26's static check, scoped precisely to the new route
    function's own source (not the whole module, which legitimately
    imports app.ai.* for the pre-existing /copilot routes).
    """
    import inspect

    from app.api.alerts import list_copilot_audits

    source = inspect.getsource(list_copilot_audits)
    forbidden = (
        "app.ai.",
        "AIContext",
        "AIRequest",
        "AIProvider",
        "app.mitre",
        "app.investigation_actions",
        "get_techniques_for_rule",
        "get_candidate_actions",
    )
    for token in forbidden:
        assert token not in source


def test_no_execution_or_network_primitives_in_new_files():
    import pathlib

    forbidden_tokens = (
        "subprocess",
        "os.system",
        "eval(",
        "exec(",
        "shell=True",
        "socket.",
        "urllib",
        "requests.",
        "httpx",
    )
    backend_dir = pathlib.Path(__file__).resolve().parents[1]
    source_files = [
        backend_dir / "app" / "schemas" / "copilot_audit.py",
        backend_dir / "app" / "services" / "copilot_audit_service.py",
        backend_dir / "app" / "repositories" / "copilot_audit.py",
    ]
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in text, f"forbidden primitive '{token}' found in {path}"


# =============================================================================
# Existing /copilot, /copilot/follow-up regression (route-conflict check)
# =============================================================================


def test_existing_post_copilot_still_works_after_adding_audits_route(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "Why?"})

    assert response.status_code == 200
    assert response.json()["alert_id"] == str(alert.id)


def test_existing_post_copilot_follow_up_still_works_after_adding_audits_route(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    response = client.post(
        f"/alerts/{alert.id}/copilot/follow-up", json={"question": "What next?", "history": []}
    )

    assert response.status_code == 200
    assert response.json()["alert_id"] == str(alert.id)


# =============================================================================
# Step 10F.6: end-to-end -- a real POST /copilot(/follow-up) call's audit
# row is what GET /copilot/audits actually returns
# =============================================================================


def test_post_copilot_creates_audit_visible_through_get_audits(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    post_response = client.post(f"/alerts/{alert.id}/copilot", json={"question": "Why was this alert generated?"})
    assert post_response.status_code == 200

    get_response = client.get(f"/alerts/{alert.id}/copilot/audits")
    assert get_response.status_code == 200
    items = get_response.json()["items"]
    assert len(items) == 1
    assert items[0]["request_type"] == "ask"
    assert items[0]["outcome"] == "success"
    assert items[0]["validation_status"] == "passed"
    assert items[0]["http_status"] == 200
    assert items[0]["alert_id"] == str(alert.id)


def test_post_copilot_follow_up_creates_audit_visible_through_get_audits(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    post_response = client.post(
        f"/alerts/{alert.id}/copilot/follow-up",
        json={"question": "What next?", "history": [{"role": "user", "content": "prior turn"}]},
    )
    assert post_response.status_code == 200

    get_response = client.get(f"/alerts/{alert.id}/copilot/audits")
    assert get_response.status_code == 200
    items = get_response.json()["items"]
    assert len(items) == 1
    assert items[0]["request_type"] == "follow_up"
    assert items[0]["outcome"] == "success"
    assert items[0]["validation_status"] == "passed"
    assert items[0]["http_status"] == 200
    assert items[0]["history_turn_count"] == 1
