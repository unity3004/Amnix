"""Integration tests for GET /events/{event_id}/alerts (Step 12Y) -- the
authoritative SecurityEvent -> Alert reverse relationship query. Requires
PostgreSQL.

Mirrors tests/test_alert_cases_api.py's own fixture/helper shape exactly
(same client fixture, same _register_and_login/_create_admin_and_login/
_bearer helpers, same phase-grouped test structure) since this is the
same "authoritative reverse relationship" pattern (Step 12V), one hop
over: Alert <-> Case there, SecurityEvent <-> Alert here. This route
lives in app/api/events.py but returns Alert data through the exact same
AlertService/AlertRead path GET /alerts and GET /alerts/{id} already use.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.security_event import SecurityEvent
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


def _unique_email(prefix: str = "eventalerts") -> str:
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


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": datetime.now(timezone.utc),
        "event_type": "authentication_failure",
        "source": "test-source",
        "raw_data": {},
    }
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _create_alert(client, token, event_ids, **overrides):
    now = datetime.now(timezone.utc).isoformat()
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Test alert",
        "description": "d",
        "severity": "high",
        "confidence": "high",
        "first_seen": now,
        "evidence": {},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    resp = client.post("/alerts", json=payload, headers=_bearer(token))
    assert resp.status_code == 201, resp.text
    return resp


# =============================================================================
# Authentication / authorization
# =============================================================================


def test_requires_authentication(client, db_session):
    event = _make_event(db_session)
    resp = client.get(f"/events/{event.id}/alerts")
    assert resp.status_code == 401


def test_authenticated_analyst_can_list_linked_alerts(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


def test_authenticated_admin_can_list_linked_alerts(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    event = _make_event(db_session)
    _create_alert(client, admin_token, [event.id])

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(admin_token))
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


# =============================================================================
# Resource existence
# =============================================================================


def test_nonexistent_event_returns_404(client, db_session):
    _, token, _ = _register_and_login(client)
    resp = client.get(f"/events/{uuid.uuid4()}/alerts", headers=_bearer(token))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Security event not found"


def test_existing_event_with_zero_linked_alerts_returns_200_empty(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "limit": 50, "offset": 0}


def test_malformed_event_uuid_returns_422(client, db_session):
    _, token, _ = _register_and_login(client)
    resp = client.get("/events/not-a-uuid/alerts", headers=_bearer(token))
    assert resp.status_code == 422


# =============================================================================
# Relationship correctness
# =============================================================================


def test_one_linked_alert(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id], title="The only alert")

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "The only alert"


def test_multiple_linked_alerts_are_all_returned(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id], rule_id="brute_force_authentication", title="Alert A")
    _create_alert(client, token, [event.id], rule_id="suspicious_powershell_execution", title="Alert B")

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    titles = {a["title"] for a in resp.json()["items"]}
    assert titles == {"Alert A", "Alert B"}


def test_relationship_isolation_unrelated_alert_never_returned(client, db_session):
    _, token, _ = _register_and_login(client)
    event_x = _make_event(db_session)
    event_y = _make_event(db_session)
    _create_alert(client, token, [event_x.id], title="Alert for X")
    _create_alert(client, token, [event_y.id], rule_id="suspicious_powershell_execution", title="Alert for Y")

    resp = client.get(f"/events/{event_x.id}/alerts", headers=_bearer(token))
    titles = [a["title"] for a in resp.json()["items"]]
    assert titles == ["Alert for X"]
    assert "Alert for Y" not in titles


def test_alert_linked_to_multiple_events_appears_for_each(client, db_session):
    """The many-to-many relationship allows one Alert to cite multiple
    SecurityEvents -- this must not break the reverse (event -> alert)
    lookup for either event.
    """
    _, token, _ = _register_and_login(client)
    event_a = _make_event(db_session)
    event_b = _make_event(db_session)
    _create_alert(client, token, [event_a.id, event_b.id], title="Shared alert")

    resp_a = client.get(f"/events/{event_a.id}/alerts", headers=_bearer(token))
    resp_b = client.get(f"/events/{event_b.id}/alerts", headers=_bearer(token))
    assert [a["title"] for a in resp_a.json()["items"]] == ["Shared alert"]
    assert [a["title"] for a in resp_b.json()["items"]] == ["Shared alert"]


def test_deterministic_ordering_is_repeatable_across_identical_requests(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id], rule_id="brute_force_authentication", title="First")
    _create_alert(client, token, [event.id], rule_id="suspicious_powershell_execution", title="Second")

    resp1 = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    resp2 = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    assert {a["title"] for a in resp1.json()["items"]} == {"First", "Second"}
    assert resp1.json()["items"] == resp2.json()["items"]


def test_no_duplicate_results_for_a_single_linked_alert(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    items = resp.json()["items"]
    assert len(items) == len({item["id"] for item in items})


# =============================================================================
# Pagination
# =============================================================================


def test_pagination_limit_and_offset(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    for i in range(3):
        _create_alert(client, token, [event.id], rule_id="brute_force_authentication", title=f"alert-{i}")

    page1 = client.get(f"/events/{event.id}/alerts?limit=2&offset=0", headers=_bearer(token))
    page2 = client.get(f"/events/{event.id}/alerts?limit=2&offset=2", headers=_bearer(token))
    assert len(page1.json()["items"]) == 2
    assert len(page2.json()["items"]) == 1
    assert page1.json()["limit"] == 2
    assert page2.json()["offset"] == 2


@pytest.mark.parametrize("limit", [0, 201])
def test_limit_bounds_are_enforced(client, db_session, limit):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    resp = client.get(f"/events/{event.id}/alerts?limit={limit}", headers=_bearer(token))
    assert resp.status_code == 422


def test_negative_offset_is_rejected(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    resp = client.get(f"/events/{event.id}/alerts?offset=-1", headers=_bearer(token))
    assert resp.status_code == 422


def test_offset_beyond_result_set_returns_empty(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])

    resp = client.get(f"/events/{event.id}/alerts?offset=50", headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json()["items"] == []


def test_response_never_includes_a_total(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    assert "total" not in resp.json()


# =============================================================================
# Response schema
# =============================================================================


def test_response_schema_matches_alert_read(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])

    resp = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    item = resp.json()["items"][0]
    expected_keys = {
        "id",
        "rule_id",
        "title",
        "description",
        "severity",
        "confidence",
        "status",
        "first_seen",
        "last_seen",
        "created_at",
        "updated_at",
        "evidence",
        "alert_metadata",
        "source_event_ids",
    }
    assert set(item.keys()) == expected_keys
    # The returned Alert genuinely cites this event -- never a value
    # invented by the endpoint itself.
    assert item["source_event_ids"] == [str(event.id)]


def test_reverse_query_stays_consistent_with_forward_alert_to_event_ids(client, db_session):
    """Both directions read the same alert_security_events rows -- never
    two independently maintained views of the relationship.
    """
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    alert = _create_alert(client, token, [event.id]).json()

    forward = client.get(f"/alerts/{alert['id']}", headers=_bearer(token))
    reverse = client.get(f"/events/{event.id}/alerts", headers=_bearer(token))
    assert forward.json()["source_event_ids"] == [str(event.id)]
    assert reverse.json()["items"][0]["id"] == alert["id"]


# =============================================================================
# IDOR / cross-resource injection
# =============================================================================


def test_alert_id_query_parameter_is_not_accepted_as_a_filter(client, db_session):
    """The event_id in the path is the only resource selector this route
    accepts -- a client cannot inject an arbitrary alert_id through a
    query parameter to widen or redirect the result set. FastAPI ignores
    any query parameter the route signature does not declare, so this
    must return exactly the same result with or without the extra param.
    """
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])
    other_event = _make_event(db_session)
    other_alert = _create_alert(client, token, [other_event.id], rule_id="suspicious_powershell_execution").json()

    resp = client.get(f"/events/{event.id}/alerts?alert_id={other_alert['id']}", headers=_bearer(token))
    assert resp.status_code == 200
    ids = [item["id"] for item in resp.json()["items"]]
    assert other_alert["id"] not in ids


def test_random_alert_id_cannot_be_surfaced_via_random_event_id(client, db_session):
    _, token, _ = _register_and_login(client)
    event = _make_event(db_session)
    _create_alert(client, token, [event.id])

    resp = client.get(f"/events/{uuid.uuid4()}/alerts", headers=_bearer(token))
    assert resp.status_code == 404
