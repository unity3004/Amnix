"""Integration tests for GET /alerts/{alert_id}/cases (Step 12V) --
the authoritative Alert -> Case reverse relationship query Step 12U's
discovery found missing. Require PostgreSQL.

Mirrors tests/test_case_api.py's own fixture/helper shape exactly (same
client fixture, same _register_and_login/_create_admin_and_login/
_bearer/_make_alert helpers) since this route lives in app/api/alerts.py
but returns Case data through the exact same CaseService/CaseRead path
GET /cases and GET /cases/{id} already use.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.core.security import hash_password
from app.main import app
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository

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


def _unique_email(prefix: str = "alertcases") -> str:
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


def _make_alert(db_session, **overrides) -> Alert:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="test", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="API test alert",
        description="d",
        severity="high",
        confidence="high",
        status="new",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    defaults.update(overrides)
    return AlertRepository(db_session).create(Alert(**defaults))


def _create_case(client, token, **overrides):
    payload = {"title": "Test case", "description": "A test case description."}
    payload.update(overrides)
    return client.post("/cases", json=payload, headers=_bearer(token))


def _link(client, token, case_id, alert_id):
    resp = client.post(f"/cases/{case_id}/alerts", json={"alert_id": alert_id}, headers=_bearer(token))
    assert resp.status_code == 201, resp.text
    return resp


# =============================================================================
# Authentication / authorization
# =============================================================================


def test_requires_authentication(client, db_session):
    alert = _make_alert(db_session)
    resp = client.get(f"/alerts/{alert.id}/cases")
    assert resp.status_code == 401


def test_authenticated_analyst_can_list_linked_cases(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case_resp = _create_case(client, token)
    _link(client, token, case_resp.json()["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


def test_authenticated_admin_can_list_linked_cases(client, db_session):
    _, admin_token, _ = _create_admin_and_login(client, db_session)
    alert = _make_alert(db_session)
    case_resp = _create_case(client, admin_token)
    _link(client, admin_token, case_resp.json()["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(admin_token))
    assert resp.status_code == 200
    assert len(resp.json()["items"]) == 1


# =============================================================================
# Resource existence (Phase 8)
# =============================================================================


def test_nonexistent_alert_returns_404(client, db_session):
    _, token, _ = _register_and_login(client)
    resp = client.get(f"/alerts/{uuid.uuid4()}/cases", headers=_bearer(token))
    assert resp.status_code == 404
    assert resp.json()["detail"] == "Alert not found"


def test_existing_alert_with_zero_linked_cases_returns_200_empty(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json() == {"items": [], "limit": 50, "offset": 0}


def test_malformed_alert_uuid_returns_422(client, db_session):
    _, token, _ = _register_and_login(client)
    resp = client.get("/alerts/not-a-uuid/cases", headers=_bearer(token))
    assert resp.status_code == 422


# =============================================================================
# Relationship correctness (Phase 4/13)
# =============================================================================


def test_one_linked_case(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case_resp = _create_case(client, token, title="The only case")
    _link(client, token, case_resp.json()["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    items = resp.json()["items"]
    assert len(items) == 1
    assert items[0]["title"] == "The only case"


def test_multiple_linked_cases_are_all_returned(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case_a = _create_case(client, token, title="Case A").json()
    case_b = _create_case(client, token, title="Case B").json()
    _link(client, token, case_a["id"], str(alert.id))
    _link(client, token, case_b["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    titles = {c["title"] for c in resp.json()["items"]}
    assert titles == {"Case A", "Case B"}


def test_relationship_isolation_unrelated_case_never_returned(client, db_session):
    _, token, _ = _register_and_login(client)
    alert_x = _make_alert(db_session, title="alert x")
    alert_y = _make_alert(db_session, title="alert y")
    case_for_x = _create_case(client, token, title="Case for X").json()
    case_for_y = _create_case(client, token, title="Case for Y").json()
    _link(client, token, case_for_x["id"], str(alert_x.id))
    _link(client, token, case_for_y["id"], str(alert_y.id))

    resp = client.get(f"/alerts/{alert_x.id}/cases", headers=_bearer(token))
    titles = [c["title"] for c in resp.json()["items"]]
    assert titles == ["Case for X"]
    assert "Case for Y" not in titles


def test_deterministic_ordering_is_repeatable_across_identical_requests(client, db_session):
    """The exact ordering RULE (linked_at DESC, Case.id DESC) is proven
    at the repository level with explicit, distinct linked_at values
    (test_list_cases_for_alert_returns_only_linked_cases_newest_link_first)
    -- server_default=func.now() resolves to this whole test's single
    transaction start time (Postgres transaction_timestamp() semantics),
    so two links made back-to-back through this HTTP client share an
    identical linked_at here regardless of real-world elapsed time. What
    THIS test can genuinely prove end-to-end is determinism: the same
    request issued twice must return items in the same order both times,
    never a query with no stable ORDER BY that could reshuffle rows
    arbitrarily between calls.
    """
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case_a = _create_case(client, token, title="Linked first").json()
    case_b = _create_case(client, token, title="Linked second").json()
    _link(client, token, case_a["id"], str(alert.id))
    _link(client, token, case_b["id"], str(alert.id))

    resp1 = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    resp2 = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert {c["title"] for c in resp1.json()["items"]} == {"Linked first", "Linked second"}
    assert resp1.json()["items"] == resp2.json()["items"]


# =============================================================================
# Pagination (Phase 9)
# =============================================================================


def test_pagination_limit_and_offset(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    for i in range(3):
        case = _create_case(client, token, title=f"case-{i}").json()
        _link(client, token, case["id"], str(alert.id))

    page1 = client.get(f"/alerts/{alert.id}/cases?limit=2&offset=0", headers=_bearer(token))
    page2 = client.get(f"/alerts/{alert.id}/cases?limit=2&offset=2", headers=_bearer(token))
    assert len(page1.json()["items"]) == 2
    assert len(page2.json()["items"]) == 1
    assert page1.json()["limit"] == 2
    assert page2.json()["offset"] == 2


@pytest.mark.parametrize("limit", [0, 201])
def test_limit_bounds_are_enforced(client, db_session, limit):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    resp = client.get(f"/alerts/{alert.id}/cases?limit={limit}", headers=_bearer(token))
    assert resp.status_code == 422


def test_negative_offset_is_rejected(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    resp = client.get(f"/alerts/{alert.id}/cases?offset=-1", headers=_bearer(token))
    assert resp.status_code == 422


def test_offset_beyond_result_set_returns_empty(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases?offset=50", headers=_bearer(token))
    assert resp.status_code == 200
    assert resp.json()["items"] == []


def test_response_never_includes_a_total(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert "total" not in resp.json()


# =============================================================================
# Response schema (Phase 3)
# =============================================================================


def test_response_schema_matches_case_read(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    item = resp.json()["items"][0]
    expected_keys = {
        "id",
        "case_number",
        "title",
        "description",
        "status",
        "priority",
        "severity",
        "created_at",
        "updated_at",
        "created_by",
        "owner_id",
        "closed_at",
        "closure_reason",
    }
    assert set(item.keys()) == expected_keys
    # Severity is derived from the actual linked alert (high), never a
    # stored/invented value.
    assert item["severity"] == "high"


# =============================================================================
# Link/unlink lifecycle (Phase 18/19/21)
# =============================================================================


def test_duplicate_link_attempt_does_not_produce_a_duplicate_relationship_result(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))

    dup_resp = client.post(f"/cases/{case['id']}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))
    assert dup_resp.status_code == 409

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert len(resp.json()["items"]) == 1


def test_unlink_removes_the_relationship(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))
    assert len(client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token)).json()["items"]) == 1

    unlink_resp = client.delete(f"/cases/{case['id']}/alerts/{alert.id}", headers=_bearer(token))
    assert unlink_resp.status_code == 204

    resp = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert resp.json()["items"] == []


def test_reverse_query_stays_consistent_with_forward_case_to_alert_query(client, db_session):
    """Both directions read the same case_alerts rows -- never two
    independently maintained views of the relationship.
    """
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))

    forward = client.get(f"/cases/{case['id']}/alerts", headers=_bearer(token))
    reverse = client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    assert forward.json()["items"][0]["id"] == str(alert.id)
    assert reverse.json()["items"][0]["id"] == case["id"]


# =============================================================================
# Audit semantics (Phase 10)
# =============================================================================


def test_viewing_linked_cases_creates_no_audit_entry(client, db_session):
    _, token, _ = _register_and_login(client)
    alert = _make_alert(db_session)
    case = _create_case(client, token).json()
    _link(client, token, case["id"], str(alert.id))

    audit_before = client.get(f"/cases/{case['id']}/audit", headers=_bearer(token)).json()["items"]

    client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))
    client.get(f"/alerts/{alert.id}/cases", headers=_bearer(token))

    audit_after = client.get(f"/cases/{case['id']}/audit", headers=_bearer(token)).json()["items"]
    assert audit_after == audit_before
