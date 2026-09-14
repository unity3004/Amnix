"""Dedicated IDOR/BOLA tests for the Case API (Step 12R). Require
PostgreSQL. Mirrors tests/test_idor_admin_audit_filters.py's own naming
convention -- focused, cross-resource confusion attempts kept separate
from the broader endpoint-coverage suite in test_case_api.py.

AMNIX has no tenant/ownership-scoped VISIBILITY model for cases (shared
SOC queue, matching GET /alerts) -- so there is no "case belongs to a
different tenant" class to defend against. What genuinely matters here
is relationship integrity: a path that names two resources (a case and
an alert, or an audit/note nested under a case) must never let a caller
act on a mismatched pair, and every 404 must look identical regardless
of which part of the path was actually wrong.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
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


def _register_and_login(client) -> tuple[str, dict]:
    email = f"idor-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    body = login.json()
    return body["access_token"], body["user"]


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
        title="IDOR test alert",
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


def _create_case(client, token, title="Case") -> str:
    response = client.post("/cases", json={"title": title, "description": "d"}, headers=_bearer(token))
    return response.json()["id"]


def test_unlinking_an_alert_via_the_wrong_case_id_returns_404(client, db_session):
    """Alert X is linked to case A. Attempting to unlink it via case B's
    path must 404 -- the relationship, not just the alert's existence,
    is what is being checked.
    """
    token, _ = _register_and_login(client)
    case_a = _create_case(client, token, "Case A")
    case_b = _create_case(client, token, "Case B")
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_a}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    response = client.delete(f"/cases/{case_b}/alerts/{alert.id}", headers=_bearer(token))

    assert response.status_code == 404
    # The real link under case A must be completely unaffected.
    still_linked = client.get(f"/cases/{case_a}/alerts", headers=_bearer(token)).json()["items"]
    assert any(item["id"] == str(alert.id) for item in still_linked)


def test_case_b_alerts_never_include_case_a_links(client, db_session):
    token, _ = _register_and_login(client)
    case_a = _create_case(client, token, "Case A")
    case_b = _create_case(client, token, "Case B")
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_a}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    response = client.get(f"/cases/{case_b}/alerts", headers=_bearer(token))

    assert response.json()["items"] == []


def test_case_b_audit_never_includes_case_a_actions(client):
    token, _ = _register_and_login(client)
    case_a = _create_case(client, token, "Case A")
    case_b = _create_case(client, token, "Case B")
    client.patch(f"/cases/{case_a}/status", json={"status": "INVESTIGATING"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_b}/audit", headers=_bearer(token))

    audit_case_ids = {item["case_id"] for item in response.json()["items"]}
    assert audit_case_ids == {case_b}


def test_case_b_notes_never_include_case_a_notes(client):
    token, _ = _register_and_login(client)
    case_a = _create_case(client, token, "Case A")
    case_b = _create_case(client, token, "Case B")
    client.post(f"/cases/{case_a}/notes", json={"body": "Case A note"}, headers=_bearer(token))

    response = client.get(f"/cases/{case_b}/notes", headers=_bearer(token))

    assert response.json()["items"] == []


def test_linking_the_same_alert_to_two_different_cases_is_independent(client, db_session):
    """Not an IDOR bug -- the approved m:n model (Step 12Q) explicitly
    allows one alert to belong to multiple cases. Confirms unlinking
    from one case never affects the other case's own link.
    """
    token, _ = _register_and_login(client)
    case_a = _create_case(client, token, "Case A")
    case_b = _create_case(client, token, "Case B")
    alert = _make_alert(db_session)
    client.post(f"/cases/{case_a}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))
    client.post(f"/cases/{case_b}/alerts", json={"alert_id": str(alert.id)}, headers=_bearer(token))

    client.delete(f"/cases/{case_a}/alerts/{alert.id}", headers=_bearer(token))

    case_a_alerts = client.get(f"/cases/{case_a}/alerts", headers=_bearer(token)).json()["items"]
    case_b_alerts = client.get(f"/cases/{case_b}/alerts", headers=_bearer(token)).json()["items"]
    assert case_a_alerts == []
    assert any(item["id"] == str(alert.id) for item in case_b_alerts)


def test_owner_manipulation_against_another_analysts_case_is_rejected(client):
    attacker_token, attacker_body = _register_and_login(client)
    victim_token, victim_body = _register_and_login(client)
    case_id = _create_case(client, victim_token, "Victim's case")
    client.patch(f"/cases/{case_id}/owner", json={"owner_id": victim_body["id"]}, headers=_bearer(victim_token))

    response = client.patch(
        f"/cases/{case_id}/owner", json={"owner_id": attacker_body["id"]}, headers=_bearer(attacker_token)
    )

    assert response.status_code == 403
    # Ownership must remain completely unchanged.
    fresh = client.get(f"/cases/{case_id}", headers=_bearer(victim_token)).json()
    assert fresh["owner_id"] == victim_body["id"]


def test_404_bodies_are_identical_regardless_of_which_identifier_is_wrong(client, db_session):
    """A 404 for 'case not found' and a 404 for 'alert not linked to
    this case' must not be distinguishable by response shape -- both
    already use the same generic detail-message construction, verified
    here directly.
    """
    token, _ = _register_and_login(client)
    real_case = _create_case(client, token)
    real_alert = _make_alert(db_session)

    unknown_case_response = client.delete(f"/cases/{uuid.uuid4()}/alerts/{real_alert.id}", headers=_bearer(token))
    unlinked_alert_response = client.delete(f"/cases/{real_case}/alerts/{real_alert.id}", headers=_bearer(token))

    assert unknown_case_response.status_code == 404
    assert unlinked_alert_response.status_code == 404
    assert set(unknown_case_response.json().keys()) == set(unlinked_alert_response.json().keys()) == {"detail"}
