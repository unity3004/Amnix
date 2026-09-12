"""Dashboard Data Foundation: integration tests for GET /alerts. Require
PostgreSQL.

Covers the approved test plan: authentication, RBAC, empty/one/many
results, newest-first ordering, status/severity/rule_id/since/until
filters (individually and combined), pagination bounds, invalid
enum/datetime handling, and bounded-query behavior.
"""

import uuid
from datetime import datetime, timedelta, timezone

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


def _unique_email(prefix: str = "alertslist") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8]}@example.com"


def _register_and_login(client, *, password: str = VALID_PASSWORD) -> str:
    email = _unique_email()
    register_response = client.post("/auth/register", json={"email": email, "password": password})
    assert register_response.status_code == 201, register_response.text
    login_response = client.post("/auth/login", json={"email": email, "password": password})
    assert login_response.status_code == 200, login_response.text
    return login_response.json()["access_token"]


def _create_admin_and_login(client, db_session) -> str:
    email = _unique_email("admin")
    admin_user = User(email=email, password_hash=hash_password(VALID_PASSWORD), role="admin")
    db_session.add(admin_user)
    db_session.commit()
    login_response = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    assert login_response.status_code == 200, login_response.text
    return login_response.json()["access_token"]


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


def _make_alert(db_session, event_ids=None, **overrides) -> Alert:
    now = datetime.now(timezone.utc)
    events = AlertRepository(db_session).get_security_events_by_ids(event_ids or [_make_event(db_session).id])
    defaults = {
        "rule_id": "brute_force_authentication",
        "title": "Test alert",
        "description": "d",
        "severity": "high",
        "confidence": "high",
        "status": "new",
        "first_seen": now,
        "last_seen": now,
        "evidence": {},
        "security_events": events,
    }
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


# =============================================================================
# Authentication / RBAC
# =============================================================================


def test_unauthenticated_list_alerts_is_401(client):
    response = client.get("/alerts")
    assert response.status_code == 401


def test_analyst_can_list_alerts(client):
    token = _register_and_login(client)
    response = client.get("/alerts", headers=_bearer(token))
    assert response.status_code == 200


def test_admin_can_list_alerts(client, db_session):
    token = _create_admin_and_login(client, db_session)
    response = client.get("/alerts", headers=_bearer(token))
    assert response.status_code == 200


# =============================================================================
# Result shape / ordering
# =============================================================================


def test_empty_result(client):
    token = _register_and_login(client)
    response = client.get("/alerts", headers=_bearer(token))
    body = response.json()
    assert body == {"items": [], "limit": 50, "offset": 0}


def test_one_result(client, db_session):
    token = _register_and_login(client)
    alert = _make_alert(db_session)
    response = client.get("/alerts", headers=_bearer(token))
    body = response.json()
    assert len(body["items"]) == 1
    assert body["items"][0]["id"] == str(alert.id)
    assert body["items"][0]["source_event_ids"] == [str(alert.security_events[0].id)]


def test_multiple_results_newest_first(client, db_session):
    token = _register_and_login(client)
    now = datetime.now(timezone.utc)
    oldest = _make_alert(db_session, first_seen=now - timedelta(minutes=10), last_seen=now - timedelta(minutes=10))
    middle = _make_alert(db_session, first_seen=now - timedelta(minutes=5), last_seen=now - timedelta(minutes=5))
    newest = _make_alert(db_session, first_seen=now, last_seen=now)

    response = client.get("/alerts", headers=_bearer(token))
    ids = [item["id"] for item in response.json()["items"]]
    assert ids == [str(newest.id), str(middle.id), str(oldest.id)]


# =============================================================================
# Filters
# =============================================================================


def test_status_filter(client, db_session):
    token = _register_and_login(client)
    matching = _make_alert(db_session, status="investigating")
    _make_alert(db_session, status="new")

    response = client.get("/alerts?status=investigating", headers=_bearer(token))
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(matching.id)


def test_severity_filter(client, db_session):
    token = _register_and_login(client)
    matching = _make_alert(db_session, severity="critical")
    _make_alert(db_session, severity="low")

    response = client.get("/alerts?severity=critical", headers=_bearer(token))
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(matching.id)


def test_rule_id_filter(client, db_session):
    token = _register_and_login(client)
    matching = _make_alert(db_session, rule_id="suspicious_powershell_execution")
    _make_alert(db_session, rule_id="brute_force_authentication")

    response = client.get("/alerts?rule_id=suspicious_powershell_execution", headers=_bearer(token))
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(matching.id)


def test_since_filter(client, db_session):
    token = _register_and_login(client)
    now = datetime.now(timezone.utc)
    old = _make_alert(db_session, first_seen=now - timedelta(hours=2), last_seen=now - timedelta(hours=2))
    recent = _make_alert(db_session, first_seen=now, last_seen=now)

    response = client.get("/alerts", params={"since": (now - timedelta(minutes=1)).isoformat()}, headers=_bearer(token))
    ids = {item["id"] for item in response.json()["items"]}
    assert str(recent.id) in ids
    assert str(old.id) not in ids


def test_until_filter(client, db_session):
    token = _register_and_login(client)
    now = datetime.now(timezone.utc)
    old = _make_alert(db_session, first_seen=now - timedelta(hours=2), last_seen=now - timedelta(hours=2))
    recent = _make_alert(db_session, first_seen=now, last_seen=now)

    response = client.get("/alerts", params={"until": (now - timedelta(minutes=1)).isoformat()}, headers=_bearer(token))
    ids = {item["id"] for item in response.json()["items"]}
    assert str(old.id) in ids
    assert str(recent.id) not in ids


def test_combined_filters(client, db_session):
    token = _register_and_login(client)
    now = datetime.now(timezone.utc)
    matching = _make_alert(db_session, status="new", severity="critical", first_seen=now, last_seen=now)
    _make_alert(db_session, status="resolved", severity="critical", first_seen=now, last_seen=now)
    _make_alert(db_session, status="new", severity="low", first_seen=now, last_seen=now)

    response = client.get(
        "/alerts",
        params={"status": "new", "severity": "critical", "since": (now - timedelta(minutes=1)).isoformat()},
        headers=_bearer(token),
    )
    items = response.json()["items"]
    assert len(items) == 1
    assert items[0]["id"] == str(matching.id)


# =============================================================================
# Pagination / validation
# =============================================================================


def test_invalid_limit_zero_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?limit=0", headers=_bearer(token))
    assert response.status_code == 422


def test_invalid_limit_oversized_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?limit=201", headers=_bearer(token))
    assert response.status_code == 422


def test_negative_offset_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?offset=-1", headers=_bearer(token))
    assert response.status_code == 422


def test_invalid_status_enum_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?status=not-a-real-status", headers=_bearer(token))
    assert response.status_code == 422


def test_invalid_severity_enum_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?severity=not-a-real-severity", headers=_bearer(token))
    assert response.status_code == 422


def test_invalid_datetime_is_422(client):
    token = _register_and_login(client)
    response = client.get("/alerts?since=not-a-real-timestamp", headers=_bearer(token))
    assert response.status_code == 422


def test_until_before_since_is_422(client):
    token = _register_and_login(client)
    now = datetime.now(timezone.utc)
    response = client.get(
        "/alerts",
        params={"since": now.isoformat(), "until": (now - timedelta(hours=1)).isoformat()},
        headers=_bearer(token),
    )
    assert response.status_code == 422
    assert "until" in response.json()["detail"].lower()


def test_bounded_query_behavior(client, db_session):
    token = _register_and_login(client)
    for _ in range(5):
        _make_alert(db_session)

    response = client.get("/alerts?limit=2", headers=_bearer(token))
    body = response.json()
    assert len(body["items"]) == 2
    assert body["limit"] == 2
