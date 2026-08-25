"""Integration tests for GET /alerts/{id}/investigation. Require PostgreSQL.

These exercise the full stack (FastAPI -> service -> repository -> DB),
using the `db_session` fixture from conftest.py.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import event as sa_event

from app.core.database import get_db
from app.main import app
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService

pytestmark = pytest.mark.integration

START = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": START,
        "event_type": "authentication_failure",
        "source": "test",
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
        "title": "Brute force authentication detected",
        "description": "5 failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": START.isoformat(),
        "evidence": {"failure_count": 5},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    service = AlertService(AlertRepository(db_session))
    return service.create(AlertCreate(**payload))


def test_get_investigation_returns_200_with_full_context(client, db_session):
    event = _make_event(db_session, hostname="WKS-01", username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])

    response = client.get(f"/alerts/{alert.id}/investigation")

    assert response.status_code == 200
    body = response.json()
    assert body["alert"]["id"] == str(alert.id)
    assert len(body["timeline"]) == 1
    assert body["timeline"][0]["event_id"] == str(event.id)
    assert body["entities"]["hostnames"] == ["WKS-01"]
    assert body["entities"]["usernames"] == ["jdoe"]
    assert "jdoe" in body["summary"]["text"]
    assert body["summary"]["event_count"] == 1
    assert "generated_at" in body


def test_get_investigation_with_multiple_events(client, db_session):
    event_a = _make_event(db_session, event_timestamp=START, hostname="WKS-01")
    event_b = _make_event(db_session, event_timestamp=START + timedelta(minutes=2), hostname="WKS-02")
    alert = _create_alert(db_session, [event_a.id, event_b.id])

    response = client.get(f"/alerts/{alert.id}/investigation")

    assert response.status_code == 200
    body = response.json()
    assert len(body["timeline"]) == 2
    assert body["timeline"][0]["event_id"] == str(event_a.id)
    assert body["timeline"][1]["event_id"] == str(event_b.id)
    assert body["entities"]["hostnames"] == ["WKS-01", "WKS-02"]


def test_get_investigation_unknown_alert_returns_404(client):
    response = client.get(f"/alerts/{uuid.uuid4()}/investigation")

    assert response.status_code == 404


def test_get_investigation_malformed_uuid_returns_422(client):
    response = client.get("/alerts/not-a-uuid/investigation")

    assert response.status_code == 422


def test_get_investigation_does_not_change_alert_status(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])
    assert alert.status == "new"

    client.get(f"/alerts/{alert.id}/investigation")

    db_session.refresh(alert)
    assert alert.status == "new"


def test_get_investigation_twice_is_idempotent(client, db_session):
    event = _make_event(db_session)
    alert = _create_alert(db_session, [event.id])

    first = client.get(f"/alerts/{alert.id}/investigation").json()
    second = client.get(f"/alerts/{alert.id}/investigation").json()

    assert first["timeline"] == second["timeline"]
    assert first["entities"] == second["entities"]
    assert first["summary"]["text"] == second["summary"]["text"]


def _count_statements(db_session, fn):
    statements = []
    connection = db_session.connection()

    def _before_cursor_execute(conn, cursor, statement, parameters, context, executemany):
        statements.append(statement)

    sa_event.listen(connection, "before_cursor_execute", _before_cursor_execute)
    try:
        result = fn()
    finally:
        sa_event.remove(connection, "before_cursor_execute", _before_cursor_execute)
    return result, statements


def test_get_by_id_with_events_query_count_does_not_scale_with_event_count(db_session):
    repo = AlertRepository(db_session)

    one_event = _make_event(db_session)
    alert_with_one_id = _create_alert(db_session, [one_event.id]).id

    many_events = [_make_event(db_session, source="test", event_timestamp=START) for _ in range(6)]
    alert_with_many_id = _create_alert(db_session, [e.id for e in many_events]).id

    # Clear the identity map before each measurement (capturing plain
    # UUIDs above, not ORM objects, so this doesn't detach anything we
    # still need) so neither call is affected by attribute-expiration
    # from the other alert/events' intervening commits — each
    # measurement should reflect a fresh, independent request, which is
    # what the real endpoint does.
    db_session.expunge_all()
    _, statements_one = _count_statements(db_session, lambda: repo.get_by_id_with_events(alert_with_one_id))

    db_session.expunge_all()
    _, statements_many = _count_statements(db_session, lambda: repo.get_by_id_with_events(alert_with_many_id))

    # selectinload issues a small, constant number of statements (one for
    # the Alert row, one batched IN-query for its events) regardless of
    # how many events are associated — not one query per event.
    assert len(statements_one) == len(statements_many)
    assert len(statements_one) <= 2
