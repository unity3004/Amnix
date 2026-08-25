"""Integration tests for the Alert API. Require PostgreSQL.

These exercise the full stack (FastAPI -> service -> repository -> DB),
using the `db_session` fixture from conftest.py, which runs each test in a
rolled-back transaction against a dedicated `<db>_test` database.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app
from app.models.security_event import SecurityEvent

pytestmark = pytest.mark.integration


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


@pytest.fixture
def source_event(db_session) -> SecurityEvent:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="test",
        username="jdoe",
        source_ip="10.0.0.5",
        raw_data={},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _payload(source_event_id, **overrides):
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Brute force authentication detected for jdoe from 10.0.0.5",
        "description": "5 authentication failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "evidence": {"failure_count": 5, "username": "jdoe", "source_ip": "10.0.0.5"},
        "source_event_ids": [str(source_event_id)],
    }
    payload.update(overrides)
    return payload


def test_create_alert_returns_201(client, source_event):
    response = client.post("/alerts", json=_payload(source_event.id))

    assert response.status_code == 201
    body = response.json()
    assert body["rule_id"] == "brute_force_authentication"
    assert body["status"] == "new"
    assert body["source_event_ids"] == [str(source_event.id)]
    assert "id" in body
    assert "created_at" in body
    assert "updated_at" in body


def test_create_alert_with_unknown_event_id_returns_422(client):
    response = client.post("/alerts", json=_payload(uuid.uuid4()))

    assert response.status_code == 422


def test_create_alert_missing_required_field_returns_422(client, source_event):
    payload = _payload(source_event.id)
    del payload["rule_id"]

    response = client.post("/alerts", json=payload)

    assert response.status_code == 422


def test_get_alert_returns_created_alert(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    get_response = client.get(f"/alerts/{alert_id}")

    assert get_response.status_code == 200
    assert get_response.json()["id"] == alert_id


def test_get_unknown_alert_returns_404(client):
    response = client.get(f"/alerts/{uuid.uuid4()}")

    assert response.status_code == 404


def test_get_alert_with_malformed_uuid_returns_422(client):
    response = client.get("/alerts/not-a-uuid")

    assert response.status_code == 422


def test_patch_status_valid_transition_returns_200(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "acknowledged"})

    assert response.status_code == 200
    assert response.json()["status"] == "acknowledged"


def test_patch_status_invalid_transition_returns_409(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    # NEW -> RESOLVED is not a valid transition.
    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "resolved"})

    assert response.status_code == 409


def test_patch_status_full_lifecycle_to_resolved(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    for target in ("acknowledged", "investigating", "resolved"):
        response = client.patch(f"/alerts/{alert_id}/status", json={"status": target})
        assert response.status_code == 200
        assert response.json()["status"] == target


def test_patch_status_on_resolved_alert_returns_409(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]
    for target in ("investigating", "resolved"):
        client.patch(f"/alerts/{alert_id}/status", json={"status": target})

    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "acknowledged"})

    assert response.status_code == 409


def test_patch_status_unknown_alert_returns_404(client):
    response = client.patch(f"/alerts/{uuid.uuid4()}/status", json={"status": "acknowledged"})

    assert response.status_code == 404


def test_patch_status_malformed_uuid_returns_422(client):
    response = client.patch("/alerts/not-a-uuid/status", json={"status": "acknowledged"})

    assert response.status_code == 422


def test_patch_status_invalid_status_value_returns_422(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    response = client.patch(f"/alerts/{alert_id}/status", json={"status": "not_a_real_status"})

    assert response.status_code == 422


def test_patch_status_cannot_smuggle_other_fields(client, source_event):
    create_response = client.post("/alerts", json=_payload(source_event.id))
    alert_id = create_response.json()["id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "acknowledged", "title": "renamed via status endpoint"},
    )

    # extra="forbid" on AlertStatusUpdate rejects the unexpected field
    # outright, rather than silently ignoring it.
    assert response.status_code == 422
