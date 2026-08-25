"""Integration tests for the SecurityEvent API. Require PostgreSQL.

These exercise the full stack (FastAPI -> service -> repository -> DB),
using the `db_session` fixture from conftest.py, which runs each test in a
rolled-back transaction against a dedicated `<db>_test` database.
"""

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app

pytestmark = pytest.mark.integration

VALID_PAYLOAD = {
    "event_timestamp": "2026-08-25T10:00:00Z",
    "event_type": "process_creation",
    "source": "sysmon",
    "hostname": "WKS-01",
    "username": "jdoe",
    "process_name": "powershell.exe",
    "process_id": 4321,
    "source_ip": "10.0.0.5",
    "severity": "high",
    "raw_data": {
        "EventID": 1,
        "Image": r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
    },
}


@pytest.fixture
def client(db_session):
    def _override_get_db():
        yield db_session

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()


def test_create_event_returns_201_and_normalized_event(client):
    response = client.post("/events", json=VALID_PAYLOAD)

    assert response.status_code == 201
    body = response.json()
    assert body["event_type"] == "process_creation"
    assert body["source"] == "sysmon"
    assert body["hostname"] == "WKS-01"
    assert body["source_ip"] == "10.0.0.5"
    assert "id" in body
    assert "created_at" in body


def test_created_event_is_persisted_and_retrievable(client):
    create_response = client.post("/events", json=VALID_PAYLOAD)
    event_id = create_response.json()["id"]

    get_response = client.get(f"/events/{event_id}")

    assert get_response.status_code == 200
    body = get_response.json()
    assert body["id"] == event_id
    assert body["raw_data"] == VALID_PAYLOAD["raw_data"]
    assert body["process_name"] == "powershell.exe"


def test_get_unknown_event_returns_404(client):
    response = client.get("/events/00000000-0000-0000-0000-000000000000")

    assert response.status_code == 404


def test_get_event_with_malformed_id_returns_422(client):
    response = client.get("/events/not-a-uuid")

    assert response.status_code == 422


def test_create_event_missing_required_field_returns_422(client):
    payload = dict(VALID_PAYLOAD)
    del payload["event_type"]

    response = client.post("/events", json=payload)

    assert response.status_code == 422


def test_create_event_with_naive_timestamp_returns_422(client):
    payload = dict(VALID_PAYLOAD)
    payload["event_timestamp"] = "2026-08-25T10:00:00"

    response = client.post("/events", json=payload)

    assert response.status_code == 422


def test_create_event_minimal_required_fields_only(client):
    minimal_payload = {
        "event_timestamp": "2026-08-25T10:00:00Z",
        "event_type": "network_connection",
        "source": "network_sensor",
        "raw_data": {"protocol": "tcp"},
    }

    response = client.post("/events", json=minimal_payload)

    assert response.status_code == 201
    body = response.json()
    assert body["hostname"] is None
    assert body["username"] is None
