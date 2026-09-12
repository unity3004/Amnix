"""Integration tests for the SecurityEvent API. Require PostgreSQL.

These exercise the full stack (FastAPI -> service -> repository -> DB),
using the `db_session` fixture from conftest.py, which runs each test in a
rolled-back transaction against a dedicated `<db>_test` database.
"""

import uuid

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


# =============================================================================
# Step 10H: automatic alert generation from ingested events
# =============================================================================


def _all_alerts(db_session):
    from sqlalchemy import select

    from app.models.alert import Alert

    return list(db_session.scalars(select(Alert)))


def test_ingesting_a_qualifying_brute_force_sequence_creates_an_alert(client, db_session):
    payload = dict(VALID_PAYLOAD)
    payload["event_type"] = "authentication_failure"

    responses = []
    for i in range(5):
        event_payload = dict(payload)
        event_payload["event_timestamp"] = f"2026-08-25T10:00:{i * 10:02d}Z"
        responses.append(client.post("/events", json=event_payload))

    # Ingestion itself is unaffected -- every POST still returns 201.
    assert all(r.status_code == 201 for r in responses)

    alerts = _all_alerts(db_session)
    matching = [a for a in alerts if a.rule_id == "brute_force_authentication"]
    assert len(matching) == 1


def test_ingesting_a_non_qualifying_sequence_creates_no_alert(client, db_session):
    payload = dict(VALID_PAYLOAD)
    payload["event_type"] = "authentication_failure"

    for i in range(2):
        event_payload = dict(payload)
        event_payload["event_timestamp"] = f"2026-08-25T10:00:{i * 10:02d}Z"
        response = client.post("/events", json=event_payload)
        assert response.status_code == 201

    matching = [a for a in _all_alerts(db_session) if a.rule_id == "brute_force_authentication"]
    assert matching == []


def test_ingesting_a_suspicious_powershell_event_creates_an_alert(client, db_session):
    payload = dict(VALID_PAYLOAD)
    payload["command_line"] = "powershell -WindowStyle Hidden -Command Invoke-Expression"

    response = client.post("/events", json=payload)

    assert response.status_code == 201
    matching = [a for a in _all_alerts(db_session) if a.rule_id == "suspicious_powershell_execution"]
    assert len(matching) == 1


def test_repeated_identical_window_does_not_duplicate_alerts_via_the_api(client, db_session):
    payload = dict(VALID_PAYLOAD)
    payload["event_type"] = "authentication_failure"

    for i in range(6):
        event_payload = dict(payload)
        event_payload["event_timestamp"] = f"2026-08-25T10:00:{i * 10:02d}Z"
        response = client.post("/events", json=event_payload)
        assert response.status_code == 201

    matching = [a for a in _all_alerts(db_session) if a.rule_id == "brute_force_authentication"]
    assert len(matching) == 1


def test_create_event_response_schema_unchanged_by_alert_generation(client):
    """POST /events's response is still exactly SecurityEventRead --
    Step 10H must not add any alert-related field to it.
    """
    payload = dict(VALID_PAYLOAD)
    payload["command_line"] = "powershell -WindowStyle Hidden -Command Invoke-Expression"

    response = client.post("/events", json=payload)

    assert response.status_code == 201
    expected_fields = {
        "event_timestamp",
        "event_type",
        "source",
        "source_event_id",
        "hostname",
        "username",
        "source_ip",
        "source_port",
        "destination_ip",
        "destination_port",
        "process_name",
        "process_id",
        "parent_process_name",
        "command_line",
        "file_hash",
        "file_path",
        "severity",
        "raw_data",
        "event_metadata",
        "id",
        "created_at",
    }
    assert set(response.json().keys()) == expected_fields


def test_broken_alert_generation_dependency_does_not_break_ingestion(client, db_session):
    """Defense in depth at the route level (see app.api.events.create_event's
    own docstring): even if the injected AlertGenerationService itself
    misbehaves and raises directly, ingestion still succeeds.
    """
    from app.api.events import get_alert_generation_service
    from app.main import app

    class _BrokenAlertGenerationService:
        def generate_from_event(self, event):
            raise RuntimeError("simulated total alert-generation failure")

    app.dependency_overrides[get_alert_generation_service] = lambda: _BrokenAlertGenerationService()
    try:
        response = client.post("/events", json=VALID_PAYLOAD)
    finally:
        del app.dependency_overrides[get_alert_generation_service]

    assert response.status_code == 201
