"""Dashboard Data Foundation: end-to-end data integrity verification.
Requires PostgreSQL.

Proves the new read APIs expose exactly what the existing ingestion
pipeline actually persisted -- never a parallel data model -- by
driving the real HTTP surface end-to-end:

    POST /events -> SecurityEvent -> GET /events

    POST /events -> DetectionEngine -> AlertGenerationService
                  -> Alert -> GET /alerts

No mocking of the detection engine or alert generation service: this
uses the real brute_force_authentication rule, the same one already
exercised by tests/test_alert_generation_service.py and Step 11N/12A's
own live-verification scripts.
"""

import uuid
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.core.database import get_db
from app.main import app

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


def _authenticate(client) -> str:
    email = f"integrity-{uuid.uuid4().hex[:8]}@example.com"
    client.post("/auth/register", json={"email": email, "password": VALID_PASSWORD})
    login = client.post("/auth/login", json={"email": email, "password": VALID_PASSWORD})
    return login.json()["access_token"]


def _bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def test_posted_event_is_exposed_by_get_events(client):
    token = _authenticate(client)
    payload = {
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_creation",
        "source": "integrity-test",
        "hostname": "workstation-integrity-01",
        "raw_data": {"note": "data integrity check"},
    }

    created = client.post("/events", json=payload, headers=_bearer(token))
    assert created.status_code == 201, created.text
    created_body = created.json()

    listed = client.get("/events?source=integrity-test", headers=_bearer(token))
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) == 1

    # The list item must be the SAME persisted row, not a re-derived or
    # partial projection -- every field matches the create response,
    # which itself came from SecurityEventRead.model_validate() against
    # the real ORM row.
    assert items[0] == created_body


def test_ingestion_pipeline_produces_an_alert_visible_via_get_alerts(client):
    """Drives the real brute_force_authentication detection rule (5
    authentication_failure events for the same username/source_ip
    within its window, matching Settings.brute_force_threshold's
    default) through the real AlertGenerationService, then confirms the
    resulting Alert is retrievable via the new list endpoint with a
    matching rule_id and non-empty source_event_ids.
    """
    token = _authenticate(client)
    marker_username = f"integrity-user-{uuid.uuid4().hex[:8]}"
    event_ids = []

    for _ in range(6):
        payload = {
            "event_timestamp": datetime.now(timezone.utc).isoformat(),
            "event_type": "authentication_failure",
            "source": "integrity-test-brute-force",
            "username": marker_username,
            "source_ip": "10.0.0.99",
            "raw_data": {},
        }
        response = client.post("/events", json=payload, headers=_bearer(token))
        assert response.status_code == 201, response.text
        event_ids.append(response.json()["id"])

    listed = client.get("/alerts?rule_id=brute_force_authentication", headers=_bearer(token))
    assert listed.status_code == 200
    items = listed.json()["items"]
    assert len(items) >= 1, "the real DetectionEngine/AlertGenerationService did not produce an alert"

    alert = items[0]
    assert alert["rule_id"] == "brute_force_authentication"
    assert alert["status"] == "new"
    assert len(alert["source_event_ids"]) > 0
    # Every cited source event must be one this test actually posted --
    # never a fabricated or cross-contaminated reference.
    assert set(alert["source_event_ids"]).issubset(set(event_ids))

    # And the alert itself must be independently retrievable via the
    # existing single-resource endpoint with the exact same id -- the
    # new list endpoint and the pre-existing detail endpoint must agree,
    # never a parallel/divergent data model.
    detail = client.get(f"/alerts/{alert['id']}", headers=_bearer(token))
    assert detail.status_code == 200
    assert detail.json() == alert
