"""Integration tests for the Alert <-> SecurityEvent many-to-many
relationship. Require PostgreSQL (see conftest.py's db_session fixture).
"""

from datetime import datetime, timezone

import pytest

from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService, UnknownSourceEventsError

pytestmark = pytest.mark.integration


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": datetime.now(timezone.utc),
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


def _alert_payload(*event_ids, **overrides):
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Brute force authentication detected",
        "description": "5 failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "evidence": {"failure_count": 5},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    return AlertCreate(**payload)


def test_alert_with_one_event(db_session):
    event = _make_event(db_session)
    service = AlertService(AlertRepository(db_session))

    alert = service.create(_alert_payload(event.id))

    assert len(alert.security_events) == 1
    assert alert.security_events[0].id == event.id
    assert alert.source_event_ids == [event.id]


def test_alert_with_multiple_events(db_session):
    event_a = _make_event(db_session, username="alice")
    event_b = _make_event(db_session, username="alice")
    service = AlertService(AlertRepository(db_session))

    alert = service.create(_alert_payload(event_a.id, event_b.id))

    assert {e.id for e in alert.security_events} == {event_a.id, event_b.id}
    assert set(alert.source_event_ids) == {event_a.id, event_b.id}


def test_event_can_be_associated_with_multiple_alerts(db_session):
    event = _make_event(db_session)
    service = AlertService(AlertRepository(db_session))

    alert_one = service.create(_alert_payload(event.id, rule_id="brute_force_authentication"))
    alert_two = service.create(_alert_payload(event.id, rule_id="suspicious_powershell_execution"))

    db_session.refresh(event)
    associated_alert_ids = {a.id for a in event.alerts}
    assert associated_alert_ids == {alert_one.id, alert_two.id}


def test_create_with_unknown_event_id_raises(db_session):
    import uuid

    service = AlertService(AlertRepository(db_session))
    unknown_id = uuid.uuid4()

    with pytest.raises(UnknownSourceEventsError) as exc_info:
        service.create(_alert_payload(unknown_id))

    assert unknown_id in exc_info.value.missing_ids


def test_alert_events_relationship_survives_reload(db_session):
    event = _make_event(db_session)
    service = AlertService(AlertRepository(db_session))
    created = service.create(_alert_payload(event.id))

    reloaded = db_session.get(Alert, created.id)

    assert reloaded is not None
    assert [e.id for e in reloaded.security_events] == [event.id]
