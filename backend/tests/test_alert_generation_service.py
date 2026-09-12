"""Integration tests for AlertGenerationService (Step 10H): the service
that turns DetectionEngine output into real Alerts. Require PostgreSQL
(see conftest.py's db_session fixture).

Repository-level dedup tests use the same self-contained
_make_event/_create_alert helper convention already established
throughout this test suite.
"""

from datetime import datetime, timedelta, timezone

import pytest

from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.repositories.security_event import SecurityEventRepository
from app.schemas.alert import AlertCreate
from app.services.alert_generation_service import AlertGenerationService
from app.services.alert_service import AlertService
from app.services.detection_service import DetectionEngine

pytestmark = pytest.mark.integration

BASE_TIME = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": BASE_TIME,
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


def _create_alert(db_session, event_ids, **overrides) -> Alert:
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Test alert",
        "description": "Test alert description.",
        "severity": "high",
        "confidence": "high",
        "first_seen": BASE_TIME.isoformat(),
        "evidence": {},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    service = AlertService(AlertRepository(db_session))
    return service.create(AlertCreate(**payload))


def _service(db_session, **kwargs) -> AlertGenerationService:
    return AlertGenerationService(
        security_event_repository=SecurityEventRepository(db_session),
        alert_repository=AlertRepository(db_session),
        alert_service=AlertService(AlertRepository(db_session)),
        **kwargs,
    )


def _alerts_with_rule(db_session, rule_id: str) -> list[Alert]:
    from sqlalchemy import select

    return list(db_session.scalars(select(Alert).where(Alert.rule_id == rule_id)))


# =============================================================================
# Brute-force correlation
# =============================================================================


def test_qualifying_brute_force_sequence_creates_one_alert(db_session):
    events = [
        _make_event(
            db_session,
            username="jdoe",
            source_ip="10.0.0.5",
            event_timestamp=BASE_TIME + timedelta(seconds=i * 10),
        )
        for i in range(5)
    ]
    service = _service(db_session)

    created = service.generate_from_event(events[-1])

    assert len(created) == 1
    assert created[0].rule_id == "brute_force_authentication"
    assert _alerts_with_rule(db_session, "brute_force_authentication") == created


def test_non_qualifying_sequence_creates_no_alert(db_session):
    events = [
        _make_event(
            db_session, username="jdoe", source_ip="10.0.0.5", event_timestamp=BASE_TIME + timedelta(seconds=i * 10)
        )
        for i in range(3)
    ]
    service = _service(db_session)

    created = service.generate_from_event(events[-1])

    assert created == []
    assert _alerts_with_rule(db_session, "brute_force_authentication") == []


def test_events_outside_correlation_window_do_not_count(db_session):
    old_events = [
        _make_event(
            db_session, username="jdoe", source_ip="10.0.0.5", event_timestamp=BASE_TIME - timedelta(hours=1) + timedelta(seconds=i)
        )
        for i in range(4)
    ]
    new_event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5", event_timestamp=BASE_TIME)
    service = _service(db_session, correlation_window_seconds=300)

    created = service.generate_from_event(new_event)

    assert created == []


def test_different_identity_pairs_produce_independent_alerts(db_session):
    for i in range(5):
        _make_event(
            db_session, username="alice", source_ip="10.0.0.1", event_timestamp=BASE_TIME + timedelta(seconds=i * 10)
        )
    last_alice = _make_event(
        db_session, username="alice", source_ip="10.0.0.1", event_timestamp=BASE_TIME + timedelta(seconds=50)
    )
    service = _service(db_session)
    service.generate_from_event(last_alice)

    for i in range(5):
        _make_event(
            db_session, username="bob", source_ip="10.0.0.2", event_timestamp=BASE_TIME + timedelta(seconds=i * 10)
        )
    last_bob = _make_event(
        db_session, username="bob", source_ip="10.0.0.2", event_timestamp=BASE_TIME + timedelta(seconds=50)
    )
    created = service.generate_from_event(last_bob)

    assert len(created) == 1
    assert len(_alerts_with_rule(db_session, "brute_force_authentication")) == 2


# =============================================================================
# Deduplication
# =============================================================================


def test_re_evaluating_the_same_window_does_not_create_a_duplicate(db_session):
    events = [
        _make_event(
            db_session, username="jdoe", source_ip="10.0.0.5", event_timestamp=BASE_TIME + timedelta(seconds=i * 10)
        )
        for i in range(5)
    ]
    service = _service(db_session)
    first_run = service.generate_from_event(events[-1])
    assert len(first_run) == 1

    # A 6th failure for the same identity within the window: the
    # earliest qualifying window (events[0:5]) is unchanged, so the
    # exact-event-set dedup check must suppress a second alert.
    sixth = _make_event(
        db_session, username="jdoe", source_ip="10.0.0.5", event_timestamp=BASE_TIME + timedelta(seconds=55)
    )
    second_run = service.generate_from_event(sixth)

    assert second_run == []
    assert len(_alerts_with_rule(db_session, "brute_force_authentication")) == 1


def test_exists_with_rule_and_exact_events_true_and_false_cases(db_session):
    event_a = _make_event(db_session)
    event_b = _make_event(db_session)
    alert = _create_alert(db_session, [event_a.id, event_b.id], rule_id="brute_force_authentication")
    repo = AlertRepository(db_session)

    assert repo.exists_with_rule_and_exact_events("brute_force_authentication", [event_a.id, event_b.id]) is True
    # Different rule_id, same events -> not a match.
    assert repo.exists_with_rule_and_exact_events("suspicious_powershell_execution", [event_a.id, event_b.id]) is False
    # Subset -> not an exact match.
    assert repo.exists_with_rule_and_exact_events("brute_force_authentication", [event_a.id]) is False
    # Superset -> not an exact match.
    event_c = _make_event(db_session)
    assert (
        repo.exists_with_rule_and_exact_events("brute_force_authentication", [event_a.id, event_b.id, event_c.id])
        is False
    )
    assert repo.exists_with_rule_and_exact_events("brute_force_authentication", []) is False
    assert alert.id is not None  # sanity: the fixture alert was actually created


# =============================================================================
# PowerShell rules
# =============================================================================


def test_suspicious_powershell_event_creates_alert(db_session):
    event = _make_event(
        db_session,
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell -WindowStyle Hidden -Command Invoke-Expression",
    )
    service = _service(db_session)

    created = service.generate_from_event(event)

    assert len(created) == 1
    assert created[0].rule_id == "suspicious_powershell_execution"


def test_benign_powershell_event_creates_no_alert(db_session):
    event = _make_event(
        db_session, event_type="process_creation", process_name="powershell.exe", command_line="Get-Process"
    )
    service = _service(db_session)

    created = service.generate_from_event(event)

    assert created == []


def test_encoded_powershell_event_creates_alert(db_session):
    event = _make_event(
        db_session,
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell.exe -enc SQBFAFgA",
    )
    service = _service(db_session)

    created = service.generate_from_event(event)

    assert {a.rule_id for a in created} == {"encoded_powershell_command"}


def test_event_matching_two_rules_creates_two_alerts(db_session):
    event = _make_event(
        db_session,
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell -enc SQBFAFgA -WindowStyle Hidden",
    )
    service = _service(db_session)

    created = service.generate_from_event(event)

    assert {a.rule_id for a in created} == {"encoded_powershell_command", "suspicious_powershell_execution"}


# =============================================================================
# Alert field mapping
# =============================================================================


def test_created_alert_fields_match_detection_result(db_session):
    event = _make_event(
        db_session,
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell -enc SQBFAFgA",
        hostname="WKS-77",
        username="jdoe",
    )
    service = _service(db_session)

    created = service.generate_from_event(event)[0]

    assert created.rule_id == "encoded_powershell_command"
    assert created.severity == "high"
    assert created.confidence == "high"
    assert created.evidence["process_name"] == "powershell.exe"
    assert created.evidence["command_line"] == "powershell -enc SQBFAFgA"
    assert created.source_event_ids == [event.id]
    assert created.status == "new"
    assert "detection_id" in created.alert_metadata
    assert created.first_seen == created.last_seen


# =============================================================================
# Failure isolation
# =============================================================================


def test_detection_engine_failure_does_not_raise(db_session):
    class _BrokenDetectionEngine:
        def evaluate_events(self, events):
            raise RuntimeError("simulated detection engine failure")

    event = _make_event(db_session)
    service = _service(db_session, detection_engine=_BrokenDetectionEngine())

    created = service.generate_from_event(event)

    assert created == []


def test_alert_creation_failure_for_one_result_does_not_block_others(db_session, caplog):
    class _PartiallyBrokenAlertService(AlertService):
        def create(self, payload):
            if payload.rule_id == "encoded_powershell_command":
                raise RuntimeError("simulated alert creation failure; internal detail: db_password=hunter2")
            return super().create(payload)

    event = _make_event(
        db_session,
        event_type="process_creation",
        process_name="powershell.exe",
        command_line="powershell -enc SQBFAFgA -WindowStyle Hidden",
    )
    service = AlertGenerationService(
        security_event_repository=SecurityEventRepository(db_session),
        alert_repository=AlertRepository(db_session),
        alert_service=_PartiallyBrokenAlertService(AlertRepository(db_session)),
    )

    with caplog.at_level("ERROR"):
        created = service.generate_from_event(event)

    # suspicious_powershell_execution still succeeds even though
    # encoded_powershell_command's creation failed.
    assert len(created) == 1
    assert created[0].rule_id == "suspicious_powershell_execution"
    assert not any("hunter2" in record.getMessage() for record in caplog.records)


def test_real_detection_engine_default_construction(db_session):
    """AlertGenerationService is usable with no detection_engine argument
    at all (the DI factory in app.api.events relies on this default).
    """
    event = _make_event(
        db_session, event_type="process_creation", process_name="powershell.exe", command_line="-enc abc"
    )
    service = AlertGenerationService(
        security_event_repository=SecurityEventRepository(db_session),
        alert_repository=AlertRepository(db_session),
        alert_service=AlertService(AlertRepository(db_session)),
    )
    assert isinstance(service._detection_engine, DetectionEngine)

    created = service.generate_from_event(event)
    assert len(created) == 1
