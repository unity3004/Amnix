"""Unit tests for Alert Pydantic schemas. No database required."""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas.alert import MAX_EVIDENCE_BYTES, AlertCreate, AlertStatus, AlertStatusUpdate


def _base_payload(**overrides):
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Brute force authentication detected for jdoe from 10.0.0.5",
        "description": "5 authentication failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "evidence": {"failure_count": 5, "username": "jdoe", "source_ip": "10.0.0.5"},
        "source_event_ids": [str(uuid.uuid4())],
    }
    payload.update(overrides)
    return payload


def test_valid_alert_passes_validation():
    alert = AlertCreate(**_base_payload())
    assert alert.rule_id == "brute_force_authentication"
    assert alert.severity.value == "high"
    assert alert.confidence.value == "high"


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(severity="apocalyptic"))


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(confidence="extremely_sure"))


def test_status_is_not_a_creation_field():
    # status is deliberately not part of AlertCreate at all: every alert
    # is created as NEW server-side, and status only ever changes via
    # PATCH /alerts/{id}/status. Supplying it should be rejected as an
    # unknown field (extra="forbid"), not silently accepted/ignored.
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(status="resolved"))


def test_invalid_status_rejected_on_status_update_schema():
    # This is where "invalid status" as user input actually applies:
    # the lifecycle endpoint's payload.
    with pytest.raises(ValidationError):
        AlertStatusUpdate(status="not_a_real_status")


def test_valid_status_update_schema():
    update = AlertStatusUpdate(status="acknowledged")
    assert update.status == AlertStatus.ACKNOWLEDGED


def test_missing_required_field_raises():
    payload = _base_payload()
    del payload["rule_id"]
    with pytest.raises(ValidationError):
        AlertCreate(**payload)


def test_missing_evidence_raises():
    payload = _base_payload()
    del payload["evidence"]
    with pytest.raises(ValidationError):
        AlertCreate(**payload)


def test_empty_source_event_ids_rejected():
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(source_event_ids=[]))


def test_missing_source_event_ids_rejected():
    payload = _base_payload()
    del payload["source_event_ids"]
    with pytest.raises(ValidationError):
        AlertCreate(**payload)


def test_blank_title_rejected():
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(title="   "))


def test_naive_first_seen_rejected():
    naive = datetime(2026, 8, 25, 10, 0, 0).isoformat()
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(first_seen=naive))


def test_far_future_first_seen_rejected():
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(first_seen=future))


def test_last_seen_before_first_seen_rejected():
    now = datetime.now(timezone.utc)
    payload = _base_payload(first_seen=now.isoformat(), last_seen=(now - timedelta(minutes=5)).isoformat())
    with pytest.raises(ValidationError):
        AlertCreate(**payload)


def test_last_seen_equal_to_first_seen_is_allowed():
    now = datetime.now(timezone.utc).isoformat()
    alert = AlertCreate(**_base_payload(first_seen=now, last_seen=now))
    assert alert.last_seen == alert.first_seen


def test_last_seen_optional_and_defaults_to_none():
    alert = AlertCreate(**_base_payload())
    assert alert.last_seen is None


def test_oversized_evidence_rejected():
    huge_evidence = {"blob": "A" * (MAX_EVIDENCE_BYTES + 1)}
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(evidence=huge_evidence))


def test_unexpected_extra_field_rejected():
    with pytest.raises(ValidationError):
        AlertCreate(**_base_payload(unexpected_field="x"))


def test_status_update_rejects_extra_fields():
    # The status endpoint's own schema is single-purpose: it must not be
    # possible to smuggle other fields (title, evidence, ...) through it.
    with pytest.raises(ValidationError):
        AlertStatusUpdate(status="acknowledged", title="sneaky rename")
