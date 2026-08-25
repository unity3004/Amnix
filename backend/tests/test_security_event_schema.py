"""Unit tests for SecurityEvent Pydantic validation. No database required."""

from datetime import datetime, timedelta, timezone

import pytest
from pydantic import ValidationError

from app.schemas.security_event import MAX_RAW_DATA_BYTES, SecurityEventCreate


def _base_payload(**overrides):
    payload = {
        "event_timestamp": datetime.now(timezone.utc).isoformat(),
        "event_type": "process_creation",
        "source": "sysmon",
        "raw_data": {"EventID": 1},
    }
    payload.update(overrides)
    return payload


def test_valid_event_passes_validation():
    event = SecurityEventCreate(**_base_payload())
    assert event.event_type == "process_creation"
    assert event.source == "sysmon"


def test_full_valid_event_with_all_fields_passes_validation():
    payload = _base_payload(
        source_event_id="4688-1",
        hostname="WKS-01.corp.local",
        username="jdoe",
        source_ip="10.0.0.5",
        source_port=51234,
        destination_ip="10.0.0.1",
        destination_port=443,
        process_name="powershell.exe",
        process_id=4321,
        parent_process_name="explorer.exe",
        command_line="powershell.exe -Command Get-Process",
        file_hash="a" * 64,
        file_path=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        severity="high",
        event_metadata={"rule_name": "suspicious_powershell"},
    )
    event = SecurityEventCreate(**payload)
    assert str(event.source_ip) == "10.0.0.5"
    assert event.severity.value == "high"


def test_missing_required_field_raises():
    payload = _base_payload()
    del payload["event_type"]
    with pytest.raises(ValidationError):
        SecurityEventCreate(**payload)


def test_missing_raw_data_raises():
    payload = _base_payload()
    del payload["raw_data"]
    with pytest.raises(ValidationError):
        SecurityEventCreate(**payload)


def test_blank_event_type_raises():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(event_type="   "))


def test_naive_timestamp_rejected():
    naive = datetime(2026, 8, 25, 10, 0, 0).isoformat()
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(event_timestamp=naive))


def test_far_future_timestamp_rejected():
    future = (datetime.now(timezone.utc) + timedelta(days=10)).isoformat()
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(event_timestamp=future))


def test_slightly_past_timestamp_is_allowed():
    past = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
    event = SecurityEventCreate(**_base_payload(event_timestamp=past))
    assert event.event_timestamp.tzinfo is not None


def test_invalid_ip_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(source_ip="not-an-ip"))


def test_valid_ipv6_accepted():
    event = SecurityEventCreate(**_base_payload(source_ip="2001:db8::1"))
    assert str(event.source_ip) == "2001:db8::1"


def test_oversized_raw_data_rejected():
    huge = {"blob": "A" * (MAX_RAW_DATA_BYTES + 1)}
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(raw_data=huge))


def test_invalid_severity_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(severity="apocalyptic"))


def test_invalid_file_hash_format_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(file_hash="not-a-hash"))


def test_valid_sha256_file_hash_accepted():
    event = SecurityEventCreate(**_base_payload(file_hash="b" * 64))
    assert event.file_hash == "b" * 64


def test_port_out_of_range_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(source_port=70000))


def test_negative_port_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(destination_port=-1))


def test_unexpected_extra_field_rejected():
    with pytest.raises(ValidationError):
        SecurityEventCreate(**_base_payload(unexpected_field="x"))
