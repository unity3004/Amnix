"""Unit tests for app.core.security_events (Step 11J). Pure unit tests —
no database, no Redis, no FastAPI app involved.

Covers the architecture guarantees (structured schema, unknown event
types cannot silently pass, valid machine-readable output), the
no-secret-field guarantee at the dataclass-shape level (not just "we
didn't happen to put a password in this particular test"), the
fingerprint helper's properties, and log_security_event's failure
isolation in complete isolation from any real security boundary (the
wired-in call sites are covered separately in
tests/test_security_events_wiring.py).
"""

import dataclasses
import json
import logging

import pytest

from app.core.security_events import (
    SecurityEvent,
    SecurityEventOutcome,
    SecurityEventType,
    fingerprint_login_identifier,
    log_security_event,
)

# =============================================================================
# Architecture (1-3)
# =============================================================================


def test_structured_event_has_expected_fields():
    event = SecurityEvent(
        event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
        method="POST",
        path="/auth/login",
        status_code=200,
        actor_user_id="11111111-1111-1111-1111-111111111111",
        client_ip="127.0.0.1",
    )
    payload = json.loads(event.to_json())

    assert payload["event_type"] == "AUTH_LOGIN_SUCCESS"
    assert payload["outcome"] == "success"
    assert payload["status_code"] == 200
    assert payload["method"] == "POST"
    assert payload["path"] == "/auth/login"
    assert payload["actor_user_id"] == "11111111-1111-1111-1111-111111111111"
    assert payload["client_ip"] == "127.0.0.1"
    assert "timestamp" in payload
    assert payload["logger"] == "amnix.security"


def test_unknown_event_type_cannot_silently_pass():
    """A raw string standing in for a real SecurityEventType must be
    rejected immediately at construction, not silently accepted and
    only fail later (or never) at serialization time.
    """
    with pytest.raises(TypeError):
        SecurityEvent(
            event_type="NOT_A_REAL_EVENT_TYPE",  # type: ignore[arg-type]
            method="GET",
            path="/whatever",
            status_code=200,
        )


def test_formatter_produces_valid_machine_readable_output():
    event = SecurityEvent(
        event_type=SecurityEventType.REQUEST_BODY_TOO_LARGE, method="POST", path="/events", status_code=413
    )

    output = event.to_json()

    parsed = json.loads(output)  # raises if not valid JSON
    assert isinstance(parsed, dict)
    assert parsed["event_type"] == "REQUEST_BODY_TOO_LARGE"


def test_optional_none_fields_are_omitted_not_serialized_as_null():
    event = SecurityEvent(
        event_type=SecurityEventType.AUTH_TOKEN_INVALID, method="GET", path="/events", status_code=401
    )

    payload = json.loads(event.to_json())

    for optional_key in ("actor_user_id", "target_user_id", "target_is_active", "client_ip"):
        assert optional_key not in payload


def test_outcome_is_derived_and_cannot_be_supplied_by_the_caller():
    """outcome is a computed property, not a constructor argument --
    every event type in the fixed taxonomy has exactly one correct
    outcome, so there is no code path that can mismatch them.
    """
    assert "outcome" not in {f.name for f in dataclasses.fields(SecurityEvent)}

    success_event = SecurityEvent(
        event_type=SecurityEventType.ADMIN_USER_STATUS_CHANGED, method="PATCH", path="/admin/users/x/status",
        status_code=200,
    )
    failure_event = SecurityEvent(
        event_type=SecurityEventType.AUTHORIZATION_DENIED, method="PATCH", path="/admin/users/x/status",
        status_code=403,
    )

    assert success_event.outcome is SecurityEventOutcome.SUCCESS
    assert failure_event.outcome is SecurityEventOutcome.FAILURE


# =============================================================================
# Security: no field on SecurityEvent can ever carry sensitive data (4-11)
# =============================================================================


def test_security_event_has_no_field_that_could_carry_a_secret():
    """Structural guarantee, not a per-test scan: the complete, fixed set
    of fields SecurityEvent can ever serialize. If a future change adds
    a field named e.g. "password" or "token", this test fails
    immediately and loudly, rather than relying on every future test
    remembering to scan for it.
    """
    field_names = {f.name for f in dataclasses.fields(SecurityEvent)}

    expected_fields = {
        "event_type",
        "method",
        "path",
        "status_code",
        "actor_user_id",
        "target_user_id",
        "target_is_active",
        "client_ip",
        "login_identifier_fingerprint",
    }
    assert field_names == expected_fields

    forbidden_substrings = (
        "password",
        "hash",
        "token",
        "secret",
        "authorization",
        "cookie",
        "api_key",
        "apikey",
        "body",
        "traceback",
        "exception",
    )
    for name in field_names:
        for forbidden in forbidden_substrings:
            assert forbidden not in name.lower(), f"field name {name!r} contains forbidden substring {forbidden!r}"


@pytest.mark.parametrize("event_type", list(SecurityEventType))
def test_every_event_type_serializes_without_any_forbidden_substring(event_type):
    """Construct every real event type with maximally-populated (but
    still legitimate-shaped) fields and scan the actual serialized
    output -- not just the field names -- for anything resembling a
    leaked secret.
    """
    event = SecurityEvent(
        event_type=event_type,
        method="POST",
        path="/some/real/path",
        status_code=200,
        actor_user_id="11111111-1111-1111-1111-111111111111",
        target_user_id="22222222-2222-2222-2222-222222222222",
        target_is_active=False,
        client_ip="203.0.113.10",
        login_identifier_fingerprint=fingerprint_login_identifier("analyst@example.com"),
    )

    output = event.to_json().lower()

    for forbidden in (
        "password",
        "correct horse battery staple",
        "bearer ",  # a Bearer-scheme header value, not the unrelated event name "AUTHORIZATION_DENIED"
        "cookie",
        "argon2",
        "secret",
        "traceback",
        "analyst@example.com",  # the raw email must never appear, only its fingerprint
    ):
        assert forbidden not in output


# =============================================================================
# Login identifier fingerprint
# =============================================================================


def test_fingerprint_is_deterministic_for_the_same_identifier():
    assert fingerprint_login_identifier("analyst@example.com") == fingerprint_login_identifier("analyst@example.com")


def test_fingerprint_differs_for_different_identifiers():
    assert fingerprint_login_identifier("a@example.com") != fingerprint_login_identifier("b@example.com")


def test_fingerprint_does_not_contain_the_original_email():
    fingerprint = fingerprint_login_identifier("someone-distinctive@example.com")

    assert "someone-distinctive" not in fingerprint
    assert "example.com" not in fingerprint


def test_fingerprint_is_a_short_fixed_length_hex_string():
    fingerprint = fingerprint_login_identifier("x@example.com")

    assert len(fingerprint) == 16
    int(fingerprint, 16)  # raises ValueError if not valid hex


# =============================================================================
# log_security_event: emission and failure isolation
# =============================================================================


def test_log_security_event_emits_at_info_for_success(caplog):
    event = SecurityEvent(
        event_type=SecurityEventType.AUTH_LOGIN_SUCCESS, method="POST", path="/auth/login", status_code=200
    )

    with caplog.at_level(logging.INFO, logger="amnix.security"):
        log_security_event(event)

    assert len(caplog.records) == 1
    assert caplog.records[0].levelno == logging.INFO
    assert caplog.records[0].name == "amnix.security"
    parsed = json.loads(caplog.records[0].message)
    assert parsed["event_type"] == "AUTH_LOGIN_SUCCESS"


def test_log_security_event_emits_at_warning_for_failure(caplog):
    event = SecurityEvent(
        event_type=SecurityEventType.AUTH_LOGIN_FAILURE, method="POST", path="/auth/login", status_code=401
    )

    with caplog.at_level(logging.INFO, logger="amnix.security"):
        log_security_event(event)

    assert caplog.records[0].levelno == logging.WARNING


def test_log_security_event_never_raises_when_the_logger_itself_is_broken(monkeypatch):
    import app.core.security_events as security_events_module

    def _broken_log(*args, **kwargs):
        raise RuntimeError("logging backend is completely broken")

    monkeypatch.setattr(security_events_module._logger, "log", _broken_log)
    event = SecurityEvent(
        event_type=SecurityEventType.AUTH_TOKEN_INVALID, method="GET", path="/events", status_code=401
    )

    log_security_event(event)  # must not raise
