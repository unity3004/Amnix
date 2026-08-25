"""Unit tests for the Alert status state machine. No database required."""

import pytest

from app.schemas.alert import AlertStatus
from app.services.alert_lifecycle import InvalidAlertStatusTransition, assert_valid_transition, is_valid_transition

ALL_STATUSES = list(AlertStatus)


def test_new_to_acknowledged_is_valid():
    assert is_valid_transition(AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)


def test_new_to_investigating_is_valid():
    assert is_valid_transition(AlertStatus.NEW, AlertStatus.INVESTIGATING)


def test_new_to_escalated_is_valid():
    assert is_valid_transition(AlertStatus.NEW, AlertStatus.ESCALATED)


def test_new_to_resolved_is_invalid():
    assert not is_valid_transition(AlertStatus.NEW, AlertStatus.RESOLVED)


def test_acknowledged_to_investigating_is_valid():
    assert is_valid_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING)


def test_acknowledged_to_escalated_is_valid():
    assert is_valid_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.ESCALATED)


def test_acknowledged_to_resolved_is_invalid():
    # Acknowledged only means "seen" — resolving requires having gone
    # through INVESTIGATING or ESCALATED first.
    assert not is_valid_transition(AlertStatus.ACKNOWLEDGED, AlertStatus.RESOLVED)


def test_investigating_to_resolved_is_valid():
    assert is_valid_transition(AlertStatus.INVESTIGATING, AlertStatus.RESOLVED)


def test_investigating_to_escalated_is_valid():
    assert is_valid_transition(AlertStatus.INVESTIGATING, AlertStatus.ESCALATED)


def test_investigating_to_acknowledged_is_invalid():
    assert not is_valid_transition(AlertStatus.INVESTIGATING, AlertStatus.ACKNOWLEDGED)


def test_escalated_to_resolved_is_valid():
    assert is_valid_transition(AlertStatus.ESCALATED, AlertStatus.RESOLVED)


def test_escalated_to_investigating_is_invalid():
    # De-escalation is deliberately not supported in this first version.
    assert not is_valid_transition(AlertStatus.ESCALATED, AlertStatus.INVESTIGATING)


@pytest.mark.parametrize("target", ALL_STATUSES)
def test_resolved_is_fully_terminal(target):
    # No outgoing transitions from RESOLVED at all, including RESOLVED -> RESOLVED.
    assert not is_valid_transition(AlertStatus.RESOLVED, target)


@pytest.mark.parametrize("status", ALL_STATUSES)
def test_same_state_transition_is_invalid(status):
    assert not is_valid_transition(status, status)


def test_assert_valid_transition_raises_on_invalid():
    with pytest.raises(InvalidAlertStatusTransition):
        assert_valid_transition(AlertStatus.RESOLVED, AlertStatus.INVESTIGATING)


def test_assert_valid_transition_error_reports_both_states():
    with pytest.raises(InvalidAlertStatusTransition) as exc_info:
        assert_valid_transition(AlertStatus.NEW, AlertStatus.RESOLVED)

    assert exc_info.value.current == AlertStatus.NEW
    assert exc_info.value.requested == AlertStatus.RESOLVED


def test_assert_valid_transition_does_not_raise_on_valid():
    assert_valid_transition(AlertStatus.NEW, AlertStatus.ACKNOWLEDGED)
