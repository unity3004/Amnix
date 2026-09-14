"""Unit tests for the Case status state machine. No database required."""

import pytest

from app.schemas.case import CaseStatus
from app.services.case_lifecycle import InvalidCaseStatusTransition, assert_valid_transition, is_valid_transition

ALL_STATUSES = list(CaseStatus)


def test_open_to_investigating_is_valid():
    assert is_valid_transition(CaseStatus.OPEN, CaseStatus.INVESTIGATING)


@pytest.mark.parametrize("target", [CaseStatus.RESOLVED, CaseStatus.CLOSED])
def test_open_cannot_skip_investigating(target):
    assert not is_valid_transition(CaseStatus.OPEN, target)


def test_investigating_to_resolved_is_valid():
    assert is_valid_transition(CaseStatus.INVESTIGATING, CaseStatus.RESOLVED)


@pytest.mark.parametrize("target", [CaseStatus.OPEN, CaseStatus.CLOSED])
def test_investigating_cannot_jump_to(target):
    assert not is_valid_transition(CaseStatus.INVESTIGATING, target)


def test_resolved_to_investigating_is_valid():
    """Analyst determined more work is needed before final closure --
    does NOT represent reopening a closed case (see case_lifecycle.py's
    own docstring; CaseService distinguishes this from CLOSED ->
    INVESTIGATING at the audit-action level, not here).
    """
    assert is_valid_transition(CaseStatus.RESOLVED, CaseStatus.INVESTIGATING)


def test_resolved_to_closed_is_valid():
    assert is_valid_transition(CaseStatus.RESOLVED, CaseStatus.CLOSED)


def test_resolved_cannot_jump_to_open():
    assert not is_valid_transition(CaseStatus.RESOLVED, CaseStatus.OPEN)


def test_closed_to_investigating_is_valid():
    """Reopening is deliberately allowed, unlike Alert.RESOLVED's fully
    terminal design -- a Case is a longer-lived record where new
    information after closure is a normal SOC workflow.
    """
    assert is_valid_transition(CaseStatus.CLOSED, CaseStatus.INVESTIGATING)


@pytest.mark.parametrize("target", [CaseStatus.OPEN, CaseStatus.RESOLVED])
def test_closed_cannot_jump_to(target):
    assert not is_valid_transition(CaseStatus.CLOSED, target)


@pytest.mark.parametrize("status", ALL_STATUSES)
def test_same_state_transition_is_invalid(status):
    assert not is_valid_transition(status, status)


def test_assert_valid_transition_raises_on_invalid():
    with pytest.raises(InvalidCaseStatusTransition):
        assert_valid_transition(CaseStatus.OPEN, CaseStatus.CLOSED)


def test_assert_valid_transition_error_reports_both_states():
    with pytest.raises(InvalidCaseStatusTransition) as exc_info:
        assert_valid_transition(CaseStatus.OPEN, CaseStatus.RESOLVED)

    assert exc_info.value.current == CaseStatus.OPEN
    assert exc_info.value.requested == CaseStatus.RESOLVED


def test_assert_valid_transition_does_not_raise_on_valid():
    assert_valid_transition(CaseStatus.OPEN, CaseStatus.INVESTIGATING)


def test_no_containment_state_exists():
    """Step 12Q's explicit decision: no CONTAINMENT state -- this is a
    permanent characteristic of the approved lifecycle, not an oversight.
    """
    assert {s.value for s in CaseStatus} == {"OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"}
