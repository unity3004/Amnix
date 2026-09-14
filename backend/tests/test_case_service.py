"""Integration tests for CaseService (Step 12R). Require PostgreSQL.

Covers business-rule enforcement: creation, multi-field update (with
per-field audit / no-op behavior), lifecycle transitions (including
closure-reason requirements and reopen semantics), ownership
authorization (self-assign / release / admin reassignment / inactive
owner rejection), alert linking/unlinking, and note creation.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.api.dependencies import AuthenticatedUser
from app.core.security import hash_password
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import CaseNoteRepository
from app.repositories.user import UserRepository
from app.schemas.case import CasePriority, CaseStatus
from app.services.alert_service import AlertNotFoundError
from app.services.case_lifecycle import InvalidCaseStatusTransition
from app.services.case_service import (
    AlertAlreadyLinkedError,
    AlertNotLinkedError,
    CaseNotFoundError,
    CaseOwnerNotFoundError,
    CaseOwnershipAuthorizationError,
    CaseService,
    ClosureReasonRequiredError,
    InactiveCaseOwnerError,
)

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"caseservice-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _auth(user: User) -> AuthenticatedUser:
    return AuthenticatedUser(id=user.id, email=user.email, role=user.role, is_active=user.is_active)


def _make_alert(db_session, **overrides) -> Alert:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="test", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="Service test alert",
        description="d",
        severity="high",
        confidence="high",
        status="new",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    defaults.update(overrides)
    return AlertRepository(db_session).create(Alert(**defaults))


def _service(db_session) -> CaseService:
    return CaseService(
        db_session,
        CaseRepository(db_session),
        CaseAlertRepository(db_session),
        CaseAuditRepository(db_session),
        CaseNoteRepository(db_session),
        AlertRepository(db_session),
        UserRepository(db_session),
    )


# =============================================================================
# Creation
# =============================================================================


def test_create_case_persists_with_open_status_and_audit(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    case = service.create_case(
        title="Suspicious activity", description="Investigating.", priority=CasePriority.HIGH, created_by=analyst.id
    )

    assert case.status == "OPEN"
    assert case.priority == "high"
    assert case.created_by == analyst.id
    assert case.owner_id is None
    audits = service.list_audits(case.id, limit=50, offset=0)
    assert len(audits) == 1
    assert audits[0].action == "CASE_CREATED"
    assert audits[0].previous_value is None
    assert audits[0].actor_user_id == analyst.id


def test_create_case_generates_a_real_case_number(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    case_a = service.create_case(title="a", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    case_b = service.create_case(title="b", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    assert isinstance(case_a.case_number, int)
    assert case_a.case_number != case_b.case_number


def test_derive_severity_is_none_for_a_case_with_no_linked_alerts(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    assert service.derive_severity(case.id) is None


def test_derive_severity_is_the_max_severity_among_linked_alerts(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    low_alert = _make_alert(db_session, severity="low")
    critical_alert = _make_alert(db_session, severity="critical")
    service.link_alert(case.id, alert_id=low_alert.id, actor_id=analyst.id)
    service.link_alert(case.id, alert_id=critical_alert.id, actor_id=analyst.id)

    assert service.derive_severity(case.id) == "critical"


# =============================================================================
# Update
# =============================================================================


def test_update_case_changes_only_provided_fields_and_audits_each(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="old title", description="old desc", priority=CasePriority.LOW, created_by=analyst.id)

    updated = service.update_case(
        case.id, title="new title", description=None, priority=CasePriority.HIGH, actor_id=analyst.id
    )

    assert updated.title == "new title"
    assert updated.description == "old desc"
    assert updated.priority == "high"
    audits = service.list_audits(case.id, limit=50, offset=0)
    actions = {a.action for a in audits}
    assert "CASE_TITLE_CHANGED" in actions
    assert "CASE_PRIORITY_CHANGED" in actions
    assert "CASE_DESCRIPTION_CHANGED" not in actions


def test_update_case_with_unchanged_values_creates_no_audit(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="same", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    before_count = len(service.list_audits(case.id, limit=50, offset=0))

    result = service.update_case(case.id, title="same", description=None, priority=None, actor_id=analyst.id)

    assert result.title == "same"
    assert len(service.list_audits(case.id, limit=50, offset=0)) == before_count


def test_update_case_raises_not_found_for_unknown_case(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    with pytest.raises(CaseNotFoundError):
        service.update_case(uuid.uuid4(), title="x", description=None, priority=None, actor_id=analyst.id)


# =============================================================================
# Status transitions
# =============================================================================


def test_open_to_investigating_records_generic_status_changed(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    updated = service.change_status(
        case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id
    )

    assert updated.status == "INVESTIGATING"
    actions = [a.action for a in service.list_audits(case.id, limit=50, offset=0)]
    assert "CASE_STATUS_CHANGED" in actions


def test_invalid_transition_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    with pytest.raises(InvalidCaseStatusTransition):
        service.change_status(case.id, new_status=CaseStatus.CLOSED, closure_reason="x", actor_id=analyst.id)


def test_closing_without_closure_reason_is_rejected(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.RESOLVED, closure_reason=None, actor_id=analyst.id)

    with pytest.raises(ClosureReasonRequiredError):
        service.change_status(case.id, new_status=CaseStatus.CLOSED, closure_reason=None, actor_id=analyst.id)

    with pytest.raises(ClosureReasonRequiredError):
        service.change_status(case.id, new_status=CaseStatus.CLOSED, closure_reason="   ", actor_id=analyst.id)


def test_closing_sets_closed_at_and_closure_reason_and_records_case_closed(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.RESOLVED, closure_reason=None, actor_id=analyst.id)

    closed = service.change_status(
        case.id, new_status=CaseStatus.CLOSED, closure_reason="Root cause identified.", actor_id=analyst.id
    )

    assert closed.status == "CLOSED"
    assert closed.closed_at is not None
    assert closed.closure_reason == "Root cause identified."
    actions = [a.action for a in service.list_audits(case.id, limit=50, offset=0)]
    assert "CASE_CLOSED" in actions
    assert "CASE_STATUS_CHANGED" not in [a for a in actions if a == "CASE_CLOSED"]


def test_reopening_a_closed_case_clears_closure_fields_and_records_case_reopened(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.RESOLVED, closure_reason=None, actor_id=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.CLOSED, closure_reason="Done.", actor_id=analyst.id)

    reopened = service.change_status(
        case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id
    )

    assert reopened.status == "INVESTIGATING"
    assert reopened.closed_at is None
    assert reopened.closure_reason is None
    actions = [a.action for a in service.list_audits(case.id, limit=50, offset=0)]
    assert "CASE_REOPENED" in actions


def test_resolved_to_investigating_does_not_touch_closure_fields_or_record_reopened(db_session):
    """RESOLVED -> INVESTIGATING does not represent closure -- it must
    use the generic CASE_STATUS_CHANGED action, never CASE_REOPENED,
    since the case was never actually closed.
    """
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    service.change_status(case.id, new_status=CaseStatus.RESOLVED, closure_reason=None, actor_id=analyst.id)

    result = service.change_status(
        case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id
    )

    assert result.closed_at is None
    assert result.closure_reason is None
    audits = service.list_audits(case.id, limit=50, offset=0)
    reopen_actions = [a for a in audits if a.action == "CASE_REOPENED"]
    assert reopen_actions == []


def test_status_change_raises_not_found_for_unknown_case(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    with pytest.raises(CaseNotFoundError):
        service.change_status(uuid.uuid4(), new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)


# =============================================================================
# Ownership
# =============================================================================


def test_analyst_can_self_assign_unowned_case(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    updated = service.change_owner(case.id, new_owner_id=analyst.id, actor=_auth(analyst))

    assert updated.owner_id == analyst.id
    actions = [a.action for a in service.list_audits(case.id, limit=50, offset=0)]
    assert "CASE_OWNER_CHANGED" in actions


def test_analyst_can_release_own_case(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_owner(case.id, new_owner_id=analyst.id, actor=_auth(analyst))

    updated = service.change_owner(case.id, new_owner_id=None, actor=_auth(analyst))

    assert updated.owner_id is None


def test_analyst_cannot_assign_unowned_case_to_another_analyst(db_session):
    analyst = _make_user(db_session)
    other_analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    with pytest.raises(CaseOwnershipAuthorizationError):
        service.change_owner(case.id, new_owner_id=other_analyst.id, actor=_auth(analyst))


def test_analyst_cannot_reassign_another_analysts_case(db_session):
    owner = _make_user(db_session)
    other_analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=owner.id)
    service.change_owner(case.id, new_owner_id=owner.id, actor=_auth(owner))

    with pytest.raises(CaseOwnershipAuthorizationError):
        service.change_owner(case.id, new_owner_id=other_analyst.id, actor=_auth(other_analyst))


def test_analyst_cannot_take_another_analysts_case_for_themselves(db_session):
    owner = _make_user(db_session)
    other_analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=owner.id)
    service.change_owner(case.id, new_owner_id=owner.id, actor=_auth(owner))

    with pytest.raises(CaseOwnershipAuthorizationError):
        service.change_owner(case.id, new_owner_id=other_analyst.id, actor=_auth(other_analyst))


def test_admin_can_assign_any_active_user_to_any_case(db_session):
    admin = _make_user(db_session, role="admin")
    analyst = _make_user(db_session)
    target = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_owner(case.id, new_owner_id=analyst.id, actor=_auth(analyst))

    updated = service.change_owner(case.id, new_owner_id=target.id, actor=_auth(admin))

    assert updated.owner_id == target.id


def test_admin_can_release_any_case(db_session):
    admin = _make_user(db_session, role="admin")
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_owner(case.id, new_owner_id=analyst.id, actor=_auth(analyst))

    updated = service.change_owner(case.id, new_owner_id=None, actor=_auth(admin))

    assert updated.owner_id is None


def test_assigning_a_nonexistent_user_is_rejected(db_session):
    """Uses an admin actor deliberately: an analyst assigning an
    arbitrary UUID would already be rejected by the object-level
    authorization rule (it isn't self-assignment) before the
    user-existence check is ever reached -- admin's unconditional
    assignment rights are what actually exercises that check.
    """
    admin = _make_user(db_session, role="admin")
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    with pytest.raises(CaseOwnerNotFoundError):
        service.change_owner(case.id, new_owner_id=uuid.uuid4(), actor=_auth(admin))


def test_assigning_an_inactive_user_is_rejected(db_session):
    admin = _make_user(db_session, role="admin")
    analyst = _make_user(db_session)
    inactive = _make_user(db_session, is_active=False)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    with pytest.raises(InactiveCaseOwnerError):
        service.change_owner(case.id, new_owner_id=inactive.id, actor=_auth(admin))


def test_later_deactivation_does_not_clear_existing_owner(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.change_owner(case.id, new_owner_id=analyst.id, actor=_auth(analyst))

    analyst.is_active = False
    db_session.commit()

    fresh = service.get_case(case.id)
    assert fresh.owner_id == analyst.id


def test_owner_change_raises_not_found_for_unknown_case(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    with pytest.raises(CaseNotFoundError):
        service.change_owner(uuid.uuid4(), new_owner_id=analyst.id, actor=_auth(analyst))


# =============================================================================
# Alert linking / unlinking
# =============================================================================


def test_link_alert_succeeds_and_audits(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)

    link = service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    assert link.case_id == case.id
    assert link.alert_id == alert.id
    actions_and_alerts = [(a.action, a.related_alert_id) for a in service.list_audits(case.id, limit=50, offset=0)]
    assert ("CASE_ALERT_LINKED", alert.id) in actions_and_alerts


def test_link_nonexistent_alert_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    with pytest.raises(AlertNotFoundError):
        service.link_alert(case.id, alert_id=uuid.uuid4(), actor_id=analyst.id)


def test_link_alert_to_nonexistent_case_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    alert = _make_alert(db_session)

    with pytest.raises(CaseNotFoundError):
        service.link_alert(uuid.uuid4(), alert_id=alert.id, actor_id=analyst.id)


def test_duplicate_link_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)
    service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    with pytest.raises(AlertAlreadyLinkedError):
        service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)


def test_unlink_alert_succeeds_and_audits_without_deleting_the_alert(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)
    service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    service.unlink_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    assert service.list_alerts(case.id) == []
    # The Alert itself must still exist, untouched.
    assert AlertRepository(db_session).get_by_id(alert.id) is not None
    actions_and_alerts = [(a.action, a.related_alert_id) for a in service.list_audits(case.id, limit=50, offset=0)]
    assert ("CASE_ALERT_UNLINKED", alert.id) in actions_and_alerts


def test_unlink_nonexistent_relationship_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)

    with pytest.raises(AlertNotLinkedError):
        service.unlink_alert(case.id, alert_id=alert.id, actor_id=analyst.id)


# =============================================================================
# list_cases_for_alert (Step 12V -- the reverse relationship)
# =============================================================================


def test_list_cases_for_alert_returns_zero_cases_for_an_unlinked_alert(db_session):
    service = _service(db_session)
    alert = _make_alert(db_session)

    assert service.list_cases_for_alert(alert.id, limit=50, offset=0) == []


def test_list_cases_for_alert_raises_not_found_for_unknown_alert(db_session):
    service = _service(db_session)

    with pytest.raises(AlertNotFoundError):
        service.list_cases_for_alert(uuid.uuid4(), limit=50, offset=0)


def test_list_cases_for_alert_returns_every_case_the_alert_is_linked_to(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    alert = _make_alert(db_session)
    case_a = service.create_case(title="a", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    case_b = service.create_case(title="b", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    unrelated_case = service.create_case(title="unrelated", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.link_alert(case_a.id, alert_id=alert.id, actor_id=analyst.id)
    service.link_alert(case_b.id, alert_id=alert.id, actor_id=analyst.id)

    result_ids = {c.id for c in service.list_cases_for_alert(alert.id, limit=50, offset=0)}

    assert result_ids == {case_a.id, case_b.id}
    assert unrelated_case.id not in result_ids


def test_list_cases_for_alert_stays_consistent_with_list_alerts_after_unlink(db_session):
    """Step 12V: the reverse query must reflect the SAME case_alerts
    state list_alerts (the existing Case -> Alert direction) already
    does -- there is exactly one relationship table, read from both
    directions, never two independently-maintained views of it.
    """
    analyst = _make_user(db_session)
    service = _service(db_session)
    alert = _make_alert(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    assert [c.id for c in service.list_cases_for_alert(alert.id, limit=50, offset=0)] == [case.id]
    assert [a.id for a in service.list_alerts(case.id)] == [alert.id]

    service.unlink_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    assert service.list_cases_for_alert(alert.id, limit=50, offset=0) == []
    assert service.list_alerts(case.id) == []


# =============================================================================
# Notes
# =============================================================================


def test_add_note_persists_with_author_and_no_audit_row(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    before_count = len(service.list_audits(case.id, limit=50, offset=0))

    note = service.add_note(case.id, body="Observed lateral movement.", actor_id=analyst.id)

    assert note.author_id == analyst.id
    assert note.body == "Observed lateral movement."
    assert len(service.list_audits(case.id, limit=50, offset=0)) == before_count


def test_add_note_to_nonexistent_case_raises(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    with pytest.raises(CaseNotFoundError):
        service.add_note(uuid.uuid4(), body="x", actor_id=analyst.id)
