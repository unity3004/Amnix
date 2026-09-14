"""Integration tests for the Case/CaseAlert/CaseAudit/CaseNote models
(Step 12R). Require PostgreSQL.

Covers model/schema-level guarantees directly against the real
database: valid construction, non-blank/enum CHECK constraints,
case_number uniqueness (via the native sequence), composite PK on
CaseAlert, related_alert_id/action consistency on CaseAudit, and FK
RESTRICT/CASCADE behavior.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case, CaseAlert
from app.models.case_audit import CaseAudit
from app.models.case_note import CaseNote
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"caseuser-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _make_alert(db_session, **overrides) -> Alert:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc),
        event_type="authentication_failure",
        source="test",
        raw_data={},
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="Test case-model alert",
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


def _make_case(db_session, created_by, **overrides) -> Case:
    defaults = dict(title="Test case", description="A test case description.", created_by=created_by)
    defaults.update(overrides)
    case = Case(**defaults)
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


# =============================================================================
# Case model
# =============================================================================


def test_valid_case_persists_with_defaults(db_session):
    analyst = _make_user(db_session)

    case = _make_case(db_session, analyst.id)

    assert case.id is not None
    assert isinstance(case.case_number, int)
    assert case.status == "OPEN"
    assert case.priority == "medium"
    assert case.owner_id is None
    assert case.closed_at is None
    assert case.closure_reason is None
    assert case.created_at is not None
    assert case.updated_at is not None


def test_case_number_is_unique_and_sequential(db_session):
    analyst = _make_user(db_session)

    case_a = _make_case(db_session, analyst.id)
    case_b = _make_case(db_session, analyst.id)

    assert case_a.case_number != case_b.case_number


def test_case_number_cannot_be_forced_to_duplicate(db_session):
    analyst = _make_user(db_session)
    case_a = _make_case(db_session, analyst.id)

    duplicate = Case(title="dup", description="d", created_by=analyst.id, case_number=case_a.case_number)
    db_session.add(duplicate)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_blank_title_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = Case(title="   ", description="d", created_by=analyst.id)
    db_session.add(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_blank_description_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="   ", created_by=analyst.id)
    db_session.add(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_invalid_status_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id, status="NOT_A_REAL_STATUS")
    db_session.add(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.parametrize("status", ["OPEN", "INVESTIGATING", "RESOLVED", "CLOSED"])
def test_valid_status_values_are_accepted(db_session, status):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id, status=status)
    assert case.status == status


def test_invalid_priority_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id, priority="urgent")
    db_session.add(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


@pytest.mark.parametrize("priority", ["critical", "high", "medium", "low"])
def test_valid_priority_values_are_accepted(db_session, priority):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id, priority=priority)
    assert case.priority == priority


def test_nonexistent_created_by_is_rejected(db_session):
    case = Case(title="t", description="d", created_by=uuid.uuid4())
    db_session.add(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_user_referenced_as_created_by_is_restricted(db_session):
    analyst = _make_user(db_session)
    _make_case(db_session, analyst.id)

    db_session.delete(analyst)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_user_referenced_as_owner_is_restricted(db_session):
    analyst = _make_user(db_session)
    owner = _make_user(db_session)
    _make_case(db_session, analyst.id, owner_id=owner.id)

    db_session.delete(owner)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# =============================================================================
# CaseAlert (composite PK / join table)
# =============================================================================


def test_case_alert_link_persists(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)

    link = CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id)
    db_session.add(link)
    db_session.commit()

    assert link.linked_at is not None


def test_duplicate_case_alert_link_is_rejected_by_composite_pk(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)

    db_session.add(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    db_session.commit()

    db_session.add(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_linking_a_nonexistent_alert_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    db_session.add(CaseAlert(case_id=case.id, alert_id=uuid.uuid4(), linked_by=analyst.id))
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_an_alert_referenced_by_a_case_is_restricted(db_session):
    """The Alert itself must never be deletable while cited by a case --
    mirrors alert_security_events' own RESTRICT-on-security_event_id
    reasoning.
    """
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)
    db_session.add(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    db_session.commit()

    db_session.delete(alert)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_case_cascades_to_case_alerts(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)
    db_session.add(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    db_session.commit()

    db_session.delete(case)
    db_session.commit()

    assert db_session.get(CaseAlert, (case.id, alert.id)) is None


# =============================================================================
# CaseAudit
# =============================================================================


def test_valid_case_created_audit_persists(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    audit = CaseAudit(case_id=case.id, actor_user_id=analyst.id, action="CASE_CREATED", new_value="title='t'")
    db_session.add(audit)
    db_session.commit()

    assert audit.id is not None
    assert audit.related_alert_id is None


def test_unknown_audit_action_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    audit = CaseAudit(case_id=case.id, actor_user_id=analyst.id, action="NOT_A_REAL_ACTION")
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_link_action_without_related_alert_id_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    audit = CaseAudit(case_id=case.id, actor_user_id=analyst.id, action="CASE_ALERT_LINKED", related_alert_id=None)
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_non_link_action_with_related_alert_id_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)

    audit = CaseAudit(
        case_id=case.id, actor_user_id=analyst.id, action="CASE_STATUS_CHANGED", related_alert_id=alert.id
    )
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_link_action_with_related_alert_id_is_accepted(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    alert = _make_alert(db_session)

    audit = CaseAudit(
        case_id=case.id, actor_user_id=analyst.id, action="CASE_ALERT_LINKED", related_alert_id=alert.id
    )
    db_session.add(audit)
    db_session.commit()

    assert audit.related_alert_id == alert.id


def test_deleting_a_case_referenced_by_an_audit_is_restricted(db_session):
    """RESTRICT, not CASCADE (unlike CaseAlert/CaseNote): an audit row is
    an accountability record that must outlive its Case, mirroring
    AdminAudit's own actor/target RESTRICT reasoning exactly.
    """
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    db_session.add(CaseAudit(case_id=case.id, actor_user_id=analyst.id, action="CASE_CREATED"))
    db_session.commit()

    db_session.delete(case)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# =============================================================================
# CaseNote
# =============================================================================


def test_valid_case_note_persists(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    note = CaseNote(case_id=case.id, author_id=analyst.id, body="Observed lateral movement.")
    db_session.add(note)
    db_session.commit()

    assert note.id is not None
    assert note.created_at is not None


def test_blank_case_note_body_is_rejected(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)

    note = CaseNote(case_id=case.id, author_id=analyst.id, body="   ")
    db_session.add(note)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_case_cascades_to_case_notes(db_session):
    analyst = _make_user(db_session)
    case = _make_case(db_session, analyst.id)
    note = CaseNote(case_id=case.id, author_id=analyst.id, body="A note.")
    db_session.add(note)
    db_session.commit()
    note_id = note.id

    db_session.delete(case)
    db_session.commit()

    assert db_session.get(CaseNote, note_id) is None


def test_case_note_has_no_updated_at_column():
    """v1 is fully immutable -- no edit path exists at all (Step 12Q/12R
    decision)."""
    assert not hasattr(CaseNote, "updated_at")
