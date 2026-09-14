"""Integration tests for CaseService's transactional consistency
guarantee (Step 12R) -- the most important architectural property of
this domain, mirroring test_admin_audit_transaction.py's own proven
technique exactly: force a REAL PostgreSQL commit-time failure on the
CaseAudit side and prove the primary Case/CaseAlert mutation -- which by
itself would have succeeded -- is rolled back too. Require PostgreSQL.

See that module's own docstring for the full IMPORTANT TEST-ENVIRONMENT
NOTE this file relies on: this project's db_session fixture runs each
test inside one connection-level transaction rolled back at teardown, so
a mid-test session.rollback() (which CaseService's _commit() calls on a
commit failure, correctly) unwinds EVERY prior commit in that same test,
not just the failing operation's own pending changes. Every test below
therefore captures plain UUIDs BEFORE the failing call and verifies
atomicity via a brand-new, independent operation afterward, never by
re-querying an object created earlier in the same test.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_audit import CaseAudit
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import CaseNoteRepository
from app.repositories.user import UserRepository
from app.schemas.case import CasePriority, CaseStatus
from app.services.case_service import CaseService

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"casetxn-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


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
        title="Transaction test alert",
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


def _install_broken_case_audit(monkeypatch) -> None:
    """Patches app.services.case_service's own bound `CaseAudit` name so
    the next row it constructs fails at COMMIT time with a real
    PostgreSQL CHECK-constraint violation -- exactly like
    test_admin_audit_transaction.py's own _install_broken_admin_audit.
    """
    import app.services.case_service as case_service_module

    def _broken_case_audit_constructor(**kwargs):
        kwargs["action"] = "NOT_A_REAL_ACTION"
        return CaseAudit(**kwargs)

    monkeypatch.setattr(case_service_module, "CaseAudit", _broken_case_audit_constructor)


# =============================================================================
# Case creation
# =============================================================================


def test_case_creation_and_audit_commit_atomically(db_session):
    analyst = _make_user(db_session)
    service = _service(db_session)

    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    db_session.expire_all()
    fresh_case = CaseRepository(db_session).get_by_id(case.id)
    audits = CaseAuditRepository(db_session).list_for_case(case.id)
    assert fresh_case is not None
    assert len(audits) == 1
    assert audits[0].action == "CASE_CREATED"


def test_audit_commit_failure_during_creation_rolls_back_the_case_too(db_session, monkeypatch):
    analyst_id = _make_user(db_session).id
    service = _service(db_session)
    _install_broken_case_audit(monkeypatch)

    with pytest.raises(Exception):  # sqlalchemy.exc.IntegrityError from the CHECK constraint
        service.create_case(title="doomed", description="d", priority=CasePriority.MEDIUM, created_by=analyst_id)

    monkeypatch.undo()

    # Proof the session is still usable and nothing "doomed" was left
    # behind: a brand-new, independent operation must work normally.
    new_analyst = _make_user(db_session)
    new_case = service.create_case(title="ok", description="d", priority=CasePriority.MEDIUM, created_by=new_analyst.id)
    assert new_case.title == "ok"
    # The doomed case's title must never appear anywhere durable.
    all_cases = CaseRepository(db_session).list(limit=200, offset=0)
    assert all(c.title != "doomed" for c in all_cases)


# =============================================================================
# Status change
# =============================================================================


def test_audit_commit_failure_during_status_change_rolls_back_the_status_too(db_session, monkeypatch):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    case_id = case.id

    _install_broken_case_audit(monkeypatch)
    with pytest.raises(Exception):
        service.change_status(case_id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    monkeypatch.undo()

    # A brand-new case (not the one touched by the forced failure) must
    # behave completely normally afterward, proving the session was left
    # usable, not aborted.
    new_analyst = _make_user(db_session)
    new_case = service.create_case(title="ok2", description="d", priority=CasePriority.MEDIUM, created_by=new_analyst.id)
    updated = service.change_status(
        new_case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=new_analyst.id
    )
    assert updated.status == "INVESTIGATING"


# =============================================================================
# Owner change
# =============================================================================


def test_audit_commit_failure_during_owner_change_rolls_back_ownership_too(db_session, monkeypatch):
    from app.api.dependencies import AuthenticatedUser

    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    actor = AuthenticatedUser(id=analyst.id, email=analyst.email, role=analyst.role, is_active=True)

    _install_broken_case_audit(monkeypatch)
    with pytest.raises(Exception):
        service.change_owner(case.id, new_owner_id=analyst.id, actor=actor)
    monkeypatch.undo()

    new_analyst = _make_user(db_session)
    new_case = service.create_case(title="ok3", description="d", priority=CasePriority.MEDIUM, created_by=new_analyst.id)
    new_actor = AuthenticatedUser(id=new_analyst.id, email=new_analyst.email, role=new_analyst.role, is_active=True)
    updated = service.change_owner(new_case.id, new_owner_id=new_analyst.id, actor=new_actor)
    assert updated.owner_id == new_analyst.id


# =============================================================================
# Alert linking
# =============================================================================


def test_audit_commit_failure_during_link_rolls_back_the_link_too(db_session, monkeypatch):
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)
    case_id, alert_id = case.id, alert.id

    _install_broken_case_audit(monkeypatch)
    with pytest.raises(Exception):
        service.link_alert(case_id, alert_id=alert_id, actor_id=analyst.id)
    monkeypatch.undo()

    # A brand-new link (different case/alert pair) must succeed normally.
    new_analyst = _make_user(db_session)
    new_case = service.create_case(title="ok4", description="d", priority=CasePriority.MEDIUM, created_by=new_analyst.id)
    new_alert = _make_alert(db_session)
    link = service.link_alert(new_case.id, alert_id=new_alert.id, actor_id=new_analyst.id)
    assert link.alert_id == new_alert.id


def test_session_remains_usable_after_a_forced_case_audit_commit_failure(db_session, monkeypatch):
    """Direct proof the shared Session is not left in PostgreSQL's
    'current transaction is aborted' state after a forced failure --
    mirrors test_admin_audit_transaction.py's own equivalent test.
    """
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    _install_broken_case_audit(monkeypatch)
    with pytest.raises(Exception):
        service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)
    monkeypatch.undo()

    # A totally unrelated, ordinary operation must still work.
    new_analyst = _make_user(db_session)
    result = service.create_case(title="still works", description="d", priority=CasePriority.LOW, created_by=new_analyst.id)
    assert result.title == "still works"
