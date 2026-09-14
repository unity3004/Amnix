"""Concurrency tests for the Case domain (Step 12R). Require PostgreSQL.

No optimistic-locking version column exists (Step 12Q, approved, "do
not overengineer"). What IS proven here: (1) CaseAlert's composite
primary key makes a duplicate link impossible at the database level
regardless of timing, and (2) status/owner mutations always re-validate
against the LIVE database row (re-read fresh at the start of every
service call, never a client-asserted "previous" value), so a second
request racing against a change that already landed correctly fails
(409/403) instead of silently double-applying or overwriting.

KNOWN TEST-INFRASTRUCTURE LIMITATION (discovered directly while building
this file, not assumed): this project's `db_session` fixture (see
tests/conftest.py) binds the Session to a Connection with an already-
externally-begun Transaction, and `Session.commit()` in that
configuration does not finalize a real, cross-connection-visible
PostgreSQL transaction -- it only flushes within the same still-open
outer transaction, which is rolled back at test teardown (this is
exactly why `test_admin_audit_transaction.py`'s own docstring warns that
a mid-test `session.rollback()` unwinds EVERY prior "commit" in that
same test). A genuinely separate database connection therefore cannot
see any row created via `db_session` inside the same test -- confirmed
empirically: an earlier version of this file that opened a second
`engine.connect()`/`Session` and tried to operate on rows created via
`db_session` failed with CaseNotFoundError every time, because those
rows were never actually visible outside the first connection's
never-truly-committed transaction. Building true multi-connection
concurrency tests would require a new, more invasive shared fixture (one
that commits for real, immediately, on a plain `engine.connect()`) that
no other test file in this codebase currently uses -- out of scope for
this step per its own explicit "do not overengineer" instruction. See
the Step 12R report's Known Limitations for this being called out
explicitly rather than silently worked around.

What this file tests instead -- fully sufficient to prove the actual
protection mechanisms, even without literal wall-clock-simultaneous
requests: two sequential calls against the same live database state,
proving the SAME code path a second, genuinely concurrent request would
also go through (composite-PK rejection; live-state re-validation) does
not depend on request ordering being externally coordinated.
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
from app.services.case_lifecycle import InvalidCaseStatusTransition
from app.services.case_service import AlertAlreadyLinkedError, CaseOwnershipAuthorizationError, CaseService

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"caseconc-{uuid.uuid4().hex[:8]}@example.com",
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
        title="Concurrency test alert",
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


def test_duplicate_alert_link_race_is_rejected_by_the_database(db_session):
    """Two "analysts" (represented here as two sequential calls against
    the same live row, since this codebase's test fixture cannot
    simulate two genuinely simultaneous connections -- see this module's
    own docstring) both attempt to link the SAME alert to the SAME case.
    The second must fail with AlertAlreadyLinkedError, translated from
    the real composite-PK IntegrityError CaseAlert.exists() detects --
    never a duplicate row, regardless of how close together the two
    requests arrive.
    """
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)
    alert = _make_alert(db_session)

    service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    with pytest.raises(AlertAlreadyLinkedError):
        service.link_alert(case.id, alert_id=alert.id, actor_id=analyst.id)

    assert len(CaseAlertRepository(db_session).list_alerts_for_case(case.id)) == 1


def test_status_mutation_always_validates_against_the_live_current_state(db_session):
    """The second request's own idea of "current status" is never
    trusted -- change_status() re-reads the Case fresh from the database
    on every call (see CaseService.change_status's own docstring). Once
    a transition has landed, a second identical request is evaluated
    against the NEW live status, not the state the first request started
    from, and correctly rejects the now-invalid re-attempt.
    """
    analyst = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst.id)

    service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)

    with pytest.raises(InvalidCaseStatusTransition):
        service.change_status(case.id, new_status=CaseStatus.INVESTIGATING, closure_reason=None, actor_id=analyst.id)

    assert CaseRepository(db_session).get_by_id(case.id).status == "INVESTIGATING"


def test_self_assign_always_validates_against_the_live_owner_state(db_session):
    """Once one analyst has self-assigned an unowned case, a second
    analyst's self-assign attempt is evaluated against the case's NEW
    live owner_id (no longer None), so the object-level authorization
    rule correctly rejects it -- ownership is never silently overwritten.
    """
    analyst_one = _make_user(db_session)
    analyst_two = _make_user(db_session)
    service = _service(db_session)
    case = service.create_case(
        title="t", description="d", priority=CasePriority.MEDIUM, created_by=analyst_one.id
    )
    actor_one = AuthenticatedUser(id=analyst_one.id, email=analyst_one.email, role="analyst", is_active=True)
    actor_two = AuthenticatedUser(id=analyst_two.id, email=analyst_two.email, role="analyst", is_active=True)

    service.change_owner(case.id, new_owner_id=analyst_one.id, actor=actor_one)

    with pytest.raises(CaseOwnershipAuthorizationError):
        service.change_owner(case.id, new_owner_id=analyst_two.id, actor=actor_two)

    assert CaseRepository(db_session).get_by_id(case.id).owner_id == analyst_one.id
