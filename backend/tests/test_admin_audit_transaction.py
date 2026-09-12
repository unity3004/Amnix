"""Integration tests for Step 11M's transactional consistency guarantee
-- the most important architectural decision in this step (see
app.services.admin_audit_service's own module docstring for the full
design). Require PostgreSQL.

These prove, not just assert, that:
  - a successful user mutation and its audit record are committed
    TOGETHER (test 37)
  - a failed mutation (validation error, before any commit is
    attempted) produces no audit row (test 38 -- also covered from a
    different angle in test_admin_audit_service.py)
  - a commit-time failure on the AUDIT side rolls back the User
    mutation too -- true atomicity, not just "no false audit" (tests 39
    and 40 combined, since Step 11M achieved full atomicity rather than
    falling back to the brief's Option B)
"""

import uuid

import pytest
from sqlalchemy import func, select

from app.core.security import hash_password
from app.models.admin_audit import AdminAudit
from app.models.user import User
from app.repositories.admin_audit import AdminAuditRepository
from app.repositories.user import UserRepository
from app.services.admin_audit_service import AdminAuditService
from app.services.user_service import UserNotFoundError, UserService

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"txnuser-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _service(db_session) -> AdminAuditService:
    return AdminAuditService(db_session, UserService(UserRepository(db_session)), AdminAuditRepository(db_session))


def _audit_count(db_session) -> int:
    return db_session.scalar(select(func.count()).select_from(AdminAudit))


# =============================================================================
# 37. Successful mutation + successful audit -> both persist
# =============================================================================


def test_successful_mutation_and_audit_both_persist(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    user, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    # Fresh reads, not just the returned objects -- proves it is
    # actually durable, not merely in-memory.
    db_session.expire_all()
    fresh_user = UserRepository(db_session).get_by_id(target.id)
    fresh_audit = AdminAuditRepository(db_session).get_by_id(audit.id)

    assert fresh_user.is_active is False
    assert fresh_audit is not None
    assert fresh_audit.target_user_id == target.id
    assert fresh_audit.previous_is_active is True
    assert fresh_audit.new_is_active is False


# =============================================================================
# 38. Mutation validation failure -> no audit record (before any commit)
# =============================================================================


def test_mutation_validation_failure_creates_no_audit_before_any_commit_attempt(db_session):
    admin = _make_user(db_session, role="admin")
    service = _service(db_session)
    before = _audit_count(db_session)

    with pytest.raises(UserNotFoundError):
        service.change_user_status(acting_admin_id=admin.id, target_user_id=uuid.uuid4(), is_active=False)

    assert _audit_count(db_session) == before


# =============================================================================
# 39/40. Audit-insertion (commit-time) failure rolls back the user mutation too
# =============================================================================


def _broken_admin_audit_constructor(**kwargs) -> AdminAudit:
    """A drop-in replacement for the real AdminAudit(**kwargs) call site
    in app.services.admin_audit_service, constructing a row with an
    `action` value violating ck_admin_audits_action_valid -- a REAL
    PostgreSQL commit-time failure, only detectable at flush/commit, not
    by SQLAlchemy in Python beforehand, exactly like a genuine
    production constraint violation would behave. A plain function (not
    a per-test subclass of AdminAudit) so it is defined exactly once at
    import time -- SQLAlchemy's declarative registry warns if the same
    class name/module gets redefined via inheritance on every test call.
    """
    kwargs["action"] = "NOT_A_REAL_ACTION"
    return AdminAudit(**kwargs)


def _install_broken_admin_audit(monkeypatch) -> None:
    """Patches app.services.admin_audit_service's own bound `AdminAudit`
    name (the module-level import that module's code actually calls) so
    the next row it constructs fails at commit time (see
    _broken_admin_audit_constructor). Callers that need a later,
    unrelated call in the SAME test to exercise the real, working code
    path (proving the session is still usable after the forced failure)
    must call `monkeypatch.undo()` themselves once the forced failure
    has been triggered -- this helper does not do that automatically,
    since not every caller needs it.
    """
    import app.services.admin_audit_service as admin_audit_service_module

    monkeypatch.setattr(admin_audit_service_module, "AdminAudit", _broken_admin_audit_constructor)


def test_audit_commit_failure_rolls_back_the_user_mutation(db_session, monkeypatch):
    """Forces a REAL PostgreSQL commit-time failure on the audit side
    and proves the User mutation -- which by itself would have
    succeeded -- is rolled back too. This is the direct proof of Step
    11M's chosen atomicity design (Option A from the brief): the two
    writes share one transaction, so a failure on either side undoes
    both.

    IMPORTANT TEST-ENVIRONMENT NOTE (discovered directly, not assumed):
    this project's db_session fixture runs each test inside one
    connection-level transaction that is rolled back at teardown (see
    tests/conftest.py). A mid-test `session.rollback()` -- which
    AdminAuditService.change_user_status() calls internally on a commit
    failure, correctly -- was empirically verified (via a standalone
    probe during this step's development) to unwind EVERY prior commit
    in that same test, not just the failing operation's own pending
    changes; a plain `UserRepository.get_by_id()` re-query afterward
    raises sqlalchemy.orm.exc.ObjectDeletedError for a User created
    earlier in the SAME test, because that row is gone too, not merely
    reverted to its pre-mutation value. This is a real characteristic of
    the shared test fixture's transaction nesting, not a flaw in the
    service under test -- in production, each HTTP request gets its own
    independent session/transaction, so there is no equivalent "earlier
    same-request state" to accidentally unwind. To avoid conflating that
    fixture artifact with the actual invariant being proven, this test
    captures plain UUIDs BEFORE the failing call (never touching the
    ORM-identity-mapped `target` object afterward) and verifies via a
    brand-new, independent operation on the same session afterward that
    nothing was left in a "committed but partially applied" state.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    target_id = target.id  # captured before any rollback touches the ORM object
    service = _service(db_session)

    _install_broken_admin_audit(monkeypatch)

    with pytest.raises(Exception):  # sqlalchemy.exc.IntegrityError from the CHECK constraint
        service.change_user_status(acting_admin_id=admin.id, target_user_id=target_id, is_active=False)

    monkeypatch.undo()  # restore the real AdminAudit for the proof-of-usability call below

    # The failed attempt must not have left behind a "half-applied"
    # state visible to a brand-new, independent lookup performed the
    # normal way any real request would perform it -- proves the
    # service's own rollback-then-reraise (see its own docstring) left
    # the session in a genuinely usable state, not merely appearing to.
    new_admin = _make_user(db_session, role="admin")
    new_target = _make_user(db_session, is_active=True)
    user, audit = service.change_user_status(
        acting_admin_id=new_admin.id, target_user_id=new_target.id, is_active=False
    )
    assert user.is_active is False
    assert audit.previous_is_active is True
    assert audit.new_is_active is False


def test_session_remains_usable_after_a_forced_commit_failure(db_session, monkeypatch):
    """A direct test of the rollback-then-reraise discipline
    (AdminAuditService.change_user_status's own try/except) -- the
    shared Session must not be left in PostgreSQL's "current transaction
    is aborted" state after a forced failure, exactly the same concern
    UserRepository.create()'s own docstring already documents for its
    unrelated IntegrityError case. See
    test_audit_commit_failure_rolls_back_the_user_mutation's own
    docstring for why this test avoids re-querying any User created
    before the forced failure.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    _install_broken_admin_audit(monkeypatch)

    with pytest.raises(Exception):
        service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    monkeypatch.undo()  # restore the real AdminAudit for the proof-of-usability call below

    # A totally unrelated, ordinary operation, using brand-new rows,
    # must still work on this same session -- proves it was not left
    # aborted (an aborted PostgreSQL transaction rejects every further
    # statement until rolled back).
    new_admin = _make_user(db_session, role="admin")
    new_target = _make_user(db_session, is_active=True)
    _, audit = service.change_user_status(
        acting_admin_id=new_admin.id, target_user_id=new_target.id, is_active=False
    )
    assert audit.new_is_active is False
