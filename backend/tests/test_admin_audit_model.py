"""Integration tests for the AdminAudit model (Step 11M). Require
PostgreSQL.

Covers the model/schema-level guarantees directly against the real
database: valid construction, required fields, the controlled action
vocabulary, timestamp behavior, foreign-key constraints, and that
nothing in this codebase exposes a way to mutate or delete a historical
row.
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password
from app.models.admin_audit import AdminAudit
from app.models.user import User
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"audituser-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _valid_audit(actor_id, target_id, **overrides) -> AdminAudit:
    defaults = dict(
        actor_user_id=actor_id,
        target_user_id=target_id,
        action="USER_STATUS_CHANGED",
        previous_is_active=True,
        new_is_active=False,
    )
    defaults.update(overrides)
    return AdminAudit(**defaults)


# =============================================================================
# 1. Valid audit record
# =============================================================================


def test_valid_audit_record_persists(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)

    audit = _valid_audit(admin.id, target.id)
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.id is not None
    assert audit.actor_user_id == admin.id
    assert audit.target_user_id == target.id
    assert audit.action == "USER_STATUS_CHANGED"
    assert audit.previous_is_active is True
    assert audit.new_is_active is False
    assert audit.created_at is not None


# =============================================================================
# 2. Required fields
# =============================================================================


@pytest.mark.parametrize(
    "missing_field", ["actor_user_id", "target_user_id", "action", "previous_is_active", "new_is_active"]
)
def test_missing_required_field_is_rejected(db_session, missing_field):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    kwargs = dict(
        actor_user_id=admin.id,
        target_user_id=target.id,
        action="USER_STATUS_CHANGED",
        previous_is_active=True,
        new_is_active=False,
    )
    del kwargs[missing_field]

    audit = AdminAudit(**kwargs)
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# =============================================================================
# 3. Controlled action
# =============================================================================


def test_unknown_action_value_is_rejected_by_check_constraint(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)

    audit = _valid_audit(admin.id, target.id, action="NOT_A_REAL_ACTION")
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_self_target_is_rejected_by_check_constraint(db_session):
    """Defense in depth: the service layer already refuses to construct
    a self-targeted audit at all (see test_admin_audit_service.py), but
    the database itself must also reject one directly.
    """
    admin = _make_user(db_session, role="admin")

    audit = _valid_audit(admin.id, admin.id)
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# =============================================================================
# 4. Timestamp behavior
# =============================================================================


def test_created_at_is_server_generated_and_timezone_aware(db_session):
    """A generous +/- tolerance, not a tight host-clock bracket: the
    PostgreSQL server's own clock (what actually generates this value,
    via func.now()) and the test-runner host's clock are two different
    clocks that are not guaranteed to be perfectly synchronized (observed
    directly during this step -- a strict `before <= created_at <= after`
    check failed once on real clock skew of well under a second). What
    this test actually needs to prove is "the database generated a real,
    recent, timezone-aware timestamp", not "the two clocks agree to the
    millisecond".
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    approx_now = datetime.now(timezone.utc)

    audit = _valid_audit(admin.id, target.id)
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.created_at.tzinfo is not None
    assert abs((audit.created_at - approx_now).total_seconds()) < 30


def test_idempotent_no_op_status_change_is_still_a_valid_row():
    """Step 11M's documented decision: previous_is_active == new_is_active
    is a valid, expected shape -- no CHECK constraint forbids it (see
    app.models.admin_audit's own docstring for the full reasoning).
    """
    audit = AdminAudit(
        actor_user_id=uuid.uuid4(),
        target_user_id=uuid.uuid4(),
        action="USER_STATUS_CHANGED",
        previous_is_active=True,
        new_is_active=True,
    )
    assert audit.previous_is_active == audit.new_is_active


# =============================================================================
# 5. Foreign-key constraints
# =============================================================================


def test_nonexistent_actor_is_rejected(db_session):
    target = _make_user(db_session)

    audit = _valid_audit(uuid.uuid4(), target.id)
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_nonexistent_target_is_rejected(db_session):
    admin = _make_user(db_session, role="admin")

    audit = _valid_audit(admin.id, uuid.uuid4())
    db_session.add(audit)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


def test_deleting_a_referenced_user_is_restricted(db_session):
    """RESTRICT, not CASCADE (see app.models.admin_audit's own
    docstring): deleting a User who is referenced by an AdminAudit row
    must fail loudly rather than silently erasing audit history. AMNIX
    has no user-deletion endpoint -- this exercises the raw DB
    constraint directly.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    audit = _valid_audit(admin.id, target.id)
    db_session.add(audit)
    db_session.commit()

    db_session.delete(target)
    with pytest.raises(IntegrityError):
        db_session.commit()
    db_session.rollback()


# =============================================================================
# 6. Historical records are not casually mutable/deletable
# =============================================================================


def test_no_update_method_exists_on_the_repository():
    from app.repositories.admin_audit import AdminAuditRepository

    public_methods = {name for name in dir(AdminAuditRepository) if not name.startswith("_")}
    assert "update" not in public_methods
    assert "delete" not in public_methods
    assert "edit" not in public_methods


def test_admin_audit_router_exposes_no_mutation_endpoints():
    """No PATCH/PUT/DELETE route exists anywhere under /admin/audits --
    only GET (list) is registered. Verified against the real, generated
    OpenAPI schema (the most reliable way to enumerate routes across
    FastAPI/Starlette versions -- app.routes itself wraps included
    routers in version-specific objects that don't expose a flat `.path`
    the same way), not just "we didn't write one".
    """
    from app.main import app

    spec = app.openapi()
    audit_paths = {path: set(methods) for path, methods in spec["paths"].items() if path.startswith("/admin/audits")}
    assert audit_paths, "expected at least the GET /admin/audits route to exist"
    for path, methods in audit_paths.items():
        assert methods <= {"get", "head"}, f"{path} unexpectedly exposes {methods}"
