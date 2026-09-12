"""Integration tests for AdminAuditService (Step 11M). Require
PostgreSQL.

Covers the service-level business behavior directly: correct audit data
on success, actor/target correctness, before/after state, the
server-controlled action, and that failed/self-target/nonexistent-target
operations create no audit row at all. The full atomic-transaction
guarantee (commit-failure rollback) is tested separately in
tests/test_admin_audit_transaction.py; the authorization boundary (who
may call this at all) is tested separately in
tests/test_admin_audit_api.py against the full HTTP stack -- this file
tests the service directly, which has no authorization logic of its own
at all (see AdminAuditService's own docstring: RBAC is entirely
require_admin's job, upstream of this service).
"""

import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import func, select

from app.core.security import hash_password
from app.models.admin_audit import AdminAudit
from app.models.user import User
from app.repositories.admin_audit import AdminAuditRepository
from app.repositories.user import UserRepository
from app.services.admin_audit_service import AdminAuditService
from app.services.user_service import CannotModifyOwnAccountError, UserNotFoundError, UserService

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


def _service(db_session) -> AdminAuditService:
    return AdminAuditService(db_session, UserService(UserRepository(db_session)), AdminAuditRepository(db_session))


def _audit_count(db_session) -> int:
    return db_session.scalar(select(func.count()).select_from(AdminAudit))


# =============================================================================
# 17-22. Successful status change: correct data, actor/target, before/after, action
# =============================================================================


def test_successful_status_change_creates_correct_audit_data(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    user, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert user.is_active is False
    assert audit.actor_user_id == admin.id
    assert audit.target_user_id == target.id
    assert audit.action == "USER_STATUS_CHANGED"
    assert audit.previous_is_active is True
    assert audit.new_is_active is False
    assert isinstance(audit.created_at, datetime)
    assert audit.created_at.tzinfo is not None


def test_actor_user_id_comes_from_authenticated_identity_argument(db_session):
    """The service takes acting_admin_id as an explicit argument (the
    route passes AuthenticatedUser.id, from get_current_user -- Step
    11E) -- it never derives actor identity from the target, the
    request, or anywhere else.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert audit.actor_user_id == admin.id
    assert audit.actor_user_id != target.id


def test_target_user_id_comes_from_the_requested_target(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert audit.target_user_id == target.id


def test_previous_state_is_correct_when_disabling(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert audit.previous_is_active is True


def test_previous_state_is_correct_when_enabling(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=False)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=True)

    assert audit.previous_is_active is False


def test_new_state_is_correct(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert audit.new_is_active is False


def test_idempotent_no_op_change_still_creates_an_audit_record(db_session):
    """Step 11M's documented decision (see app.models.admin_audit's own
    docstring): a no-op status change is still a full, ordinary success
    at the API/service level, so it is still recorded.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    _, audit = service.change_user_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=True)

    assert audit.previous_is_active is True
    assert audit.new_is_active is True


def test_action_is_server_controlled_and_cannot_be_influenced_by_caller(db_session):
    """change_user_status() has no `action` parameter at all -- there is
    no code path a caller could use to request a different action value.
    """
    import inspect

    signature = inspect.signature(AdminAuditService.change_user_status)
    assert "action" not in signature.parameters


# =============================================================================
# 23-25. Failed operations create no audit
# =============================================================================


def test_failed_mutation_nonexistent_target_creates_no_audit(db_session):
    admin = _make_user(db_session, role="admin")
    service = _service(db_session)
    before = _audit_count(db_session)

    with pytest.raises(UserNotFoundError):
        service.change_user_status(acting_admin_id=admin.id, target_user_id=uuid.uuid4(), is_active=False)

    assert _audit_count(db_session) == before


def test_self_target_creates_no_audit(db_session):
    admin = _make_user(db_session, role="admin")
    service = _service(db_session)
    before = _audit_count(db_session)

    with pytest.raises(CannotModifyOwnAccountError):
        service.change_user_status(acting_admin_id=admin.id, target_user_id=admin.id, is_active=False)

    assert _audit_count(db_session) == before


def test_self_target_does_not_mutate_the_admins_own_state(db_session):
    admin = _make_user(db_session, role="admin", is_active=True)
    service = _service(db_session)

    with pytest.raises(CannotModifyOwnAccountError):
        service.change_user_status(acting_admin_id=admin.id, target_user_id=admin.id, is_active=False)

    db_session.expire_all()
    fresh = UserRepository(db_session).get_by_id(admin.id)
    assert fresh.is_active is True


# =============================================================================
# 26. Unauthorized caller cannot create audit
# =============================================================================


def test_service_has_no_authorization_logic_of_its_own(db_session):
    """AdminAuditService performs no role/authorization check anywhere
    in change_user_status() -- authorization is entirely require_admin's
    job (Step 11F), upstream, at the route layer (see
    tests/test_admin_audit_api.py for the actual 401/403 boundary
    tests). This test documents and verifies that claim directly: the
    service happily proceeds for ANY acting_admin_id passed to it,
    including one belonging to an analyst account -- proving the
    boundary is enforced by the caller (the route), not duplicated here.
    """
    analyst = _make_user(db_session, role="analyst")
    target = _make_user(db_session)
    service = _service(db_session)

    # The service itself has no way to know or care that `analyst` is
    # not an admin -- that check never happens inside this service.
    user, audit = service.change_user_status(
        acting_admin_id=analyst.id, target_user_id=target.id, is_active=False
    )

    assert audit.actor_user_id == analyst.id
    assert user.is_active is False
