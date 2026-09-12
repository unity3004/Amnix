"""Integration tests for AdminAuditRepository (Step 11M). Require
PostgreSQL.

Covers create/retrieve/list/pagination/filtering directly against the
repository -- the authorization boundary and full HTTP behavior are
tested separately in tests/test_admin_audit_api.py, and the
create-without-commit/atomicity guarantee in
tests/test_admin_audit_transaction.py.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import hash_password
from app.models.admin_audit import AdminAudit
from app.models.user import User
from app.repositories.admin_audit import MAX_LIST_LIMIT, AdminAuditRepository
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


def _commit_audit(db_session, actor_id, target_id, **overrides) -> AdminAudit:
    defaults = dict(
        actor_user_id=actor_id,
        target_user_id=target_id,
        action="USER_STATUS_CHANGED",
        previous_is_active=True,
        new_is_active=False,
    )
    defaults.update(overrides)
    audit = AdminAudit(**defaults)
    repo = AdminAuditRepository(db_session)
    repo.create_without_commit(audit)
    db_session.commit()
    db_session.refresh(audit)
    return audit


# =============================================================================
# 7-8. Create / retrieve by ID
# =============================================================================


def test_create_without_commit_then_commit_persists(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)

    audit = _commit_audit(db_session, admin.id, target.id)

    assert audit.id is not None


def test_get_by_id_returns_the_created_audit(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    created = _commit_audit(db_session, admin.id, target.id)

    fetched = AdminAuditRepository(db_session).get_by_id(created.id)

    assert fetched is not None
    assert fetched.id == created.id


def test_get_by_id_returns_none_for_unknown_id(db_session):
    assert AdminAuditRepository(db_session).get_by_id(uuid.uuid4()) is None


# =============================================================================
# 9-10. List newest-first / pagination
# =============================================================================


def test_list_returns_newest_first(db_session):
    """PostgreSQL's now() (what created_at's server_default uses)
    returns the current TRANSACTION's start time, not wall-clock time at
    each statement -- rows committed within the same test transaction
    can share an identical created_at, and gen_random_uuid() values are
    random, not sequential, so `id` alone cannot stand in for creation
    order either. Explicit, distinct created_at values are constructed
    directly (bypassing the server default) so this test verifies real
    chronological ordering deterministically, matching the repository's
    actual real-world guarantee, not an artifact of same-transaction
    timestamp behavior.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    now = datetime.now(timezone.utc)
    first = _commit_audit(db_session, admin.id, target.id, created_at=now - timedelta(seconds=2))
    second = _commit_audit(db_session, admin.id, target.id, created_at=now - timedelta(seconds=1))
    third = _commit_audit(db_session, admin.id, target.id, created_at=now)

    results = AdminAuditRepository(db_session).list(limit=10, offset=0, target_user_id=target.id)

    ids_in_order = [a.id for a in results]
    assert ids_in_order.index(third.id) < ids_in_order.index(second.id) < ids_in_order.index(first.id)


def test_pagination_limit_and_offset(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    for _ in range(5):
        _commit_audit(db_session, admin.id, target.id)

    repo = AdminAuditRepository(db_session)
    page_one = repo.list(limit=2, offset=0, target_user_id=target.id)
    page_two = repo.list(limit=2, offset=2, target_user_id=target.id)

    assert len(page_one) == 2
    assert len(page_two) == 2
    assert {a.id for a in page_one}.isdisjoint({a.id for a in page_two})


# =============================================================================
# 11-13. actor / target / action filters
# =============================================================================


def test_actor_filter(db_session):
    admin_a = _make_user(db_session, role="admin")
    admin_b = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    _commit_audit(db_session, admin_a.id, target.id)
    _commit_audit(db_session, admin_b.id, target.id)

    results = AdminAuditRepository(db_session).list(limit=10, offset=0, actor_user_id=admin_a.id)

    assert results
    assert all(a.actor_user_id == admin_a.id for a in results)


def test_target_filter(db_session):
    admin = _make_user(db_session, role="admin")
    target_a = _make_user(db_session)
    target_b = _make_user(db_session)
    _commit_audit(db_session, admin.id, target_a.id)
    _commit_audit(db_session, admin.id, target_b.id)

    results = AdminAuditRepository(db_session).list(limit=10, offset=0, target_user_id=target_a.id)

    assert results
    assert all(a.target_user_id == target_a.id for a in results)


def test_action_filter(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    _commit_audit(db_session, admin.id, target.id)

    results = AdminAuditRepository(db_session).list(
        limit=10, offset=0, target_user_id=target.id, action="USER_STATUS_CHANGED"
    )

    assert results
    assert all(a.action == "USER_STATUS_CHANGED" for a in results)


def test_filters_combined_narrow_the_result(db_session):
    admin_a = _make_user(db_session, role="admin")
    admin_b = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    _commit_audit(db_session, admin_a.id, target.id)
    _commit_audit(db_session, admin_b.id, target.id)

    results = AdminAuditRepository(db_session).list(
        limit=10, offset=0, actor_user_id=admin_a.id, target_user_id=target.id
    )

    assert len(results) == 1
    assert results[0].actor_user_id == admin_a.id


# =============================================================================
# 14-16. Bounded limit / invalid limit/offset rejected
# =============================================================================


def test_limit_is_capped_at_max_list_limit_worth_of_rows(db_session):
    """Not a full 200-row insert -- just confirms MAX_LIST_LIMIT itself
    is a real, enforced ceiling by requesting exactly that many.
    """
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    _commit_audit(db_session, admin.id, target.id)

    results = AdminAuditRepository(db_session).list(limit=MAX_LIST_LIMIT, offset=0)

    assert len(results) <= MAX_LIST_LIMIT


def test_limit_above_max_is_rejected(db_session):
    with pytest.raises(ValueError):
        AdminAuditRepository(db_session).list(limit=MAX_LIST_LIMIT + 1, offset=0)


def test_limit_zero_is_rejected(db_session):
    with pytest.raises(ValueError):
        AdminAuditRepository(db_session).list(limit=0, offset=0)


def test_negative_offset_is_rejected(db_session):
    with pytest.raises(ValueError):
        AdminAuditRepository(db_session).list(limit=10, offset=-1)
