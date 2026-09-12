"""Integration tests for UserService (Step 11G). Require PostgreSQL (see
conftest.py's db_session fixture).

These test the business logic directly (self-target rejection, not-found
handling, idempotency, field isolation) — the authorization boundary
(who may call this at all) is tested separately in tests/test_admin_api.py
against the full HTTP stack.
"""

import uuid

import pytest

from app.core.security import hash_password
from app.models.user import User
from app.repositories.user import UserRepository
from app.services.user_service import CannotModifyOwnAccountError, UserNotFoundError, UserService

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"user-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _service(db_session) -> UserService:
    return UserService(UserRepository(db_session))


def test_disabling_an_active_user_succeeds(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    result = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert result.is_active is False
    assert result.id == target.id


def test_enabling_an_inactive_user_succeeds(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=False)
    service = _service(db_session)

    result = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=True)

    assert result.is_active is True


def test_setting_the_same_active_state_twice_is_idempotent(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, is_active=True)
    service = _service(db_session)

    first = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)
    second = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert first.is_active is False
    assert second.is_active is False


def test_nonexistent_target_raises_user_not_found(db_session):
    admin = _make_user(db_session, role="admin")
    service = _service(db_session)

    with pytest.raises(UserNotFoundError):
        service.set_active_status(acting_admin_id=admin.id, target_user_id=uuid.uuid4(), is_active=False)


def test_self_target_raises_cannot_modify_own_account(db_session):
    admin = _make_user(db_session, role="admin")
    service = _service(db_session)

    with pytest.raises(CannotModifyOwnAccountError):
        service.set_active_status(acting_admin_id=admin.id, target_user_id=admin.id, is_active=False)


def test_admin_can_disable_another_admin(db_session):
    """No 'last active admin' protection is implemented in Step 11G
    (see UserService's own docstring and the final report) -- disabling
    another admin account is allowed exactly like disabling an analyst.
    """
    acting_admin = _make_user(db_session, role="admin")
    other_admin = _make_user(db_session, role="admin")
    service = _service(db_session)

    result = service.set_active_status(
        acting_admin_id=acting_admin.id, target_user_id=other_admin.id, is_active=False
    )

    assert result.is_active is False
    assert result.role == "admin"


def test_role_is_never_modified_by_set_active_status(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session, role="analyst")
    service = _service(db_session)

    result = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert result.role == "analyst"


def test_password_hash_is_never_modified_by_set_active_status(db_session):
    admin = _make_user(db_session, role="admin")
    target = _make_user(db_session)
    original_hash = target.password_hash
    service = _service(db_session)

    result = service.set_active_status(acting_admin_id=admin.id, target_user_id=target.id, is_active=False)

    assert result.password_hash == original_hash
