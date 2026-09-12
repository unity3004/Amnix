"""Integration tests for UserRepository (Step 11B). Require PostgreSQL
(see conftest.py's db_session fixture).
"""

import uuid

import pytest

from app.core.security import hash_password, normalize_email
from app.models.user import User
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration


def _valid_user(**overrides) -> User:
    defaults = dict(
        email=f"analyst-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
    )
    defaults.update(overrides)
    return User(**defaults)


def test_create_persists_and_returns_server_generated_fields(db_session):
    repo = UserRepository(db_session)

    user = repo.create(_valid_user())

    assert user.id is not None
    assert user.created_at is not None
    assert user.updated_at is not None


def test_get_by_id_returns_the_created_user(db_session):
    repo = UserRepository(db_session)
    created = repo.create(_valid_user())

    fetched = repo.get_by_id(created.id)

    assert fetched is not None
    assert fetched.id == created.id


def test_get_by_id_returns_none_for_unknown_id(db_session):
    repo = UserRepository(db_session)

    assert repo.get_by_id(uuid.uuid4()) is None


def test_get_by_email_returns_the_created_user(db_session):
    repo = UserRepository(db_session)
    email = normalize_email(f"lookup-{uuid.uuid4().hex[:8]}@example.com")
    created = repo.create(_valid_user(email=email))

    fetched = repo.get_by_email(email)

    assert fetched is not None
    assert fetched.id == created.id


def test_get_by_email_returns_none_for_unknown_email(db_session):
    repo = UserRepository(db_session)

    assert repo.get_by_email("nobody-here@example.com") is None


def test_save_persists_an_in_place_mutation(db_session):
    repo = UserRepository(db_session)
    user = repo.create(_valid_user(is_active=True))

    user.is_active = False
    saved = repo.save(user)

    assert saved.is_active is False
    refetched = repo.get_by_id(user.id)
    assert refetched.is_active is False


def test_get_by_email_is_an_exact_match_not_case_insensitive_on_its_own(db_session):
    """UserRepository performs no normalization itself (see its own
    module docstring) -- the caller must normalize before both create()
    and get_by_email(), which this test demonstrates directly: looking
    up a non-normalized variant of a stored (already-normalized) email
    does not find it.
    """
    repo = UserRepository(db_session)
    email = normalize_email(f"CaseTest-{uuid.uuid4().hex[:8]}@Example.com")
    repo.create(_valid_user(email=email))

    assert repo.get_by_email(email.upper()) is None
    assert repo.get_by_email(email) is not None
