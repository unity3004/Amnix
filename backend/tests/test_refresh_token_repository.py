"""Integration tests for RefreshTokenRepository (Step 11D). Require
PostgreSQL (see conftest.py's db_session fixture).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import hash_password
from app.core.tokens import generate_refresh_token, hash_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token import RefreshTokenRepository

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"analyst-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
    )
    defaults.update(overrides)
    user = User(**defaults)
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    return user


def _new_token(user_id: uuid.UUID, **overrides) -> RefreshToken:
    now = datetime.now(timezone.utc)
    defaults = dict(
        user_id=user_id,
        token_hash=hash_refresh_token(generate_refresh_token()),
        family_id=uuid.uuid4(),
        expires_at=now + timedelta(days=7),
    )
    defaults.update(overrides)
    return RefreshToken(**defaults)


def test_create_persists_and_returns_server_generated_fields(db_session):
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)

    token = repo.create(_new_token(user.id))

    assert token.id is not None
    assert token.issued_at is not None


def test_get_by_token_hash_for_update_finds_the_token(db_session):
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)
    raw = generate_refresh_token()
    created = repo.create(_new_token(user.id, token_hash=hash_refresh_token(raw)))

    found = repo.get_by_token_hash_for_update(hash_refresh_token(raw))

    assert found is not None
    assert found.id == created.id


def test_get_by_token_hash_for_update_returns_none_for_unknown_hash(db_session):
    repo = RefreshTokenRepository(db_session)

    assert repo.get_by_token_hash_for_update(hash_refresh_token("nonexistent")) is None


def test_rotate_persists_new_token_and_revokes_old_one_atomically(db_session):
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)
    old_token = repo.create(_new_token(user.id))
    new_token = _new_token(user.id, family_id=old_token.family_id)

    result = repo.rotate(old_token=old_token, new_token=new_token)

    assert result.id is not None
    assert result.family_id == old_token.family_id
    db_session.refresh(old_token)
    assert old_token.revoked_at is not None
    assert old_token.replaced_by_id == result.id


def test_rotate_preserves_family_id(db_session):
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)
    family_id = uuid.uuid4()
    old_token = repo.create(_new_token(user.id, family_id=family_id))

    new_token = repo.rotate(old_token=old_token, new_token=_new_token(user.id, family_id=family_id))

    assert new_token.family_id == family_id


def test_revoke_family_revokes_every_unrevoked_token_in_the_family(db_session):
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)
    family_id = uuid.uuid4()
    first = repo.create(_new_token(user.id, family_id=family_id))
    second = repo.create(_new_token(user.id, family_id=family_id))
    other_family = repo.create(_new_token(user.id, family_id=uuid.uuid4()))

    repo.revoke_family(family_id)

    db_session.refresh(first)
    db_session.refresh(second)
    db_session.refresh(other_family)
    assert first.revoked_at is not None
    assert second.revoked_at is not None
    assert other_family.revoked_at is None


def test_revoke_family_does_not_touch_already_revoked_tokens_timestamp(db_session):
    """Idempotence: revoking a family that already has a revoked token
    must not change that token's existing revoked_at value.
    """
    user = _make_user(db_session)
    repo = RefreshTokenRepository(db_session)
    family_id = uuid.uuid4()
    token = repo.create(_new_token(user.id, family_id=family_id))
    token.revoked_at = datetime.now(timezone.utc) - timedelta(days=1)
    db_session.commit()
    original_revoked_at = token.revoked_at

    repo.revoke_family(family_id)

    db_session.refresh(token)
    assert token.revoked_at == original_revoked_at


def test_revoke_family_on_unknown_family_is_a_safe_no_op(db_session):
    repo = RefreshTokenRepository(db_session)

    repo.revoke_family(uuid.uuid4())  # must not raise
