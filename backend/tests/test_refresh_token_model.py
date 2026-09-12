"""Integration tests for the RefreshToken persistence model (Step 11D).
Require PostgreSQL (see conftest.py's db_session fixture).

Mirrors test_user_model.py's conventions: valid rows are accepted,
invalid ones are rejected by real database constraints.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password
from app.core.tokens import generate_refresh_token, hash_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import User

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


def _valid_token_kwargs(user_id: uuid.UUID, **overrides) -> dict:
    now = datetime.now(timezone.utc)
    defaults = dict(
        user_id=user_id,
        token_hash=hash_refresh_token(generate_refresh_token()),
        family_id=uuid.uuid4(),
        expires_at=now + timedelta(days=7),
    )
    defaults.update(overrides)
    return defaults


# --- valid creation ----------------------------------------------------


def test_valid_refresh_token_persists(db_session):
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id))

    db_session.add(token)
    db_session.commit()
    db_session.refresh(token)

    assert token.id is not None
    assert token.issued_at is not None
    assert token.issued_at.tzinfo is not None
    assert token.revoked_at is None
    assert token.replaced_by_id is None


def test_multiple_tokens_can_share_a_family(db_session):
    user = _make_user(db_session)
    family_id = uuid.uuid4()

    first = RefreshToken(**_valid_token_kwargs(user.id, family_id=family_id))
    second = RefreshToken(**_valid_token_kwargs(user.id, family_id=family_id))
    db_session.add_all([first, second])
    db_session.commit()

    assert first.family_id == second.family_id == family_id


# --- invalid token_hash --------------------------------------------------


def test_non_sha256_token_hash_is_rejected(db_session):
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id, token_hash="not-a-real-hash"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(token)
            db_session.flush()


def test_uppercase_hex_token_hash_is_rejected(db_session):
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id, token_hash="A" * 64))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(token)
            db_session.flush()


def test_duplicate_token_hash_is_rejected(db_session):
    user = _make_user(db_session)
    shared_hash = hash_refresh_token(generate_refresh_token())
    db_session.add(RefreshToken(**_valid_token_kwargs(user.id, token_hash=shared_hash)))
    db_session.commit()

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(RefreshToken(**_valid_token_kwargs(user.id, token_hash=shared_hash)))
            db_session.flush()


# --- foreign keys / cascade behavior --------------------------------------


def test_unknown_user_id_is_rejected(db_session):
    token = RefreshToken(**_valid_token_kwargs(uuid.uuid4()))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(token)
            db_session.flush()


def test_deleting_user_cascades_to_refresh_tokens(db_session):
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id))
    db_session.add(token)
    db_session.commit()
    token_id = token.id

    db_session.delete(user)
    db_session.commit()

    assert db_session.get(RefreshToken, token_id) is None


def test_replaced_by_id_set_null_when_successor_deleted(db_session):
    user = _make_user(db_session)
    family_id = uuid.uuid4()
    old_token = RefreshToken(**_valid_token_kwargs(user.id, family_id=family_id))
    db_session.add(old_token)
    db_session.commit()

    new_token = RefreshToken(**_valid_token_kwargs(user.id, family_id=family_id))
    db_session.add(new_token)
    db_session.flush()
    old_token.revoked_at = datetime.now(timezone.utc)
    old_token.replaced_by_id = new_token.id
    db_session.commit()

    db_session.delete(new_token)
    db_session.commit()
    db_session.refresh(old_token)

    assert old_token.replaced_by_id is None
    assert old_token.revoked_at is not None  # deleting the successor does not un-revoke the predecessor


# --- cross-field CHECK constraints -----------------------------------------


def test_replaced_by_id_without_revoked_at_is_rejected(db_session):
    """A token cannot be marked "replaced" without also being revoked --
    see ck_refresh_tokens_replaced_implies_revoked.
    """
    user = _make_user(db_session)
    old_token = RefreshToken(**_valid_token_kwargs(user.id))
    db_session.add(old_token)
    db_session.commit()

    new_token = RefreshToken(**_valid_token_kwargs(user.id, family_id=old_token.family_id))
    db_session.add(new_token)
    db_session.flush()
    old_token.replaced_by_id = new_token.id  # revoked_at intentionally left NULL

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.flush()


def test_token_cannot_be_replaced_by_itself(db_session):
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id))
    db_session.add(token)
    db_session.commit()

    token.revoked_at = datetime.now(timezone.utc)
    token.replaced_by_id = token.id

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.flush()


def test_revoked_at_without_replaced_by_id_is_allowed(db_session):
    """Explicit revocation (e.g. reuse-detected family revocation) never
    requires a successor -- only the reverse direction is constrained.
    """
    user = _make_user(db_session)
    token = RefreshToken(**_valid_token_kwargs(user.id))
    db_session.add(token)
    db_session.commit()

    token.revoked_at = datetime.now(timezone.utc)
    db_session.commit()

    assert token.replaced_by_id is None
    assert token.revoked_at is not None


# --- schema/migration correctness -----------------------------------------


def test_table_schema_matches_the_model(_pg_engine):
    inspector = inspect(_pg_engine)
    columns = {c["name"]: c for c in inspector.get_columns("refresh_tokens")}

    expected_columns = {
        "id",
        "user_id",
        "token_hash",
        "family_id",
        "issued_at",
        "expires_at",
        "revoked_at",
        "replaced_by_id",
    }
    assert set(columns) == expected_columns
    assert columns["issued_at"]["type"].timezone is True
    assert columns["expires_at"]["type"].timezone is True
    assert columns["revoked_at"]["nullable"] is True
    assert columns["user_id"]["nullable"] is False


def test_token_hash_unique_index_exists(_pg_engine):
    inspector = inspect(_pg_engine)
    indexes = inspector.get_indexes("refresh_tokens")
    token_hash_index = next(ix for ix in indexes if ix["name"] == "ix_refresh_tokens_token_hash")

    assert token_hash_index["unique"] is True


def test_expected_foreign_keys_exist(_pg_engine):
    inspector = inspect(_pg_engine)
    fks = {fk["name"] or fk["constrained_columns"][0]: fk for fk in inspector.get_foreign_keys("refresh_tokens")}

    user_fk = next(fk for fk in inspector.get_foreign_keys("refresh_tokens") if fk["constrained_columns"] == ["user_id"])
    assert user_fk["referred_table"] == "users"
    assert user_fk["options"].get("ondelete") == "CASCADE"

    replaced_fk = next(
        fk for fk in inspector.get_foreign_keys("refresh_tokens") if fk["constrained_columns"] == ["replaced_by_id"]
    )
    assert replaced_fk["referred_table"] == "refresh_tokens"
    assert replaced_fk["options"].get("ondelete") == "SET NULL"


def test_expected_check_constraints_exist(_pg_engine):
    inspector = inspect(_pg_engine)
    constraint_names = {c["name"] for c in inspector.get_check_constraints("refresh_tokens")}

    expected = {
        "ck_refresh_tokens_token_hash_sha256_hex",
        "ck_refresh_tokens_replaced_implies_revoked",
        "ck_refresh_tokens_replaced_by_not_self",
    }
    assert expected <= constraint_names
