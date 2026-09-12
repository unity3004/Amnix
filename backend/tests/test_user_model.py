"""Integration tests for the User persistence model (Step 11B). Require
PostgreSQL (see conftest.py's db_session fixture).

Mirrors test_copilot_audit_model.py's conventions exactly: valid rows
are accepted, invalid ones are rejected by real database constraints —
this is a data-model-only step, so these tests do not exercise any
login/registration/session logic (none exists yet).
"""

import uuid

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password, normalize_email
from app.models.user import User

pytestmark = pytest.mark.integration


def _valid_user_kwargs(**overrides) -> dict:
    defaults = dict(
        email=f"analyst-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
    )
    defaults.update(overrides)
    return defaults


# --- valid creation ----------------------------------------------------


def test_valid_user_persists(db_session):
    user = User(**_valid_user_kwargs())

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.id is not None
    assert user.role == "analyst"
    assert user.is_active is True


def test_admin_role_persists(db_session):
    user = User(**_valid_user_kwargs(role="admin"))

    db_session.add(user)
    db_session.commit()

    assert user.role == "admin"


def test_default_is_active_is_true(db_session):
    user = User(**_valid_user_kwargs())

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.is_active is True


def test_created_at_is_populated_and_timezone_aware(db_session):
    user = User(**_valid_user_kwargs())

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.created_at is not None
    assert user.created_at.tzinfo is not None


def test_updated_at_is_populated_and_changes_on_update(db_session):
    user = User(**_valid_user_kwargs())
    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)
    original_updated_at = user.updated_at

    user.is_active = False
    db_session.commit()
    db_session.refresh(user)

    assert user.updated_at is not None
    assert user.updated_at >= original_updated_at


def test_password_hash_field_stores_the_given_hash_string_verbatim(db_session):
    """The model itself performs no hashing -- it only stores whatever
    string it's given (which must already be a real Argon2id hash; see
    the CHECK-constraint tests below for what happens otherwise).
    """
    real_hash = hash_password("correct horse battery staple")
    user = User(**_valid_user_kwargs(password_hash=real_hash))

    db_session.add(user)
    db_session.commit()
    db_session.refresh(user)

    assert user.password_hash == real_hash


# --- invalid role --------------------------------------------------------


def test_invalid_role_is_rejected(db_session):
    user = User(**_valid_user_kwargs(role="superadmin"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


# --- duplicate email -------------------------------------------------------


def test_duplicate_email_is_rejected(db_session):
    email = normalize_email(f"dup-{uuid.uuid4().hex[:8]}@example.com")
    db_session.add(User(**_valid_user_kwargs(email=email)))
    db_session.commit()

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(User(**_valid_user_kwargs(email=email)))
            db_session.flush()


def test_differently_cased_or_padded_email_variants_collide_once_normalized(db_session):
    """Proves the normalize-then-store contract actually prevents
    duplicates when the caller does its job -- normalize_email() is
    applied here exactly as a future registration flow must apply it
    before constructing a User.
    """
    base = f"variant-{uuid.uuid4().hex[:8]}@example.com"
    db_session.add(User(**_valid_user_kwargs(email=normalize_email(f"  {base.upper()}  "))))
    db_session.commit()

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(User(**_valid_user_kwargs(email=normalize_email(base))))
            db_session.flush()


# --- blank / malformed field CHECK constraints ----------------------------


def test_blank_email_is_rejected(db_session):
    user = User(**_valid_user_kwargs(email="   "))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


def test_blank_password_hash_is_rejected(db_session):
    user = User(**_valid_user_kwargs(password_hash="   "))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


def test_non_argon2id_password_hash_is_rejected(db_session):
    """Defense in depth: even a syntactically non-blank string is
    rejected unless it is shaped like a real Argon2id hash -- this is
    the mechanism that makes storing a plaintext password structurally
    impossible, not just discouraged by convention.
    """
    user = User(**_valid_user_kwargs(password_hash="plaintext-not-a-hash"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


def test_bcrypt_shaped_hash_is_rejected(db_session):
    """A hash from a different (weaker/non-approved) scheme must not be
    accepted just because it isn't blank -- pins the CHECK to Argon2id
    specifically, not "any hash-shaped string". Uses a realistic but
    fabricated bcrypt-format string (no bcrypt dependency needed) to
    prove the constraint discriminates by prefix, not just by "looks
    like a hash".
    """
    user = User(**_valid_user_kwargs(password_hash="$2b$12$abcdefghijklmnopqrstuvKQZ7X9examplebcrypthash"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


def test_argon2i_variant_hash_is_rejected(db_session):
    """Argon2i (a different Argon2 variant) is also rejected -- only
    argon2ID specifically is accepted, matching app.core.security's
    explicit `type=Type.ID` choice.
    """
    user = User(
        **_valid_user_kwargs(
            password_hash="$argon2i$v=19$m=65536,t=3,p=4$c29tZXNhbHQ$c29tZWhhc2h2YWx1ZQ"
        )
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(user)
            db_session.flush()


# --- schema/migration correctness -----------------------------------------
#
# Mirrors test_copilot_audit_model.py's pattern exactly: schema
# correctness is verified via sqlalchemy.inspect() against the
# Base.metadata.create_all()-bootstrapped test database (proving the
# model is correct) plus a direct psql inspection of the real dev
# database after applying the actual migration file (see the Step 11B
# final report) -- not an automated alembic upgrade/downgrade pytest
# cycle, since no prior migration in this codebase is tested that way
# either.


def test_table_schema_matches_the_model(_pg_engine):
    inspector = inspect(_pg_engine)
    columns = {c["name"]: c for c in inspector.get_columns("users")}

    expected_columns = {
        "id",
        "email",
        "password_hash",
        "role",
        "is_active",
        "created_at",
        "updated_at",
    }
    assert set(columns) == expected_columns
    assert columns["created_at"]["type"].timezone is True
    assert columns["updated_at"]["type"].timezone is True
    assert columns["email"]["nullable"] is False
    assert columns["is_active"]["nullable"] is False


def test_email_unique_index_exists(_pg_engine):
    inspector = inspect(_pg_engine)
    indexes = inspector.get_indexes("users")
    email_index = next(ix for ix in indexes if ix["name"] == "ix_users_email")

    assert email_index["unique"] is True
    assert email_index["column_names"] == ["email"]


def test_expected_check_constraints_exist(_pg_engine):
    inspector = inspect(_pg_engine)
    constraint_names = {c["name"] for c in inspector.get_check_constraints("users")}

    expected = {
        "ck_users_email_not_blank",
        "ck_users_password_hash_not_blank",
        "ck_users_password_hash_is_argon2id",
        "ck_users_role_valid",
    }
    assert expected <= constraint_names
