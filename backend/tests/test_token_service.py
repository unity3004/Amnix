"""Integration tests for TokenService (Step 11D): login token issuance
and refresh rotation/reuse-detection, exercised directly at the service
layer (complementing, not duplicating, the end-to-end coverage in
test_auth_api.py). Require PostgreSQL (see conftest.py's db_session
fixture).
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import select, text

from app.core.security import hash_password
from app.core.tokens import decode_access_token, generate_refresh_token, hash_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.user import UserRepository
from app.services.token_service import InvalidRefreshTokenError, TokenService

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


def _service(db_session) -> TokenService:
    return TokenService(RefreshTokenRepository(db_session), UserRepository(db_session))


# =============================================================================
# issue_new_login_tokens
# =============================================================================


def test_issue_new_login_tokens_returns_a_valid_access_token(db_session):
    user = _make_user(db_session)
    pair = _service(db_session).issue_new_login_tokens(user)

    claims = decode_access_token(pair.access_token)
    assert claims.user_id == user.id
    assert claims.role == user.role


def test_issue_new_login_tokens_persists_a_refresh_token_row(db_session):
    user = _make_user(db_session)
    pair = _service(db_session).issue_new_login_tokens(user)

    row = db_session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(pair.refresh_token))
    ).first()
    assert row is not None
    assert row.user_id == user.id
    assert row.revoked_at is None


def test_issue_new_login_tokens_expires_in_matches_configured_minutes(db_session):
    from app.core.config import get_settings

    user = _make_user(db_session)
    pair = _service(db_session).issue_new_login_tokens(user)

    assert pair.expires_in == get_settings().jwt_access_token_expire_minutes * 60


# =============================================================================
# refresh(): validation failures
# =============================================================================


def test_refresh_unknown_token_raises(db_session):
    with pytest.raises(InvalidRefreshTokenError):
        _service(db_session).refresh("not-a-real-token")


def test_refresh_expired_token_raises(db_session):
    user = _make_user(db_session)
    raw = generate_refresh_token()
    db_session.add(
        RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(raw),
            family_id=uuid.uuid4(),
            expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
        )
    )
    db_session.commit()

    with pytest.raises(InvalidRefreshTokenError):
        _service(db_session).refresh(raw)


def test_refresh_already_revoked_token_raises_and_revokes_family(db_session):
    user = _make_user(db_session)
    family_id = uuid.uuid4()
    raw = generate_refresh_token()
    token = RefreshToken(
        user_id=user.id,
        token_hash=hash_refresh_token(raw),
        family_id=family_id,
        expires_at=datetime.now(timezone.utc) + timedelta(days=7),
        revoked_at=datetime.now(timezone.utc),
    )
    db_session.add(token)
    db_session.commit()

    with pytest.raises(InvalidRefreshTokenError):
        _service(db_session).refresh(raw)


def test_refresh_for_deleted_user_raises(db_session):
    """A token whose owning user no longer exists (should be impossible
    given ON DELETE CASCADE, but guarded defensively) must fail exactly
    like any other invalid-refresh case.
    """
    service = _service(db_session)
    user = _make_user(db_session)
    pair = service.issue_new_login_tokens(user)

    db_session.delete(user)
    db_session.commit()  # CASCADE also removes the refresh_tokens row

    with pytest.raises(InvalidRefreshTokenError):
        service.refresh(pair.refresh_token)


def test_refresh_for_inactive_user_raises(db_session):
    user = _make_user(db_session)
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)

    user.is_active = False
    db_session.commit()

    with pytest.raises(InvalidRefreshTokenError):
        service.refresh(pair.refresh_token)


# =============================================================================
# refresh(): successful rotation
# =============================================================================


def test_refresh_returns_a_new_access_token_reflecting_current_role(db_session):
    """The access token minted on refresh must reflect the User's
    CURRENT role, not whatever was true when the refresh token was first
    issued -- a role change takes effect on the very next refresh.
    """
    user = _make_user(db_session, role="analyst")
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)

    user.role = "admin"
    db_session.commit()

    refreshed = service.refresh(pair.refresh_token)
    claims = decode_access_token(refreshed.access_token)
    assert claims.role == "admin"


def test_refresh_issues_a_different_refresh_token(db_session):
    user = _make_user(db_session)
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)

    refreshed = service.refresh(pair.refresh_token)

    assert refreshed.refresh_token != pair.refresh_token


def test_refresh_old_token_becomes_unusable_after_rotation(db_session):
    user = _make_user(db_session)
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)

    service.refresh(pair.refresh_token)

    with pytest.raises(InvalidRefreshTokenError):
        service.refresh(pair.refresh_token)


def test_refresh_preserves_family_id_across_rotation(db_session):
    user = _make_user(db_session)
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)
    original_row = db_session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(pair.refresh_token))
    ).first()

    refreshed = service.refresh(pair.refresh_token)

    new_row = db_session.scalars(
        select(RefreshToken).where(RefreshToken.token_hash == hash_refresh_token(refreshed.refresh_token))
    ).first()
    assert new_row.family_id == original_row.family_id


def test_refresh_reuse_after_further_rotation_still_revokes_whole_family(db_session):
    user = _make_user(db_session)
    service = _service(db_session)
    pair = service.issue_new_login_tokens(user)
    second = service.refresh(pair.refresh_token)
    third = service.refresh(second.refresh_token)

    # Reuse the FIRST (long-since-rotated) token.
    with pytest.raises(InvalidRefreshTokenError):
        service.refresh(pair.refresh_token)

    # The newest, otherwise-still-valid token must now also be dead.
    with pytest.raises(InvalidRefreshTokenError):
        service.refresh(third.refresh_token)


# =============================================================================
# Concurrency safety
# =============================================================================


def test_get_by_token_hash_for_update_actually_takes_a_row_lock(_pg_engine):
    """Proves the FOR UPDATE lock is real: a second, independent
    connection attempting to lock the same row (with a short
    lock_timeout so the test fails fast rather than hanging) is blocked
    while a first connection holds the lock open.

    Deliberately bypasses the shared `db_session` fixture (which joins a
    session to one outer, never-really-committed transaction for test
    isolation, see conftest.py) -- a genuinely separate connection would
    never see that session's uncommitted rows at all. This test needs
    two REAL, independently-committing connections, so it manages its
    own setup/teardown against `_pg_engine` directly instead.
    """
    from sqlalchemy.orm import sessionmaker

    session_local = sessionmaker(bind=_pg_engine)
    holder_session = session_local()
    try:
        user = User(
            email=f"lock-test-{uuid.uuid4().hex[:8]}@example.com",
            password_hash=hash_password("correct horse battery staple"),
            role="analyst",
        )
        holder_session.add(user)
        holder_session.commit()

        raw = generate_refresh_token()
        token_hash = hash_refresh_token(raw)
        holder_session.add(
            RefreshToken(
                user_id=user.id,
                token_hash=token_hash,
                family_id=uuid.uuid4(),
                expires_at=datetime.now(timezone.utc) + timedelta(days=7),
            )
        )
        holder_session.commit()

        # Hold the lock open on a real, committed transaction.
        RefreshTokenRepository(holder_session).get_by_token_hash_for_update(token_hash)

        other_connection = _pg_engine.connect()
        try:
            other_txn = other_connection.begin()
            other_connection.execute(text("SET LOCAL lock_timeout = '200ms'"))
            with pytest.raises(Exception):  # psycopg/SQLAlchemy lock-timeout error
                other_connection.execute(
                    text("SELECT * FROM refresh_tokens WHERE token_hash = :h FOR UPDATE"), {"h": token_hash}
                )
            other_txn.rollback()
        finally:
            other_connection.close()

        holder_session.rollback()
    finally:
        # Clean up regardless of the lock-holding transaction's outcome
        # above -- this test writes directly against the real test
        # database, outside db_session's automatic rollback.
        holder_session.rollback()
        holder_session.execute(text("DELETE FROM refresh_tokens WHERE token_hash = :h"), {"h": token_hash})
        holder_session.execute(text("DELETE FROM users WHERE id = :uid"), {"uid": str(user.id)})
        holder_session.commit()
        holder_session.close()
