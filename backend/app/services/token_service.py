"""TokenService: issues and rotates access/refresh token pairs
(Step 11D).

Built on app.core.tokens (JWT + opaque-refresh-token crypto, unmodified)
and app.repositories.refresh_token / app.repositories.user (persistence
only). This service owns the *decisions* — is this token expired, is
this reuse, is the account still active, should we rotate — none of
which live in either repository or in app.core.tokens itself.

Step 11D scope: issue_new_login_tokens() is called by
AuthService.login() only after credentials are already verified valid
for an active user — it does not itself check a password or is_active
again for that path. refresh() is the standalone entry point for
POST /auth/refresh and performs its own full validation, since a
refresh token is presented on its own with no accompanying password.

Token family / rotation model — see app.models.refresh_token's own
docstring for the full column-level rationale. Summary: every fresh
login starts a brand new `family_id`; every refresh mints a new token
in the SAME family and marks the presented one revoked+replaced;
presenting an already-revoked token is treated as reuse and revokes the
entire family (app.repositories.refresh_token.revoke_family) on the
assumption the whole chain may be compromised, not just the one token
someone just replayed. This is the standard rotate-and-detect pattern
Step 11A's architecture review specified.

Concurrency safety: refresh() obtains the presented token via
get_by_token_hash_for_update() (a `SELECT ... FOR UPDATE` row lock)
before making any decision about it, and rotate() commits the
revoke-old+insert-new pair atomically while that lock is held — see
both methods' own docstrings in app.repositories.refresh_token for why
this is what makes two concurrent refresh attempts against the same
token resolve safely (one wins, rotates; the other sees the
already-revoked row and is treated as reuse) instead of both minting a
child token from the same parent.
"""

import uuid
from datetime import datetime, timedelta, timezone
from typing import NamedTuple

from app.core.config import get_settings
from app.core.tokens import create_access_token, generate_refresh_token, hash_refresh_token
from app.models.refresh_token import RefreshToken
from app.models.user import User
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.user import UserRepository


class TokenServiceError(Exception):
    """Base class for every error TokenService raises."""


class InvalidRefreshTokenError(TokenServiceError):
    """Raised for every refresh failure mode — unknown token, already-
    revoked (reuse), expired, or an inactive/deleted account — with the
    exact same generic message, mirroring AuthService.InvalidCredentials
    Error's own reasoning: a refresh endpoint is exactly as much an
    enumeration/oracle surface as login is, so it must be exactly as
    generic.
    """

    def __init__(self) -> None:
        super().__init__("Invalid or expired refresh token.")


class TokenPair(NamedTuple):
    access_token: str
    refresh_token: str
    expires_in: int


class TokenService:
    def __init__(self, refresh_token_repository: RefreshTokenRepository, user_repository: UserRepository) -> None:
        self._refresh_token_repository = refresh_token_repository
        self._user_repository = user_repository

    def issue_new_login_tokens(self, user: User) -> TokenPair:
        """Start a brand-new token family for `user` and return the
        first access/refresh pair in it. Callers (AuthService.login())
        must have already fully verified credentials and `is_active`
        before calling this — it performs no such check itself.
        """
        settings = get_settings()
        now = datetime.now(timezone.utc)
        raw_refresh_token = generate_refresh_token()

        refresh_row = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(raw_refresh_token),
            family_id=uuid.uuid4(),
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
        self._refresh_token_repository.create(refresh_row)

        access_token = create_access_token(user_id=user.id, role=user.role)
        return TokenPair(
            access_token=access_token,
            refresh_token=raw_refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )

    def refresh(self, raw_refresh_token: str) -> TokenPair:
        """Validate `raw_refresh_token` and, if valid, rotate it —
        returning a fresh access/refresh pair in the same family. See
        this module's docstring for the full reuse-detection/rotation
        model.
        """
        token_hash = hash_refresh_token(raw_refresh_token)
        existing = self._refresh_token_repository.get_by_token_hash_for_update(token_hash)

        if existing is None:
            raise InvalidRefreshTokenError()

        if existing.revoked_at is not None:
            # Reuse of an already-rotated (or explicitly revoked) token
            # — the legitimate client already moved on to a successor;
            # someone else presenting this one suggests the chain may be
            # compromised, so the whole family is revoked, not just this
            # request rejected.
            self._refresh_token_repository.revoke_family(existing.family_id)
            raise InvalidRefreshTokenError()

        now = datetime.now(timezone.utc)
        if existing.expires_at < now:
            raise InvalidRefreshTokenError()

        user = self._user_repository.get_by_id(existing.user_id)
        if user is None or not user.is_active:
            raise InvalidRefreshTokenError()

        settings = get_settings()
        new_raw_refresh_token = generate_refresh_token()
        new_row = RefreshToken(
            user_id=user.id,
            token_hash=hash_refresh_token(new_raw_refresh_token),
            family_id=existing.family_id,
            expires_at=now + timedelta(days=settings.refresh_token_expire_days),
        )
        self._refresh_token_repository.rotate(old_token=existing, new_token=new_row)

        # Always minted from the freshly-loaded User row, never from the
        # old token's own claims — a role change takes effect on the
        # very next refresh.
        access_token = create_access_token(user_id=user.id, role=user.role)
        return TokenPair(
            access_token=access_token,
            refresh_token=new_raw_refresh_token,
            expires_in=settings.jwt_access_token_expire_minutes * 60,
        )
