"""Persistence access for RefreshToken.

Same shape/discipline as UserRepository: thin, no business logic, no
decision-making about whether a token IS valid — that is
app.services.token_service's job (see its own docstring for the
rotation/reuse-detection flow this repository's methods exist to
support).

get_by_token_hash_for_update() takes a row-level PostgreSQL lock
(`SELECT ... FOR UPDATE`) — this is the concurrency-safety mechanism
Step 11D requires: if two requests present the same not-yet-revoked
refresh token concurrently, the second one blocks on this lock until
the first's rotate() call commits, and then sees the row it just locked
already has `revoked_at` set — correctly treating the second request as
reuse rather than letting both requests rotate the same token into two
separate children.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import func, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.refresh_token import RefreshToken


class RefreshTokenRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, refresh_token: RefreshToken) -> RefreshToken:
        self._db.add(refresh_token)
        try:
            self._db.commit()
        except IntegrityError:
            self._db.rollback()
            raise
        self._db.refresh(refresh_token)
        return refresh_token

    def get_by_token_hash_for_update(self, token_hash: str) -> RefreshToken | None:
        """Locked lookup by token_hash — see this module's own docstring
        for why FOR UPDATE is required here specifically (not needed on
        any other lookup in this repository).
        """
        stmt = select(RefreshToken).where(RefreshToken.token_hash == token_hash).with_for_update()
        return self._db.scalars(stmt).first()

    def rotate(self, *, old_token: RefreshToken, new_token: RefreshToken) -> RefreshToken:
        """Atomically persist `new_token` and mark `old_token` revoked +
        pointing at it, in a single commit. The caller must have already
        obtained `old_token` via get_by_token_hash_for_update() in this
        same session, so this commit is protected by that row lock for
        its entire duration — no other request can observe `old_token`
        as still-valid while this rotation is in flight.
        """
        self._db.add(new_token)
        self._db.flush()
        old_token.revoked_at = datetime.now(timezone.utc)
        old_token.replaced_by_id = new_token.id
        try:
            self._db.commit()
        except IntegrityError:
            self._db.rollback()
            raise
        self._db.refresh(new_token)
        return new_token

    def revoke_family(self, family_id: uuid.UUID) -> None:
        """Marks every not-yet-revoked token in `family_id` as revoked
        now — used when TokenService.refresh() detects reuse of an
        already-rotated token, on the assumption that a replayed old
        token means the rest of the chain may be compromised too.
        """
        stmt = (
            update(RefreshToken)
            .where(RefreshToken.family_id == family_id)
            .where(RefreshToken.revoked_at.is_(None))
            .values(revoked_at=func.now())
        )
        self._db.execute(stmt)
        self._db.commit()
