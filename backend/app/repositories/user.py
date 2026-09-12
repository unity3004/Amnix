"""Persistence access for User.

Same shape as AlertRepository/SecurityEventRepository/CopilotAuditRepository:
a thin wrapper around the Session, no validation, no normalization, no
business logic. In particular, create() does not call
app.core.security.normalize_email() itself — that must already have been
applied by whatever constructs the User instance passed in (see
app.models.user's own docstring for why that boundary lives one layer
up, not here).

Built now, in Step 11B, rather than deferred to Step 11C, because every
other model in AMNIX already has exactly this kind of repository and a
future login/registration step cannot function without get_by_email() —
this is not a speculative abstraction, it is the same minimal shape
every other persisted model already uses.

Step 11C: create() rolls back on a failed commit before re-raising.
Unlike Alert/SecurityEvent, a User row can genuinely race (two
concurrent registrations for the same normalized email both passing
AuthService.register()'s pre-insert get_by_email() check before either
commits — see that method's own docstring), so a commit failure here is
an expected, not exceptional, outcome this repository must leave the
session usable after. Without the rollback, PostgreSQL leaves the
transaction aborted and every subsequent statement on this session
fails with "current transaction is aborted" until something rolls it
back -- this repository is the one place that knows a commit was just
attempted and failed, so it is the right place to recover it. The
IntegrityError itself is still re-raised unchanged, not translated —
that stays AuthService's job (see app.services.auth_service.
EmailAlreadyRegisteredError).
"""

import uuid

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.models.user import User


class UserRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, user: User) -> User:
        self._db.add(user)
        try:
            self._db.commit()
        except IntegrityError:
            self._db.rollback()
            raise
        self._db.refresh(user)
        return user

    def get_by_id(self, user_id: uuid.UUID) -> User | None:
        return self._db.get(User, user_id)

    def get_by_email(self, email: str) -> User | None:
        """`email` must already be normalized by the caller (see
        app.core.security.normalize_email) -- this performs an exact
        match against the stored, already-normalized value, not a
        case-insensitive lookup of its own.
        """
        stmt = select(User).where(User.email == email)
        return self._db.scalars(stmt).first()

    def save(self, user: User) -> User:
        """Persist in-place mutations made to an already-loaded User
        (Step 11G: UserService.set_active_status() sets `is_active`
        directly on the ORM instance before calling this) — mirrors
        AlertRepository.save()'s exact shape. No validation or field
        selection happens here; the caller decides what changed.
        """
        self._db.commit()
        self._db.refresh(user)
        return user
