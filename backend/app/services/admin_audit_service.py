"""AdminAuditService: durable administrative accountability (Step 11M).

Owns exactly two things: (1) the ATOMIC orchestration of "mutate a
User's admin-controlled state, and durably record that this exact
change happened" for the one operation currently in scope
(PATCH /admin/users/{user_id}/status), and (2) read-only, bounded
retrieval of the resulting history for GET /admin/audits.

============================================================
THE TRANSACTIONAL GUARANTEE — read this before changing anything here
============================================================

Discovery (see the Step 11M final report) found that every existing
write-repository in AMNIX (UserRepository.save(), AlertRepository.save(),
SecurityEventRepository.create(), CopilotAuditRepository.create()) commits
its own unit of work immediately and independently — there is exactly
one transaction-management pattern already established in this codebase,
and it does not expose a shared transaction boundary across two
repositories.

Rather than either (a) accepting a real "user mutation committed, but
its audit row silently never was" race window, or (b) rewriting that
established repository pattern project-wide, this service uses the
SMALLEST change that achieves TRUE atomicity for this one operation:

  UserService.prepare_active_status_change() mutates the target User
  in memory ONLY (no commit — see that method's own docstring; it is a
  new method added specifically for this purpose, and
  UserService.set_active_status() itself is completely unchanged and
  still persists on its own, exactly as before Step 11M).

  AdminAuditRepository.create_without_commit() adds the new AdminAudit
  row to the SAME SQLAlchemy Session, also without committing.

  This service then issues exactly ONE db.commit() covering BOTH the
  dirty User row and the new AdminAudit row — SQLAlchemy's ordinary
  unit-of-work batches them into one PostgreSQL transaction. Either
  both the User UPDATE and the AdminAudit INSERT land together, or (if
  the commit itself fails, e.g. a constraint violation, a connection
  drop) neither does — the transaction rolls back as a whole.

This is Option A from the Step 11M brief ("perform the user mutation
and audit insertion within the same database transaction") — achieved
without touching UserRepository, AlertRepository, SecurityEventRepository,
CopilotAuditRepository, or set_active_status()'s own existing contract
at all. Proven, not just asserted: see
tests/test_admin_audit_transaction.py, which forces a commit-time
failure (an intentionally-invalid AdminAudit that violates its own CHECK
constraint) and confirms the User's `is_active` value is UNCHANGED in a
fresh read afterward.

============================================================
AUDIT WRITE FAILURE POLICY
============================================================

If db.commit() raises, this service rolls back (so the shared Session
stays usable afterward — the same defensive pattern
UserRepository.create() already established for its own concurrent-
registration race, see that method's own docstring) and RE-RAISES. It
never swallows the exception. Because atomicity is achieved (see
above), a failed commit here means the User mutation ALSO never
persisted — so there is no "which one actually happened?" ambiguity for
the caller to resolve: nothing happened, and the exception (which the
route layer does not catch) becomes an honest 500, not a false 200.
This is a stronger guarantee than the brief's fallback Option B
required, achieved because Option A turned out to be reachable without
disproportionate redesign — not an oversight, not scope creep.

============================================================
WHAT THIS SERVICE DELIBERATELY DOES NOT DO
============================================================

It does not decide RBAC (that is require_admin, unchanged, Step 11F).
It does not decide the self-target/not-found business rules (that is
still entirely UserService's job, reused unmodified in shape). It never
constructs an AdminAudit for a failed validation, a failed
authentication, or a failed authorization — those exceptions propagate
straight out of prepare_active_status_change() before any AdminAudit
object is ever built.
"""

import uuid

from sqlalchemy.orm import Session

from app.models.admin_audit import AdminAudit
from app.models.user import User
from app.repositories.admin_audit import DEFAULT_LIST_LIMIT, AdminAuditRepository
from app.schemas.admin_audit import AdminAuditAction
from app.services.user_service import UserService


class AdminAuditService:
    def __init__(self, db: Session, user_service: UserService, audit_repository: AdminAuditRepository) -> None:
        self._db = db
        self._user_service = user_service
        self._audit_repository = audit_repository

    def change_user_status(
        self, *, acting_admin_id: uuid.UUID, target_user_id: uuid.UUID, is_active: bool
    ) -> tuple[User, AdminAudit]:
        """Atomically mutate `target_user_id`'s active status and record
        an AdminAudit row for it — see this module's own docstring for
        the full transactional guarantee.

        Raises CannotModifyOwnAccountError / UserNotFoundError exactly
        as UserService.set_active_status() does (both propagate
        unmodified from prepare_active_status_change(), before any
        commit or AdminAudit construction is attempted) — the route
        layer's existing 409/404 handling needs no changes.
        """
        user, previous_is_active = self._user_service.prepare_active_status_change(
            acting_admin_id=acting_admin_id, target_user_id=target_user_id, is_active=is_active
        )

        audit = AdminAudit(
            actor_user_id=acting_admin_id,
            target_user_id=target_user_id,
            action=AdminAuditAction.USER_STATUS_CHANGED.value,
            previous_is_active=previous_is_active,
            new_is_active=is_active,
        )
        self._audit_repository.create_without_commit(audit)

        try:
            self._db.commit()
        except Exception:
            self._db.rollback()
            raise

        self._db.refresh(user)
        self._db.refresh(audit)
        return user, audit

    def list_audits(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        actor_user_id: uuid.UUID | None = None,
        target_user_id: uuid.UUID | None = None,
        action: str | None = None,
    ) -> list[AdminAudit]:
        """Thin, read-only pass-through to AdminAuditRepository.list()
        — no business logic of its own, mirroring
        CopilotAuditService.list_for_alert()'s own shape.
        """
        return self._audit_repository.list(
            limit=limit, offset=offset, actor_user_id=actor_user_id, target_user_id=target_user_id, action=action
        )
