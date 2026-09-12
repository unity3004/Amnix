"""Persistence access for AdminAudit.

Deliberately the ONE repository in AMNIX whose write method does NOT
commit on its own — every other write repository in this codebase
(AlertRepository, SecurityEventRepository, CopilotAuditRepository,
UserRepository) commits its own unit of work immediately. This
repository's `create_without_commit()` breaks that pattern on purpose:
see app.services.admin_audit_service.AdminAuditService's own docstring
for why true transactional atomicity with the User mutation this audit
row describes requires deferring the commit to that orchestrating layer
instead. This is the one, narrowly-scoped exception to the "each
repository commits its own work" convention — not a new general
pattern other repositories should adopt.

Otherwise the same shape as CopilotAuditRepository: no business logic,
no exception translation (that stays app.services.admin_audit_service's
job), bounded pagination with the exact same DEFAULT_LIST_LIMIT/
MAX_LIST_LIMIT convention already established there.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.admin_audit import AdminAudit

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class AdminAuditRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create_without_commit(self, audit: AdminAudit) -> AdminAudit:
        """Adds `audit` to the session WITHOUT committing. The caller
        (AdminAuditService) is responsible for committing — atomically,
        alongside the User mutation this row describes. Calling this
        alone does not persist anything; a crash or exception before the
        caller's own commit leaves nothing durable, exactly as intended.
        """
        self._db.add(audit)
        return audit

    def get_by_id(self, audit_id: uuid.UUID) -> AdminAudit | None:
        return self._db.get(AdminAudit, audit_id)

    def list(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        actor_user_id: uuid.UUID | None = None,
        target_user_id: uuid.UUID | None = None,
        action: str | None = None,
    ) -> list[AdminAudit]:
        """Newest-first (created_at DESC, id DESC tie-break — the same
        deterministic-ordering convention CopilotAuditRepository already
        uses). `limit` is capped at MAX_LIST_LIMIT so this can never
        become an unbounded query regardless of what a caller passes;
        `actor_user_id`/`target_user_id`/`action` are optional equality
        filters, applied only when given.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = select(AdminAudit).order_by(AdminAudit.created_at.desc(), AdminAudit.id.desc())
        if actor_user_id is not None:
            stmt = stmt.where(AdminAudit.actor_user_id == actor_user_id)
        if target_user_id is not None:
            stmt = stmt.where(AdminAudit.target_user_id == target_user_id)
        if action is not None:
            stmt = stmt.where(AdminAudit.action == action)
        stmt = stmt.limit(limit).offset(offset)

        return list(self._db.scalars(stmt))
