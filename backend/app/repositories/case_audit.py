"""Persistence access for CaseAudit.

Direct structural copy of app.repositories.admin_audit.AdminAuditRepository
-- the same deliberate "does not commit on its own" exception (see that
module's own docstring), the same bounded-pagination convention.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case_audit import CaseAudit

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class CaseAuditRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create_without_commit(self, audit: CaseAudit) -> CaseAudit:
        """Adds `audit` to the session WITHOUT committing -- the caller
        (CaseService) commits atomically alongside the Case mutation
        this row describes.
        """
        self._db.add(audit)
        return audit

    def get_by_id(self, audit_id: uuid.UUID) -> CaseAudit | None:
        return self._db.get(CaseAudit, audit_id)

    def list_for_case(
        self, case_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[CaseAudit]:
        """Newest-first, with `id` as a deterministic tie-breaker for
        rows sharing a `created_at` value. Always scoped to exactly one
        case. `limit` is capped at MAX_LIST_LIMIT so this can never
        become an unbounded query regardless of what a caller passes.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(CaseAudit)
            .where(CaseAudit.case_id == case_id)
            .order_by(CaseAudit.created_at.desc(), CaseAudit.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._db.scalars(stmt))
