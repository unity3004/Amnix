"""Persistence access for Case.

Same shape as app.repositories.alert -- a thin wrapper around the
Session, no business logic, no authorization, no lifecycle validation
(that is app.services.case_service.CaseService's job).

`create_without_commit()`/`save_without_commit()` mirror
AdminAuditRepository's own deliberate exception to "each write
repository commits its own work": Case mutations must commit atomically
together with their CaseAudit row (see CaseService), so committing here
would defeat that guarantee. This is the SAME narrowly-scoped exception
already established for AdminAudit/AdminAuditRepository, not a second,
competing pattern.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case import Case

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class CaseRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create_without_commit(self, case: Case) -> Case:
        """Adds `case` to the session WITHOUT committing -- the caller
        (CaseService) commits atomically alongside the case's
        CASE_CREATED audit row.
        """
        self._db.add(case)
        return case

    def get_by_id(self, case_id: uuid.UUID) -> Case | None:
        return self._db.get(Case, case_id)

    def list(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        status: str | None = None,
        priority: str | None = None,
        owner_id: uuid.UUID | None = None,
    ) -> list[Case]:
        """Newest-first (created_at DESC, id DESC tie-break -- the same
        deterministic-ordering convention every other bounded list
        repository in AMNIX already uses). `limit` is capped at
        MAX_LIST_LIMIT so this can never become an unbounded query
        regardless of what a caller passes; `status`/`priority`/
        `owner_id` are optional equality filters, applied only when
        given.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = select(Case).order_by(Case.created_at.desc(), Case.id.desc())
        if status is not None:
            stmt = stmt.where(Case.status == status)
        if priority is not None:
            stmt = stmt.where(Case.priority == priority)
        if owner_id is not None:
            stmt = stmt.where(Case.owner_id == owner_id)
        stmt = stmt.limit(limit).offset(offset)

        return list(self._db.scalars(stmt))
