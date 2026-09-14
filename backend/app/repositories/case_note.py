"""Persistence access for CaseNote.

Same shape as app.repositories.copilot_audit.CopilotAuditRepository:
`create()` commits on its own -- notes are NOT paired with a CaseAudit
row (see app.models.case_note's own docstring for why), so there is no
atomicity requirement forcing a deferred commit here, unlike
CaseRepository/CaseAuditRepository/CaseAlertRepository.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.case_note import CaseNote

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class CaseNoteRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, note: CaseNote) -> CaseNote:
        self._db.add(note)
        self._db.commit()
        self._db.refresh(note)
        return note

    def get_by_id(self, note_id: uuid.UUID) -> CaseNote | None:
        return self._db.get(CaseNote, note_id)

    def list_for_case(
        self, case_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[CaseNote]:
        """Chronological (created_at ASC, id ASC -- an analyst journal
        reads oldest-first, unlike every audit-style list in this
        codebase). `limit` is capped at MAX_LIST_LIMIT so this can never
        become an unbounded query regardless of what a caller passes.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(CaseNote)
            .where(CaseNote.case_id == case_id)
            .order_by(CaseNote.created_at.asc(), CaseNote.id.asc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._db.scalars(stmt))
