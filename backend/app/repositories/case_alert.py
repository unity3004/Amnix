"""Persistence access for CaseAlert (the Case <-> Alert join) and both
cross-table read queries (real Alert rows linked to a Case, and --
Step 12V -- real Case rows linked to an Alert) that naturally belong
alongside it.

Same "no commit of its own" exception as CaseRepository/CaseAuditRepository
-- linking/unlinking an alert must commit atomically together with its
CASE_ALERT_LINKED/CASE_ALERT_UNLINKED audit row (see CaseService).

Both `list_alerts_for_case()` and `list_cases_for_alert()` live here, not
on AlertRepository (which stays completely untouched by this step, exactly
as it was left at the end of Step 12U's discovery): both are fundamentally
case_alerts-driven queries, and keeping them here means Alert's own
repository never needs to become "case-aware" in either direction.

Step 12V discovery: `case_alerts`' composite primary key is
(case_id, alert_id) -- a leading-column index that does NOT efficiently
support `WHERE alert_id = ?` alone. This was already anticipated back in
Step 12R: `ix_case_alerts_alert_id` (see app.models.case.CaseAlert's own
__table_args__, and the migration that created it) has existed on this
table since it was first created, with no caller until now -- so
`list_cases_for_alert()` below is a genuine index-backed reverse lookup
from day one, not a new migration.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.alert import Alert
from app.models.case import Case, CaseAlert

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class CaseAlertRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create_without_commit(self, link: CaseAlert) -> CaseAlert:
        self._db.add(link)
        return link

    def delete_without_commit(self, link: CaseAlert) -> None:
        self._db.delete(link)

    def get(self, case_id: uuid.UUID, alert_id: uuid.UUID) -> CaseAlert | None:
        return self._db.get(CaseAlert, (case_id, alert_id))

    def exists(self, case_id: uuid.UUID, alert_id: uuid.UUID) -> bool:
        return self.get(case_id, alert_id) is not None

    def list_alerts_for_case(self, case_id: uuid.UUID) -> list[Alert]:
        """The real, linked Alert rows for one Case, newest-link-first.
        Uses selectinload(Alert.security_events) -- exactly like
        AlertRepository.list_recent() -- so serializing each Alert's
        source_event_ids costs one extra batched query total, never one
        query per linked alert (no N+1).
        """
        stmt = (
            select(Alert)
            .join(CaseAlert, CaseAlert.alert_id == Alert.id)
            .where(CaseAlert.case_id == case_id)
            .options(selectinload(Alert.security_events))
            .order_by(CaseAlert.linked_at.desc())
        )
        return list(self._db.scalars(stmt))

    def list_cases_for_alert(
        self, alert_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[Case]:
        """The real, linked Case rows for one Alert -- the authoritative
        reverse relationship Step 12U discovered was missing. A single
        parameterized JOIN through case_alerts, filtered by the exact
        alert_id (uuid.UUID, never a raw string interpolated into SQL);
        the database enforces the relationship, never Python-side
        filtering over an unbounded fetch-all.

        Ordered newest-link-first (`linked_at DESC`) with `Case.id DESC`
        as an explicit tie-break -- unlike list_alerts_for_case() above,
        this method's own ordering is exercised by a dedicated
        determinism test (Step 12V), so the tie-break is made explicit
        here rather than left to incidental row-storage order on a
        linked_at collision.

        `limit`/`offset` are validated here (defense in depth) exactly
        like every other bounded-list repository method in this
        codebase, in addition to the FastAPI Query bounds enforced at
        the API layer.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(Case)
            .join(CaseAlert, CaseAlert.case_id == Case.id)
            .where(CaseAlert.alert_id == alert_id)
            .order_by(CaseAlert.linked_at.desc(), Case.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._db.scalars(stmt))
