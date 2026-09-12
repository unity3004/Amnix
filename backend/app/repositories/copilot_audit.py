"""Persistence access for CopilotAudit.

Same shape as app.repositories.alert / app.repositories.security_event —
a thin wrapper around the Session, no business logic, no exception
translation (that is app.services.copilot_audit_service's job, exactly
like AlertNotFoundError is raised by AlertService, never by
AlertRepository). This repository also carries no MITRE or investigation
-action logic of any kind: it only ever reads/writes CopilotAudit rows
exactly as given to it.

Transaction behavior: `create()` commits, exactly like
AlertRepository.create()/.save() and SecurityEventRepository.create() --
there is exactly one transaction-management pattern in this codebase
(each write-repository commits its own unit of work), and this
repository does not invent a second one. See
CopilotAuditService's module docstring for why this is safe to call
from CopilotService's read-only ask()/follow_up() paths.
"""

import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.copilot_audit import CopilotAudit

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class CopilotAuditRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, audit: CopilotAudit) -> CopilotAudit:
        self._db.add(audit)
        self._db.commit()
        self._db.refresh(audit)
        return audit

    def get_by_id(self, audit_id: uuid.UUID) -> CopilotAudit | None:
        return self._db.get(CopilotAudit, audit_id)

    def list_for_alert(
        self, alert_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[CopilotAudit]:
        """Newest-first, with `id` as a deterministic tie-breaker for rows
        sharing a `created_at` value (timestamps alone are not guaranteed
        unique). Always scoped to exactly one alert -- there is no code
        path here that can return another alert's rows. `limit` is capped
        at MAX_LIST_LIMIT so this can never become an unbounded query
        regardless of what a caller passes.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(CopilotAudit)
            .where(CopilotAudit.alert_id == alert_id)
            .order_by(CopilotAudit.created_at.desc(), CopilotAudit.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._db.scalars(stmt))
