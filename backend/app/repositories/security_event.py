"""Persistence access for SecurityEvent."""

import uuid
from datetime import datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent

# Step 10H: a defensive cap on list_recent_by_type, exactly like
# CopilotAuditRepository.MAX_LIST_LIMIT — a burst of same-type telemetry
# within one correlation window must not turn this into an unbounded
# query, even though it is already scoped by event_type + a time window.
MAX_CORRELATION_CANDIDATES = 1000

# Dashboard Data Foundation: the same DEFAULT_LIST_LIMIT/MAX_LIST_LIMIT
# convention already established by CopilotAuditRepository/
# AdminAuditRepository — see list_recent() below.
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class SecurityEventRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, event: SecurityEvent) -> SecurityEvent:
        self._db.add(event)
        self._db.commit()
        self._db.refresh(event)
        return event

    def get_by_id(self, event_id: uuid.UUID) -> SecurityEvent | None:
        return self._db.get(SecurityEvent, event_id)

    def list_recent_by_type(self, event_type: str, since: datetime) -> list[SecurityEvent]:
        """Events of exactly `event_type` observed at or after `since`,
        oldest first. Used by app.services.alert_generation_service to
        gather correlation candidates for a newly-ingested event (e.g.
        prior authentication_failure events for brute-force correlation)
        — scoped by both event_type and event_timestamp so it uses the
        existing ix_security_events_event_type / _event_timestamp
        indexes rather than scanning the whole table.
        """
        stmt = (
            select(SecurityEvent)
            .where(SecurityEvent.event_type == event_type)
            .where(SecurityEvent.event_timestamp >= since)
            .order_by(SecurityEvent.event_timestamp)
            .limit(MAX_CORRELATION_CANDIDATES)
        )
        return list(self._db.scalars(stmt))

    def list_recent(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        event_type: str | None = None,
        source: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Newest-first (event_timestamp DESC, id DESC tie-break —
        the same deterministic-ordering convention CopilotAuditRepository/
        AdminAuditRepository already use), for the Dashboard Data
        Foundation's GET /events. `event_type`/`source` are optional
        equality filters using the existing ix_security_events_event_type/
        _source indexes; `since`/`until` bound `event_timestamp` using the
        existing ix_security_events_event_timestamp index. No new index
        was added for this milestone (see the final report's Index
        Analysis section) -- ordering and every filter here map onto an
        index that already existed before this method was written.

        `limit` is capped at MAX_LIST_LIMIT so this can never become an
        unbounded query regardless of what a caller passes; validated
        here defensively (not only at the API layer), matching
        AdminAuditRepository.list()'s own reasoning.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = select(SecurityEvent).order_by(SecurityEvent.event_timestamp.desc(), SecurityEvent.id.desc())
        if event_type is not None:
            stmt = stmt.where(SecurityEvent.event_type == event_type)
        if source is not None:
            stmt = stmt.where(SecurityEvent.source == source)
        if since is not None:
            stmt = stmt.where(SecurityEvent.event_timestamp >= since)
        if until is not None:
            stmt = stmt.where(SecurityEvent.event_timestamp <= until)
        stmt = stmt.limit(limit).offset(offset)

        return list(self._db.scalars(stmt))
