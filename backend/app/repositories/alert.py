"""Persistence access for Alert."""

import uuid
from collections.abc import Sequence
from datetime import datetime

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models.alert import Alert, alert_security_events
from app.models.security_event import SecurityEvent

# Dashboard Data Foundation: the same DEFAULT_LIST_LIMIT/MAX_LIST_LIMIT
# convention already established by CopilotAuditRepository/
# AdminAuditRepository — see list_recent() below.
DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class AlertRepository:
    def __init__(self, db: Session) -> None:
        self._db = db

    def create(self, alert: Alert) -> Alert:
        self._db.add(alert)
        self._db.commit()
        self._db.refresh(alert)
        return alert

    def save(self, alert: Alert) -> Alert:
        self._db.commit()
        self._db.refresh(alert)
        return alert

    def get_by_id(self, alert_id: uuid.UUID) -> Alert | None:
        return self._db.get(Alert, alert_id)

    def get_by_id_with_events(self, alert_id: uuid.UUID) -> Alert | None:
        """Fetch an Alert with its security_events collection eagerly
        loaded via a single batched query (selectinload), instead of
        letting each access to `.security_events` trigger its own lazy
        query. Used by the investigation endpoint, which always needs
        the full event collection, unlike plain GET/PATCH /alerts/{id}.
        """
        stmt = select(Alert).options(selectinload(Alert.security_events)).where(Alert.id == alert_id)
        return self._db.scalars(stmt).first()

    def list_recent(
        self,
        *,
        limit: int = DEFAULT_LIST_LIMIT,
        offset: int = 0,
        status: str | None = None,
        severity: str | None = None,
        rule_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[Alert]:
        """Newest-first (first_seen DESC, id DESC tie-break — the same
        deterministic-ordering convention CopilotAuditRepository/
        AdminAuditRepository already use), for the Dashboard Data
        Foundation's GET /alerts. `status`/`rule_id` are optional
        equality filters using the existing ix_alerts_status/_rule_id
        indexes; `since`/`until` bound `first_seen` using the existing
        ix_alerts_first_seen index. `severity` has no dedicated index
        (a 4-value column gains little from one at current/near-term
        table sizes — see the final report's Index Analysis section) but
        is still a plain, safely parameterized equality filter, never a
        raw fragment. No new index was added for this milestone.

        Uses selectinload(Alert.security_events) — exactly like
        get_by_id_with_events() — so that serializing
        AlertRead.source_event_ids for every alert in the returned page
        costs one extra batched query total, not one query per alert
        (N+1). This is the one respect in which this method is NOT a
        bare copy of AdminAuditRepository.list()'s shape: Alert has a
        relationship its response schema reads that AdminAudit does not.

        `limit` is capped at MAX_LIST_LIMIT so this can never become an
        unbounded query regardless of what a caller passes; validated
        here defensively (not only at the API layer), matching
        AdminAuditRepository.list()'s own reasoning.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(Alert)
            .options(selectinload(Alert.security_events))
            .order_by(Alert.first_seen.desc(), Alert.id.desc())
        )
        if status is not None:
            stmt = stmt.where(Alert.status == status)
        if severity is not None:
            stmt = stmt.where(Alert.severity == severity)
        if rule_id is not None:
            stmt = stmt.where(Alert.rule_id == rule_id)
        if since is not None:
            stmt = stmt.where(Alert.first_seen >= since)
        if until is not None:
            stmt = stmt.where(Alert.first_seen <= until)
        stmt = stmt.limit(limit).offset(offset)

        return list(self._db.scalars(stmt))

    def get_security_events_by_ids(self, event_ids: Sequence[uuid.UUID]) -> list[SecurityEvent]:
        if not event_ids:
            return []
        stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        return list(self._db.scalars(stmt))

    def list_alerts_for_event(
        self, event_id: uuid.UUID, *, limit: int = DEFAULT_LIST_LIMIT, offset: int = 0
    ) -> list[Alert]:
        """Step 12Y: the authoritative reverse relationship -- which real,
        persisted Alerts (if any) cite this SecurityEvent as evidence, via
        the exact same alert_security_events join
        exists_with_rule_and_exact_events() above already reads, just in
        the other direction. A single parameterized JOIN filtered by the
        exact event_id (never Python-side filtering over an unbounded
        fetch-all), using the existing
        ix_alert_security_events_security_event_id index -- present on
        this table since it was first created, with no caller until now,
        so this is a genuine index-backed reverse lookup from day one,
        not a new migration (same shape as Step 12V's
        CaseAlertRepository.list_cases_for_alert() discovery).

        Uses selectinload(Alert.security_events) -- exactly like
        list_recent()/get_by_id_with_events() -- so serializing each
        returned Alert's source_event_ids costs one extra batched query
        total, never one query per alert (no N+1).

        Ordered by the same convention as list_recent() (`first_seen
        DESC`, `id DESC` tie-break) -- no new sort model introduced for
        this one reverse-lookup endpoint.

        `limit`/`offset` are validated here (defense in depth), exactly
        like every other bounded-list repository method in this
        codebase, in addition to the FastAPI Query bounds enforced at the
        API layer.
        """
        if not (1 <= limit <= MAX_LIST_LIMIT):
            raise ValueError(f"limit must be between 1 and {MAX_LIST_LIMIT}, got {limit}")
        if offset < 0:
            raise ValueError(f"offset must be >= 0, got {offset}")

        stmt = (
            select(Alert)
            .join(alert_security_events, alert_security_events.c.alert_id == Alert.id)
            .where(alert_security_events.c.security_event_id == event_id)
            .options(selectinload(Alert.security_events))
            .order_by(Alert.first_seen.desc(), Alert.id.desc())
            .limit(limit)
            .offset(offset)
        )
        return list(self._db.scalars(stmt))

    def exists_with_rule_and_exact_events(self, rule_id: str, event_ids: Sequence[uuid.UUID]) -> bool:
        """Step 10H: the automatic-alert-generation dedup check. True if
        an Alert with this exact `rule_id` already references EXACTLY
        this set of SecurityEvents (same count, same ids) — i.e. a prior
        detection run already produced an alert for this identical
        evidence set. A single bounded query, not a fetch-all-then-
        compare-in-Python: for each candidate alert (already narrowed by
        the indexed `rule_id` column), it counts how many of its
        associated events fall inside the target set and how many it has
        in total, and only matches when both counts equal the target
        set's size — which, since alert_security_events has no duplicate
        (alert_id, security_event_id) pairs, is exactly set equality.
        """
        if not event_ids:
            return False
        target_ids = list(event_ids)
        target_size = len(target_ids)

        matching_count = (
            select(func.count())
            .select_from(alert_security_events)
            .where(alert_security_events.c.alert_id == Alert.id)
            .where(alert_security_events.c.security_event_id.in_(target_ids))
            .correlate(Alert)
            .scalar_subquery()
        )
        total_count = (
            select(func.count())
            .select_from(alert_security_events)
            .where(alert_security_events.c.alert_id == Alert.id)
            .correlate(Alert)
            .scalar_subquery()
        )
        stmt = (
            select(Alert.id)
            .where(Alert.rule_id == rule_id)
            .where(total_count == target_size)
            .where(matching_count == target_size)
            .limit(1)
        )
        return self._db.scalars(stmt).first() is not None
