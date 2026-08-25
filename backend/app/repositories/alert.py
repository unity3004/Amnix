"""Persistence access for Alert."""

import uuid
from collections.abc import Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.alert import Alert
from app.models.security_event import SecurityEvent


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

    def get_security_events_by_ids(self, event_ids: Sequence[uuid.UUID]) -> list[SecurityEvent]:
        if not event_ids:
            return []
        stmt = select(SecurityEvent).where(SecurityEvent.id.in_(event_ids))
        return list(self._db.scalars(stmt))
