"""Persistence access for SecurityEvent."""

import uuid

from sqlalchemy.orm import Session

from app.models.security_event import SecurityEvent


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
