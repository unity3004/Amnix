"""Business logic for creating, retrieving, and transitioning Alerts."""

import uuid
from datetime import datetime

from app.models.alert import Alert
from app.repositories.alert import AlertRepository
from app.schemas.alert import AlertCreate, AlertStatus
from app.schemas.detection import DetectionSeverity
from app.services.alert_lifecycle import assert_valid_transition


class UnknownSourceEventsError(ValueError):
    """Raised when AlertCreate.source_event_ids references SecurityEvents
    that do not exist. Failing loudly here matters: silently dropping an
    unknown ID would let an alert be created with less evidence than the
    caller intended, without anyone noticing.
    """

    def __init__(self, missing_ids: set[uuid.UUID]) -> None:
        self.missing_ids = missing_ids
        super().__init__(f"Unknown source_event_ids: {sorted(str(i) for i in missing_ids)}")


class AlertNotFoundError(Exception):
    def __init__(self, alert_id: uuid.UUID) -> None:
        self.alert_id = alert_id
        super().__init__(f"Alert '{alert_id}' not found")


class AlertService:
    def __init__(self, repository: AlertRepository) -> None:
        self._repository = repository

    def create(self, payload: AlertCreate) -> Alert:
        events = self._repository.get_security_events_by_ids(payload.source_event_ids)
        found_ids = {event.id for event in events}
        missing_ids = set(payload.source_event_ids) - found_ids
        if missing_ids:
            raise UnknownSourceEventsError(missing_ids)

        first_seen = payload.first_seen
        last_seen = payload.last_seen if payload.last_seen is not None else first_seen

        alert = Alert(
            rule_id=payload.rule_id,
            title=payload.title,
            description=payload.description,
            severity=payload.severity.value,
            confidence=payload.confidence.value,
            status=AlertStatus.NEW.value,
            first_seen=first_seen,
            last_seen=last_seen,
            evidence=payload.evidence,
            alert_metadata=payload.alert_metadata,
            security_events=events,
        )
        return self._repository.create(alert)

    def get(self, alert_id: uuid.UUID) -> Alert | None:
        return self._repository.get_by_id(alert_id)

    def get_with_events(self, alert_id: uuid.UUID) -> Alert | None:
        return self._repository.get_by_id_with_events(alert_id)

    def list_recent(
        self,
        *,
        limit: int,
        offset: int,
        status: AlertStatus | None = None,
        severity: DetectionSeverity | None = None,
        rule_id: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[Alert]:
        """Thin passthrough to AlertRepository.list_recent() — Dashboard
        Data Foundation's GET /alerts. Converts the typed `status`/
        `severity` enums to their plain string values at this boundary
        (mirroring how update_status() above already does `new_status.
        value` before persisting) — the repository/database layer only
        ever sees plain strings, exactly like every other Alert column.
        """
        return self._repository.list_recent(
            limit=limit,
            offset=offset,
            status=status.value if status is not None else None,
            severity=severity.value if severity is not None else None,
            rule_id=rule_id,
            since=since,
            until=until,
        )

    def list_for_event(self, event_id: uuid.UUID, *, limit: int, offset: int) -> list[Alert]:
        """Thin passthrough to AlertRepository.list_alerts_for_event() --
        Step 12Y's GET /events/{event_id}/alerts. Existence of the
        SecurityEvent itself is checked by the route (via
        SecurityEventService.get(), the exact same 404 pattern GET
        /events/{event_id} already uses) -- this method assumes a valid
        event_id and simply returns whatever Alerts (zero or more) are
        actually linked to it.
        """
        return self._repository.list_alerts_for_event(event_id, limit=limit, offset=offset)

    def update_status(self, alert_id: uuid.UUID, new_status: AlertStatus) -> Alert:
        alert = self._repository.get_by_id(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)

        current_status = AlertStatus(alert.status)
        assert_valid_transition(current_status, new_status)

        alert.status = new_status.value
        return self._repository.save(alert)
