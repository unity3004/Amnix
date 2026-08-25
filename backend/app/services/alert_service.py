"""Business logic for creating, retrieving, and transitioning Alerts."""

import uuid

from app.models.alert import Alert
from app.repositories.alert import AlertRepository
from app.schemas.alert import AlertCreate, AlertStatus
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

    def update_status(self, alert_id: uuid.UUID, new_status: AlertStatus) -> Alert:
        alert = self._repository.get_by_id(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)

        current_status = AlertStatus(alert.status)
        assert_valid_transition(current_status, new_status)

        alert.status = new_status.value
        return self._repository.save(alert)
