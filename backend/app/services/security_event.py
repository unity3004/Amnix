"""Business logic for ingesting and retrieving SecurityEvents."""

import uuid

from app.models.security_event import SecurityEvent
from app.repositories.security_event import SecurityEventRepository
from app.schemas.security_event import SecurityEventCreate


class SecurityEventService:
    def __init__(self, repository: SecurityEventRepository) -> None:
        self._repository = repository

    def ingest(self, payload: SecurityEventCreate) -> SecurityEvent:
        data = payload.model_dump(mode="python")
        if data.get("source_ip") is not None:
            data["source_ip"] = str(data["source_ip"])
        if data.get("destination_ip") is not None:
            data["destination_ip"] = str(data["destination_ip"])
        if data.get("severity") is not None:
            data["severity"] = data["severity"].value

        event = SecurityEvent(**data)
        return self._repository.create(event)

    def get(self, event_id: uuid.UUID) -> SecurityEvent | None:
        return self._repository.get_by_id(event_id)
