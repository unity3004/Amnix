"""Business logic for ingesting and retrieving SecurityEvents."""

import uuid
from datetime import datetime

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

    def list_recent(
        self,
        *,
        limit: int,
        offset: int,
        event_type: str | None = None,
        source: str | None = None,
        since: datetime | None = None,
        until: datetime | None = None,
    ) -> list[SecurityEvent]:
        """Thin passthrough to SecurityEventRepository.list_recent() —
        Dashboard Data Foundation's GET /events. No business logic of
        its own, matching how `get()` above is also a bare passthrough;
        exists only so app.api.events never calls the repository layer
        directly, the same convention every other route in AMNIX follows.
        """
        return self._repository.list_recent(
            limit=limit, offset=offset, event_type=event_type, source=source, since=since, until=until
        )
