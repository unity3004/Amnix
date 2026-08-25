"""Pydantic schemas for the deterministic InvestigationContext.

InvestigationContext is computed on demand by the InvestigationEngine from
an existing Alert and its associated SecurityEvents — nothing here is
persisted, and none of it is AI-generated. Every field is either a direct
projection of stored data or a deterministic function of it (sorting,
deduplication, counting, template-based text).
"""

import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress

from app.schemas.alert import AlertRead


class TimelineEntry(BaseModel):
    """One SecurityEvent's contribution to the investigation timeline.

    Includes `command_line`, which is not in the literal spec list of
    timeline fields (timestamp/type/source/host/user/source_ip/
    destination_ip/process/event_id). Two of AMNIX's three existing
    detection rules (suspicious/encoded PowerShell) are specifically
    about command-line content — a timeline without it would not
    actually be useful for investigating the alerts this system already
    generates, so it's included as a deliberate, justified addition.
    """

    model_config = ConfigDict(frozen=True)

    event_id: uuid.UUID
    event_timestamp: datetime
    event_type: str
    source: str
    hostname: str | None
    username: str | None
    source_ip: IPvAnyAddress | None
    destination_ip: IPvAnyAddress | None
    process_name: str | None
    command_line: str | None


class InvestigationEntities(BaseModel):
    """Unique values extracted from the investigation's related events.

    Each list is sorted (not insertion-order) so output is deterministic
    regardless of how events happen to be ordered coming out of the
    database. No relationships between these values are inferred — they
    are independent deduplicated sets, not a graph. `command_line` is
    deliberately not deduplicated here: unlike a hostname or username,
    two "equal" command lines from different events aren't really the
    same fact worth collapsing, and each is already visible per-event in
    `timeline`.
    """

    model_config = ConfigDict(frozen=True)

    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)


class InvestigationSummary(BaseModel):
    """A deterministic, template-generated factual summary — NOT an AI
    summary. `text` is always reconstructible from the other fields here
    plus the Alert's own rule_id/title; nothing in it is inferred or
    guessed.
    """

    model_config = ConfigDict(frozen=True)

    text: str
    event_count: int
    unique_host_count: int
    unique_user_count: int
    timespan_seconds: float | None
    first_event_at: datetime | None
    last_event_at: datetime | None


class InvestigationContext(BaseModel):
    """The full deterministic investigation context for one Alert.

    `timeline` doubles as the "related events" view: since related-event
    discovery is currently just "events directly associated with the
    Alert" (see InvestigationEngine), a separate raw related_events list
    would duplicate the same event data timeline already carries in a
    second shape. If future correlation broadens what counts as
    "related" beyond the Alert's own events, that's the natural point to
    reconsider this.
    """

    model_config = ConfigDict(frozen=True)

    alert: AlertRead
    timeline: list[TimelineEntry]
    entities: InvestigationEntities
    summary: InvestigationSummary
    generated_at: datetime
