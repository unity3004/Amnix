"""Pydantic schemas for the Alert domain model and its lifecycle.

Alert.severity/.confidence reuse DetectionSeverity/DetectionConfidence
from app.schemas.detection rather than duplicating an identical enum:
they represent the same axes (AMNIX's own impact assessment and its
confidence in the detection logic), just now persisted on a trackable
Alert instead of an ephemeral DetectionResult. AlertStatus is new — it
has no DetectionResult equivalent, since detections don't have a
lifecycle, alerts do.
"""

import json
import uuid
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.schemas.detection import DetectionConfidence, DetectionSeverity

# Ingestion boundary limits, mirroring app.schemas.security_event: alert
# input is untrusted (it may originate from automated detection pipelines
# that themselves ingest untrusted telemetry), so it's bounded the same way.
MAX_EVIDENCE_BYTES = 256 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_SOURCE_EVENT_IDS = 1000
MAX_FUTURE_SKEW = timedelta(hours=24)


class AlertStatus(str, Enum):
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    ESCALATED = "escalated"


def _json_size(value: dict[str, Any]) -> int:
    return len(json.dumps(value).encode("utf-8"))


class AlertCreate(BaseModel):
    """Input schema for POST /alerts.

    Mirrors the shape of a DetectionResult (rule_id, title, description,
    severity, confidence, evidence, related events) since that's what an
    Alert is normally created from — but is deliberately its own schema,
    not a reuse of DetectionResult: this is a validated, untrusted API
    boundary with its own constraints (e.g. bounding source_event_ids)
    that DetectionResult, an internal/ephemeral engine output, doesn't
    need.

    `status` is intentionally NOT accepted here. Every alert is created
    as NEW; status only ever changes through PATCH /alerts/{id}/status,
    which enforces the lifecycle state machine. This is what makes "no
    arbitrary status manipulation" true by construction rather than by
    convention.
    """

    model_config = ConfigDict(extra="forbid")

    rule_id: str = Field(min_length=1, max_length=100)
    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1, max_length=10_000)

    severity: DetectionSeverity
    confidence: DetectionConfidence

    first_seen: datetime
    last_seen: datetime | None = None

    evidence: dict[str, Any]
    alert_metadata: dict[str, Any] | None = None

    # An alert must trace to concrete evidence: at least one triggering
    # SecurityEvent. See final report for the trade-off this implies.
    source_event_ids: list[uuid.UUID] = Field(min_length=1, max_length=MAX_SOURCE_EVENT_IDS)

    @field_validator("rule_id", "title", "description")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        stripped = v.strip()
        if not stripped:
            raise ValueError("must not be blank")
        return stripped

    @field_validator("first_seen", "last_seen")
    @classmethod
    def _tz_aware_and_sane(cls, v: datetime | None) -> datetime | None:
        if v is None:
            return v
        if v.tzinfo is None:
            raise ValueError("must be timezone-aware")
        if v > datetime.now(timezone.utc) + MAX_FUTURE_SKEW:
            raise ValueError("must not be too far in the future")
        return v

    @field_validator("evidence")
    @classmethod
    def _evidence_bounded(cls, v: dict[str, Any]) -> dict[str, Any]:
        if _json_size(v) > MAX_EVIDENCE_BYTES:
            raise ValueError(f"evidence exceeds maximum size of {MAX_EVIDENCE_BYTES} bytes")
        return v

    @field_validator("alert_metadata")
    @classmethod
    def _metadata_bounded(cls, v: dict[str, Any] | None) -> dict[str, Any] | None:
        if v is not None and _json_size(v) > MAX_METADATA_BYTES:
            raise ValueError(f"alert_metadata exceeds maximum size of {MAX_METADATA_BYTES} bytes")
        return v

    @model_validator(mode="after")
    def _last_seen_not_before_first_seen(self) -> "AlertCreate":
        if self.last_seen is not None and self.last_seen < self.first_seen:
            raise ValueError("last_seen must not be before first_seen")
        return self


class AlertStatusUpdate(BaseModel):
    """Input schema for PATCH /alerts/{id}/status.

    Deliberately a single-field, extra="forbid" schema: this is the only
    endpoint that can mutate an existing alert, and it can mutate exactly
    one thing. id, rule_id, first_seen, evidence, and source events are
    not reachable through this schema at all, not merely ignored.
    """

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus


class AlertRead(BaseModel):
    """Output schema for retrieved/created alerts."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    rule_id: str
    title: str
    description: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    status: AlertStatus
    first_seen: datetime
    last_seen: datetime
    created_at: datetime
    updated_at: datetime
    evidence: dict[str, Any]
    alert_metadata: dict[str, Any] | None
    source_event_ids: list[uuid.UUID]
