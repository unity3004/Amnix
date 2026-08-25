"""Pydantic schemas for detection results.

DetectionResult.severity and .confidence are intentionally distinct from
SecurityEvent.severity (see app.schemas.security_event.Severity): that
field is the *source-reported* level from the raw telemetry (e.g. a
Windows Event log level or syslog severity). DetectionSeverity here is
AMNIX's own assessment of the *impact* of the specific behavior a rule
matched — a different concept, not to be confused or merged with it.

DetectionConfidence is a separate axis again: how sure the rule is that
its logic correctly identified the behavior it claims to have found,
independent of how severe that behavior would be if true. A rule can be
highly confident it saw exactly the pattern it looks for, while that
pattern still turns out to be low-impact — and vice versa.
"""

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class DetectionSeverity(str, Enum):
    """AMNIX's assessment of the impact of the detected behavior, if true."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class DetectionConfidence(str, Enum):
    """How confident the rule is that it correctly identified the behavior."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class DetectionResult(BaseModel):
    """A single, structured output of a detection rule evaluation.

    This is intentionally NOT a database model — no Alert table exists
    yet. Detection results are computed on demand by the DetectionEngine,
    deterministically, from SecurityEvent data, and are immutable once
    built.
    """

    model_config = ConfigDict(frozen=True)

    detection_id: uuid.UUID
    rule_id: str
    rule_name: str
    severity: DetectionSeverity
    confidence: DetectionConfidence
    title: str
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    related_event_ids: list[uuid.UUID] = Field(default_factory=list)
    detected_at: datetime
