"""Common interface and shared helpers for detection rules."""

import uuid
from abc import ABC, abstractmethod
from collections.abc import Sequence
from datetime import datetime, timezone

from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionConfidence, DetectionResult, DetectionSeverity

# Rules should not assume upstream validation always bounded free-text
# fields — data could reach the engine from a future source that bypasses
# the ingestion API's own limits. Truncating before any substring/regex
# scan keeps a single oversized field from making detection expensive,
# regardless of where the event came from.
MAX_SCAN_LENGTH = 8192

PROCESS_CREATION_EVENT_TYPE = "process_creation"

_POWERSHELL_PROCESS_NAMES = frozenset({"powershell.exe", "powershell", "pwsh.exe", "pwsh"})


def truncate_for_scanning(value: str | None, limit: int = MAX_SCAN_LENGTH) -> str:
    """Bound a free-text field before substring/regex scanning."""
    if not value:
        return ""
    return value[:limit]


def is_powershell_process(process_name: str | None) -> bool:
    """True if `process_name` names a PowerShell executable (Windows or Core)."""
    if not process_name:
        return False
    return process_name.strip().lower() in _POWERSHELL_PROCESS_NAMES


class DetectionRule(ABC):
    """Interface every detection rule must implement.

    A rule is a deterministic, stateless function from a collection of
    SecurityEvents to zero or more DetectionResults. The DetectionEngine
    depends only on this interface — it never inspects a rule's
    internals — so new rules can be added by registering an instance
    without modifying the engine.
    """

    rule_id: str
    name: str
    description: str
    severity: DetectionSeverity
    confidence: DetectionConfidence

    @abstractmethod
    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        """Evaluate a collection of events and return any detections."""
        raise NotImplementedError

    def _build_result(
        self,
        *,
        title: str,
        description: str,
        evidence: dict,
        related_event_ids: Sequence[uuid.UUID],
    ) -> DetectionResult:
        """Build a DetectionResult using this rule's own identity/severity/confidence."""
        return DetectionResult(
            detection_id=uuid.uuid4(),
            rule_id=self.rule_id,
            rule_name=self.name,
            severity=self.severity,
            confidence=self.confidence,
            title=title,
            description=description,
            evidence=evidence,
            related_event_ids=list(related_event_ids),
            detected_at=datetime.now(timezone.utc),
        )
