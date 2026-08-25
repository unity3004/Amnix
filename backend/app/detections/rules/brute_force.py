"""Brute-force authentication detection.

Flags a burst of repeated authentication failures correlated by the pair
(username, source_ip), within a configurable time window.

`event_type` is expected to already be normalized to
AUTH_FAILURE_EVENT_TYPE by the ingestion/normalization layer for any
source that reports authentication failures (Windows 4625, Linux
"Failed password", etc.) — this rule does not interpret source-specific
failure codes itself.
"""

from collections.abc import Sequence
from itertools import groupby

from app.core.config import get_settings
from app.detections.base import DetectionRule
from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionConfidence, DetectionResult, DetectionSeverity

AUTH_FAILURE_EVENT_TYPE = "authentication_failure"

_GroupKey = tuple[str | None, str | None]


class BruteForceDetectionRule(DetectionRule):
    """Detects >= `threshold` authentication failures for the same
    (username, source_ip) pair within `window_seconds`.

    Severity is fixed at HIGH: a burst of failures crossing the
    threshold is a meaningful signal regardless of count. Confidence is
    fixed at HIGH because the match is an exact, deterministic count —
    not a fuzzy heuristic — though whether it's truly malicious (versus,
    say, a user who forgot their password) is a separate judgment left
    to the analyst; that uncertainty is not what `confidence` measures
    here.
    """

    rule_id = "brute_force_authentication"
    name = "Brute Force Authentication"
    description = (
        "Detects repeated authentication failures for the same user and "
        "source IP within a short time window, indicative of a "
        "credential-guessing (brute force) attempt."
    )
    severity = DetectionSeverity.HIGH
    confidence = DetectionConfidence.HIGH

    def __init__(self, threshold: int | None = None, window_seconds: int | None = None) -> None:
        settings = get_settings()
        self.threshold = threshold if threshold is not None else settings.brute_force_threshold
        self.window_seconds = (
            window_seconds if window_seconds is not None else settings.brute_force_window_seconds
        )

    def evaluate(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        failures = [e for e in events if (e.event_type or "").strip().lower() == AUTH_FAILURE_EVENT_TYPE]
        if not failures:
            return []

        results: list[DetectionResult] = []
        for (username, source_ip), group in self._group_by_identity(failures):
            window = self._find_qualifying_window(sorted(group, key=lambda e: e.event_timestamp))
            if window is None:
                continue
            results.append(self._build_detection(username, source_ip, window))
        return results

    @staticmethod
    def _group_by_identity(events: list[SecurityEvent]):
        def key(event: SecurityEvent) -> _GroupKey:
            source_ip = str(event.source_ip) if event.source_ip is not None else None
            return (event.username, source_ip)

        # Nothing to correlate on if both dimensions are missing.
        correlatable = [e for e in events if e.username is not None or e.source_ip is not None]
        correlatable.sort(key=key)
        return groupby(correlatable, key=key)

    def _find_qualifying_window(self, events: list[SecurityEvent]) -> list[SecurityEvent] | None:
        """Two-pointer scan for the earliest window of >= threshold events
        whose span does not exceed window_seconds. O(n) since `left` only
        moves forward.
        """
        left = 0
        for right in range(len(events)):
            span = (events[right].event_timestamp - events[left].event_timestamp).total_seconds()
            while span > self.window_seconds:
                left += 1
                span = (events[right].event_timestamp - events[left].event_timestamp).total_seconds()
            if right - left + 1 >= self.threshold:
                return events[left : right + 1]
        return None

    def _build_detection(
        self, username: str | None, source_ip: str | None, window: list[SecurityEvent]
    ) -> DetectionResult:
        first, last = window[0], window[-1]
        who = username or "unknown user"
        origin = source_ip or "unknown source"
        evidence = {
            "failure_count": len(window),
            "username": username,
            "source_ip": source_ip,
            "window_seconds": self.window_seconds,
            "threshold": self.threshold,
            "first_failure_at": first.event_timestamp.isoformat(),
            "last_failure_at": last.event_timestamp.isoformat(),
        }
        return self._build_result(
            title=f"Brute force authentication detected for {who} from {origin}",
            description=(
                f"{len(window)} authentication failures for {who} from {origin} "
                f"within {self.window_seconds} seconds (threshold: {self.threshold})."
            ),
            evidence=evidence,
            related_event_ids=[e.id for e in window],
        )
