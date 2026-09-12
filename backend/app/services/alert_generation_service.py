"""AlertGenerationService: turns DetectionEngine output into real Alerts,
triggered automatically after SecurityEvent ingestion (see app.api.events).

Step 10H. Before this, DetectionEngine/DetectionRuleRegistry existed and
were unit-tested in isolation, but nothing in the application ever called
them — every Alert had to be created by a caller POSTing fully-formed
alert data directly to POST /alerts. This class is the missing link:
ingest -> correlate -> detect -> alert, closing that gap without changing
anything about how alerts, once created, are investigated or audited.

Correlation candidates: a rule like BruteForceDetectionRule needs to see
more than just the single event that was just ingested — it correlates
authentication failures across a time window. Rather than have this
class (or DetectionEngine) know which specific rules need history, it
fetches every recent SecurityEvent that shares the just-ingested event's
`event_type`, within `correlation_window_seconds` of its own timestamp
(see SecurityEventRepository.list_recent_by_type), and hands the whole
set to DetectionEngine.evaluate_events(). Rules that only ever look at
one event at a time (the PowerShell rules) simply ignore the extra
context; that decision belongs entirely to each rule, exactly as
DetectionEngine's own docstring already establishes.

Deduplication: DetectionResult.detection_id is a fresh UUID on every
evaluate() call, so it cannot be used to recognize "this is the same
detection I already alerted on". Re-running detection as new events
arrive within the same window will, in the common case, keep finding the
same earliest qualifying window and therefore the same related_event_ids
for as long as the earliest event in it stays inside the lookback window
— so before creating an Alert for a DetectionResult, this class checks
AlertRepository.exists_with_rule_and_exact_events(rule_id,
related_event_ids) and skips creating a duplicate. A later window that
genuinely covers a different (even overlapping) set of events is treated
as a new, additional detection — deliberately: AMNIX has no
alert-merging/escalation-of-an-existing-alert concept yet (see
app.models.alert's own docstring), and inventing one here would be well
outside this step's scope.

Failure isolation, mirroring the audit layer's own established
guarantee (see CopilotService._record_copilot_audit): automatic alert
generation is a best-effort side effect of event ingestion, never a
precondition for it. generate_from_event() never raises. If detection
evaluation itself fails, or creating an Alert for one particular
DetectionResult fails, the failure is logged server-side and generation
continues/returns whatever succeeded — the SecurityEvent that triggered
it has already been durably ingested by the time this runs and that must
never be undone or reported as failed because of a problem here.
"""

import logging
from datetime import timedelta

from app.core.config import get_settings
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.repositories.security_event import SecurityEventRepository
from app.schemas.alert import AlertCreate
from app.schemas.detection import DetectionResult
from app.services.alert_service import AlertService
from app.services.detection_service import DetectionEngine, build_default_engine

logger = logging.getLogger(__name__)


class AlertGenerationService:
    def __init__(
        self,
        security_event_repository: SecurityEventRepository,
        alert_repository: AlertRepository,
        alert_service: AlertService,
        detection_engine: DetectionEngine | None = None,
        correlation_window_seconds: int | None = None,
    ) -> None:
        self._security_event_repository = security_event_repository
        self._alert_repository = alert_repository
        self._alert_service = alert_service
        self._detection_engine = detection_engine if detection_engine is not None else build_default_engine()
        # Reuses the existing brute-force correlation window setting as
        # the general "how far back to look for correlatable siblings of
        # this event" lookback -- it is the only correlation-window
        # concept that exists in AMNIX today, and single-event rules
        # (the PowerShell rules) are indifferent to its value since they
        # never look past the one event that actually matches.
        self._correlation_window_seconds = (
            correlation_window_seconds
            if correlation_window_seconds is not None
            else get_settings().brute_force_window_seconds
        )

    def generate_from_event(self, event: SecurityEvent) -> list[Alert]:
        """Best-effort: never raises (see module docstring). Returns the
        Alerts actually created for `event` — an empty list means either
        "nothing matched" or "something failed and was logged", which is
        the correct level of detail for a caller that must not change
        its own behavior either way (see app.api.events.create_event).
        """
        try:
            candidates = self._fetch_candidates(event)
            results = self._detection_engine.evaluate_events(candidates)
        except Exception:
            logger.exception("Detection evaluation failed while processing SecurityEvent %s", event.id)
            return []

        created: list[Alert] = []
        for result in results:
            try:
                if self._alert_repository.exists_with_rule_and_exact_events(result.rule_id, result.related_event_ids):
                    continue
                created.append(self._alert_service.create(_to_alert_create(result)))
            except Exception:
                logger.exception(
                    "Failed to create Alert from DetectionResult %s (rule_id=%s) for SecurityEvent %s",
                    result.detection_id,
                    result.rule_id,
                    event.id,
                )
        return created

    def _fetch_candidates(self, event: SecurityEvent) -> list[SecurityEvent]:
        since = event.event_timestamp - timedelta(seconds=self._correlation_window_seconds)
        candidates = self._security_event_repository.list_recent_by_type(event.event_type, since=since)
        # `event` was already committed by SecurityEventService.ingest()
        # before this runs, and event.event_timestamp >= since by
        # construction, so it is always already present in `candidates`
        # -- no separate "include the current event" step is needed.
        return candidates


def _to_alert_create(result: DetectionResult) -> AlertCreate:
    """DetectionResult and AlertCreate deliberately share the
    severity/confidence enums (see app.schemas.alert's own docstring),
    so this is a direct field mapping, not a translation. `first_seen`/
    `last_seen` both use `detected_at` (when AMNIX computed the
    detection) rather than trying to derive a rule-specific "when did
    the underlying activity start" timestamp generically here — exactly
    matching Alert's own documented "every alert starts with first_seen
    == last_seen" convention. `alert_metadata` carries the originating
    detection_id purely for traceability; it is not evidence and is
    never used for any decision.
    """
    return AlertCreate(
        rule_id=result.rule_id,
        title=result.title,
        description=result.description,
        severity=result.severity,
        confidence=result.confidence,
        first_seen=result.detected_at,
        last_seen=result.detected_at,
        evidence=result.evidence,
        alert_metadata={"detection_id": str(result.detection_id)},
        source_event_ids=result.related_event_ids,
    )
