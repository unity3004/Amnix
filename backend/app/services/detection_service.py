"""DetectionEngine: evaluates SecurityEvents against registered detection rules."""

import logging
from collections.abc import Sequence

from app.detections.base import DetectionRule
from app.detections.registry import DetectionRuleRegistry, build_default_registry
from app.models.security_event import SecurityEvent
from app.schemas.detection import DetectionResult

logger = logging.getLogger(__name__)


class DetectionEngine:
    """Runs registered detection rules against SecurityEvent data.

    The engine has no knowledge of how any individual rule works — it
    only depends on the DetectionRule interface. New rules are added by
    registering them, not by modifying this class.

    A rule that raises does not stop other rules from running: one
    faulty or unexpectedly-failing rule should not blind the engine to
    every other detection. The failure is logged, not silently dropped.
    """

    def __init__(self, registry: DetectionRuleRegistry | None = None) -> None:
        self._registry = registry if registry is not None else DetectionRuleRegistry()

    def register(self, rule: DetectionRule) -> None:
        self._registry.register(rule)

    def evaluate_event(self, event: SecurityEvent) -> list[DetectionResult]:
        """Evaluate a single event against all registered rules."""
        return self.evaluate_events([event])

    def evaluate_events(self, events: Sequence[SecurityEvent]) -> list[DetectionResult]:
        """Evaluate a collection of events against all registered rules.

        Use this when a rule needs to correlate across multiple events
        (e.g. brute force). Rules that only look at one event at a time
        simply ignore the rest of the collection.
        """
        results: list[DetectionResult] = []
        for rule in self._registry.rules:
            try:
                results.extend(rule.evaluate(events))
            except Exception:
                logger.exception("Detection rule '%s' raised during evaluation", rule.rule_id)
        return results


def build_default_engine() -> DetectionEngine:
    """Build a DetectionEngine pre-populated with AMNIX's built-in rules."""
    return DetectionEngine(build_default_registry())
