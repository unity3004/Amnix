"""Unit tests for the DetectionEngine and rule registry. No database required."""

import pytest

from app.detections.base import DetectionRule
from app.detections.registry import DetectionRuleRegistry, build_default_registry
from app.schemas.detection import DetectionConfidence, DetectionSeverity
from app.services.detection_service import DetectionEngine


class _AlwaysMatchRule(DetectionRule):
    rule_id = "always_match"
    name = "Always Match"
    description = "Matches every non-empty event collection, for testing."
    severity = DetectionSeverity.LOW
    confidence = DetectionConfidence.LOW

    def evaluate(self, events):
        if not events:
            return []
        return [
            self._build_result(
                title="matched",
                description="matched",
                evidence={},
                related_event_ids=[e.id for e in events],
            )
        ]


class _AlsoAlwaysMatchRule(_AlwaysMatchRule):
    rule_id = "also_always_match"
    name = "Also Always Match"


class _NeverMatchRule(DetectionRule):
    rule_id = "never_match"
    name = "Never Match"
    description = "Never matches, for testing."
    severity = DetectionSeverity.LOW
    confidence = DetectionConfidence.LOW

    def evaluate(self, events):
        return []


class _BrokenRule(DetectionRule):
    rule_id = "broken"
    name = "Broken"
    description = "Always raises, for testing engine fault isolation."
    severity = DetectionSeverity.LOW
    confidence = DetectionConfidence.LOW

    def evaluate(self, events):
        raise RuntimeError("boom")


def test_no_matching_rules_returns_empty(event_factory):
    engine = DetectionEngine()
    engine.register(_NeverMatchRule())

    assert engine.evaluate_events([event_factory()]) == []


def test_one_matching_rule_returns_one_result(event_factory):
    engine = DetectionEngine()
    engine.register(_AlwaysMatchRule())
    engine.register(_NeverMatchRule())

    results = engine.evaluate_events([event_factory()])

    assert len(results) == 1
    assert results[0].rule_id == "always_match"


def test_multiple_matching_rules_return_multiple_results(event_factory):
    engine = DetectionEngine()
    engine.register(_AlwaysMatchRule())
    engine.register(_AlsoAlwaysMatchRule())

    results = engine.evaluate_events([event_factory()])

    assert len(results) == 2
    assert {r.rule_id for r in results} == {"always_match", "also_always_match"}


def test_rule_isolation_broken_rule_does_not_block_others(event_factory):
    engine = DetectionEngine()
    engine.register(_BrokenRule())
    engine.register(_AlwaysMatchRule())

    results = engine.evaluate_events([event_factory()])

    assert len(results) == 1
    assert results[0].rule_id == "always_match"


def test_rule_isolation_rules_do_not_share_state(event_factory):
    # Two independently-registered instances of the same matching rule
    # each see the full event set and produce independent results.
    engine = DetectionEngine()
    engine.register(_AlwaysMatchRule())
    engine.register(_NeverMatchRule())
    events = [event_factory(), event_factory()]

    results = engine.evaluate_events(events)

    assert len(results) == 1
    assert set(results[0].related_event_ids) == {e.id for e in events}


def test_evaluate_event_wraps_a_single_event(event_factory):
    engine = DetectionEngine()
    engine.register(_AlwaysMatchRule())
    event = event_factory()

    results = engine.evaluate_event(event)

    assert len(results) == 1
    assert results[0].related_event_ids == [event.id]


def test_registry_rejects_duplicate_rule_ids():
    registry = DetectionRuleRegistry()
    registry.register(_NeverMatchRule())

    with pytest.raises(ValueError):
        registry.register(_NeverMatchRule())


def test_default_registry_includes_builtin_rules():
    registry = build_default_registry()

    rule_ids = {rule.rule_id for rule in registry.rules}

    assert rule_ids == {
        "brute_force_authentication",
        "suspicious_powershell_execution",
        "encoded_powershell_command",
    }
