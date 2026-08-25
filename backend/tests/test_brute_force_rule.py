"""Unit tests for the brute-force detection rule. No database required."""

from datetime import datetime, timedelta, timezone

from app.detections.rules.brute_force import AUTH_FAILURE_EVENT_TYPE, BruteForceDetectionRule

THRESHOLD = 5
WINDOW_SECONDS = 300

START = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)


def _rule() -> BruteForceDetectionRule:
    return BruteForceDetectionRule(threshold=THRESHOLD, window_seconds=WINDOW_SECONDS)


def _failures(event_factory, count, *, username="jdoe", source_ip="10.0.0.5", spacing_seconds=30):
    return [
        event_factory(
            event_type=AUTH_FAILURE_EVENT_TYPE,
            username=username,
            source_ip=source_ip,
            event_timestamp=START + timedelta(seconds=spacing_seconds * i),
        )
        for i in range(count)
    ]


def test_below_threshold_no_detection(event_factory):
    events = _failures(event_factory, THRESHOLD - 1)
    assert _rule().evaluate(events) == []


def test_threshold_reached_detects(event_factory):
    events = _failures(event_factory, THRESHOLD)

    results = _rule().evaluate(events)

    assert len(results) == 1
    result = results[0]
    assert result.rule_id == "brute_force_authentication"
    assert result.evidence["failure_count"] == THRESHOLD
    assert result.evidence["username"] == "jdoe"
    assert result.evidence["source_ip"] == "10.0.0.5"
    assert result.evidence["window_seconds"] == WINDOW_SECONDS
    assert len(result.related_event_ids) == THRESHOLD
    assert set(result.related_event_ids) == {e.id for e in events}


def test_events_outside_window_no_detection(event_factory):
    # 5 events spaced 120s apart span 480s, which exceeds the 300s window.
    events = _failures(event_factory, THRESHOLD, spacing_seconds=120)
    assert _rule().evaluate(events) == []


def test_different_usernames_do_not_correlate(event_factory):
    # Same source IP, same window, but each user only has 1 failure.
    # A rule that (incorrectly) grouped only by source_ip would find 5
    # events here and fire a false detection.
    events = [
        event_factory(
            event_type=AUTH_FAILURE_EVENT_TYPE,
            username=f"user{i}",
            source_ip="10.0.0.5",
            event_timestamp=START + timedelta(seconds=10 * i),
        )
        for i in range(THRESHOLD)
    ]
    assert _rule().evaluate(events) == []


def test_different_source_ips_do_not_correlate(event_factory):
    # Same username, same window, but each source IP only has 1 failure.
    events = [
        event_factory(
            event_type=AUTH_FAILURE_EVENT_TYPE,
            username="jdoe",
            source_ip=f"10.0.0.{i}",
            event_timestamp=START + timedelta(seconds=10 * i),
        )
        for i in range(THRESHOLD)
    ]
    assert _rule().evaluate(events) == []


def test_non_auth_failure_events_are_ignored(event_factory):
    events = [
        event_factory(event_type="process_creation", username="jdoe", source_ip="10.0.0.5")
        for _ in range(THRESHOLD)
    ]
    assert _rule().evaluate(events) == []


def test_events_with_no_username_and_no_source_ip_are_ignored(event_factory):
    events = _failures(event_factory, THRESHOLD, username=None, source_ip=None)
    assert _rule().evaluate(events) == []


def test_threshold_and_window_come_from_configuration_not_hardcoded(event_factory):
    # A rule configured with a much lower threshold/window should behave
    # differently from the default, proving these aren't hardcoded.
    lenient_rule = BruteForceDetectionRule(threshold=2, window_seconds=60)
    events = _failures(event_factory, 2, spacing_seconds=10)

    results = lenient_rule.evaluate(events)

    assert len(results) == 1
    assert results[0].evidence["failure_count"] == 2
    assert results[0].evidence["threshold"] == 2
    assert results[0].evidence["window_seconds"] == 60


def test_multiple_independent_groups_each_detected(event_factory):
    group_a = _failures(event_factory, THRESHOLD, username="alice", source_ip="10.0.0.1")
    group_b = _failures(event_factory, THRESHOLD, username="bob", source_ip="10.0.0.2")

    results = _rule().evaluate(group_a + group_b)

    assert len(results) == 2
    usernames = {r.evidence["username"] for r in results}
    assert usernames == {"alice", "bob"}
