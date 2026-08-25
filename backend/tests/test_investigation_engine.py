"""Unit tests for the InvestigationEngine. No database required.

Uses the alert_factory/event_factory fixtures from conftest.py to build
transient (unpersisted) Alert/SecurityEvent objects directly in memory.
"""

from datetime import datetime, timedelta, timezone

from app.services.investigation_service import InvestigationEngine

ENGINE = InvestigationEngine()

START = datetime(2026, 8, 25, 10, 0, 0, tzinfo=timezone.utc)


def test_alert_with_one_event(event_factory, alert_factory):
    event = event_factory(event_timestamp=START, hostname="WKS-01", username="jdoe")
    alert = alert_factory(security_events=[event])

    context = ENGINE.build_context(alert)

    assert len(context.timeline) == 1
    assert context.timeline[0].event_id == event.id
    assert context.summary.event_count == 1


def test_alert_with_multiple_events(event_factory, alert_factory):
    events = [
        event_factory(event_timestamp=START + timedelta(seconds=i * 30))
        for i in range(4)
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert len(context.timeline) == 4
    assert {entry.event_id for entry in context.timeline} == {e.id for e in events}
    assert context.summary.event_count == 4


def test_timeline_ordering_is_chronological(event_factory, alert_factory):
    late = event_factory(event_timestamp=START + timedelta(minutes=10))
    early = event_factory(event_timestamp=START)
    middle = event_factory(event_timestamp=START + timedelta(minutes=5))
    # Deliberately constructed out of order.
    alert = alert_factory(security_events=[late, early, middle])

    context = ENGINE.build_context(alert)

    assert [entry.event_id for entry in context.timeline] == [early.id, middle.id, late.id]


def test_equal_timestamp_tie_break_is_deterministic_by_event_id(event_factory, alert_factory):
    event_a = event_factory(event_timestamp=START)
    event_b = event_factory(event_timestamp=START)
    expected_order = sorted([event_a.id, event_b.id])

    # Run twice, in each input order, and confirm the output order is
    # always the same — driven by event id, not input/insertion order.
    for events in ([event_a, event_b], [event_b, event_a]):
        alert = alert_factory(security_events=events)
        context = ENGINE.build_context(alert)
        assert [entry.event_id for entry in context.timeline] == expected_order


def test_unique_hostname_extraction(event_factory, alert_factory):
    events = [
        event_factory(hostname="WKS-01"),
        event_factory(hostname="WKS-01"),
        event_factory(hostname="WKS-02"),
        event_factory(hostname=None),
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.hostnames == ["WKS-01", "WKS-02"]


def test_unique_username_extraction(event_factory, alert_factory):
    events = [
        event_factory(username="alice"),
        event_factory(username="bob"),
        event_factory(username="alice"),
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.usernames == ["alice", "bob"]


def test_unique_ip_extraction(event_factory, alert_factory):
    events = [
        event_factory(source_ip="10.0.0.5", destination_ip="10.0.0.1"),
        event_factory(source_ip="10.0.0.5", destination_ip="10.0.0.2"),
        event_factory(source_ip="10.0.0.6", destination_ip=None),
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.source_ips == ["10.0.0.5", "10.0.0.6"]
    assert context.entities.destination_ips == ["10.0.0.1", "10.0.0.2"]


def test_unique_process_extraction(event_factory, alert_factory):
    events = [
        event_factory(process_name="powershell.exe"),
        event_factory(process_name="cmd.exe"),
        event_factory(process_name="powershell.exe"),
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.process_names == ["cmd.exe", "powershell.exe"]


def test_unique_file_hash_extraction(event_factory, alert_factory):
    events = [
        event_factory(file_hash="a" * 64),
        event_factory(file_hash="b" * 64),
        event_factory(file_hash="a" * 64),
        event_factory(file_hash=None),
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.file_hashes == sorted({"a" * 64, "b" * 64})


def test_empty_optional_fields_do_not_crash_and_produce_empty_entities(event_factory, alert_factory):
    events = [
        event_factory(
            hostname=None,
            username=None,
            source_ip=None,
            destination_ip=None,
            process_name=None,
            file_hash=None,
            command_line=None,
        )
        for _ in range(3)
    ]
    alert = alert_factory(security_events=events)

    context = ENGINE.build_context(alert)

    assert context.entities.hostnames == []
    assert context.entities.usernames == []
    assert context.entities.source_ips == []
    assert context.entities.destination_ips == []
    assert context.entities.process_names == []
    assert context.entities.file_hashes == []
    assert context.timeline[0].hostname is None
    assert context.timeline[0].command_line is None
    # No "It involves ..." clause when there's nothing to involve.
    assert "involves" not in context.summary.text


def test_alert_with_no_events_does_not_crash(alert_factory):
    alert = alert_factory(security_events=[])

    context = ENGINE.build_context(alert)

    assert context.timeline == []
    assert context.summary.event_count == 0
    assert context.summary.first_event_at is None
    assert context.summary.timespan_seconds is None


def test_summary_text_is_exact_and_deterministic(event_factory, alert_factory):
    events = [
        event_factory(event_timestamp=START, hostname="WKS-01", username="jdoe"),
        event_factory(event_timestamp=START + timedelta(minutes=4), hostname="WKS-01", username="jdoe"),
    ]
    alert = alert_factory(
        security_events=events, rule_id="brute_force_authentication", title="Brute force detected"
    )

    context = ENGINE.build_context(alert)

    expected = (
        "Alert 'Brute force detected' was generated by rule 'brute_force_authentication'. "
        "It involves user jdoe and host WKS-01. "
        "The alert contains 2 related security events spanning 4 minutes."
    )
    assert context.summary.text == expected


def test_summary_text_singular_forms(event_factory, alert_factory):
    event = event_factory(event_timestamp=START, hostname="WKS-01", username="jdoe")
    alert = alert_factory(security_events=[event], rule_id="brute_force_authentication", title="Single event alert")

    context = ENGINE.build_context(alert)

    assert context.summary.text == (
        "Alert 'Single event alert' was generated by rule 'brute_force_authentication'. "
        "It involves user jdoe and host WKS-01. "
        "The alert contains 1 related security event."
    )


def test_summary_text_multiple_users_and_hosts(event_factory, alert_factory):
    events = [
        event_factory(event_timestamp=START, hostname="WKS-01", username="alice"),
        event_factory(event_timestamp=START, hostname="WKS-02", username="bob"),
    ]
    alert = alert_factory(security_events=events, title="Multi-entity alert")

    context = ENGINE.build_context(alert)

    assert "users alice and bob" in context.summary.text
    assert "hosts WKS-01 and WKS-02" in context.summary.text


def test_build_context_does_not_mutate_alert_status(event_factory, alert_factory):
    event = event_factory()
    alert = alert_factory(security_events=[event], status="new")

    ENGINE.build_context(alert)

    assert alert.status == "new"
