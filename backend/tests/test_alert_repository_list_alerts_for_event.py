"""Step 12Y: repository-level tests for
AlertRepository.list_alerts_for_event() -- the authoritative
SecurityEvent -> Alert reverse relationship query. Requires PostgreSQL.

Mirrors tests/test_alert_list_query_efficiency.py's own shape (same
query-counting technique) for the N+1 proof, since serializing each
returned Alert's source_event_ids has the identical selectinload N+1
risk list_recent() already guards against.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import event

from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository

pytestmark = pytest.mark.integration


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": datetime.now(timezone.utc),
        "event_type": "authentication_failure",
        "source": "test-source",
        "raw_data": {},
    }
    defaults.update(overrides)
    event_obj = SecurityEvent(**defaults)
    db_session.add(event_obj)
    db_session.commit()
    db_session.refresh(event_obj)
    return event_obj


def _make_alert(db_session, event_ids, **overrides) -> Alert:
    now = datetime.now(timezone.utc)
    events = AlertRepository(db_session).get_security_events_by_ids(event_ids)
    defaults = {
        "rule_id": "brute_force_authentication",
        "title": "Test alert",
        "description": "d",
        "severity": "high",
        "confidence": "high",
        "status": "new",
        "first_seen": now,
        "last_seen": now,
        "evidence": {},
        "security_events": events,
    }
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


def test_returns_only_alerts_linked_to_the_given_event(db_session):
    event_x = _make_event(db_session)
    event_y = _make_event(db_session)
    alert_for_x = _make_alert(db_session, [event_x.id])
    _make_alert(db_session, [event_y.id], rule_id="suspicious_powershell_execution")

    results = AlertRepository(db_session).list_alerts_for_event(event_x.id)

    assert [a.id for a in results] == [alert_for_x.id]


def test_returns_empty_list_for_event_with_no_linked_alerts(db_session):
    event_obj = _make_event(db_session)
    results = AlertRepository(db_session).list_alerts_for_event(event_obj.id)
    assert results == []


def test_returns_empty_list_for_nonexistent_event_id(db_session):
    results = AlertRepository(db_session).list_alerts_for_event(uuid.uuid4())
    assert results == []


def test_ordering_is_first_seen_desc_id_desc(db_session):
    event_obj = _make_event(db_session)
    now = datetime.now(timezone.utc)
    older = _make_alert(db_session, [event_obj.id], rule_id="brute_force_authentication", first_seen=now - timedelta(hours=1), last_seen=now - timedelta(hours=1))
    newer = _make_alert(db_session, [event_obj.id], rule_id="suspicious_powershell_execution", first_seen=now, last_seen=now)

    results = AlertRepository(db_session).list_alerts_for_event(event_obj.id)

    assert [a.id for a in results] == [newer.id, older.id]


def test_pagination_limit_and_offset(db_session):
    event_obj = _make_event(db_session)
    rule_ids = ["brute_force_authentication", "suspicious_powershell_execution", "encoded_powershell_command"]
    now = datetime.now(timezone.utc)
    made = [
        _make_alert(db_session, [event_obj.id], rule_id=rule_ids[i], first_seen=now - timedelta(seconds=i), last_seen=now)
        for i in range(3)
    ]

    page1 = AlertRepository(db_session).list_alerts_for_event(event_obj.id, limit=2, offset=0)
    page2 = AlertRepository(db_session).list_alerts_for_event(event_obj.id, limit=2, offset=2)

    assert len(page1) == 2
    assert len(page2) == 1
    # Newest-first: made[0] has the latest first_seen.
    assert page1[0].id == made[0].id


def test_invalid_limit_raises(db_session):
    event_obj = _make_event(db_session)
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts_for_event(event_obj.id, limit=0)


def test_invalid_offset_raises(db_session):
    event_obj = _make_event(db_session)
    with pytest.raises(ValueError):
        AlertRepository(db_session).list_alerts_for_event(event_obj.id, offset=-1)


def _count_queries_for_list_and_serialize(db_session, event_id, *, n_alerts: int) -> tuple[int, list]:
    queries: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    connection = db_session.get_bind()
    event.listen(connection, "before_cursor_execute", _capture)
    try:
        alerts = AlertRepository(db_session).list_alerts_for_event(event_id, limit=50)
        assert len(alerts) == n_alerts
        for alert in alerts:
            _ = alert.source_event_ids
    finally:
        event.remove(connection, "before_cursor_execute", _capture)

    return len(queries), queries


def test_list_alerts_for_event_does_not_n_plus_one_with_three_alerts(db_session):
    event_obj = _make_event(db_session)
    for i in range(3):
        _make_alert(db_session, [event_obj.id], rule_id=f"rule-{i}")

    query_count, queries = _count_queries_for_list_and_serialize(db_session, event_obj.id, n_alerts=3)
    assert query_count == 2, f"expected 2 queries (page + batched selectinload), got {query_count}: {queries}"


def test_list_alerts_for_event_query_count_does_not_scale_with_result_size(db_session):
    event_one = _make_event(db_session)
    _make_alert(db_session, [event_one.id], rule_id="rule-a")
    count_for_one, _ = _count_queries_for_list_and_serialize(db_session, event_one.id, n_alerts=1)

    event_five = _make_event(db_session)
    for i in range(5):
        _make_alert(db_session, [event_five.id], rule_id=f"rule-{i}")
    count_for_five, _ = _count_queries_for_list_and_serialize(db_session, event_five.id, n_alerts=5)

    assert count_for_one == count_for_five == 2
