"""Dashboard Data Foundation: query-efficiency proof for
AlertRepository.list_recent(). Requires PostgreSQL.

The brief explicitly requires proving that retrieving a multi-alert
page and serializing `source_event_ids` for every alert does not
produce one relationship query per alert (N+1) -- this is a repository-
level test, not an HTTP-level one, because it asserts on SQL execution
counts, an implementation detail no HTTP response can observe directly.
"""

import uuid
from datetime import datetime, timezone

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


def _count_queries_for_list_and_serialize(db_session, *, n_alerts: int) -> tuple[int, list]:
    for _ in range(n_alerts):
        evt = _make_event(db_session)
        _make_alert(db_session, event_ids=[evt.id])

    queries: list[str] = []

    def _capture(conn, cursor, statement, parameters, context, executemany):
        queries.append(statement)

    connection = db_session.get_bind()
    event.listen(connection, "before_cursor_execute", _capture)
    try:
        alerts = AlertRepository(db_session).list_recent(limit=50)
        # Force serialization of the relationship-derived property for
        # every alert, exactly like AlertRead.model_validate() does for
        # each item in a GET /alerts response.
        for alert in alerts:
            _ = alert.source_event_ids
    finally:
        event.remove(connection, "before_cursor_execute", _capture)

    return len(queries), queries


def test_list_recent_does_not_n_plus_one_with_three_alerts(db_session):
    query_count, queries = _count_queries_for_list_and_serialize(db_session, n_alerts=3)
    # Expected: exactly one SELECT for the Alert page, plus exactly one
    # batched selectinload SELECT for every referenced SecurityEvent --
    # never one additional query per alert.
    assert query_count == 2, f"expected 2 queries (page + batched selectinload), got {query_count}: {queries}"


def test_list_recent_query_count_does_not_scale_with_result_size(db_session):
    """The real N+1 proof: query count for 1 alert vs. 5 alerts must be
    identical. If selectinload were ever accidentally removed/broken,
    this test (not just the fixed-count one above) would catch it even
    if someone "fixed" the count to match a new, still-broken baseline.
    """
    count_for_one, _ = _count_queries_for_list_and_serialize(db_session, n_alerts=1)
    count_for_five, _ = _count_queries_for_list_and_serialize(db_session, n_alerts=5)
    assert count_for_one == count_for_five == 2
