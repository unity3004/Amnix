"""Integration tests for CopilotAuditRepository (Step 10F.3). Require
PostgreSQL (see conftest.py's db_session fixture).

Data-model-level constraint testing (invalid enums, bounded fields, ...)
already lives in test_copilot_audit_model.py (Step 10F.2) and is not
repeated here -- these tests instead exercise the repository's own
behavior: create/get_by_id/list_for_alert, ordering, pagination bounds,
and alert isolation.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case
from app.models.copilot_audit import CopilotAudit
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.copilot_audit import MAX_LIST_LIMIT, CopilotAuditRepository
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {
        "event_timestamp": datetime.now(timezone.utc),
        "event_type": "authentication_failure",
        "source": "test",
        "raw_data": {},
    }
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _make_alert(db_session, **overrides) -> Alert:
    event = _make_event(db_session)
    now = datetime.now(timezone.utc)
    defaults = {
        "rule_id": "brute_force_authentication",
        "title": "Test alert",
        "description": "Test alert description.",
        "severity": "high",
        "confidence": "high",
        "first_seen": now,
        "last_seen": now,
        "evidence": {},
        "security_events": [event],
    }
    defaults.update(overrides)
    alert = Alert(**defaults)
    db_session.add(alert)
    db_session.commit()
    db_session.refresh(alert)
    return alert


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"copilotauditrepo-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _make_case(db_session, **overrides) -> Case:
    analyst = _make_user(db_session)
    defaults = dict(title="Test case", description="A test case description.", created_by=analyst.id)
    defaults.update(overrides)
    case = Case(**defaults)
    db_session.add(case)
    db_session.commit()
    db_session.refresh(case)
    return case


def _case_audit_kwargs(case_id: uuid.UUID, **overrides) -> dict:
    defaults = dict(
        alert_id=None,
        case_id=case_id,
        request_type="case_brief",
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome="success",
        validation_status="passed",
        http_status=200,
        question_fingerprint="a" * 64,
        question_length=10,
        history_turn_count=None,
        duration_ms=5,
    )
    defaults.update(overrides)
    return defaults


def _create_with_timestamp(repo: CopilotAuditRepository, db_session, alert_id: uuid.UUID, created_at: datetime) -> CopilotAudit:
    """Postgres' `now()` returns the *transaction* start time, not the
    wall clock, and every test in this suite runs inside one outer
    transaction (see conftest.py's db_session fixture) -- so successive
    repo.create() calls within a single test would otherwise all get the
    exact same server-generated created_at. Ordering tests need genuinely
    distinct timestamps, so they set created_at explicitly rather than
    relying on the server default (see test_list_for_alert_tie_breaks_
    deterministically_by_id for the complementary case that WANTS a tie).
    """
    audit = CopilotAudit(**_audit_kwargs(alert_id))
    audit.created_at = created_at
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)
    return audit


def _audit_kwargs(alert_id: uuid.UUID, **overrides) -> dict:
    defaults = dict(
        alert_id=alert_id,
        request_type="ask",
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome="success",
        validation_status="passed",
        http_status=200,
        question_fingerprint="a" * 64,
        question_length=10,
        history_turn_count=None,
        duration_ms=5,
    )
    defaults.update(overrides)
    return defaults


def test_create_persists_and_returns_server_generated_fields(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)

    audit = repo.create(CopilotAudit(**_audit_kwargs(alert.id)))

    assert audit.id is not None
    assert audit.created_at is not None
    assert audit.created_at.tzinfo is not None


def test_create_is_independently_readable_after_commit(db_session):
    """Proves create() truly committed, not merely flushed: a fresh
    get_by_id() call sees the row.
    """
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    created = repo.create(CopilotAudit(**_audit_kwargs(alert.id)))

    fetched = repo.get_by_id(created.id)

    assert fetched is not None
    assert fetched.id == created.id


def test_get_by_id_returns_none_for_unknown_id(db_session):
    repo = CopilotAuditRepository(db_session)

    assert repo.get_by_id(uuid.uuid4()) is None


def test_list_for_alert_returns_only_that_alerts_audits(db_session):
    alert_a = _make_alert(db_session)
    alert_b = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    repo.create(CopilotAudit(**_audit_kwargs(alert_a.id)))
    repo.create(CopilotAudit(**_audit_kwargs(alert_a.id)))
    repo.create(CopilotAudit(**_audit_kwargs(alert_b.id)))

    results = repo.list_for_alert(alert_a.id)

    assert len(results) == 2
    assert all(r.alert_id == alert_a.id for r in results)


def test_list_for_alert_never_returns_another_alerts_rows(db_session):
    alert_a = _make_alert(db_session)
    alert_b = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    repo.create(CopilotAudit(**_audit_kwargs(alert_b.id)))

    results = repo.list_for_alert(alert_a.id)

    assert results == []


def test_list_for_alert_is_newest_first(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    base = datetime.now(timezone.utc)
    first = _create_with_timestamp(repo, db_session, alert.id, base)
    second = _create_with_timestamp(repo, db_session, alert.id, base + timedelta(milliseconds=1))
    third = _create_with_timestamp(repo, db_session, alert.id, base + timedelta(milliseconds=2))

    results = repo.list_for_alert(alert.id)

    assert [r.id for r in results] == [third.id, second.id, first.id]


def test_list_for_alert_tie_breaks_deterministically_by_id(db_session):
    """Rows sharing the exact same created_at (server clock resolution,
    or two rows in the same statement-level snapshot) must still sort in
    a fixed, reproducible order -- id DESC is the documented tie-breaker.
    """
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    shared_ts = datetime.now(timezone.utc)
    first = CopilotAudit(**_audit_kwargs(alert.id))
    second = CopilotAudit(**_audit_kwargs(alert.id))
    first.created_at = shared_ts
    second.created_at = shared_ts
    db_session.add_all([first, second])
    db_session.commit()

    results = repo.list_for_alert(alert.id)

    assert len(results) == 2
    assert results[0].created_at == results[1].created_at == shared_ts
    assert results[0].id == max(first.id, second.id)
    assert results[1].id == min(first.id, second.id)


def test_list_for_alert_respects_limit(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    for _ in range(5):
        repo.create(CopilotAudit(**_audit_kwargs(alert.id)))

    results = repo.list_for_alert(alert.id, limit=2)

    assert len(results) == 2


def test_list_for_alert_respects_offset(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    base = datetime.now(timezone.utc)
    created = [
        _create_with_timestamp(repo, db_session, alert.id, base + timedelta(milliseconds=i)) for i in range(3)
    ]
    newest_first_ids = [c.id for c in reversed(created)]

    page_two = repo.list_for_alert(alert.id, limit=1, offset=1)

    assert [r.id for r in page_two] == newest_first_ids[1:2]


def test_list_for_alert_limit_is_bounded(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)

    with pytest.raises(ValueError):
        repo.list_for_alert(alert.id, limit=MAX_LIST_LIMIT + 1)

    with pytest.raises(ValueError):
        repo.list_for_alert(alert.id, limit=0)


def test_list_for_alert_rejects_negative_offset(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)

    with pytest.raises(ValueError):
        repo.list_for_alert(alert.id, offset=-1)


def test_list_for_alert_returns_empty_list_for_alert_with_no_audits(db_session):
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)

    assert repo.list_for_alert(alert.id) == []


# =============================================================================
# Case scope (Step 13D) -- list_for_case
# =============================================================================


def test_list_for_case_returns_only_that_cases_audits(db_session):
    case_a = _make_case(db_session)
    case_b = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)
    repo.create(CopilotAudit(**_case_audit_kwargs(case_a.id)))
    repo.create(CopilotAudit(**_case_audit_kwargs(case_a.id)))
    repo.create(CopilotAudit(**_case_audit_kwargs(case_b.id)))

    results = repo.list_for_case(case_a.id)

    assert len(results) == 2
    assert all(r.case_id == case_a.id for r in results)


def test_list_for_case_never_returns_another_cases_or_an_alerts_rows(db_session):
    case_a = _make_case(db_session)
    case_b = _make_case(db_session)
    alert = _make_alert(db_session)
    repo = CopilotAuditRepository(db_session)
    repo.create(CopilotAudit(**_case_audit_kwargs(case_b.id)))
    repo.create(CopilotAudit(**_audit_kwargs(alert.id)))

    results = repo.list_for_case(case_a.id)

    assert results == []


def test_list_for_case_is_newest_first(db_session):
    case = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)
    base = datetime.now(timezone.utc)

    def _create_case_audit_with_timestamp(created_at):
        audit = CopilotAudit(**_case_audit_kwargs(case.id))
        audit.created_at = created_at
        db_session.add(audit)
        db_session.commit()
        db_session.refresh(audit)
        return audit

    first = _create_case_audit_with_timestamp(base)
    second = _create_case_audit_with_timestamp(base + timedelta(milliseconds=1))
    third = _create_case_audit_with_timestamp(base + timedelta(milliseconds=2))

    results = repo.list_for_case(case.id)

    assert [r.id for r in results] == [third.id, second.id, first.id]


def test_list_for_case_respects_limit(db_session):
    case = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)
    for _ in range(5):
        repo.create(CopilotAudit(**_case_audit_kwargs(case.id)))

    results = repo.list_for_case(case.id, limit=2)

    assert len(results) == 2


def test_list_for_case_limit_is_bounded(db_session):
    case = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)

    with pytest.raises(ValueError):
        repo.list_for_case(case.id, limit=MAX_LIST_LIMIT + 1)

    with pytest.raises(ValueError):
        repo.list_for_case(case.id, limit=0)


def test_list_for_case_rejects_negative_offset(db_session):
    case = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)

    with pytest.raises(ValueError):
        repo.list_for_case(case.id, offset=-1)


def test_list_for_case_returns_empty_list_for_case_with_no_audits(db_session):
    case = _make_case(db_session)
    repo = CopilotAuditRepository(db_session)

    assert repo.list_for_case(case.id) == []
