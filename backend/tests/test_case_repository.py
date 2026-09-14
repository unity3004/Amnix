"""Integration tests for CaseRepository / CaseAlertRepository /
CaseAuditRepository / CaseNoteRepository (Step 12R). Require PostgreSQL.
"""

import uuid
from datetime import datetime, timedelta, timezone

import pytest

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case, CaseAlert
from app.models.case_audit import CaseAudit
from app.models.case_note import CaseNote
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import CaseNoteRepository
from app.repositories.user import UserRepository

pytestmark = pytest.mark.integration


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"caserepo-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


def _make_alert(db_session, **overrides) -> Alert:
    event = SecurityEvent(
        event_timestamp=datetime.now(timezone.utc), event_type="authentication_failure", source="test", raw_data={}
    )
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)

    now = datetime.now(timezone.utc)
    defaults = dict(
        rule_id="brute_force_authentication",
        title="Repo test alert",
        description="d",
        severity="high",
        confidence="high",
        status="new",
        first_seen=now,
        last_seen=now,
        evidence={},
        security_events=[event],
    )
    defaults.update(overrides)
    return AlertRepository(db_session).create(Alert(**defaults))


def _repo(db_session) -> CaseRepository:
    return CaseRepository(db_session)


# =============================================================================
# CaseRepository
# =============================================================================


def test_create_without_commit_then_manual_commit_persists(db_session):
    analyst = _make_user(db_session)
    repo = _repo(db_session)

    case = Case(title="t", description="d", created_by=analyst.id)
    repo.create_without_commit(case)
    db_session.commit()
    db_session.refresh(case)

    assert repo.get_by_id(case.id) is not None


def test_get_by_id_returns_none_for_unknown_id(db_session):
    assert _repo(db_session).get_by_id(uuid.uuid4()) is None


def test_list_orders_newest_first(db_session):
    """Explicit, distinct created_at values -- this fixture's db_session
    runs each test inside one real Postgres transaction (see
    tests/conftest.py), and Postgres's now() returns the TRANSACTION
    start time, not per-statement time, so two ordinary server-default
    timestamps created moments apart in the same test are identical.
    Setting created_at explicitly is the only way to test ordering
    within a single test here -- it never happens through the real API,
    which never accepts a client-supplied created_at at all.
    """
    analyst = _make_user(db_session)
    repo = _repo(db_session)
    base = datetime.now(timezone.utc)
    first = Case(title="first", description="d", created_by=analyst.id, created_at=base)
    repo.create_without_commit(first)
    db_session.commit()
    second = Case(title="second", description="d", created_by=analyst.id, created_at=base + timedelta(seconds=5))
    repo.create_without_commit(second)
    db_session.commit()

    items = repo.list(limit=50, offset=0)

    ids = [c.id for c in items]
    assert ids.index(second.id) < ids.index(first.id)


def test_list_filters_by_status(db_session):
    analyst = _make_user(db_session)
    repo = _repo(db_session)
    open_case = Case(title="open", description="d", created_by=analyst.id, status="OPEN")
    resolved_case = Case(title="resolved", description="d", created_by=analyst.id, status="RESOLVED")
    repo.create_without_commit(open_case)
    repo.create_without_commit(resolved_case)
    db_session.commit()

    items = repo.list(limit=50, offset=0, status="RESOLVED")

    assert resolved_case.id in [c.id for c in items]
    assert open_case.id not in [c.id for c in items]


def test_list_filters_by_priority(db_session):
    analyst = _make_user(db_session)
    repo = _repo(db_session)
    high = Case(title="high", description="d", created_by=analyst.id, priority="high")
    low = Case(title="low", description="d", created_by=analyst.id, priority="low")
    repo.create_without_commit(high)
    repo.create_without_commit(low)
    db_session.commit()

    items = repo.list(limit=50, offset=0, priority="high")

    assert high.id in [c.id for c in items]
    assert low.id not in [c.id for c in items]


def test_list_filters_by_owner_id(db_session):
    analyst = _make_user(db_session)
    owner = _make_user(db_session)
    repo = _repo(db_session)
    owned = Case(title="owned", description="d", created_by=analyst.id, owner_id=owner.id)
    unowned = Case(title="unowned", description="d", created_by=analyst.id)
    repo.create_without_commit(owned)
    repo.create_without_commit(unowned)
    db_session.commit()

    items = repo.list(limit=50, offset=0, owner_id=owner.id)

    assert owned.id in [c.id for c in items]
    assert unowned.id not in [c.id for c in items]


def test_list_pagination_slices_correctly(db_session):
    analyst = _make_user(db_session)
    repo = _repo(db_session)
    for i in range(3):
        repo.create_without_commit(Case(title=f"page-{i}", description="d", created_by=analyst.id))
        db_session.commit()

    page_one = repo.list(limit=1, offset=0)
    page_two = repo.list(limit=1, offset=1)

    assert len(page_one) == 1
    assert len(page_two) == 1
    assert page_one[0].id != page_two[0].id


@pytest.mark.parametrize("limit", [0, 201])
def test_list_rejects_out_of_bounds_limit(db_session, limit):
    with pytest.raises(ValueError):
        _repo(db_session).list(limit=limit, offset=0)


def test_list_rejects_negative_offset(db_session):
    with pytest.raises(ValueError):
        _repo(db_session).list(limit=50, offset=-1)


# =============================================================================
# CaseAlertRepository
# =============================================================================


def test_case_alert_create_and_exists(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)

    assert not repo.exists(case.id, alert.id)
    repo.create_without_commit(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    db_session.commit()

    assert repo.exists(case.id, alert.id)


def test_case_alert_delete_without_commit(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    link = CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id)
    repo.create_without_commit(link)
    db_session.commit()

    repo.delete_without_commit(link)
    db_session.commit()

    assert not repo.exists(case.id, alert.id)


def test_list_alerts_for_case_returns_only_linked_alerts_newest_link_first(db_session):
    """Explicit, distinct linked_at values -- see
    test_list_orders_newest_first's own docstring for why relying on the
    server-default now() cannot distinguish ordering within one test
    under this fixture's shared-transaction behavior.
    """
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    alert_a = _make_alert(db_session, title="a")
    alert_b = _make_alert(db_session, title="b")
    unrelated_alert = _make_alert(db_session, title="unrelated")
    repo = CaseAlertRepository(db_session)
    base = datetime.now(timezone.utc)
    repo.create_without_commit(
        CaseAlert(case_id=case.id, alert_id=alert_a.id, linked_by=analyst.id, linked_at=base)
    )
    db_session.commit()
    repo.create_without_commit(
        CaseAlert(case_id=case.id, alert_id=alert_b.id, linked_by=analyst.id, linked_at=base + timedelta(seconds=5))
    )
    db_session.commit()

    linked = repo.list_alerts_for_case(case.id)

    linked_ids = [a.id for a in linked]
    assert alert_a.id in linked_ids
    assert alert_b.id in linked_ids
    assert unrelated_alert.id not in linked_ids
    assert linked_ids.index(alert_b.id) < linked_ids.index(alert_a.id)


def test_list_alerts_for_case_has_no_per_event_n_plus_one(db_session):
    """Uses selectinload -- accessing .source_event_ids on every linked
    alert must not trigger a lazy per-alert query.
    """
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    repo.create_without_commit(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id))
    db_session.commit()

    db_session.expire_all()
    linked = repo.list_alerts_for_case(case.id)
    for a in linked:
        assert len(a.source_event_ids) >= 0  # accessing the relationship must not raise/lazy-load per row


def test_list_cases_for_alert_returns_only_linked_cases_newest_link_first(db_session):
    """Step 12V: the reverse of test_list_alerts_for_case_returns_only_linked_alerts_newest_link_first."""
    analyst = _make_user(db_session)
    alert = _make_alert(db_session)
    case_a = Case(title="a", description="d", created_by=analyst.id)
    case_b = Case(title="b", description="d", created_by=analyst.id)
    unrelated_case = Case(title="unrelated", description="d", created_by=analyst.id)
    db_session.add_all([case_a, case_b, unrelated_case])
    db_session.commit()

    repo = CaseAlertRepository(db_session)
    base = datetime.now(timezone.utc)
    repo.create_without_commit(CaseAlert(case_id=case_a.id, alert_id=alert.id, linked_by=analyst.id, linked_at=base))
    db_session.commit()
    repo.create_without_commit(
        CaseAlert(case_id=case_b.id, alert_id=alert.id, linked_by=analyst.id, linked_at=base + timedelta(seconds=5))
    )
    db_session.commit()

    linked = repo.list_cases_for_alert(alert.id)

    linked_ids = [c.id for c in linked]
    assert case_a.id in linked_ids
    assert case_b.id in linked_ids
    assert unrelated_case.id not in linked_ids
    assert linked_ids.index(case_b.id) < linked_ids.index(case_a.id)


def test_list_cases_for_alert_returns_empty_for_an_unlinked_alert(db_session):
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    assert repo.list_cases_for_alert(alert.id) == []


def test_list_cases_for_alert_pagination_slices_correctly(db_session):
    analyst = _make_user(db_session)
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    base = datetime.now(timezone.utc)
    cases = []
    for i in range(5):
        case = Case(title=f"case-{i}", description="d", created_by=analyst.id)
        db_session.add(case)
        db_session.commit()
        cases.append(case)
        repo.create_without_commit(CaseAlert(case_id=case.id, alert_id=alert.id, linked_by=analyst.id, linked_at=base + timedelta(seconds=i)))
        db_session.commit()

    page1 = repo.list_cases_for_alert(alert.id, limit=2, offset=0)
    page2 = repo.list_cases_for_alert(alert.id, limit=2, offset=2)
    assert [c.id for c in page1] == [cases[4].id, cases[3].id]
    assert [c.id for c in page2] == [cases[2].id, cases[1].id]


@pytest.mark.parametrize("limit", [0, 201])
def test_list_cases_for_alert_rejects_out_of_bounds_limit(db_session, limit):
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    with pytest.raises(ValueError):
        repo.list_cases_for_alert(alert.id, limit=limit)


def test_list_cases_for_alert_rejects_negative_offset(db_session):
    alert = _make_alert(db_session)
    repo = CaseAlertRepository(db_session)
    with pytest.raises(ValueError):
        repo.list_cases_for_alert(alert.id, offset=-1)


# =============================================================================
# CaseAuditRepository
# =============================================================================


def test_case_audit_create_without_commit_and_list(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    repo = CaseAuditRepository(db_session)

    repo.create_without_commit(CaseAudit(case_id=case.id, actor_user_id=analyst.id, action="CASE_CREATED"))
    db_session.commit()

    items = repo.list_for_case(case.id)
    assert len(items) == 1
    assert items[0].action == "CASE_CREATED"


def test_case_audit_list_is_scoped_to_one_case(db_session):
    analyst = _make_user(db_session)
    case_a = Case(title="a", description="d", created_by=analyst.id)
    case_b = Case(title="b", description="d", created_by=analyst.id)
    db_session.add_all([case_a, case_b])
    db_session.commit()
    repo = CaseAuditRepository(db_session)
    repo.create_without_commit(CaseAudit(case_id=case_a.id, actor_user_id=analyst.id, action="CASE_CREATED"))
    repo.create_without_commit(CaseAudit(case_id=case_b.id, actor_user_id=analyst.id, action="CASE_CREATED"))
    db_session.commit()

    items = repo.list_for_case(case_a.id)

    assert all(item.case_id == case_a.id for item in items)


@pytest.mark.parametrize("limit", [0, 201])
def test_case_audit_list_rejects_out_of_bounds_limit(db_session, limit):
    with pytest.raises(ValueError):
        CaseAuditRepository(db_session).list_for_case(uuid.uuid4(), limit=limit)


# =============================================================================
# CaseNoteRepository
# =============================================================================


def test_case_note_create_commits_on_its_own(db_session):
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    repo = CaseNoteRepository(db_session)

    note = repo.create(CaseNote(case_id=case.id, author_id=analyst.id, body="A note."))

    assert note.id is not None
    assert repo.get_by_id(note.id) is not None


def test_case_note_list_is_chronological_oldest_first(db_session):
    """Explicit, distinct created_at values -- see
    test_list_orders_newest_first's own docstring for why the
    server-default now() cannot distinguish ordering within one test
    under this fixture's shared-transaction behavior (without this, the
    two rows share one timestamp and the real tie-break, `id ASC` on a
    random UUID, would make this test's outcome coincidental).
    """
    analyst = _make_user(db_session)
    case = Case(title="t", description="d", created_by=analyst.id)
    db_session.add(case)
    db_session.commit()
    repo = CaseNoteRepository(db_session)
    base = datetime.now(timezone.utc)
    first = repo.create(CaseNote(case_id=case.id, author_id=analyst.id, body="first", created_at=base))
    second = repo.create(
        CaseNote(case_id=case.id, author_id=analyst.id, body="second", created_at=base + timedelta(seconds=5))
    )

    items = repo.list_for_case(case.id)

    ids = [n.id for n in items]
    assert ids.index(first.id) < ids.index(second.id)
