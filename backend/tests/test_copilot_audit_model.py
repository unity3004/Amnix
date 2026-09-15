"""Integration tests for the CopilotAudit persistence model (Step 10F.2).

Require PostgreSQL (see conftest.py's db_session fixture). This step is
data-model-only: nothing here exercises CopilotService, the API, or any
retrieval path — these tests only prove the table/model itself is
correct (valid rows are accepted, invalid ones are rejected by real
database constraints, the Alert foreign key behaves, and no sensitive
field ever made it onto the model).
"""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import DataError, IntegrityError

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case
from app.models.copilot_audit import CopilotAudit
from app.models.security_event import SecurityEvent
from app.models.user import User
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
        email=f"copilotaudituser-{uuid.uuid4().hex[:8]}@example.com",
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


def _fingerprint(text: str = "why was this alert generated?") -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _valid_audit_kwargs(alert_id: uuid.UUID, **overrides) -> dict:
    defaults = dict(
        alert_id=alert_id,
        request_type="ask",
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome="success",
        validation_status="passed",
        http_status=200,
        question_fingerprint=_fingerprint(),
        question_length=30,
        history_turn_count=None,
        duration_ms=12,
    )
    defaults.update(overrides)
    return defaults


# --- valid creation ----------------------------------------------------


def test_valid_ask_audit_is_created(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id))

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.id is not None
    assert audit.alert_id == alert.id
    assert audit.request_type == "ask"
    assert audit.outcome == "success"
    assert audit.validation_status == "passed"
    assert audit.http_status == 200
    assert audit.created_at is not None


def test_valid_follow_up_audit_is_created(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(
        **_valid_audit_kwargs(
            alert.id,
            request_type="follow_up",
            history_turn_count=3,
            question_fingerprint=_fingerprint("what did the command do?"),
        )
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.request_type == "follow_up"
    assert audit.history_turn_count == 3


def test_valid_failure_audit_is_created(db_session):
    """A provider transport failure (timeout/auth/rate-limit): the
    provider never responded, so validation never ran and model_name is
    unknown.
    """
    alert = _make_alert(db_session)
    audit = CopilotAudit(
        **_valid_audit_kwargs(
            alert.id,
            model_name=None,
            outcome="failure",
            validation_status="not_applicable",
            http_status=502,
            duration_ms=None,
        )
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.outcome == "failure"
    assert audit.validation_status == "not_applicable"
    assert audit.model_name is None


def test_valid_validation_failure_audit_is_created(db_session):
    """The provider responded, but AMNIX rejected the content (fabricated
    event_ref, candidate-set violation, confidence-calibration rejection,
    ...) -- distinct from a transport failure.
    """
    alert = _make_alert(db_session)
    audit = CopilotAudit(
        **_valid_audit_kwargs(
            alert.id,
            outcome="failure",
            validation_status="failed",
            http_status=502,
        )
    )

    db_session.add(audit)
    db_session.commit()

    assert audit.validation_status == "failed"


# --- invalid request_type -----------------------------------------------


def test_invalid_request_type_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, request_type="initial_ask"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


# --- invalid outcome / http_status / validation_status -------------------


def test_invalid_outcome_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, outcome="partial"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_invalid_validation_status_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, validation_status="unknown"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_invalid_http_status_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, http_status=500))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_outcome_http_status_validation_status_must_be_mutually_consistent(db_session):
    """success/200/passed and failure/502/{failed,not_applicable} are the
    only combinations CopilotService's current two-outcome shape can
    produce -- a mismatched combination (e.g. success with a 502) is
    rejected outright by the database, not just by application code.
    """
    alert = _make_alert(db_session)
    audit = CopilotAudit(
        **_valid_audit_kwargs(alert.id, outcome="success", http_status=502, validation_status="passed")
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_history_turn_count_must_be_null_for_ask_requests(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, request_type="ask", history_turn_count=0))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


# --- case scope (Step 13D) ------------------------------------------------


def _valid_case_audit_kwargs(case_id: uuid.UUID, **overrides) -> dict:
    defaults = dict(
        alert_id=None,
        case_id=case_id,
        request_type="case_brief",
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome="success",
        validation_status="passed",
        http_status=200,
        question_fingerprint=_fingerprint("what should I know about this case?"),
        question_length=32,
        history_turn_count=None,
        duration_ms=12,
    )
    defaults.update(overrides)
    return defaults


def test_valid_case_brief_audit_is_created(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_case_audit_kwargs(case.id))

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.id is not None
    assert audit.case_id == case.id
    assert audit.alert_id is None
    assert audit.request_type == "case_brief"


def test_case_audit_case_relationship_resolves_the_real_case(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_case_audit_kwargs(case.id))
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.case.id == case.id
    assert audit.case.title == case.title


def test_case_audit_rejects_unknown_case_id(db_session):
    audit = CopilotAudit(**_valid_case_audit_kwargs(uuid.uuid4()))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_audit_rejects_both_alert_id_and_case_id_set(db_session):
    """Step 13D's exactly-one-scope CHECK constraint: an audit row must
    be either alert-scoped or case-scoped, never both."""
    alert = _make_alert(db_session)
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, case_id=case.id, request_type="ask"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_audit_rejects_neither_alert_id_nor_case_id_set(db_session):
    kwargs = _valid_case_audit_kwargs(uuid.uuid4())
    kwargs["case_id"] = None
    audit = CopilotAudit(**kwargs)

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_case_brief_request_type_requires_case_id_not_alert_id(db_session):
    """request_type='case_brief' is a valid enum value, but pairing it
    with an alert_id-only row still violates the exactly-one-scope
    constraint's spirit only insofar as it's still a valid *scope* (one
    of the two is set) -- this test instead proves history_turn_count
    is still forbidden for case_brief, mirroring 'ask'."""
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_case_audit_kwargs(case.id, history_turn_count=0))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_multiple_audits_can_reference_the_same_case(db_session):
    case = _make_case(db_session)
    first = CopilotAudit(**_valid_case_audit_kwargs(case.id))
    second = CopilotAudit(**_valid_case_audit_kwargs(case.id))

    db_session.add_all([first, second])
    db_session.commit()

    reloaded_case = db_session.get(Case, case.id)
    assert reloaded_case is not None


# --- case follow-up scope (Step 13E) --------------------------------------


def test_valid_case_follow_up_audit_is_created(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(
        **_valid_case_audit_kwargs(
            case.id,
            request_type="case_follow_up",
            history_turn_count=2,
            question_fingerprint=_fingerprint("what next?"),
        )
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.request_type == "case_follow_up"
    assert audit.history_turn_count == 2


def test_case_follow_up_history_turn_count_may_be_null_for_no_prior_turns(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(
        **_valid_case_audit_kwargs(case.id, request_type="case_follow_up", history_turn_count=None)
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.history_turn_count is None


def test_case_follow_up_history_turn_count_may_be_zero(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(
        **_valid_case_audit_kwargs(case.id, request_type="case_follow_up", history_turn_count=0)
    )

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.history_turn_count == 0


def test_invalid_case_follow_up_request_type_variant_is_still_rejected(db_session):
    """A near-miss string (not one of the four real vocabulary values)
    is rejected exactly like any other invalid request_type."""
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_case_audit_kwargs(case.id, request_type="case_followup"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_case_follow_up_case_relationship_resolves_the_real_case(db_session):
    case = _make_case(db_session)
    audit = CopilotAudit(**_valid_case_audit_kwargs(case.id, request_type="case_follow_up", history_turn_count=1))
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.case.id == case.id


# --- Alert foreign-key relationship --------------------------------------


def test_audit_alert_relationship_resolves_the_real_alert(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id))
    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.alert.id == alert.id
    assert audit.alert.title == alert.title


def test_audit_rejects_unknown_alert_id(db_session):
    audit = CopilotAudit(**_valid_audit_kwargs(uuid.uuid4()))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_multiple_audits_can_reference_the_same_alert(db_session):
    alert = _make_alert(db_session)
    first = CopilotAudit(**_valid_audit_kwargs(alert.id))
    second = CopilotAudit(
        **_valid_audit_kwargs(alert.id, request_type="follow_up", history_turn_count=1)
    )

    db_session.add_all([first, second])
    db_session.commit()

    reloaded_alert = db_session.get(Alert, alert.id)
    assert reloaded_alert is not None


# --- timezone-aware timestamps --------------------------------------------


def test_created_at_is_timezone_aware_and_server_generated(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id))

    db_session.add(audit)
    db_session.commit()
    db_session.refresh(audit)

    assert audit.created_at.tzinfo is not None
    now = datetime.now(timezone.utc)
    assert abs((now - audit.created_at).total_seconds()) < 30


# --- bounded fields ---------------------------------------------------


def test_provider_name_is_bounded(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, provider_name="x" * 51))

    with pytest.raises((DataError, IntegrityError)):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_provider_name_cannot_be_blank(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, provider_name="   "))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_question_fingerprint_must_be_a_well_formed_sha256_hex_digest(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, question_fingerprint="not-a-real-hash"))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_question_fingerprint_rejects_uppercase_hex(db_session):
    """The CHECK constraint requires lowercase hex specifically -- a
    correctly-shaped but differently-cased digest is still rejected, so
    fingerprints stay directly comparable byte-for-byte.
    """
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, question_fingerprint=_fingerprint().upper()))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_negative_duration_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, duration_ms=-1))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_negative_question_length_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(**_valid_audit_kwargs(alert.id, question_length=-1))

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


def test_negative_history_turn_count_is_rejected(db_session):
    alert = _make_alert(db_session)
    audit = CopilotAudit(
        **_valid_audit_kwargs(alert.id, request_type="follow_up", history_turn_count=-1)
    )

    with pytest.raises(IntegrityError):
        with db_session.begin_nested():
            db_session.add(audit)
            db_session.flush()


# --- secret/exception fields are not part of the model --------------------


def test_model_never_carries_sensitive_or_unbounded_content_fields():
    """Structural proof that nothing resembling raw prompt content,
    secrets, or raw provider exceptions was ever added to this model --
    see the module docstring's exclusion list.
    """
    column_names = {c.name for c in CopilotAudit.__table__.columns}
    forbidden_substrings = (
        "system_instruction",
        "context",
        "raw_data",
        "question_text",
        "question" + "s",  # "questions" isn't a real column either
        "answer",
        "response",
        "conversation",
        "history_text",
        "api_key",
        "secret",
        "credential",
        "token",
        "exception",
        "traceback",
        "error_message",
        "error_detail",
        "stack_trace",
    )
    # Two intentional, safe exceptions to the "question"-shaped substring
    # check: question_fingerprint (a hash) and question_length (a count).
    allowed_question_fields = {"question_fingerprint", "question_length"}

    for name in column_names:
        if name in allowed_question_fields:
            continue
        for forbidden in forbidden_substrings:
            assert forbidden not in name, f"unexpected sensitive-looking column '{name}' (matched '{forbidden}')"


def test_model_has_no_updated_at_column():
    """Audit rows are append-only, exactly like SecurityEvent -- there is
    no update path, so there must be no updated_at column to invite one.
    """
    column_names = {c.name for c in CopilotAudit.__table__.columns}
    assert "updated_at" not in column_names


# --- migration/schema correctness, indexes and constraints ----------------


def test_table_schema_matches_the_model(_pg_engine):
    inspector = inspect(_pg_engine)
    columns = {c["name"]: c for c in inspector.get_columns("copilot_audits")}

    expected_columns = {
        "id",
        "alert_id",
        "case_id",
        "request_type",
        "provider_name",
        "model_name",
        "outcome",
        "validation_status",
        "http_status",
        "question_fingerprint",
        "question_length",
        "history_turn_count",
        "duration_ms",
        "created_at",
    }
    assert set(columns) == expected_columns
    assert columns["created_at"]["type"].timezone is True
    assert columns["model_name"]["nullable"] is True
    # Step 13D: alert_id/case_id are each nullable now -- exactly one of
    # the two must be set, enforced by ck_copilot_audits_exactly_one_scope
    # rather than a NOT NULL column constraint.
    assert columns["alert_id"]["nullable"] is True
    assert columns["case_id"]["nullable"] is True


def test_alert_id_has_a_real_foreign_key(_pg_engine):
    inspector = inspect(_pg_engine)
    foreign_keys = {fk["constrained_columns"][0]: fk for fk in inspector.get_foreign_keys("copilot_audits")}

    assert set(foreign_keys) == {"alert_id", "case_id"}
    alert_fk = foreign_keys["alert_id"]
    assert alert_fk["referred_table"] == "alerts"
    assert alert_fk["referred_columns"] == ["id"]
    assert alert_fk["options"].get("ondelete") == "CASCADE"


def test_case_id_has_a_real_foreign_key(_pg_engine):
    inspector = inspect(_pg_engine)
    foreign_keys = {fk["constrained_columns"][0]: fk for fk in inspector.get_foreign_keys("copilot_audits")}

    case_fk = foreign_keys["case_id"]
    assert case_fk["referred_table"] == "cases"
    assert case_fk["referred_columns"] == ["id"]
    assert case_fk["options"].get("ondelete") == "CASCADE"


def test_expected_indexes_exist(_pg_engine):
    inspector = inspect(_pg_engine)
    index_names = {ix["name"] for ix in inspector.get_indexes("copilot_audits")}

    assert "ix_copilot_audits_alert_id" in index_names
    assert "ix_copilot_audits_case_id" in index_names
    assert "ix_copilot_audits_created_at" in index_names


def test_expected_check_constraints_exist(_pg_engine):
    inspector = inspect(_pg_engine)
    constraint_names = {c["name"] for c in inspector.get_check_constraints("copilot_audits")}

    expected = {
        "ck_copilot_audits_request_type_valid",
        "ck_copilot_audits_outcome_valid",
        "ck_copilot_audits_validation_status_valid",
        "ck_copilot_audits_http_status_valid",
        "ck_copilot_audits_provider_name_not_blank",
        "ck_copilot_audits_model_name_not_blank",
        "ck_copilot_audits_question_fingerprint_sha256_hex",
        "ck_copilot_audits_question_length_non_negative",
        "ck_copilot_audits_history_turn_count_non_negative",
        "ck_copilot_audits_duration_ms_non_negative",
        "ck_copilot_audits_history_turn_count_only_for_follow_up",
        "ck_copilot_audits_outcome_http_validation_consistency",
        "ck_copilot_audits_exactly_one_scope",
    }
    assert expected <= constraint_names
