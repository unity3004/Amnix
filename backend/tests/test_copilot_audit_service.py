"""Tests for CopilotAuditService (Step 10F.3): fingerprinting (pure,
no database) plus service-level create/retrieve/validation/failure-
translation behavior (integration, require PostgreSQL -- see
conftest.py's db_session fixture) and a structural security-regression
check over the repository/service modules themselves.
"""

import hashlib
import uuid
from datetime import datetime, timezone

import pytest
from sqlalchemy.exc import SQLAlchemyError

from app.core.security import hash_password
from app.models.alert import Alert
from app.models.case import Case
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.copilot_audit import CopilotAuditRepository
from app.repositories.user import UserRepository
from app.schemas.ai import CopilotMessage, CopilotMessageRole
from app.schemas.copilot_audit import AuditOutcome, AuditRequestType, AuditValidationStatus
from app.services.copilot_audit_service import (
    CopilotAuditAlertNotFoundError,
    CopilotAuditCaseNotFoundError,
    CopilotAuditPersistenceError,
    CopilotAuditService,
    CopilotAuditValidationError,
)

# =============================================================================
# Fingerprinting -- pure logic, no database required
# =============================================================================


def _turn(role: CopilotMessageRole, content: str) -> CopilotMessage:
    return CopilotMessage(role=role, content=content)


def test_same_ask_question_produces_the_same_fingerprint():
    a = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")
    b = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")

    assert a == b


def test_different_ask_question_produces_a_different_fingerprint():
    a = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")
    b = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Is this malicious?")

    assert a != b


def test_same_follow_up_question_and_identical_history_produces_the_same_fingerprint():
    history = [
        _turn(CopilotMessageRole.USER, "Why is this suspicious?"),
        _turn(CopilotMessageRole.ASSISTANT, "Because of repeated auth failures."),
    ]

    a = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", history)
    b = CopilotAuditService.compute_fingerprint(
        AuditRequestType.FOLLOW_UP,
        "What next?",
        [
            _turn(CopilotMessageRole.USER, "Why is this suspicious?"),
            _turn(CopilotMessageRole.ASSISTANT, "Because of repeated auth failures."),
        ],
    )

    assert a == b


def test_changing_history_content_changes_the_fingerprint():
    base_history = [_turn(CopilotMessageRole.USER, "Why is this suspicious?")]
    changed_history = [_turn(CopilotMessageRole.USER, "Why is this NOT suspicious?")]

    a = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", base_history)
    b = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", changed_history)

    assert a != b


def test_changing_history_order_changes_the_fingerprint():
    turn_a = _turn(CopilotMessageRole.USER, "First question.")
    turn_b = _turn(CopilotMessageRole.ASSISTANT, "First answer.")

    forward = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", [turn_a, turn_b])
    reversed_order = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", [turn_b, turn_a])

    assert forward != reversed_order


def test_empty_history_is_represented_deterministically():
    a = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", [])
    b = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "What next?", [])

    assert a == b
    # And it must differ from a non-empty history for the same question.
    non_empty = CopilotAuditService.compute_fingerprint(
        AuditRequestType.FOLLOW_UP, "What next?", [_turn(CopilotMessageRole.USER, "x")]
    )
    assert a != non_empty


def test_ask_and_follow_up_do_not_collide_for_identical_question_text():
    ask_fp = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Is this malicious?")
    follow_up_fp = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "Is this malicious?", [])

    assert ask_fp != follow_up_fp


def test_fingerprint_history_turn_boundary_is_not_ambiguous():
    """Two turns ["AB", "C"] must not canonicalize the same as one turn
    ["ABC"] -- guards against naive, non-length-prefixed concatenation.
    """
    two_turns = [
        _turn(CopilotMessageRole.USER, "AB"),
        _turn(CopilotMessageRole.USER, "C"),
    ]
    one_turn = [_turn(CopilotMessageRole.USER, "ABC")]

    fp_two = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "q", two_turns)
    fp_one = CopilotAuditService.compute_fingerprint(AuditRequestType.FOLLOW_UP, "q", one_turn)

    assert fp_two != fp_one


def test_fingerprint_output_is_always_lowercase_sha256_hex():
    fp = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")

    assert len(fp) == 64
    assert fp == fp.lower()
    int(fp, 16)  # raises ValueError if not valid hex


def test_fingerprint_is_deterministic_for_unicode_content():
    question = "Pourquoi cette alerte a-t-elle été générée ? éè中文 \U0001F600"

    a = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, question)
    b = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, question)

    assert a == b
    assert len(a) == 64


def test_fingerprint_whitespace_canonicalization_rule():
    """Documented rule: leading/trailing whitespace is stripped, but
    internal whitespace is preserved exactly (not collapsed).
    """
    padded = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "  Why was this alert generated?  ")
    unpadded = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")
    assert padded == unpadded

    single_space = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this alert generated?")
    double_space = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "Why was this  alert generated?")
    assert single_space != double_space


def test_fingerprint_matches_manual_reference_computation():
    """Pins the exact canonical encoding documented in
    CopilotAuditService.compute_fingerprint's docstring, so a future
    accidental change to the format is caught here rather than only
    silently changing everyone's fingerprints.
    """
    canonical = "v1:3:ask:5:hello:0:"
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    actual = CopilotAuditService.compute_fingerprint(AuditRequestType.ASK, "hello")

    assert actual == expected


def test_fingerprint_follow_up_matches_manual_reference_computation():
    turn_encoding = "user:hi"  # len("hi") in utf-8 bytes drives the turn's own prefix below
    turn_segment = f"{len(turn_encoding.encode('utf-8'))}:{turn_encoding}"
    history_blob = turn_segment
    canonical = f"v1:9:follow_up:1:q:{len(history_blob.encode('utf-8'))}:{history_blob}"
    expected = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    actual = CopilotAuditService.compute_fingerprint(
        AuditRequestType.FOLLOW_UP, "q", [_turn(CopilotMessageRole.USER, "hi")]
    )

    assert actual == expected


# =============================================================================
# Service behavior -- integration, requires PostgreSQL
# =============================================================================

pytestmark_integration = pytest.mark.integration


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
        email=f"copilotauditsvc-{uuid.uuid4().hex[:8]}@example.com",
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


def _service(db_session) -> CopilotAuditService:
    return CopilotAuditService(CopilotAuditRepository(db_session), AlertRepository(db_session))


def _case_service(db_session) -> CopilotAuditService:
    return CopilotAuditService(
        CopilotAuditRepository(db_session), AlertRepository(db_session), CaseRepository(db_session)
    )


class _FailingCopilotAuditRepository:
    """Test double simulating a genuine persistence failure -- e.g. a
    connectivity problem -- that CopilotAuditService could not have
    validated in advance.
    """

    def create(self, audit):
        raise SQLAlchemyError("simulated connection reset; internal detail: db_password=hunter2")


@pytest.mark.integration
def test_record_creates_an_ask_audit(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)

    audit = service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.ASK,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why was this alert generated?",
    )

    assert audit.id is not None
    assert audit.alert_id == alert.id
    assert audit.request_type == "ask"
    assert audit.history_turn_count is None
    assert len(audit.question_fingerprint) == 64


@pytest.mark.integration
def test_record_creates_a_follow_up_audit_with_history_turn_count(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)
    history = [
        CopilotMessage(role=CopilotMessageRole.USER, content="Why is this suspicious?"),
        CopilotMessage(role=CopilotMessageRole.ASSISTANT, content="Because of repeated auth failures."),
    ]

    audit = service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.FOLLOW_UP,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="What next?",
        history=history,
    )

    assert audit.request_type == "follow_up"
    assert audit.history_turn_count == 2


@pytest.mark.integration
def test_record_rejects_unknown_alert(db_session):
    service = _service(db_session)

    with pytest.raises(CopilotAuditAlertNotFoundError) as exc_info:
        service.record(
            alert_id=uuid.uuid4(),
            request_type=AuditRequestType.ASK,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
        )
    assert exc_info.value.alert_id is not None


@pytest.mark.integration
def test_record_rejects_mismatched_outcome_and_http_status(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            alert_id=alert.id,
            request_type=AuditRequestType.ASK,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=502,
            question="Why?",
        )


@pytest.mark.integration
def test_record_rejects_mismatched_outcome_and_validation_status(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            alert_id=alert.id,
            request_type=AuditRequestType.ASK,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.FAILURE,
            validation_status=AuditValidationStatus.PASSED,
            http_status=502,
            question="Why?",
        )


@pytest.mark.integration
def test_record_rejects_history_supplied_for_ask(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            alert_id=alert.id,
            request_type=AuditRequestType.ASK,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
            history=[CopilotMessage(role=CopilotMessageRole.USER, content="stray turn")],
        )


@pytest.mark.integration
def test_record_rejects_negative_duration(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            alert_id=alert.id,
            request_type=AuditRequestType.ASK,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
            duration_ms=-5,
        )


@pytest.mark.integration
def test_persistence_failure_is_translated_and_does_not_leak_raw_details(db_session, caplog):
    alert = _make_alert(db_session)
    service = CopilotAuditService(_FailingCopilotAuditRepository(), AlertRepository(db_session))

    with caplog.at_level("ERROR"):
        with pytest.raises(CopilotAuditPersistenceError) as exc_info:
            service.record(
                alert_id=alert.id,
                request_type=AuditRequestType.ASK,
                provider_name="mock",
                model_name="amnix-mock-v1",
                outcome=AuditOutcome.SUCCESS,
                validation_status=AuditValidationStatus.PASSED,
                http_status=200,
                question="Why?",
            )

    assert "hunter2" not in str(exc_info.value)
    assert "db_password" not in str(exc_info.value)


@pytest.mark.integration
def test_record_does_not_change_alert_status(db_session):
    alert = _make_alert(db_session)
    original_status = alert.status
    service = _service(db_session)

    service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.ASK,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why?",
    )

    db_session.refresh(alert)
    assert alert.status == original_status


@pytest.mark.integration
def test_record_does_not_modify_unrelated_alert_fields(db_session):
    alert = _make_alert(db_session)
    original_title = alert.title
    original_evidence = dict(alert.evidence)
    original_updated_at = alert.updated_at
    service = _service(db_session)

    service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.ASK,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why?",
    )

    db_session.refresh(alert)
    assert alert.title == original_title
    assert alert.evidence == original_evidence
    assert alert.updated_at == original_updated_at


@pytest.mark.integration
def test_list_for_alert_delegates_to_repository(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)
    service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.ASK,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why?",
    )

    results = service.list_for_alert(alert.id)

    assert len(results) == 1
    assert results[0].alert_id == alert.id


@pytest.mark.integration
def test_get_by_id_delegates_to_repository(db_session):
    alert = _make_alert(db_session)
    service = _service(db_session)
    created = service.record(
        alert_id=alert.id,
        request_type=AuditRequestType.ASK,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why?",
    )

    fetched = service.get_by_id(created.id)

    assert fetched is not None
    assert fetched.id == created.id


# =============================================================================
# Case scope (Step 13D) -- record()/list_for_case() behavior
# =============================================================================


@pytest.mark.integration
def test_record_creates_a_case_brief_audit(db_session):
    case = _make_case(db_session)
    service = _case_service(db_session)

    audit = service.record(
        case_id=case.id,
        request_type=AuditRequestType.CASE_BRIEF,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="What should I know about this case?",
    )

    assert audit.id is not None
    assert audit.case_id == case.id
    assert audit.alert_id is None
    assert audit.request_type == "case_brief"
    assert audit.history_turn_count is None


@pytest.mark.integration
def test_record_rejects_both_alert_id_and_case_id_supplied(db_session):
    alert = _make_alert(db_session)
    case = _make_case(db_session)
    service = _case_service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            alert_id=alert.id,
            case_id=case.id,
            request_type=AuditRequestType.CASE_BRIEF,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
        )


@pytest.mark.integration
def test_record_rejects_neither_alert_id_nor_case_id_supplied(db_session):
    service = _case_service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            request_type=AuditRequestType.CASE_BRIEF,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
        )


@pytest.mark.integration
def test_record_rejects_unknown_case(db_session):
    service = _case_service(db_session)

    with pytest.raises(CopilotAuditCaseNotFoundError) as exc_info:
        service.record(
            case_id=uuid.uuid4(),
            request_type=AuditRequestType.CASE_BRIEF,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
        )
    assert exc_info.value.case_id is not None


@pytest.mark.integration
def test_record_case_scoped_call_without_case_repository_raises_value_error(db_session):
    """A programming-error signal, not a typed CopilotAuditError an API
    layer would map to an HTTP response -- this should never actually be
    reachable through app.api.cases' own DI wiring, which always supplies
    a case_repository.
    """
    case = _make_case(db_session)
    service = _service(db_session)  # constructed WITHOUT a case_repository

    with pytest.raises(ValueError):
        service.record(
            case_id=case.id,
            request_type=AuditRequestType.CASE_BRIEF,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
        )


@pytest.mark.integration
def test_record_rejects_history_supplied_for_case_brief(db_session):
    case = _make_case(db_session)
    service = _case_service(db_session)

    with pytest.raises(CopilotAuditValidationError):
        service.record(
            case_id=case.id,
            request_type=AuditRequestType.CASE_BRIEF,
            provider_name="mock",
            model_name="amnix-mock-v1",
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question="Why?",
            history=[CopilotMessage(role=CopilotMessageRole.USER, content="stray turn")],
        )


@pytest.mark.integration
def test_list_for_case_delegates_to_repository(db_session):
    case = _make_case(db_session)
    service = _case_service(db_session)
    service.record(
        case_id=case.id,
        request_type=AuditRequestType.CASE_BRIEF,
        provider_name="mock",
        model_name="amnix-mock-v1",
        outcome=AuditOutcome.SUCCESS,
        validation_status=AuditValidationStatus.PASSED,
        http_status=200,
        question="Why?",
    )

    results = service.list_for_case(case.id)

    assert len(results) == 1
    assert results[0].case_id == case.id
    assert results[0].alert_id is None


@pytest.mark.integration
def test_list_for_case_does_not_return_another_cases_or_an_alerts_audits(db_session):
    case_a = _make_case(db_session)
    case_b = _make_case(db_session)
    alert = _make_alert(db_session)
    service = _case_service(db_session)

    service.record(
        case_id=case_a.id, request_type=AuditRequestType.CASE_BRIEF, provider_name="mock",
        model_name="amnix-mock-v1", outcome=AuditOutcome.SUCCESS, validation_status=AuditValidationStatus.PASSED,
        http_status=200, question="A",
    )
    service.record(
        case_id=case_b.id, request_type=AuditRequestType.CASE_BRIEF, provider_name="mock",
        model_name="amnix-mock-v1", outcome=AuditOutcome.SUCCESS, validation_status=AuditValidationStatus.PASSED,
        http_status=200, question="B",
    )
    service.record(
        alert_id=alert.id, request_type=AuditRequestType.ASK, provider_name="mock",
        model_name="amnix-mock-v1", outcome=AuditOutcome.SUCCESS, validation_status=AuditValidationStatus.PASSED,
        http_status=200, question="C",
    )

    results = service.list_for_case(case_a.id)

    assert len(results) == 1
    assert results[0].case_id == case_a.id


@pytest.mark.integration
def test_record_case_brief_does_not_change_case_status_or_priority(db_session):
    case = _make_case(db_session)
    service = _case_service(db_session)

    service.record(
        case_id=case.id, request_type=AuditRequestType.CASE_BRIEF, provider_name="mock",
        model_name="amnix-mock-v1", outcome=AuditOutcome.SUCCESS, validation_status=AuditValidationStatus.PASSED,
        http_status=200, question="Should I close this case?",
    )

    db_session.refresh(case)
    assert case.status == "OPEN"
    assert case.owner_id is None


# =============================================================================
# Security regression -- structural checks over the repository/service
# =============================================================================


def test_service_record_signature_has_no_forbidden_parameters():
    import inspect

    params = set(inspect.signature(CopilotAuditService.record).parameters)
    forbidden = {
        "system_instructions",
        "context",
        "ai_context",
        "raw_response",
        "response",
        "api_key",
        "secret",
        "exception",
        "traceback",
        "telemetry",
        "raw_data",
    }
    assert not (params & forbidden)


def test_repository_and_service_source_contain_no_execution_or_network_primitives():
    """Same static-source-guard pattern used by
    app.investigation_actions (see test_investigation_action_registry.py):
    proves this layer cannot fetch URLs, execute telemetry/commands, or
    call an external provider, regardless of what future code review
    might miss.
    """
    import pathlib

    forbidden_tokens = (
        "subprocess",
        "os.system",
        "eval(",
        "exec(",
        "shell=True",
        "socket.",
        "urllib",
        "requests.",
        "httpx",
        "anthropic",
    )
    backend_dir = pathlib.Path(__file__).resolve().parents[1]
    source_files = [
        backend_dir / "app" / "repositories" / "copilot_audit.py",
        backend_dir / "app" / "services" / "copilot_audit_service.py",
    ]
    for path in source_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in text, f"forbidden primitive '{token}' found in {path}"


def test_repository_has_no_mitre_or_investigation_action_logic():
    """Checks for actual usage (imports/calls), not just the word
    appearing anywhere -- this module's own docstring legitimately says
    "no MITRE... logic" in prose, which a plain substring search would
    misflag.
    """
    import pathlib

    backend_dir = pathlib.Path(__file__).resolve().parents[1]
    text = (backend_dir / "app" / "repositories" / "copilot_audit.py").read_text(encoding="utf-8")

    forbidden_usages = (
        "from app.mitre",
        "import app.mitre",
        "from app.investigation_actions",
        "import app.investigation_actions",
        "get_techniques_for_rule",
        "get_candidate_actions",
        "MitreAnalysisEntry",
        "RecommendedInvestigationAction",
    )
    for forbidden in forbidden_usages:
        assert forbidden not in text
