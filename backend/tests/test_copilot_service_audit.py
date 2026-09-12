"""Integration tests for Step 10F.4: CopilotService writing CopilotAudit
rows for ask()/follow_up(). Require PostgreSQL (see conftest.py's
db_session fixture).

Reuses the same helper/test-double patterns as test_copilot_service.py
(kept self-contained per that file's own convention) rather than
depending on private helpers defined there.
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.ai.context_builder import AIContextBuilder
from app.ai.exceptions import AIProviderError
from app.ai.provider import AIProvider
from app.models.alert import Alert
from app.models.security_event import SecurityEvent
from app.repositories.alert import AlertRepository
from app.repositories.copilot_audit import CopilotAuditRepository
from app.schemas.ai import (
    AIRequest,
    AIResponse,
    AssessmentConfidence,
    CopilotAssessment,
    CopilotFollowUpAnswer,
    CopilotMessage,
    CopilotMessageRole,
    EvidenceItem,
    FindingType,
    KeyFinding,
    MitreAnalysisEntry,
    RecommendedAction,
    RecommendedInvestigationAction,
    Verdict,
)
from app.schemas.alert import AlertCreate
from app.services.alert_service import AlertService
from app.services.copilot_audit_service import CopilotAuditService
from app.services.copilot_service import CopilotService
from app.services.investigation_service import InvestigationEngine

pytestmark = pytest.mark.integration


# --- shared test scaffolding (mirrors test_copilot_service.py) ------------


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


def _create_alert(db_session, event_ids, **overrides) -> Alert:
    payload = {
        "rule_id": "brute_force_authentication",
        "title": "Brute force authentication detected for jdoe from 10.0.0.5",
        "description": "5 authentication failures within 300 seconds.",
        "severity": "high",
        "confidence": "high",
        "first_seen": datetime.now(timezone.utc).isoformat(),
        "evidence": {"failure_count": 5, "username": "jdoe", "source_ip": "10.0.0.5"},
        "source_event_ids": [str(eid) for eid in event_ids],
    }
    payload.update(overrides)
    service = AlertService(AlertRepository(db_session))
    return service.create(AlertCreate(**payload))


def _valid_assessment(**overrides) -> CopilotAssessment:
    defaults = dict(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="A structured test assessment.",
        key_findings=[KeyFinding(type=FindingType.FACT, statement="A fact.", supporting_event_refs=[])],
        evidence=[],
        recommended_next_steps=["Review the activity."],
        recommended_action=RecommendedAction.INVESTIGATE,
        limitations=["No IP reputation data was supplied."],
    )
    defaults.update(overrides)
    return CopilotAssessment(**defaults)


def _valid_action_entry(**overrides) -> RecommendedInvestigationAction:
    defaults = dict(
        action_id="review_authentication_failures",
        label="Review authentication failure history for the affected account",
        description="Review the account's recent authentication failure and success history.",
        supporting_event_refs=[],
    )
    defaults.update(overrides)
    return RecommendedInvestigationAction(**defaults)


def _valid_follow_up_answer(**overrides) -> CopilotFollowUpAnswer:
    defaults = dict(
        answer="The available evidence is consistent with a brute-force attempt.",
        supporting_event_refs=[],
        mitre_refs=[],
        limitations=["No IP reputation data was supplied."],
    )
    defaults.update(overrides)
    return CopilotFollowUpAnswer(**defaults)


class _RecordingAIProvider(AIProvider):
    def __init__(self, assessment: CopilotAssessment | None = None, *, name: str = "recording-test-double") -> None:
        self._assessment = assessment or _valid_assessment()
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def generate(self, request: AIRequest) -> AIResponse:
        return AIResponse(content=self._assessment.model_dump_json(), provider=self.name, model="test-model", usage=None)


class _RecordingFollowUpAIProvider(AIProvider):
    def __init__(self, answer: CopilotFollowUpAnswer | None = None, *, name: str = "recording-follow-up-test-double") -> None:
        self._answer = answer or _valid_follow_up_answer()
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def generate(self, request: AIRequest) -> AIResponse:
        return AIResponse(content=self._answer.model_dump_json(), provider=self.name, model="test-model", usage=None)


class _FailingAIProvider(AIProvider):
    """Transport/provider failure: raises before ever producing an
    AIResponse -- the not_applicable/502 case.
    """

    @property
    def name(self) -> str:
        return "failing-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        raise RuntimeError("simulated provider outage; internal detail: db_password=hunter2")


class _MalformedJSONAIProvider(AIProvider):
    """Provider responds, but the content doesn't parse -- the
    failed/502 (validation) case.
    """

    @property
    def name(self) -> str:
        return "malformed-json-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        return AIResponse(content="not valid json at all", provider=self.name, model="test-model", usage=None)


class _FabricatingEventRefAIProvider(AIProvider):
    """Provider responds with a well-formed but fabricated event_ref --
    another failed/502 (validation) case, distinct from malformed JSON.
    """

    @property
    def name(self) -> str:
        return "fabricating-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        assessment = _valid_assessment(
            key_findings=[
                KeyFinding(type=FindingType.FACT, statement="A fabricated claim.", supporting_event_refs=["evt-does-not-exist"])
            ]
        )
        return AIResponse(content=assessment.model_dump_json(), provider=self.name, model="test-model", usage=None)


def _copilot_service(db_session, provider: AIProvider) -> CopilotService:
    return CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=provider,
        copilot_audit_service=CopilotAuditService(CopilotAuditRepository(db_session), AlertRepository(db_session)),
    )


def _audits_for(db_session, alert_id: uuid.UUID):
    return CopilotAuditRepository(db_session).list_for_alert(alert_id)


# =============================================================================
# ask() -- successful call
# =============================================================================


def test_successful_ask_creates_exactly_one_audit_row(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingAIProvider(name="mock"))

    service.ask(alert.id, "Why was this alert generated?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1


def test_successful_ask_audit_fields(db_session):
    from app.schemas.copilot_audit import AuditRequestType
    from app.services.copilot_audit_service import CopilotAuditService as AuditSvc

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    question = "Why was this alert generated?"
    service = _copilot_service(db_session, _RecordingAIProvider(name="mock"))

    service.ask(alert.id, question)

    audit = _audits_for(db_session, alert.id)[0]
    assert audit.request_type == "ask"
    assert audit.outcome == "success"
    assert audit.validation_status == "passed"
    assert audit.http_status == 200
    assert audit.provider_name == "mock"
    assert audit.model_name == "test-model"
    assert audit.question_fingerprint == AuditSvc.compute_fingerprint(AuditRequestType.ASK, question)
    assert audit.question_length == len(question)
    assert audit.history_turn_count is None
    assert audit.duration_ms is not None and audit.duration_ms >= 0


def test_successful_ask_leaves_alert_unchanged(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    original_status = alert.status
    service = _copilot_service(db_session, _RecordingAIProvider(name="mock"))

    service.ask(alert.id, "Why was this alert generated?")

    db_session.refresh(alert)
    assert alert.status == original_status


# --- ask(): provider/transport failure --------------------------------------


def test_ask_provider_failure_creates_exactly_one_failure_audit_row(db_session, caplog):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _FailingAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    audit = audits[0]
    assert audit.outcome == "failure"
    assert audit.validation_status == "not_applicable"
    assert audit.http_status == 502
    assert audit.model_name is None


def test_ask_provider_failure_does_not_leak_raw_exception_text(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _FailingAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    audit = _audits_for(db_session, alert.id)[0]
    for value in (audit.provider_name, audit.model_name, str(audit.http_status)):
        if value is not None:
            assert "hunter2" not in value
            assert "db_password" not in value


# --- ask(): AMNIX validation rejection --------------------------------------


def test_ask_malformed_response_creates_exactly_one_validation_failure_audit_row(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _MalformedJSONAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    audit = audits[0]
    assert audit.outcome == "failure"
    assert audit.validation_status == "failed"
    assert audit.http_status == 502


def test_ask_fabricated_event_ref_is_still_rejected_and_audited_as_validation_failure(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _FabricatingEventRefAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    assert audits[0].validation_status == "failed"
    assert audits[0].http_status == 502
    # The fabricated ref itself is never persisted anywhere on the audit row.
    for column in ("provider_name", "model_name"):
        value = getattr(audits[0], column)
        if value is not None:
            assert "evt-does-not-exist" not in value


def test_ask_malformed_response_leaves_alert_unchanged(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    original_status = alert.status
    service = _copilot_service(db_session, _MalformedJSONAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    db_session.refresh(alert)
    assert alert.status == original_status


def test_ask_validation_failure_preserves_known_model_name(db_session):
    """The provider DID respond (with model='test-model') before AMNIX
    rejected the content -- model_name must be preserved, not nulled.
    """
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _MalformedJSONAIProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "Why was this alert generated?")

    assert _audits_for(db_session, alert.id)[0].model_name == "test-model"


# =============================================================================
# follow_up()
# =============================================================================


def test_successful_follow_up_creates_exactly_one_audit_row_with_history_count(db_session):
    from app.schemas.copilot_audit import AuditRequestType
    from app.services.copilot_audit_service import CopilotAuditService as AuditSvc

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    question = "What next?"
    history = [
        CopilotMessage(role=CopilotMessageRole.USER, content="Why is this suspicious?"),
        CopilotMessage(role=CopilotMessageRole.ASSISTANT, content="Because of repeated auth failures."),
    ]
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider(name="mock"))

    service.follow_up(alert.id, question, history)

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    audit = audits[0]
    assert audit.request_type == "follow_up"
    assert audit.outcome == "success"
    assert audit.validation_status == "passed"
    assert audit.http_status == 200
    assert audit.history_turn_count == 2
    assert audit.question_fingerprint == AuditSvc.compute_fingerprint(AuditRequestType.FOLLOW_UP, question, history)
    assert audit.duration_ms is not None and audit.duration_ms >= 0


def test_follow_up_with_empty_history_records_zero(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider(name="mock"))

    service.follow_up(alert.id, "What next?", [])

    assert _audits_for(db_session, alert.id)[0].history_turn_count == 0


def test_follow_up_provider_failure_is_not_applicable_502(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _FailingAIProvider())

    with pytest.raises(AIProviderError):
        service.follow_up(alert.id, "What next?", [])

    audit = _audits_for(db_session, alert.id)[0]
    assert audit.outcome == "failure"
    assert audit.validation_status == "not_applicable"
    assert audit.http_status == 502


def test_follow_up_validation_rejection_is_failed_502(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _MalformedJSONAIProvider())

    with pytest.raises(AIProviderError):
        service.follow_up(alert.id, "What next?", [])

    audit = _audits_for(db_session, alert.id)[0]
    assert audit.outcome == "failure"
    assert audit.validation_status == "failed"
    assert audit.http_status == 502


def test_follow_up_leaves_alert_unchanged_on_every_outcome(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    for provider, should_raise in (
        (_RecordingFollowUpAIProvider(), False),
        (_FailingAIProvider(), True),
        (_MalformedJSONAIProvider(), True),
    ):
        alert = _create_alert(db_session, [event.id])
        original_status = alert.status
        service = _copilot_service(db_session, provider)

        if should_raise:
            with pytest.raises(AIProviderError):
                service.follow_up(alert.id, "What next?", [])
        else:
            service.follow_up(alert.id, "What next?", [])

        db_session.refresh(alert)
        assert alert.status == original_status


# =============================================================================
# Cross-cutting: alert resolution, fingerprinting, no content persisted
# =============================================================================


def test_unknown_alert_creates_zero_audit_rows(db_session):
    from app.services.alert_service import AlertNotFoundError

    service = _copilot_service(db_session, _RecordingAIProvider())
    unknown_id = uuid.uuid4()

    with pytest.raises(AlertNotFoundError):
        service.ask(unknown_id, "Why?")

    assert _audits_for(db_session, unknown_id) == []


def test_audit_persistence_failure_does_not_turn_success_into_error(db_session, caplog):
    from app.schemas.copilot_audit import AuditOutcome, AuditRequestType, AuditValidationStatus
    from app.services.copilot_audit_service import CopilotAuditError

    class _AlwaysFailingAuditService(CopilotAuditService):
        def record(self, **kwargs):
            raise CopilotAuditError("simulated audit persistence failure")

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=_RecordingAIProvider(),
        copilot_audit_service=_AlwaysFailingAuditService(
            CopilotAuditRepository(db_session), AlertRepository(db_session)
        ),
    )

    with caplog.at_level("ERROR"):
        response = service.ask(alert.id, "Why was this alert generated?")

    assert response.assessment is not None
    assert any("audit" in record.message.lower() for record in caplog.records)
    # The dummy service never actually wrote a row, but that must not
    # have affected the returned CopilotResponse above.
    assert _audits_for(db_session, alert.id) == []


def test_audit_persistence_failure_preserves_original_provider_failure(db_session, caplog):
    from app.services.copilot_audit_service import CopilotAuditError

    class _AlwaysFailingAuditService(CopilotAuditService):
        def record(self, **kwargs):
            raise CopilotAuditError("simulated audit persistence failure")

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=_FailingAIProvider(),
        copilot_audit_service=_AlwaysFailingAuditService(
            CopilotAuditRepository(db_session), AlertRepository(db_session)
        ),
    )

    with caplog.at_level("ERROR"):
        with pytest.raises(AIProviderError) as exc_info:
            service.ask(alert.id, "Why was this alert generated?")

    # The original provider-failure message survives, not a masked/
    # different error caused by the audit write failing.
    assert "AI provider failed to generate a response" in str(exc_info.value)


def test_repeated_identical_ask_requests_produce_the_same_fingerprint(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingAIProvider())

    service.ask(alert.id, "Why was this alert generated?")
    service.ask(alert.id, "Why was this alert generated?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 2
    assert audits[0].question_fingerprint == audits[1].question_fingerprint


def test_ask_fingerprint_differs_from_follow_up_fingerprint_for_identical_text(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    ask_service = _copilot_service(db_session, _RecordingAIProvider())
    follow_up_service = _copilot_service(db_session, _RecordingFollowUpAIProvider())

    ask_service.ask(alert.id, "Is this malicious?")
    follow_up_service.follow_up(alert.id, "Is this malicious?", [])

    audits = {a.request_type: a for a in _audits_for(db_session, alert.id)}
    assert audits["ask"].question_fingerprint != audits["follow_up"].question_fingerprint


def test_follow_up_history_change_changes_fingerprint(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider())

    service.follow_up(alert.id, "What next?", [])
    service.follow_up(alert.id, "What next?", [CopilotMessage(role=CopilotMessageRole.USER, content="turn 1")])

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 2
    assert audits[0].question_fingerprint != audits[1].question_fingerprint


def test_ask_always_records_null_history_turn_count(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingAIProvider())

    service.ask(alert.id, "Why?")

    assert _audits_for(db_session, alert.id)[0].history_turn_count is None


def test_follow_up_with_n_messages_records_n(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider())
    history = [
        CopilotMessage(role=CopilotMessageRole.USER, content="a"),
        CopilotMessage(role=CopilotMessageRole.ASSISTANT, content="b"),
        CopilotMessage(role=CopilotMessageRole.USER, content="c"),
    ]

    service.follow_up(alert.id, "What next?", history)

    assert _audits_for(db_session, alert.id)[0].history_turn_count == 3


def test_no_raw_question_or_history_content_is_persisted(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider())
    secret_question = "UNIQUE_MARKER_QUESTION_TEXT_9f3a"
    secret_history_content = "UNIQUE_MARKER_HISTORY_TEXT_2bd1"

    service.follow_up(
        alert.id, secret_question, [CopilotMessage(role=CopilotMessageRole.USER, content=secret_history_content)]
    )

    audit = _audits_for(db_session, alert.id)[0]
    for column in audit.__table__.columns:
        value = getattr(audit, column.name)
        if isinstance(value, str):
            assert secret_question not in value
            assert secret_history_content not in value


# =============================================================================
# Step 10F.6: additional coverage -- fabricated MITRE/action candidates,
# independent-row identity, deeper security/failure-isolation checks
# =============================================================================


def test_fabricated_mitre_technique_creates_failed_audit(db_session):
    event = _make_event(
        db_session, event_type="process_creation", process_name="powershell.exe", command_line="powershell -Command X"
    )
    alert = _create_alert(db_session, [event.id], rule_id="suspicious_powershell_execution")

    class _FabricatingTechniqueProvider(AIProvider):
        @property
        def name(self) -> str:
            return "fabricating-technique-test-double"

        def generate(self, request: AIRequest) -> AIResponse:
            assessment = _valid_assessment(
                mitre_analysis=[
                    MitreAnalysisEntry(
                        technique_id="T9999",
                        technique_name="Made Up Technique",
                        tactic="Nowhere",
                        confidence=AssessmentConfidence.HIGH,
                        rationale="Fabricated.",
                        supporting_event_refs=[],
                    )
                ]
            )
            return AIResponse(content=assessment.model_dump_json(), provider=self.name, model="test-model", usage=None)

    service = _copilot_service(db_session, _FabricatingTechniqueProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "What technique is this?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    assert audits[0].outcome == "failure"
    assert audits[0].validation_status == "failed"
    assert audits[0].http_status == 502


def test_fabricated_action_id_creates_failed_audit(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id], rule_id="brute_force_authentication")

    class _FabricatingActionProvider(AIProvider):
        @property
        def name(self) -> str:
            return "fabricating-action-test-double"

        def generate(self, request: AIRequest) -> AIResponse:
            assessment = _valid_assessment(
                recommended_actions=[_valid_action_entry(action_id="block_source_ip")]
            )
            return AIResponse(content=assessment.model_dump_json(), provider=self.name, model="test-model", usage=None)

    service = _copilot_service(db_session, _FabricatingActionProvider())

    with pytest.raises(AIProviderError):
        service.ask(alert.id, "What should I do?")

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 1
    assert audits[0].outcome == "failure"
    assert audits[0].validation_status == "failed"
    assert audits[0].http_status == 502


def test_follow_up_repeated_identical_requests_create_two_independent_rows(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingFollowUpAIProvider())

    service.follow_up(alert.id, "What next?", [])
    service.follow_up(alert.id, "What next?", [])

    audits = _audits_for(db_session, alert.id)
    assert len(audits) == 2
    assert audits[0].id != audits[1].id
    # Identical requests -> identical fingerprints, but each row is its
    # own independent record (distinct primary key), never deduplicated.
    assert audits[0].question_fingerprint == audits[1].question_fingerprint


def test_injected_telemetry_marker_never_appears_in_audit_row(db_session):
    injection_marker = "IGNORE_PREVIOUS_INSTRUCTIONS_MARKER_71c2"
    event = _make_event(
        db_session, event_type="process_creation", process_name="powershell.exe", command_line=injection_marker
    )
    alert = _create_alert(db_session, [event.id], rule_id="suspicious_powershell_execution")
    service = _copilot_service(db_session, _RecordingAIProvider())

    service.ask(alert.id, "What did this command do?")

    audit = _audits_for(db_session, alert.id)[0]
    for column in audit.__table__.columns:
        value = getattr(audit, column.name)
        if isinstance(value, str):
            assert injection_marker not in value


def test_system_instructions_never_appear_in_audit_row(db_session):
    from app.ai.prompts import CURRENT_SYSTEM_INSTRUCTIONS

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingAIProvider())

    service.ask(alert.id, "Why?")

    audit = _audits_for(db_session, alert.id)[0]
    # A crude but sufficient proof: no single audit field is long enough
    # to hold the (very long) system prompt, and no field contains any
    # sizeable verbatim excerpt of it.
    excerpt = CURRENT_SYSTEM_INSTRUCTIONS[:80]
    for column in audit.__table__.columns:
        value = getattr(audit, column.name)
        if isinstance(value, str):
            assert excerpt not in value


def test_security_event_uuid_never_appears_in_audit_row_except_as_alert_fk(db_session):
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = _copilot_service(db_session, _RecordingAIProvider())

    service.ask(alert.id, "Why?")

    audit = _audits_for(db_session, alert.id)[0]
    assert audit.alert_id == alert.id
    event_id_str = str(event.id)
    for column in audit.__table__.columns:
        if column.name == "alert_id":
            continue
        value = getattr(audit, column.name)
        if isinstance(value, str):
            assert event_id_str not in value


def test_raw_provider_response_content_never_appears_in_audit_row(db_session):
    unique_summary_marker = "UNIQUE_PROVIDER_RESPONSE_MARKER_a831"
    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    provider = _RecordingAIProvider(_valid_assessment(summary=unique_summary_marker))
    service = _copilot_service(db_session, provider)

    service.ask(alert.id, "Why?")

    audit = _audits_for(db_session, alert.id)[0]
    for column in audit.__table__.columns:
        value = getattr(audit, column.name)
        if isinstance(value, str):
            assert unique_summary_marker not in value


def test_audit_persistence_failure_does_not_leak_raw_sqlalchemy_exception_text(db_session, caplog):
    """Even a raw SQLAlchemyError escaping CopilotAuditService's own
    boundary (a bug in that service, not something that's supposed to
    happen -- CopilotAuditService.record() is itself responsible for
    translating SQLAlchemyError into CopilotAuditPersistenceError, see
    its own tests) must not break the Copilot response or leak
    client-visible text: _record_copilot_audit's `except Exception` (see
    its own docstring) exists specifically so CopilotService does not
    have to trust the audit layer always fails the documented way.
    """
    from sqlalchemy.exc import SQLAlchemyError

    class _RealDbErrorAuditService(CopilotAuditService):
        def record(self, **kwargs):
            raise SQLAlchemyError("connection reset by peer; internal detail: db_password=hunter2")

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    service = CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=_RecordingAIProvider(),
        copilot_audit_service=_RealDbErrorAuditService(
            CopilotAuditRepository(db_session), AlertRepository(db_session)
        ),
    )

    with caplog.at_level("ERROR"):
        response = service.ask(alert.id, "Why?")

    # The Copilot response itself succeeds normally and carries no trace
    # of the secret. (The secret legitimately appears in the SERVER-SIDE
    # log via logger.exception -- that is the required "log server-side"
    # behavior, not a leak; what matters is that it never reaches the
    # thing the caller gets back.)
    assert response.assessment is not None
    assert "hunter2" not in response.model_dump_json()
    assert any("Failed to record Copilot audit" in r.message for r in caplog.records)


def test_alert_unchanged_after_audit_persistence_failure(db_session):
    from app.services.copilot_audit_service import CopilotAuditError

    class _AlwaysFailingAuditService(CopilotAuditService):
        def record(self, **kwargs):
            raise CopilotAuditError("simulated audit persistence failure")

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    alert = _create_alert(db_session, [event.id])
    original_status = alert.status
    service = CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=_RecordingAIProvider(),
        copilot_audit_service=_AlwaysFailingAuditService(
            CopilotAuditRepository(db_session), AlertRepository(db_session)
        ),
    )

    service.ask(alert.id, "Why?")

    db_session.refresh(alert)
    assert alert.status == original_status


def test_copilot_result_identical_whether_audit_succeeds_or_fails(db_session):
    from app.services.copilot_audit_service import CopilotAuditError

    class _AlwaysFailingAuditService(CopilotAuditService):
        def record(self, **kwargs):
            raise CopilotAuditError("simulated audit persistence failure")

    event = _make_event(db_session, username="jdoe", source_ip="10.0.0.5")
    working_alert = _create_alert(db_session, [event.id])
    broken_alert = _create_alert(db_session, [event.id])
    assessment = _valid_assessment()

    working_service = _copilot_service(db_session, _RecordingAIProvider(assessment))
    broken_service = CopilotService(
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=_RecordingAIProvider(assessment),
        copilot_audit_service=_AlwaysFailingAuditService(
            CopilotAuditRepository(db_session), AlertRepository(db_session)
        ),
    )

    working_response = working_service.ask(working_alert.id, "Why?")
    broken_response = broken_service.ask(broken_alert.id, "Why?")

    assert working_response.assessment == broken_response.assessment
    assert working_response.provider == broken_response.provider
    assert working_response.model == broken_response.model
