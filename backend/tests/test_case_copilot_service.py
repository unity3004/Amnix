"""Integration tests for CaseCopilotService. Require PostgreSQL.

Mirrors tests/test_copilot_service.py's own shape exactly: simple
in-test AIProvider test doubles (recording/failing/malformed) rather than
MockAIProvider, so these tests can assert exactly what CaseCopilotService
built and sent, independent of MockAIProvider's own response formatting
(covered separately in test_mock_case_ai_provider.py).
"""

import uuid
from datetime import datetime, timezone

import pytest

from app.ai.case_context_builder import AICaseContextBuilder
from app.ai.exceptions import AIProviderTransportError, AIProviderValidationError
from app.ai.provider import AIProvider
from app.core.security import hash_password
from app.models.security_event import SecurityEvent
from app.models.user import User
from app.repositories.alert import AlertRepository
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import CaseNoteRepository
from app.repositories.copilot_audit import CopilotAuditRepository
from app.repositories.user import UserRepository
from app.schemas.ai import AIRequest, AIResponse, FindingType
from app.schemas.alert import AlertCreate
from app.schemas.case import CasePriority
from app.schemas.case_ai import AICaseRequest, CaseEvidenceItem, CaseInvestigationBrief, CaseKeyFinding
from app.services.alert_service import AlertService
from app.services.case_copilot_service import CaseCopilotService, FocusedAlertNotLinkedError
from app.services.case_service import CaseNotFoundError, CaseService
from app.services.copilot_audit_service import CopilotAuditService
from app.services.investigation_service import InvestigationEngine

pytestmark = pytest.mark.integration

START = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)


def _valid_brief(**overrides) -> CaseInvestigationBrief:
    defaults = dict(
        summary="A structured test brief.",
        key_findings=[],
        supporting_evidence=[],
        mitre_analysis=[],
        timeline_summary="No telemetry timeline was focused for this brief.",
        uncertainties=["No analyst notes have been recorded."],
        recommended_next_steps=["Review each linked alert."],
    )
    defaults.update(overrides)
    return CaseInvestigationBrief(**defaults)


class _RecordingCaseAIProvider(AIProvider):
    """Records the AICaseRequest received and returns a fixed, valid
    CaseInvestigationBrief (as JSON) -- mirrors _RecordingAIProvider in
    test_copilot_service.py exactly, generalized to generate_case().
    """

    def __init__(self, brief: CaseInvestigationBrief | None = None) -> None:
        self.last_request: AICaseRequest | None = None
        self._brief = brief or _valid_brief()

    @property
    def name(self) -> str:
        return "recording-case-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        raise AssertionError("generate() (alert-scoped) must never be called by CaseCopilotService")

    def generate_case(self, request: AICaseRequest) -> AIResponse:
        self.last_request = request
        return AIResponse(content=self._brief.model_dump_json(), provider=self.name, model="test-model", usage=None)


class _FailingCaseAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "failing-case-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        raise AssertionError("generate() (alert-scoped) must never be called by CaseCopilotService")

    def generate_case(self, request: AICaseRequest) -> AIResponse:
        raise RuntimeError("simulated outage")


class _MalformedJSONCaseAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "malformed-case-test-double"

    def generate(self, request: AIRequest) -> AIResponse:
        raise AssertionError("generate() (alert-scoped) must never be called by CaseCopilotService")

    def generate_case(self, request: AICaseRequest) -> AIResponse:
        return AIResponse(content="not valid json", provider=self.name, model="test-model", usage=None)


def _make_service(db_session, provider: AIProvider) -> CaseCopilotService:
    case_service = CaseService(
        db_session,
        CaseRepository(db_session),
        CaseAlertRepository(db_session),
        CaseAuditRepository(db_session),
        CaseNoteRepository(db_session),
        AlertRepository(db_session),
        UserRepository(db_session),
    )
    copilot_audit_service = CopilotAuditService(
        CopilotAuditRepository(db_session), AlertRepository(db_session), CaseRepository(db_session)
    )
    return CaseCopilotService(
        case_service=case_service,
        alert_service=AlertService(AlertRepository(db_session)),
        investigation_engine=InvestigationEngine(),
        context_builder=AICaseContextBuilder(),
        provider=provider,
        copilot_audit_service=copilot_audit_service,
    )


def _make_case(db_session, actor_id, **overrides):
    case_service = CaseService(
        db_session,
        CaseRepository(db_session),
        CaseAlertRepository(db_session),
        CaseAuditRepository(db_session),
        CaseNoteRepository(db_session),
        AlertRepository(db_session),
        UserRepository(db_session),
    )
    defaults = dict(title="Test case", description="d", priority=CasePriority.MEDIUM)
    defaults.update(overrides)
    return case_service.create_case(created_by=actor_id, **defaults)


def _make_event(db_session, **overrides) -> SecurityEvent:
    defaults = {"event_timestamp": START, "event_type": "authentication_failure", "source": "test", "raw_data": {}}
    defaults.update(overrides)
    event = SecurityEvent(**defaults)
    db_session.add(event)
    db_session.commit()
    db_session.refresh(event)
    return event


def _make_alert(db_session, event_ids, **overrides):
    payload = dict(
        rule_id="brute_force_authentication",
        title="Test alert",
        description="d",
        severity="high",
        confidence="high",
        first_seen=START.isoformat(),
        evidence={},
        source_event_ids=[str(eid) for eid in event_ids],
    )
    payload.update(overrides)
    return AlertService(AlertRepository(db_session)).create(AlertCreate(**payload))


def _link_alert(db_session, case_id, alert_id, actor_id):
    CaseAlertRepository(db_session)  # no-op import touch
    case_service = CaseService(
        db_session,
        CaseRepository(db_session),
        CaseAlertRepository(db_session),
        CaseAuditRepository(db_session),
        CaseNoteRepository(db_session),
        AlertRepository(db_session),
        UserRepository(db_session),
    )
    case_service.link_alert(case_id, alert_id=alert_id, actor_id=actor_id)


def _make_user(db_session, **overrides) -> User:
    defaults = dict(
        email=f"casecopilot-{uuid.uuid4().hex[:8]}@example.com",
        password_hash=hash_password("correct horse battery staple"),
        role="analyst",
        is_active=True,
    )
    defaults.update(overrides)
    return UserRepository(db_session).create(User(**defaults))


@pytest.fixture
def actor_id(db_session) -> uuid.UUID:
    return _make_user(db_session).id


def test_unknown_case_raises_case_not_found(db_session):
    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    with pytest.raises(CaseNotFoundError):
        service.ask_about_case(uuid.uuid4(), "Why?")


def test_sends_real_case_fields_and_bounded_alert_summaries(db_session, actor_id):
    case = _make_case(db_session, actor_id, title="Real case title", priority=CasePriority.HIGH)
    event = _make_event(db_session)
    alert = _make_alert(db_session, [event.id], rule_id="brute_force_authentication")
    _link_alert(db_session, case.id, alert.id, actor_id)

    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "What happened?")

    assert provider.last_request is not None
    ctx = provider.last_request.context
    assert ctx.case_id == case.id
    assert ctx.title == "Real case title"
    assert ctx.priority == "high"
    assert len(ctx.alerts) == 1
    assert ctx.alerts[0].rule_id == "brute_force_authentication"
    assert ctx.focused_alert is None


def test_no_client_controlled_context_client_only_supplies_question_and_optional_focused_alert(db_session, actor_id):
    """The context is entirely server-reconstructed from case_id -- there
    is no code path in ask_about_case()'s signature that accepts
    evidence/notes/audit/MITRE from the caller.
    """
    import inspect

    sig = inspect.signature(CaseCopilotService.ask_about_case)
    assert set(sig.parameters) == {"self", "case_id", "question", "focused_alert_id"}


def test_focused_alert_must_actually_be_linked_to_this_case(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    other_event = _make_event(db_session)
    unlinked_alert = _make_alert(db_session, [other_event.id])  # never linked to `case`

    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    with pytest.raises(FocusedAlertNotLinkedError):
        service.ask_about_case(case.id, "Tell me about this alert.", focused_alert_id=unlinked_alert.id)

    # No request should even have reached the provider.
    assert provider.last_request is None


def test_focused_alert_id_from_another_case_is_rejected_not_silently_substituted(db_session, actor_id):
    case_a = _make_case(db_session, actor_id, title="Case A")
    case_b = _make_case(db_session, actor_id, title="Case B")
    event = _make_event(db_session)
    alert_in_b = _make_alert(db_session, [event.id])
    _link_alert(db_session, case_b.id, alert_in_b.id, actor_id)

    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    with pytest.raises(FocusedAlertNotLinkedError):
        service.ask_about_case(case_a.id, "Tell me about this alert.", focused_alert_id=alert_in_b.id)


def test_focused_alert_supplies_real_timeline_into_context(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    event = _make_event(db_session, hostname="WKS-01")
    alert = _make_alert(db_session, [event.id])
    _link_alert(db_session, case.id, alert.id, actor_id)

    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "Tell me about this alert.", focused_alert_id=alert.id)

    ctx = provider.last_request.context
    assert ctx.focused_alert is not None
    assert ctx.focused_alert.alert_ref == "alert-1"
    assert len(ctx.focused_alert.timeline) == 1
    assert ctx.focused_alert.timeline[0].hostname == "WKS-01"


def test_rejects_a_fabricated_alert_ref_not_in_this_cases_context(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    brief = _valid_brief(
        key_findings=[CaseKeyFinding(type=FindingType.FACT, statement="x", supporting_alert_refs=["alert-99"], supporting_event_refs=[])]
    )
    provider = _RecordingCaseAIProvider(brief)
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderValidationError):
        service.ask_about_case(case.id, "Why?")


def test_rejects_a_fabricated_event_ref_not_in_the_focused_alerts_timeline(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    event = _make_event(db_session)
    alert = _make_alert(db_session, [event.id])
    _link_alert(db_session, case.id, alert.id, actor_id)

    brief = _valid_brief(
        supporting_evidence=[CaseEvidenceItem(field="x", value="y", event_ref="evt-99", explanation="z")]
    )
    provider = _RecordingCaseAIProvider(brief)
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderValidationError):
        service.ask_about_case(case.id, "Why?", focused_alert_id=alert.id)


def test_rejects_an_event_ref_when_no_alert_was_focused_at_all(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    brief = _valid_brief(
        supporting_evidence=[CaseEvidenceItem(field="x", value="y", event_ref="evt-1", explanation="z")]
    )
    provider = _RecordingCaseAIProvider(brief)
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderValidationError):
        service.ask_about_case(case.id, "Why?")


def test_rejects_a_mitre_technique_id_outside_the_case_wide_candidate_set(db_session, actor_id):
    from app.schemas.ai import AssessmentConfidence, MitreAnalysisEntry

    case = _make_case(db_session, actor_id)
    event = _make_event(db_session)
    alert = _make_alert(db_session, [event.id], rule_id="brute_force_authentication")
    _link_alert(db_session, case.id, alert.id, actor_id)

    brief = _valid_brief(
        mitre_analysis=[
            MitreAnalysisEntry(
                technique_id="T9999", technique_name="Fabricated", tactic="Fabricated",
                confidence=AssessmentConfidence.HIGH, rationale="fabricated", supporting_event_refs=[],
            )
        ]
    )
    provider = _RecordingCaseAIProvider(brief)
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderValidationError):
        service.ask_about_case(case.id, "Why?")


def test_normalizes_technique_name_and_tactic_to_registry_canonical_values(db_session, actor_id):
    from app.mitre.registry import get_techniques_for_rule
    from app.schemas.ai import AssessmentConfidence, MitreAnalysisEntry

    case = _make_case(db_session, actor_id)
    event = _make_event(db_session)
    alert = _make_alert(db_session, [event.id], rule_id="brute_force_authentication")
    _link_alert(db_session, case.id, alert.id, actor_id)
    real_candidate = get_techniques_for_rule("brute_force_authentication")[0]

    brief = _valid_brief(
        mitre_analysis=[
            MitreAnalysisEntry(
                technique_id=real_candidate.technique_id, technique_name="WRONG NAME", tactic="WRONG TACTIC",
                confidence=AssessmentConfidence.MEDIUM, rationale="test", supporting_event_refs=[],
            )
        ]
    )
    provider = _RecordingCaseAIProvider(brief)
    service = _make_service(db_session, provider)

    response = service.ask_about_case(case.id, "Why?")

    assert response.brief.mitre_analysis[0].technique_name == real_candidate.name
    assert response.brief.mitre_analysis[0].tactic == real_candidate.tactic


def test_mitre_candidate_set_is_the_union_across_distinct_linked_alert_rules(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    event_a = _make_event(db_session)
    event_b = _make_event(db_session)
    alert_a = _make_alert(db_session, [event_a.id], rule_id="brute_force_authentication")
    alert_b = _make_alert(db_session, [event_b.id], rule_id="suspicious_powershell_execution")
    _link_alert(db_session, case.id, alert_a.id, actor_id)
    _link_alert(db_session, case.id, alert_b.id, actor_id)

    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "Why?")

    source_rules = {c.source_rule_id for c in provider.last_request.context.mitre_candidates}
    assert source_rules <= {"brute_force_authentication", "suspicious_powershell_execution"}


def test_provider_transport_failure_raises_and_records_a_failure_audit(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    provider = _FailingCaseAIProvider()
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderTransportError):
        service.ask_about_case(case.id, "Why?")

    audits = CopilotAuditRepository(db_session).list_for_case(case.id)
    assert len(audits) == 1
    assert audits[0].outcome == "failure"
    assert audits[0].validation_status == "not_applicable"
    assert audits[0].http_status == 502
    assert audits[0].case_id == case.id
    assert audits[0].alert_id is None
    assert audits[0].request_type == "case_brief"


def test_malformed_provider_output_raises_and_records_a_failed_validation_audit(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    provider = _MalformedJSONCaseAIProvider()
    service = _make_service(db_session, provider)

    with pytest.raises(AIProviderValidationError):
        service.ask_about_case(case.id, "Why?")

    audits = CopilotAuditRepository(db_session).list_for_case(case.id)
    assert len(audits) == 1
    assert audits[0].outcome == "failure"
    assert audits[0].validation_status == "failed"


def test_successful_call_records_exactly_one_success_audit(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "Why?")

    audits = CopilotAuditRepository(db_session).list_for_case(case.id)
    assert len(audits) == 1
    assert audits[0].outcome == "success"
    assert audits[0].validation_status == "passed"
    assert audits[0].http_status == 200
    assert audits[0].request_type == "case_brief"
    assert audits[0].history_turn_count is None


def test_never_changes_case_status_priority_or_owner(db_session, actor_id):
    case = _make_case(db_session, actor_id, priority=CasePriority.LOW)
    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "Should I close this case?")

    reloaded = CaseRepository(db_session).get_by_id(case.id)
    assert reloaded.status == "OPEN"
    assert reloaded.priority == "low"
    assert reloaded.owner_id is None


def test_never_creates_a_case_note_or_links_an_alert(db_session, actor_id):
    case = _make_case(db_session, actor_id)
    provider = _RecordingCaseAIProvider()
    service = _make_service(db_session, provider)

    service.ask_about_case(case.id, "Document this for me.")

    assert CaseNoteRepository(db_session).list_for_case(case.id) == []
    assert CaseAlertRepository(db_session).list_alerts_for_case(case.id) == []
