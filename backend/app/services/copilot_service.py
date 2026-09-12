"""CopilotService: orchestrates alert -> InvestigationContext -> AIContext
-> provider call -> validated, evidence-checked CopilotResponse (or
CopilotFollowUpResponse — see Step 10C below).

Depends on AlertService (to fetch the alert with its events, exactly as
GET /alerts/{id}/investigation already does) and InvestigationEngine (the
Investigation layer) — never issues its own SecurityEvent query, and
never touches the database directly. All four collaborators are injected
through the constructor (see app.ai.factory and the get_copilot_service
FastAPI dependency in app.api.alerts) rather than constructed inside this
class, so a real AIProvider can replace MockAIProvider later without
changing this file. Notably, this module imports nothing from
app.ai.providers.anthropic (or any vendor SDK) — it only ever talks to
the AIProvider protocol and provider-neutral schemas.

Step 10A validation pipeline (provider output -> CopilotResponse): each
AIProvider is independently responsible for returning AIResponse.content
as JSON that already parses into CopilotAssessment (see
app.ai.providers.mock / app.ai.providers.anthropic) — but this class does
not trust that blindly. It re-parses content itself (defense in depth;
an external LLM's output is never fully trusted just because a provider
validated it once) and additionally performs the one check no provider
can perform alone: cross-referencing every event_ref the assessment
cites against the event_refs actually present in the AIContext this
exact request was built from. A provider only ever sees the AIContext it
was given for *this* call — but the reference set that matters for
"is this fabricated" is specifically the set CopilotService itself just
built, so that check belongs here, not duplicated into every provider.

Step 10B adds the MITRE mapping layer to this same pipeline: this class
(never AIContextBuilder, never a provider) is the one place that calls
app.mitre.registry.get_techniques_for_rule() — it is the only thing that
knows "which alert, therefore which rule_id, therefore which candidates"
for a given request. After a provider responds, this class also
unconditionally normalizes every mitre_analysis entry's technique_name/
tactic to the registry's canonical values for its (already candidate-
set-validated) technique_id, and rejects the whole response if any
technique_id is not one of the candidates that were actually offered —
never silently dropping a fabricated entry and returning the rest.

Step 10C adds follow_up(): alert-scoped conversational follow-up
questions. It deliberately re-runs steps 1-4 of ask() from scratch on
every call (fetch alert -> InvestigationContext -> MITRE candidates ->
AIContext) rather than accepting any of that from the caller — the
ALERT ISOLATION guarantee. The only new untrusted input is the client's
`history` (mapped, unmodified, into AIRequest.conversation_history) and
`question`; both are handled with exactly the same "never trust,
validate everything the provider gives back" discipline as ask(), reusing
(not duplicating) the event-ref and MITRE candidate-set/name/tactic
integrity checks via the shared private helpers below.

Step 10D adds a third application-controlled candidate system,
recommended investigation actions, following the exact same shape MITRE
established: this class (never AIContextBuilder, never a provider) is
the one place that calls
app.investigation_actions.registry.get_candidate_actions() — the only
thing that knows "which alert, therefore which rule_id + entities,
therefore which action candidates" for a given request. Candidates are
computed BEFORE the provider is invoked, from alert.rule_id and
investigation.entities alone — never from the analyst's question,
conversation history, or any telemetry field — in both ask() and
follow_up(), so a client has no code path to widen the candidate set.
After a provider responds, this class unconditionally normalizes every
recommended_actions entry's label/description to the registry's
canonical values for its (already candidate-set-validated) action_id,
and rejects the whole response if any action_id is not one of the
candidates that were actually offered — never silently dropping a
fabricated entry and returning the rest. `_normalize_mitre_entries`'s
generalized sibling, `_normalize_recommended_actions`, is shared by
ask() and follow_up() for the same reason: one implementation, not two
that could drift apart. Every recommended_actions entry describes an
investigation step only (review/check/collect existing evidence) — see
app.investigation_actions.registry's module docstring for the full
investigation-only safety contract; nothing in this class, or anywhere
else in AMNIX, executes or dispatches a recommended action.

Step 10E adds one more mechanical check, `_enforce_confidence_calibration`,
applied only in ask() (see that method's own docstring for why: it is the
only call site whose response schema, CopilotAssessment, carries a
verdict/confidence pair at all — CopilotFollowUpAnswer deliberately has
neither, so there is nothing for this check to calibrate on follow_up()'s
output; follow_up() still shares every OTHER Step 10E-relevant guarantee
with ask() — event-ref integrity, MITRE candidate-set closure, action
candidate-set closure — via the same helpers as before). Unlike the
normalize/reject helpers above, which police whether an *identifier* the
provider returned was real, this one polices whether the provider's own
*qualitative claim* (verdict + confidence) is internally consistent with
the evidence actually supplied for this request — never with what the
provider merely wrote in prose (a model could pad key_findings with a
generic FACT statement to appear evidence-backed; this check instead
looks at ai_context.timeline and assessment.evidence, both of which
CopilotService/AIContextBuilder control, not the model — see working
rule 14, "never trust model-generated content the application can verify
independently"). Like every other integrity check in this class, an
unsafe combination is rejected outright, never silently downgraded: a
provider that returns "likely_malicious"/"high" while grounding nothing
in real evidence is exhibiting a decision-safety defect, not a cosmetic
one, and correcting it silently would hide that defect instead of
surfacing it.
"""

import logging
import time
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from pydantic import BaseModel, ValidationError

from app.ai.context_builder import AIContextBuilder
from app.ai.exceptions import AIProviderTransportError, AIProviderValidationError
from app.ai.prompts import CURRENT_FOLLOW_UP_SYSTEM_INSTRUCTIONS, CURRENT_SYSTEM_INSTRUCTIONS
from app.ai.provider import AIProvider
from app.investigation_actions.models import InvestigationAction
from app.investigation_actions.registry import get_candidate_actions
from app.mitre.models import MitreTechnique
from app.mitre.registry import get_techniques_for_rule
from app.schemas.ai import (
    AIContext,
    AIConversationRole,
    AIConversationTurn,
    AIRequest,
    AIResponse,
    AssessmentConfidence,
    CopilotAssessment,
    CopilotFollowUpAnswer,
    CopilotFollowUpResponse,
    CopilotMessage,
    CopilotResponse,
    MitreAnalysisEntry,
    RecommendedInvestigationAction,
    Verdict,
)
from app.schemas.copilot_audit import AuditOutcome, AuditRequestType, AuditValidationStatus
from app.services.alert_service import AlertNotFoundError, AlertService
from app.services.copilot_audit_service import CopilotAuditService
from app.services.investigation_service import InvestigationEngine

logger = logging.getLogger(__name__)


class CopilotService:
    def __init__(
        self,
        alert_service: AlertService,
        investigation_engine: InvestigationEngine,
        context_builder: AIContextBuilder,
        provider: AIProvider,
        copilot_audit_service: CopilotAuditService,
    ) -> None:
        self._alert_service = alert_service
        self._investigation_engine = investigation_engine
        self._context_builder = context_builder
        self._provider = provider
        self._copilot_audit_service = copilot_audit_service

    def ask(self, alert_id: uuid.UUID, question: str) -> CopilotResponse:
        """Answer an analyst's question about one alert with a full
        structured assessment. Read-only: never changes the alert's
        status or any other stored data — the AI layer is advisory only.

        Step 10F.4: every call that resolves an alert produces exactly
        one CopilotAudit row via _record_copilot_audit, classified as
        success/provider-failure/validation-failure (see that helper and
        _generate/_parse_structured's docstrings for the exact
        distinction). No audit row is written if the alert itself cannot
        be resolved (see AlertNotFoundError below) — there is no valid
        alert_id to attach one to.
        """
        alert = self._alert_service.get_with_events(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)

        started = time.monotonic()
        model_name: str | None = None
        try:
            investigation = self._investigation_engine.build_context(alert)
            mitre_candidates = get_techniques_for_rule(alert.rule_id)
            action_candidates = get_candidate_actions(alert.rule_id, investigation.entities)
            ai_context = self._context_builder.build(investigation, mitre_candidates, action_candidates)

            request = AIRequest(
                system_instructions=CURRENT_SYSTEM_INSTRUCTIONS,
                context=ai_context,
                user_question=question,
            )
            response = self._generate(request, alert_id=alert_id)
            model_name = response.model

            assessment = self._parse_structured(
                CopilotAssessment, response.content, provider_name=response.provider, alert_id=alert_id
            )
            cited_refs = self._event_refs_cited_in_assessment(assessment)
            self._reject_fabricated_event_refs(
                cited_refs, ai_context, provider_name=response.provider, alert_id=alert_id
            )
            self._enforce_confidence_calibration(
                assessment, cited_refs, provider_name=response.provider, alert_id=alert_id
            )
            normalized_mitre = self._normalize_mitre_entries(
                assessment.mitre_analysis, mitre_candidates, provider_name=response.provider, alert_id=alert_id
            )
            normalized_actions = self._normalize_recommended_actions(
                assessment.recommended_actions, action_candidates, provider_name=response.provider, alert_id=alert_id
            )
            assessment = assessment.model_copy(
                update={"mitre_analysis": normalized_mitre, "recommended_actions": normalized_actions}
            )
        except AIProviderTransportError:
            self._record_copilot_audit(
                alert_id=alert_id,
                request_type=AuditRequestType.ASK,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.NOT_APPLICABLE,
                http_status=502,
                question=question,
                history=(),
                started=started,
            )
            raise
        except AIProviderValidationError:
            self._record_copilot_audit(
                alert_id=alert_id,
                request_type=AuditRequestType.ASK,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.FAILED,
                http_status=502,
                question=question,
                history=(),
                started=started,
            )
            raise

        self._record_copilot_audit(
            alert_id=alert_id,
            request_type=AuditRequestType.ASK,
            model_name=model_name,
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question=question,
            history=(),
            started=started,
        )

        return CopilotResponse(
            alert_id=alert_id,
            provider=response.provider,
            model=response.model,
            assessment=assessment,
            generated_at=datetime.now(timezone.utc),
            usage=response.usage,
        )

    def follow_up(
        self, alert_id: uuid.UUID, question: str, history: list[CopilotMessage]
    ) -> CopilotFollowUpResponse:
        """Answer an alert-scoped follow-up question, optionally informed
        by client-supplied prior conversation turns. Read-only, exactly
        like ask() — see the module docstring's Step 10C section for the
        ALERT ISOLATION guarantee this method provides: `history` and
        `question` are the ONLY things this method accepts from the
        caller. Everything else (the alert, its InvestigationContext, its
        MITRE candidates) is independently reconstructed from `alert_id`
        alone, from the database, on every call — never accepted as
        input, so a client cannot supply a replacement investigation
        context or borrow another alert's evidence/MITRE candidates.

        Step 10F.4: audited exactly like ask() (see that method's
        docstring) via the same _record_copilot_audit helper, with
        request_type=follow_up and the real `history` so
        history_turn_count/the fingerprint reflect what was actually
        supplied. follow_up() has no verdict/confidence pair (see
        _enforce_confidence_calibration's own docstring), so that check
        is not part of this method's pipeline — nothing else changes.
        """
        alert = self._alert_service.get_with_events(alert_id)
        if alert is None:
            raise AlertNotFoundError(alert_id)

        started = time.monotonic()
        model_name: str | None = None
        try:
            investigation = self._investigation_engine.build_context(alert)
            mitre_candidates = get_techniques_for_rule(alert.rule_id)
            action_candidates = get_candidate_actions(alert.rule_id, investigation.entities)
            ai_context = self._context_builder.build(investigation, mitre_candidates, action_candidates)

            request = AIRequest(
                system_instructions=CURRENT_FOLLOW_UP_SYSTEM_INSTRUCTIONS,
                context=ai_context,
                conversation_history=self._map_conversation_history(history),
                user_question=question,
            )
            response = self._generate(request, alert_id=alert_id)
            model_name = response.model

            answer = self._parse_structured(
                CopilotFollowUpAnswer, response.content, provider_name=response.provider, alert_id=alert_id
            )
            cited_refs = self._event_refs_cited_in_follow_up(answer)
            self._reject_fabricated_event_refs(
                cited_refs, ai_context, provider_name=response.provider, alert_id=alert_id
            )
            normalized_mitre = self._normalize_mitre_entries(
                answer.mitre_refs, mitre_candidates, provider_name=response.provider, alert_id=alert_id
            )
            normalized_actions = self._normalize_recommended_actions(
                answer.recommended_actions, action_candidates, provider_name=response.provider, alert_id=alert_id
            )
        except AIProviderTransportError:
            self._record_copilot_audit(
                alert_id=alert_id,
                request_type=AuditRequestType.FOLLOW_UP,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.NOT_APPLICABLE,
                http_status=502,
                question=question,
                history=history,
                started=started,
            )
            raise
        except AIProviderValidationError:
            self._record_copilot_audit(
                alert_id=alert_id,
                request_type=AuditRequestType.FOLLOW_UP,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.FAILED,
                http_status=502,
                question=question,
                history=history,
                started=started,
            )
            raise

        self._record_copilot_audit(
            alert_id=alert_id,
            request_type=AuditRequestType.FOLLOW_UP,
            model_name=model_name,
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question=question,
            history=history,
            started=started,
        )

        return CopilotFollowUpResponse(
            alert_id=alert_id,
            provider=response.provider,
            model=response.model,
            answer=answer.answer,
            generated_at=datetime.now(timezone.utc),
            supporting_event_refs=answer.supporting_event_refs,
            mitre_refs=normalized_mitre,
            recommended_actions=normalized_actions,
            limitations=answer.limitations,
            usage=response.usage,
        )

    def _record_copilot_audit(
        self,
        *,
        alert_id: uuid.UUID,
        request_type: AuditRequestType,
        model_name: str | None,
        outcome: AuditOutcome,
        validation_status: AuditValidationStatus,
        http_status: int,
        question: str,
        history: Sequence[CopilotMessage],
        started: float,
    ) -> None:
        """Writes exactly one CopilotAudit row for this call's terminal
        outcome, shared by ask() and follow_up() so there is one
        implementation of "how a Copilot attempt becomes an audit row",
        not two that could drift apart.

        Observability only, never an execution dependency: this method
        NEVER raises. Step 10F.6: deliberately catches bare `Exception`,
        not just CopilotAuditError (a CopilotAuditValidationError this
        class failed to construct correctly, or a
        CopilotAuditPersistenceError from a genuine database problem) —
        the guarantee this method makes ("an audit write failing must
        never turn an otherwise-successful Copilot response into a 502,
        and must never mask the real error when the provider or
        validation already failed") has to hold even if
        CopilotAuditService itself has a bug and lets something other
        than one of its own typed exceptions escape (e.g. a raw
        SQLAlchemyError). CopilotService is the boundary responsible for
        protecting its own return/raise semantics; it cannot assume the
        audit layer will always fail the way it's documented to. Every
        failure is still logged server-side via the existing `logger`
        (see the `except` clause below) — this is "log and continue",
        never "log and hide silently". ask()/follow_up() call this from
        inside an `except ...: ...; raise` block specifically so the
        original exception (or the successful return value) always
        wins, never this method's own outcome.

        provider_name always comes from `self._provider.name` — never
        hardcoded — so this reflects whichever AIProvider AI_PROVIDER
        actually configured for this call. duration_ms is measured here,
        server-side, from `started` (a time.monotonic() timestamp taken
        at the top of ask()/follow_up(), before alert resolution) to now
        — never a client-supplied value.
        """
        duration_ms = max(0, round((time.monotonic() - started) * 1000))
        try:
            self._copilot_audit_service.record(
                alert_id=alert_id,
                request_type=request_type,
                provider_name=self._provider.name,
                model_name=model_name,
                outcome=outcome,
                validation_status=validation_status,
                http_status=http_status,
                question=question,
                history=history,
                duration_ms=duration_ms,
            )
        except Exception:
            logger.exception(
                "Failed to record Copilot audit for alert %s (request_type=%s, outcome=%s)",
                alert_id,
                request_type.value,
                outcome.value,
            )

    @staticmethod
    def _map_conversation_history(history: list[CopilotMessage]) -> list[AIConversationTurn]:
        """Maps client-supplied CopilotMessage turns 1:1 into
        AIConversationTurn — same role, same content, unmodified,
        unreordered, unfiltered. This is the ONLY place client history
        ever crosses into the provider-facing request; nothing here
        interprets a turn's content or lets it influence anything beyond
        being one more conversational turn.
        """
        return [AIConversationTurn(role=AIConversationRole(turn.role.value), content=turn.content) for turn in history]

    def _generate(self, request: AIRequest, *, alert_id: uuid.UUID) -> AIResponse:
        """Transport/provider failure boundary: anything raised directly
        by AIProvider.generate() itself (network/timeout, SDK error,
        auth/rate-limit rejection, provider outage, ...) becomes
        AIProviderTransportError — no AIResponse was ever received here,
        so Step 10F.4's audit classifies this as
        outcome=failure/validation_status=not_applicable (validation
        never ran) rather than validation_status=failed.
        """
        try:
            return self._provider.generate(request)
        except Exception as exc:
            logger.exception(
                "AI provider '%s' failed while answering a question about alert %s",
                self._provider.name,
                alert_id,
            )
            raise AIProviderTransportError("The AI provider failed to generate a response.") from exc

    @staticmethod
    def _parse_structured(
        schema_cls: type[BaseModel], content: str, *, provider_name: str, alert_id: uuid.UUID
    ) -> BaseModel:
        """Content-validation boundary: the provider DID respond (an
        AIResponse, and therefore a model name, already exists by the
        time this is called) — it just didn't produce well-formed
        content, so this is AIProviderValidationError, not a transport
        failure.
        """
        try:
            return schema_cls.model_validate_json(content)
        except ValidationError as exc:
            # Never log `content` itself: it is the provider's raw
            # structured output and may echo back telemetry-derived
            # investigation data.
            logger.error(
                "Provider '%s' returned a response that failed %s validation for alert %s (error_count=%d)",
                provider_name,
                schema_cls.__name__,
                alert_id,
                exc.error_count(),
            )
            raise AIProviderValidationError(
                "The AI provider returned a response that did not match the expected schema."
            ) from exc

    @staticmethod
    def _event_refs_cited_in_assessment(assessment: CopilotAssessment) -> set[str]:
        cited_refs: set[str] = set()
        for finding in assessment.key_findings:
            cited_refs.update(finding.supporting_event_refs)
        for item in assessment.evidence:
            if item.event_ref is not None:
                cited_refs.add(item.event_ref)
        for mitre_entry in assessment.mitre_analysis:
            cited_refs.update(mitre_entry.supporting_event_refs)
        for action in assessment.recommended_actions:
            cited_refs.update(action.supporting_event_refs)
        return cited_refs

    @staticmethod
    def _event_refs_cited_in_follow_up(answer: CopilotFollowUpAnswer) -> set[str]:
        cited_refs: set[str] = set(answer.supporting_event_refs)
        for mitre_entry in answer.mitre_refs:
            cited_refs.update(mitre_entry.supporting_event_refs)
        for action in answer.recommended_actions:
            cited_refs.update(action.supporting_event_refs)
        return cited_refs

    @staticmethod
    def _reject_fabricated_event_refs(
        cited_refs: set[str], ai_context: AIContext, *, provider_name: str, alert_id: uuid.UUID
    ) -> None:
        """Reject (never silently strip) any event_ref cited that was not
        actually present in the AIContext supplied for this request — the
        evidence-integrity guarantee that a provider cannot fabricate a
        reference to an event that doesn't exist. Shared by ask() and
        follow_up() so there is exactly one implementation of this check,
        not two that could drift apart.
        """
        known_refs = {entry.event_ref for entry in ai_context.timeline}
        fabricated_refs = cited_refs - known_refs
        if fabricated_refs:
            logger.error(
                "Provider '%s' cited event_ref(s) not present in the supplied AIContext for "
                "alert %s (fabricated_count=%d)",
                provider_name,
                alert_id,
                len(fabricated_refs),
            )
            raise AIProviderValidationError(
                "The AI provider referenced evidence that was not present in the supplied investigation context."
            )

    @staticmethod
    def _enforce_confidence_calibration(
        assessment: CopilotAssessment, cited_refs: set[str], *, provider_name: str, alert_id: uuid.UUID
    ) -> None:
        """Step 10E: a small, explicit, non-numeric decision-safety
        policy — NOT a scoring model — that rejects a fixed set of
        verdict/confidence/evidence combinations that would let a
        provider manufacture certainty from nothing:

        1. "likely_malicious" is never accepted when the assessment
           supplied no evidence items AND cited no real timeline event
           anywhere (key_findings, evidence, mitre_analysis, or
           recommended_actions) — a strong attack conclusion must be
           grounded in *something* that was actually supplied, at any
           confidence level.
        2. "high" confidence is never accepted, for any verdict other
           than "inconclusive", under that same no-grounding condition.
           ("high-confidence inconclusive" remains valid and is left
           alone — see SYSTEM_INSTRUCTIONS rule 6: confidence that the
           evidence is genuinely insufficient is a coherent, honest
           claim, not an overclaim.)
        3. Whenever nothing was supplied, `limitations` must say so —
           silently returning a decisive-sounding assessment with no
           grounding AND no acknowledgement of that gap is rejected even
           if the verdict/confidence themselves happened to be mild.

        "No grounding" is judged from `assessment.evidence` (the
        provider's own structured evidence list) and `cited_refs` (the
        exact same event-ref set _reject_fabricated_event_refs already
        computed for this response, gathered from every field that can
        carry a supporting_event_refs/event_ref — not a second,
        independent computation) — deliberately NOT from key_findings
        *statement text*, which the provider authors itself and could
        pad with a generic sentence to appear evidence-backed without
        actually citing anything real. See working rule 14: never trust
        model-generated content the application can verify
        independently.
        """
        has_no_supplied_evidence = not assessment.evidence and not cited_refs
        if not has_no_supplied_evidence:
            return

        if assessment.verdict is Verdict.LIKELY_MALICIOUS:
            logger.error(
                "Provider '%s' returned verdict=likely_malicious with no supplied evidence "
                "for alert %s",
                provider_name,
                alert_id,
            )
            raise AIProviderValidationError(
                "The AI provider concluded a likely-malicious verdict without any supporting "
                "evidence in the supplied investigation context."
            )

        if assessment.confidence is AssessmentConfidence.HIGH and assessment.verdict is not Verdict.INCONCLUSIVE:
            logger.error(
                "Provider '%s' returned confidence=high for verdict=%s with no supplied evidence "
                "for alert %s",
                provider_name,
                assessment.verdict.value,
                alert_id,
            )
            raise AIProviderValidationError(
                "The AI provider returned high confidence for a conclusion that was not backed by "
                "any supporting evidence in the supplied investigation context."
            )

        if not assessment.limitations:
            logger.error(
                "Provider '%s' supplied no evidence and did not acknowledge the gap in "
                "limitations for alert %s",
                provider_name,
                alert_id,
            )
            raise AIProviderValidationError(
                "The AI provider did not acknowledge the absence of supporting evidence in "
                "its limitations."
            )

    @staticmethod
    def _normalize_mitre_entries(
        entries: list[MitreAnalysisEntry],
        mitre_candidates: list[MitreTechnique],
        *,
        provider_name: str,
        alert_id: uuid.UUID,
    ) -> list[MitreAnalysisEntry]:
        """The MITRE-specific half of evidence integrity, shared by
        ask() (CopilotAssessment.mitre_analysis) and follow_up()
        (CopilotFollowUpAnswer.mitre_refs) — both are `list[MitreAnalysisEntry]`,
        so one implementation covers both call sites:

        1. Reject (never silently drop) the whole response if any entry
           cites a technique_id that was not one of the candidates
           actually offered to the provider for this alert's rule_id —
           the application-controlled candidate set is the only source
           of truth for "is this a real option", and a provider (or the
           model behind it) must never be able to expand it. This
           includes follow-up requests: the candidate set is fixed by
           alert.rule_id and CANNOT be changed by conversation history
           or the current question.
        2. Unconditionally overwrite technique_name/tactic on every
           surviving entry with the registry's own canonical values for
           that technique_id — the provider's name/tactic strings are
           NEVER trusted as authoritative, even when technique_id itself
           was valid (see TECHNIQUE NAME INTEGRITY / TACTIC INTEGRITY).
        """
        candidates_by_id = {c.technique_id: c for c in mitre_candidates}

        fabricated_ids = {entry.technique_id for entry in entries} - candidates_by_id.keys()
        if fabricated_ids:
            logger.error(
                "Provider '%s' returned a MITRE technique_id not in the candidate set "
                "for alert %s (fabricated_count=%d)",
                provider_name,
                alert_id,
                len(fabricated_ids),
            )
            raise AIProviderValidationError(
                "The AI provider returned an ATT&CK technique that was not among the "
                "application-supplied candidates."
            )

        return [
            entry.model_copy(
                update={
                    "technique_name": candidates_by_id[entry.technique_id].name,
                    "tactic": candidates_by_id[entry.technique_id].tactic,
                }
            )
            for entry in entries
        ]

    @staticmethod
    def _normalize_recommended_actions(
        entries: list[RecommendedInvestigationAction],
        action_candidates: list[InvestigationAction],
        *,
        provider_name: str,
        alert_id: uuid.UUID,
    ) -> list[RecommendedInvestigationAction]:
        """Step 10D: the investigation-action counterpart to
        _normalize_mitre_entries, shared by ask()
        (CopilotAssessment.recommended_actions) and follow_up()
        (CopilotFollowUpAnswer.recommended_actions) — both are
        `list[RecommendedInvestigationAction]`, so one implementation
        covers both call sites:

        1. Reject (never silently drop) the whole response if any entry
           cites an action_id that was not one of the candidates
           actually offered to the provider for this alert's rule_id +
           entities — the application-controlled candidate set is the
           only source of truth for "is this a real option", and a
           provider (or the model behind it) must never be able to
           expand it. This includes follow-up requests: the candidate
           set is fixed by alert.rule_id + investigation.entities and
           CANNOT be changed by conversation history or the current
           question.
        2. Unconditionally overwrite label/description on every
           surviving entry with the registry's own canonical values for
           that action_id — the provider's label/description strings are
           NEVER trusted as authoritative, even when action_id itself
           was valid.
        """
        candidates_by_id = {c.action_id: c for c in action_candidates}

        fabricated_ids = {entry.action_id for entry in entries} - candidates_by_id.keys()
        if fabricated_ids:
            logger.error(
                "Provider '%s' returned a recommended-action action_id not in the candidate "
                "set for alert %s (fabricated_count=%d)",
                provider_name,
                alert_id,
                len(fabricated_ids),
            )
            raise AIProviderValidationError(
                "The AI provider recommended an investigation action that was not among the "
                "application-supplied candidates."
            )

        return [
            entry.model_copy(
                update={
                    "label": candidates_by_id[entry.action_id].label,
                    "description": candidates_by_id[entry.action_id].description,
                }
            )
            for entry in entries
        ]
