"""CaseCopilotService: orchestrates Case -> AICaseContext -> provider
call -> validated, reference-checked CaseCopilotResponse (Step 13D).

Sibling to app.services.copilot_service.CopilotService, deliberately NOT a
generalization of it or a modification to it (see the Step 13D gate
report and app.schemas.case_ai's own docstring for why AICaseContext/
CaseInvestigationBrief are kept fully independent schemas). Every
validation helper below is an independent implementation of the exact
same PATTERN CopilotService already established (closed-candidate-set
MITRE validation, fabricated-reference rejection, safe provider-failure
mapping, audit-on-every-terminal-outcome) — not a shared/refactored
helper, so the already-reviewed alert-scoped pipeline is untouched by
this file's existence.

Depends on CaseService (to fetch the case + its linked alerts/notes/
audit, exactly as the existing Case endpoints already do), AlertService +
InvestigationEngine (ONLY for the one optionally-focused alert — see
ask_about_case()'s own docstring for the N+1 guarantee this preserves),
AICaseContextBuilder, an AIProvider, and CopilotAuditService. All
injected through the constructor (see get_case_copilot_service in
app.api.cases), mirroring CopilotService's own DI shape exactly.
"""

import logging
import time
import uuid
from collections.abc import Sequence
from datetime import datetime, timezone

from pydantic import ValidationError

from app.ai.case_context_builder import AICaseContextBuilder
from app.ai.exceptions import AIProviderTransportError, AIProviderValidationError
from app.ai.prompts import CURRENT_CASE_BRIEF_SYSTEM_INSTRUCTIONS
from app.ai.provider import AIProvider
from app.models.alert import Alert
from app.mitre.models import MitreTechnique
from app.mitre.registry import get_techniques_for_rule
from app.schemas.ai import AIResponse, MitreAnalysisEntry
from app.schemas.case_ai import (
    AICaseContext,
    AICaseRequest,
    CaseCopilotResponse,
    CaseInvestigationBrief,
    MAX_CASE_ALERTS_IN_CONTEXT,
    MAX_CASE_AUDIT_IN_CONTEXT,
    MAX_CASE_MITRE_CANDIDATES,
    MAX_CASE_NOTES_IN_CONTEXT,
)
from app.schemas.copilot_audit import AuditOutcome, AuditRequestType, AuditValidationStatus
from app.services.alert_service import AlertService
from app.services.case_service import CaseService
from app.services.copilot_audit_service import CopilotAuditService
from app.services.investigation_service import InvestigationEngine

logger = logging.getLogger(__name__)


class CaseCopilotServiceError(Exception):
    """Base class for every error CaseCopilotService raises directly
    (as opposed to re-raising from CaseService/AlertService)."""


class FocusedAlertNotLinkedError(CaseCopilotServiceError):
    """Raised when `focused_alert_id` does not name an alert actually
    linked to this case -- the IDOR-relevant guard: a client cannot
    smuggle another case's (or an unrelated) alert's telemetry into this
    case's brief merely by naming its id.
    """

    def __init__(self, case_id: uuid.UUID, alert_id: uuid.UUID) -> None:
        self.case_id = case_id
        self.alert_id = alert_id
        super().__init__(f"Alert '{alert_id}' is not linked to case '{case_id}'")


class CaseCopilotService:
    def __init__(
        self,
        case_service: CaseService,
        alert_service: AlertService,
        investigation_engine: InvestigationEngine,
        context_builder: AICaseContextBuilder,
        provider: AIProvider,
        copilot_audit_service: CopilotAuditService,
    ) -> None:
        self._case_service = case_service
        self._alert_service = alert_service
        self._investigation_engine = investigation_engine
        self._context_builder = context_builder
        self._provider = provider
        self._copilot_audit_service = copilot_audit_service

    def ask_about_case(
        self, case_id: uuid.UUID, question: str, focused_alert_id: uuid.UUID | None = None
    ) -> CaseCopilotResponse:
        """Generate a Case-scoped investigation brief. Read-only: never
        changes the case's status, priority, owner, or any linked
        alert/note/audit — the AI layer is advisory only (Step 13D §16/
        §17).

        N+1 guarantee: this method fetches the case's own linked alerts,
        notes, and audit exactly once each (bounded, bulk queries CaseService
        already provides). It fetches a per-alert Investigation ONLY for
        `focused_alert_id`, when supplied -- never looped across every
        linked alert. Every other linked alert is represented in the
        context by its own already-loaded summary fields alone (rule_id,
        title, severity, status, evidence keys, event count) — see
        AICaseContextBuilder.

        Every call that resolves a case produces exactly one CopilotAudit
        row via _record_copilot_audit, classified as success/provider-
        failure/validation-failure, mirroring CopilotService.ask()'s own
        Step 10F.4 discipline exactly. No audit row is written if the
        case itself cannot be resolved -- there is no valid case_id to
        attach one to.
        """
        case = self._case_service.get_case(case_id)  # raises CaseNotFoundError
        alerts = self._case_service.list_alerts(case_id)[:MAX_CASE_ALERTS_IN_CONTEXT]
        notes = self._case_service.list_notes(case_id, limit=MAX_CASE_NOTES_IN_CONTEXT, offset=0)
        audits = self._case_service.list_audits(case_id, limit=MAX_CASE_AUDIT_IN_CONTEXT, offset=0)

        if focused_alert_id is not None and not any(a.id == focused_alert_id for a in alerts):
            raise FocusedAlertNotLinkedError(case_id, focused_alert_id)

        started = time.monotonic()
        model_name: str | None = None
        try:
            focused_investigation = None
            focused_alert_ref: str | None = None
            if focused_alert_id is not None:
                # Index among the (already-bounded) alerts list determines
                # the same alert_ref AICaseContextBuilder will assign —
                # computed once here so the request/response can agree on
                # "which ref names the focused alert" without a second
                # pass over the list.
                position = next(i for i, a in enumerate(alerts, start=1) if a.id == focused_alert_id)
                focused_alert_ref = f"alert-{position}"
                focused_alert = self._alert_service.get_with_events(focused_alert_id)
                if focused_alert is not None:
                    focused_investigation = self._investigation_engine.build_context(focused_alert)

            mitre_candidates = self._union_mitre_candidates(alerts)
            ai_context = self._context_builder.build(
                case=case,
                alerts=alerts,
                notes=notes,
                audits=audits,
                mitre_candidates=mitre_candidates,
                focused_alert_investigation=focused_investigation,
                focused_alert_ref=focused_alert_ref,
            )

            request = AICaseRequest(
                system_instructions=CURRENT_CASE_BRIEF_SYSTEM_INSTRUCTIONS,
                context=ai_context,
                user_question=question,
            )
            response = self._generate(request, case_id=case_id)
            model_name = response.model

            brief = self._parse_structured(response.content, provider_name=response.provider, case_id=case_id)
            cited_alert_refs, cited_event_refs = self._refs_cited_in_brief(brief)
            self._reject_fabricated_refs(
                cited_alert_refs, cited_event_refs, ai_context, provider_name=response.provider, case_id=case_id
            )
            normalized_mitre = self._normalize_mitre_entries(
                brief.mitre_analysis, mitre_candidates, provider_name=response.provider, case_id=case_id
            )
            brief = brief.model_copy(update={"mitre_analysis": normalized_mitre})
        except AIProviderTransportError:
            self._record_copilot_audit(
                case_id=case_id,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.NOT_APPLICABLE,
                http_status=502,
                question=question,
                started=started,
            )
            raise
        except AIProviderValidationError:
            self._record_copilot_audit(
                case_id=case_id,
                model_name=model_name,
                outcome=AuditOutcome.FAILURE,
                validation_status=AuditValidationStatus.FAILED,
                http_status=502,
                question=question,
                started=started,
            )
            raise

        self._record_copilot_audit(
            case_id=case_id,
            model_name=model_name,
            outcome=AuditOutcome.SUCCESS,
            validation_status=AuditValidationStatus.PASSED,
            http_status=200,
            question=question,
            started=started,
        )

        return CaseCopilotResponse(
            case_id=case_id,
            provider=response.provider,
            model=response.model,
            brief=brief,
            generated_at=datetime.now(timezone.utc),
            usage=response.usage,
        )

    def _record_copilot_audit(
        self,
        *,
        case_id: uuid.UUID,
        model_name: str | None,
        outcome: AuditOutcome,
        validation_status: AuditValidationStatus,
        http_status: int,
        question: str,
        started: float,
    ) -> None:
        """Mirrors CopilotService._record_copilot_audit exactly (see that
        method's own extensive docstring for the full "never raises, log
        and continue" contract) — an independent implementation, not a
        shared helper, because it audits a case_id, not an alert_id.
        """
        duration_ms = max(0, round((time.monotonic() - started) * 1000))
        try:
            self._copilot_audit_service.record(
                case_id=case_id,
                request_type=AuditRequestType.CASE_BRIEF,
                provider_name=self._provider.name,
                model_name=model_name,
                outcome=outcome,
                validation_status=validation_status,
                http_status=http_status,
                question=question,
                history=(),
                duration_ms=duration_ms,
            )
        except Exception:
            logger.exception(
                "Failed to record Copilot audit for case %s (outcome=%s)", case_id, outcome.value
            )

    def _generate(self, request: AICaseRequest, *, case_id: uuid.UUID) -> AIResponse:
        try:
            return self._provider.generate_case(request)
        except Exception as exc:
            logger.exception(
                "AI provider '%s' failed while generating an investigation brief for case %s",
                self._provider.name,
                case_id,
            )
            raise AIProviderTransportError("The AI provider failed to generate a response.") from exc

    @staticmethod
    def _parse_structured(content: str, *, provider_name: str, case_id: uuid.UUID) -> CaseInvestigationBrief:
        try:
            return CaseInvestigationBrief.model_validate_json(content)
        except ValidationError as exc:
            # Never log `content` itself: it is the provider's raw
            # structured output and may echo back case-derived data.
            logger.error(
                "Provider '%s' returned a response that failed CaseInvestigationBrief validation for "
                "case %s (error_count=%d)",
                provider_name,
                case_id,
                exc.error_count(),
            )
            raise AIProviderValidationError(
                "The AI provider returned a response that did not match the expected schema."
            ) from exc

    @staticmethod
    def _refs_cited_in_brief(brief: CaseInvestigationBrief) -> tuple[set[str], set[str]]:
        alert_refs: set[str] = set()
        event_refs: set[str] = set()
        for finding in brief.key_findings:
            alert_refs.update(finding.supporting_alert_refs)
            event_refs.update(finding.supporting_event_refs)
        for item in brief.supporting_evidence:
            if item.alert_ref is not None:
                alert_refs.add(item.alert_ref)
            if item.event_ref is not None:
                event_refs.add(item.event_ref)
        for mitre_entry in brief.mitre_analysis:
            event_refs.update(mitre_entry.supporting_event_refs)
        return alert_refs, event_refs

    @staticmethod
    def _reject_fabricated_refs(
        cited_alert_refs: set[str],
        cited_event_refs: set[str],
        ai_context: AICaseContext,
        *,
        provider_name: str,
        case_id: uuid.UUID,
    ) -> None:
        """The Case-scoped counterpart to CopilotService's own
        _reject_fabricated_event_refs, generalized to two reference
        spaces (alert_ref, event_ref) since a Case brief can cite either.
        Reject (never silently strip) any ref cited that was not actually
        offered in the AICaseContext supplied for this request.
        """
        known_alert_refs = {a.alert_ref for a in ai_context.alerts}
        known_event_refs = {e.event_ref for e in ai_context.focused_alert.timeline} if ai_context.focused_alert else set()

        fabricated_alert_refs = cited_alert_refs - known_alert_refs
        fabricated_event_refs = cited_event_refs - known_event_refs
        if fabricated_alert_refs or fabricated_event_refs:
            logger.error(
                "Provider '%s' cited fabricated reference(s) not present in the supplied AICaseContext "
                "for case %s (fabricated_alert_refs=%d, fabricated_event_refs=%d)",
                provider_name,
                case_id,
                len(fabricated_alert_refs),
                len(fabricated_event_refs),
            )
            raise AIProviderValidationError(
                "The AI provider referenced evidence that was not present in the supplied case context."
            )

    @staticmethod
    def _normalize_mitre_entries(
        entries: list[MitreAnalysisEntry],
        mitre_candidates: list[MitreTechnique],
        *,
        provider_name: str,
        case_id: uuid.UUID,
    ) -> list[MitreAnalysisEntry]:
        """The Case-scoped counterpart to CopilotService's own
        _normalize_mitre_entries — identical two-step contract (reject
        any technique_id outside the candidate set; unconditionally
        overwrite technique_name/tactic with the registry's canonical
        values for the surviving entries), applied to the case-wide
        candidate UNION rather than one alert's rule_id candidates.
        """
        candidates_by_id = {c.technique_id: c for c in mitre_candidates}

        fabricated_ids = {entry.technique_id for entry in entries} - candidates_by_id.keys()
        if fabricated_ids:
            logger.error(
                "Provider '%s' returned a MITRE technique_id not in the case-wide candidate set for "
                "case %s (fabricated_count=%d)",
                provider_name,
                case_id,
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
    def _union_mitre_candidates(alerts: Sequence[Alert]) -> list[MitreTechnique]:
        """The case-wide MITRE candidate set: the union, deduplicated by
        technique_id (first-offering rule wins), of
        get_techniques_for_rule() across every DISTINCT rule_id among
        this case's (already-bounded) linked alerts. Reuses the existing
        authoritative registry lookup verbatim -- never a second mapping
        table, never an AI-supplied technique.
        """
        seen_ids: set[str] = set()
        union: list[MitreTechnique] = []
        seen_rule_ids: set[str] = set()
        for alert in alerts:
            if alert.rule_id in seen_rule_ids:
                continue
            seen_rule_ids.add(alert.rule_id)
            for technique in get_techniques_for_rule(alert.rule_id):
                if technique.technique_id in seen_ids:
                    continue
                seen_ids.add(technique.technique_id)
                union.append(technique)
        return union[:MAX_CASE_MITRE_CANDIDATES]
