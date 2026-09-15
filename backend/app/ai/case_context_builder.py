"""AICaseContextBuilder: the single, reviewable boundary between AMNIX's
persisted Case domain data and anything that could reach an LLM prompt
for a Case-scoped brief (Step 13D).

Sibling to AIContextBuilder (app.ai.context_builder), not a generalization
of it — see app.schemas.case_ai's own docstring for why AICaseContext is a
deliberately independent schema. Converts already-loaded Case/Alert/
CaseNote/CaseAudit ORM rows (fetched and bounded by CaseCopilotService,
never queried here) into the strictly smaller AICaseContext.

Deliberately excluded, and why (mirrors AIContextBuilder's own list):
  - Alert.evidence VALUES: only the evidence dict's KEYS are included
    (AICaseAlertSummary.evidence_keys) — the full per-alert evidence blob
    is already visible in AlertRead's own detail view; including every
    value here for every linked alert would blow past this context's
    bounded-size goal for orientation purposes it does not need.
  - Alert.alert_metadata, Case timestamps beyond status/priority: same
    "operational metadata, not investigation evidence" reasoning
    AIContextBuilder already applies to Alert.
  - SecurityEvent.raw_data/event_metadata: never reachable here at all —
    this builder never touches SecurityEvent directly; per-event detail
    only ever arrives via an already-built InvestigationContext for the
    one optionally-focused alert (see `focused_alert_investigation`).
  - Real database ids anywhere except case_id itself: every Alert/
    CaseNote/CaseAudit row is represented by a synthetic, request-scoped
    ref ("alert-1", "note-1", "audit-1", ...) assigned purely from list
    position — never a real primary key a provider could later "cite"
    convincingly. See AICaseAlertSummary/AICaseNote/AICaseAuditEntry's
    own docstrings.
"""

from collections.abc import Sequence

from app.mitre.models import MitreTechnique
from app.models.alert import Alert
from app.models.case import Case
from app.models.case_audit import CaseAudit
from app.models.case_note import CaseNote
from app.schemas.ai import AITimelineEntry
from app.schemas.case_ai import (
    AICaseAlertSummary,
    AICaseAuditEntry,
    AICaseContext,
    AICaseFocusedAlert,
    AICaseMitreCandidate,
    AICaseNote,
    MAX_CASE_EVIDENCE_KEYS,
)
from app.schemas.investigation import InvestigationContext


class AICaseContextBuilder:
    def build(
        self,
        *,
        case: Case,
        alerts: Sequence[Alert],
        notes: Sequence[CaseNote],
        audits: Sequence[CaseAudit],
        mitre_candidates: Sequence[MitreTechnique] = (),
        focused_alert_investigation: InvestigationContext | None = None,
        focused_alert_ref: str | None = None,
    ) -> AICaseContext:
        return AICaseContext(
            case_id=case.id,
            title=case.title,
            description=case.description,
            status=case.status,
            priority=case.priority,
            alerts=[self._map_alert(alert, index) for index, alert in enumerate(alerts, start=1)],
            notes=[self._map_note(note, index) for index, note in enumerate(notes, start=1)],
            audit=[self._map_audit(audit, index) for index, audit in enumerate(audits, start=1)],
            focused_alert=self._map_focused_alert(focused_alert_investigation, focused_alert_ref),
            mitre_candidates=[self._map_mitre_candidate(t) for t in mitre_candidates],
        )

    @staticmethod
    def _map_alert(alert: Alert, index: int) -> AICaseAlertSummary:
        return AICaseAlertSummary(
            alert_ref=f"alert-{index}",
            rule_id=alert.rule_id,
            title=alert.title,
            severity=alert.severity,
            status=alert.status,
            evidence_keys=list(alert.evidence.keys())[:MAX_CASE_EVIDENCE_KEYS],
            event_count=len(alert.source_event_ids),
        )

    @staticmethod
    def _map_note(note: CaseNote, index: int) -> AICaseNote:
        return AICaseNote(note_ref=f"note-{index}", body=note.body)

    @staticmethod
    def _map_audit(audit: CaseAudit, index: int) -> AICaseAuditEntry:
        return AICaseAuditEntry(
            audit_ref=f"audit-{index}",
            action=audit.action,
            previous_value=audit.previous_value,
            new_value=audit.new_value,
        )

    @staticmethod
    def _map_focused_alert(
        investigation: InvestigationContext | None, alert_ref: str | None
    ) -> AICaseFocusedAlert | None:
        if investigation is None or alert_ref is None:
            return None
        return AICaseFocusedAlert(
            alert_ref=alert_ref,
            timeline=[
                AITimelineEntry(
                    event_ref=f"evt-{index}",
                    timestamp=entry.event_timestamp,
                    event_type=entry.event_type,
                    source=entry.source,
                    hostname=entry.hostname,
                    username=entry.username,
                    source_ip=str(entry.source_ip) if entry.source_ip is not None else None,
                    destination_ip=str(entry.destination_ip) if entry.destination_ip is not None else None,
                    process_name=entry.process_name,
                    command_line=entry.command_line,
                )
                for index, entry in enumerate(investigation.timeline, start=1)
            ],
        )

    @staticmethod
    def _map_mitre_candidate(technique: MitreTechnique) -> AICaseMitreCandidate:
        return AICaseMitreCandidate(
            technique_id=technique.technique_id,
            name=technique.name,
            tactic=technique.tactic,
            source_rule_id=technique.source_rule_id,
        )
