"""AIContextBuilder: the single, reviewable boundary between AMNIX's
persisted domain data and anything that could reach an LLM prompt.

Converts an already-safe InvestigationContext (itself already free of
ORM/database internals — see app.schemas.investigation) into the
strictly smaller AIContext. This is a deliberate second filtering step,
not a formality: it exists so that a field added to InvestigationContext
in the future (e.g. for some analyst-UI purpose) does not automatically
flow into an LLM prompt. Something only reaches AIContext because this
class explicitly copies it, field by field.

Deliberately excluded, and why:
  - SecurityEvent.raw_data / event_metadata: the least-trusted, most
    arbitrary blobs in the system (arbitrary source-specific JSON) —
    not in the task's allowed-content list, and the highest-risk fields
    to hand to a model.
  - Alert.alert_metadata: an analyst/enrichment extension bag, not
    investigation evidence.
  - Alert.created_at/updated_at/first_seen/last_seen: operational
    timestamps. The investigation summary already narrates the
    timespan in prose, and per-event timestamps are on the timeline —
    duplicating these adds no value.
  - SecurityEvent/Alert database ids beyond the alert's own id: real
    primary keys are meaningless to a model's reasoning and pure token
    bloat. AITimelineEntry.event_ref replaces the real event_id with a
    synthetic, request-scoped label ("evt-1", "evt-2", ...) assigned
    below purely from timeline position — see AITimelineEntry's
    docstring for why (Step 10A structured evidence references).
  - Anything resembling credentials/secrets/connection strings: never
    modeled anywhere in this pipeline, so there is nothing to filter —
    they simply do not exist on InvestigationContext to begin with.

Step 10B: `build()` also takes `mitre_candidates` — the candidate ATT&CK
techniques for this alert's rule_id, already looked up by CopilotService
via app.mitre.registry.get_techniques_for_rule() *before* calling this
method. AIContextBuilder does not import app.mitre.registry and does not
decide which techniques apply to which rule — it only maps whatever
MitreTechnique list it's handed into the smaller, prompt-safe
AIMitreCandidate shape (dropping `description`, same pattern as the
timeline mapping above). This keeps "how do we decide candidate
techniques" isolated in one place (the registry) and "how do we shape
AIContext" isolated in this one place, per Step 10B's "keep the mapping
isolated" requirement.

Step 10D: `build()` likewise takes `action_candidates` — the candidate
investigation actions for this alert's rule_id + entities, already
looked up by CopilotService via
app.investigation_actions.registry.get_candidate_actions() *before*
calling this method. Same division of responsibility as MITRE:
AIContextBuilder does not import app.investigation_actions.registry and
does not decide which actions apply to which rule/entities — it only
maps whatever InvestigationAction list it's handed into the smaller,
prompt-safe AIActionCandidate shape (dropping `applicable_rule_ids`/
`required_entities` — AMNIX's own selection machinery, not something a
model needs to see).
"""

from collections.abc import Sequence

from app.investigation_actions.models import InvestigationAction
from app.mitre.models import MitreTechnique
from app.mitre.registry import MAPPING_SOURCE, MITRE_ATTACK_VERSION
from app.schemas.ai import (
    AIActionCandidate,
    AIContext,
    AIEntities,
    AIMitreCandidate,
    AITimelineEntry,
    MITREContext,
)
from app.schemas.investigation import InvestigationContext, TimelineEntry


class AIContextBuilder:
    def build(
        self,
        investigation: InvestigationContext,
        mitre_candidates: Sequence[MitreTechnique] = (),
        action_candidates: Sequence[InvestigationAction] = (),
    ) -> AIContext:
        alert = investigation.alert
        return AIContext(
            alert_id=alert.id,
            rule_id=alert.rule_id,
            title=alert.title,
            description=alert.description,
            severity=alert.severity.value,
            confidence=alert.confidence.value,
            status=alert.status.value,
            evidence=alert.evidence,
            timeline=[
                self._map_timeline_entry(entry, index) for index, entry in enumerate(investigation.timeline, start=1)
            ],
            entities=AIEntities(
                hostnames=investigation.entities.hostnames,
                usernames=investigation.entities.usernames,
                source_ips=investigation.entities.source_ips,
                destination_ips=investigation.entities.destination_ips,
                process_names=investigation.entities.process_names,
                file_hashes=investigation.entities.file_hashes,
            ),
            investigation_summary=investigation.summary.text,
            mitre=MITREContext(
                candidate_techniques=[self._map_mitre_candidate(t) for t in mitre_candidates],
                mapping_source=MAPPING_SOURCE,
                mapping_version=MITRE_ATTACK_VERSION,
            ),
            action_candidates=[self._map_action_candidate(a, alert.rule_id) for a in action_candidates],
        )

    @staticmethod
    def _map_mitre_candidate(technique: MitreTechnique) -> AIMitreCandidate:
        return AIMitreCandidate(
            technique_id=technique.technique_id,
            name=technique.name,
            tactic=technique.tactic,
            source_rule_id=technique.source_rule_id,
        )

    @staticmethod
    def _map_action_candidate(action: InvestigationAction, rule_id: str) -> AIActionCandidate:
        return AIActionCandidate(
            action_id=action.action_id,
            label=action.label,
            description=action.description,
            # The alert's own rule_id — why this candidate was surfaced
            # for THIS investigation (see AIActionCandidate's docstring).
            source_rule_id=rule_id,
        )

    @staticmethod
    def _map_timeline_entry(entry: TimelineEntry, index: int) -> AITimelineEntry:
        return AITimelineEntry(
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
