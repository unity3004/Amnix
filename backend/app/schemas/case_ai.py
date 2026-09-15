"""Pydantic schemas for the Case-scoped AI Investigation Brief (Step 13D).

Mirrors app.schemas.ai's own split exactly: provider-facing (AICaseContext,
AICaseRequest) vs API-facing (CaseCopilotQuestionRequest, CaseCopilotResponse).
AICaseContext is a DELIBERATELY INDEPENDENT schema from AIContext -- never a
reuse/alias/subclass -- per the same "single, reviewable boundary" principle
AIContext itself documents (see app.ai.context_builder). A field only reaches
AICaseContext because AICaseContextBuilder explicitly copies it.

Step 13D discovery (see the Step 13D gate report) found the existing
alert-scoped AIContext/CopilotAssessment genuinely cannot represent a
multi-alert Case: `rule_id`/`evidence`/`timeline`/`mitre` are all
singular-alert fields there. This module is the smallest additive
extension approved to close that gap -- it does NOT modify AIContext,
CopilotAssessment, AIRequest, or any existing alert-scoped schema. The one
type reused directly (not duplicated) is `MitreAnalysisEntry`: a case-level
MITRE finding has the exact same shape/validation need (technique_id,
technique_name, tactic, confidence, rationale, supporting_event_refs) as an
alert-level one, and reusing it means CaseCopilotService can apply the
exact same "provider output is untrusted; the API response is the
validated, normalized result" discipline app.services.copilot_service
already established, without inventing a parallel class.

CaseInvestigationBrief deliberately has NO verdict/confidence pair (unlike
CopilotAssessment) -- mirroring CopilotFollowUpAnswer's own precedent for
the identical reason: Step 13D's own brief lists summary/key_findings/
supporting_evidence/timeline_summary/uncertainties/recommended_next_steps
as the preferred output fields, explicitly excludes any risk/threat/
confidence-percentage field, and a Case (unlike a single Alert) has no
single "is this malicious" question a verdict could even coherently
answer -- it may contain zero, one, or many alerts of differing
severities. Per-MITRE-entry `confidence` (from the reused
MitreAnalysisEntry) is kept because it is an already-validated, narrow,
existing contract (how well evidence supports ONE technique), not an
invented case-wide score.
"""

import uuid
from datetime import datetime
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.ai import AITimelineEntry, FindingType, MitreAnalysisEntry

MAX_CASE_QUESTION_LENGTH = 2000

# Case-context bounds (Step 13D §8). Applied defensively both here
# (Field constraints on the built context) and again in
# CaseCopilotService (which truncates before ever calling the builder) --
# defense in depth, matching every other bounded-list construct in AMNIX.
MAX_CASE_ALERTS_IN_CONTEXT = 20
MAX_CASE_NOTES_IN_CONTEXT = 20
MAX_CASE_AUDIT_IN_CONTEXT = 20
MAX_CASE_MITRE_CANDIDATES = 30
MAX_CASE_EVIDENCE_KEYS = 20

# Structured brief bounds -- same reasoning as app.schemas.ai's own
# MAX_* constants: a security control against an unboundedly large
# payload from a misbehaving or adversarially-steered model, not just
# tidiness.
MAX_BRIEF_SUMMARY_LENGTH = 3000
MAX_BRIEF_STATEMENT_LENGTH = 500
MAX_BRIEF_KEY_FINDINGS = 20
MAX_BRIEF_EVIDENCE_ITEMS = 20
MAX_BRIEF_NEXT_STEPS = 10
MAX_BRIEF_UNCERTAINTIES = 10
MAX_BRIEF_MITRE_ANALYSIS_ENTRIES = 10
MAX_TIMELINE_SUMMARY_LENGTH = 1000
MAX_REFS_PER_ITEM = 20


class AICaseAlertSummary(BaseModel):
    """AI-safe, bounded view of one linked Alert -- deliberately NOT the
    full per-event timeline: that would require a per-alert Investigation
    fetch for every linked alert, exactly the N+1 pattern this codebase
    has repeatedly ruled out (see Step 13B/13C's own architectural
    notes). `alert_ref` is a synthetic, request-scoped label (same
    pattern as AITimelineEntry.event_ref) assigned by AICaseContextBuilder
    purely from list position -- never the real database id, so a
    provider can cite "which alert" without ever handling, and therefore
    without ever being able to fabricate, a real primary key.
    """

    model_config = ConfigDict(frozen=True)

    alert_ref: str
    rule_id: str
    title: str
    severity: str
    status: str
    evidence_keys: list[str] = Field(default_factory=list, max_length=MAX_CASE_EVIDENCE_KEYS)
    event_count: int


class AICaseNote(BaseModel):
    """AI-safe view of one CaseNote -- untrusted, analyst-authored
    content (see Step 13D §6 trust boundary table). `note_ref` is
    synthetic, same reasoning as `alert_ref`.
    """

    model_config = ConfigDict(frozen=True)

    note_ref: str
    body: str


class AICaseAuditEntry(BaseModel):
    """AI-safe view of one CaseAudit row -- application-generated but
    still treated as plain data here, never as an instruction.
    `audit_ref` is synthetic, same reasoning as `alert_ref`.
    """

    model_config = ConfigDict(frozen=True)

    audit_ref: str
    action: str
    previous_value: str | None
    new_value: str | None


class AICaseFocusedAlert(BaseModel):
    """The one alert's full investigation timeline the analyst explicitly
    focused (Step 13D §7/§19) -- reuses AITimelineEntry verbatim so the
    exact same event_ref fabrication check CopilotService already applies
    generalizes cleanly to the Case-scoped pipeline. Optional: most Case
    briefs are generated with no alert focused, using only the bounded
    per-alert summaries above.
    """

    model_config = ConfigDict(frozen=True)

    alert_ref: str
    timeline: list[AITimelineEntry]


class AICaseMitreCandidate(BaseModel):
    """AI-safe, TRUSTED view of one candidate ATT&CK technique for this
    Case -- the union of app.mitre.registry.get_techniques_for_rule()
    across every DISTINCT rule_id among the case's linked alerts (see
    CaseCopilotService). Same trust status as AIMitreCandidate
    (app.schemas.ai): application-generated, never derived from
    telemetry, never mutable by anything downstream of
    AICaseContextBuilder.
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str
    tactic: str
    source_rule_id: str


class AICaseContext(BaseModel):
    """Everything -- and only what -- the AI layer is allowed to see
    about a Case. Built exclusively by AICaseContextBuilder from
    already-safe, already-loaded Case/Alert/CaseNote/CaseAudit data --
    never from raw ORM objects reaching a provider directly.
    """

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    title: str
    description: str
    status: str
    priority: str

    alerts: list[AICaseAlertSummary] = Field(default_factory=list, max_length=MAX_CASE_ALERTS_IN_CONTEXT)
    notes: list[AICaseNote] = Field(default_factory=list, max_length=MAX_CASE_NOTES_IN_CONTEXT)
    audit: list[AICaseAuditEntry] = Field(default_factory=list, max_length=MAX_CASE_AUDIT_IN_CONTEXT)
    focused_alert: AICaseFocusedAlert | None = None
    mitre_candidates: list[AICaseMitreCandidate] = Field(default_factory=list, max_length=MAX_CASE_MITRE_CANDIDATES)


class AICaseRequest(BaseModel):
    """A provider-neutral Case-brief generation request -- the Case-scoped
    counterpart to app.schemas.ai.AIRequest, kept fully independent of it
    (see this module's own docstring) rather than widening AIRequest's
    `context` field to a union: AIProvider gains a dedicated
    `generate_case()` method (see app.ai.provider) so the alert-scoped
    `generate()` code path in every existing provider is completely
    untouched by this step. Same field-separation discipline as
    AIRequest: `system_instructions` is the only field that may ever
    carry a directive; `context` and `user_question` are always data.

    No `conversation_history` field: Step 13D's approved scope is the
    single-shot "Generate Investigation Brief" action only (§19's
    follow-up extension is explicitly deferred -- see the final report's
    Known Limitations).
    """

    model_config = ConfigDict(frozen=True)

    system_instructions: str
    context: AICaseContext
    user_question: str


ShortStatement = Annotated[str, Field(min_length=1, max_length=MAX_BRIEF_STATEMENT_LENGTH)]


class CaseKeyFinding(BaseModel):
    """One discrete claim the brief makes, tagged as fact/inference/concern
    (reusing FindingType from app.schemas.ai verbatim -- identical
    meaning, identical need). `supporting_alert_refs` must each name an
    `AICaseAlertSummary.alert_ref` actually present in the AICaseContext
    this brief was built from; `supporting_event_refs` must each name an
    `AICaseFocusedAlert.timeline` event_ref, only ever non-empty when a
    focused alert was supplied. CaseCopilotService rejects the whole
    response if either set contains a reference that was not actually
    offered -- see that module's `_reject_fabricated_refs`.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: FindingType
    statement: ShortStatement
    supporting_alert_refs: list[str] = Field(default_factory=list, max_length=MAX_REFS_PER_ITEM)
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=MAX_REFS_PER_ITEM)


class CaseEvidenceItem(BaseModel):
    """One structured piece of evidence -- never a giant free-form blob.
    `alert_ref`/`event_ref`, if present, are validated the same way as
    on CaseKeyFinding.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: Annotated[str, Field(min_length=1, max_length=100)]
    value: ShortStatement
    alert_ref: str | None = None
    event_ref: str | None = None
    explanation: ShortStatement


class CaseInvestigationBrief(BaseModel):
    """A structured, evidence-grounded Case investigation brief -- the
    typed replacement for arbitrary Copilot prose, at Case scope. See
    this module's own top-of-file docstring for why there is deliberately
    no verdict/confidence pair. `extra="forbid"` and bounded string/list
    lengths throughout, exactly like CopilotAssessment: this is the one
    schema an external LLM's raw output must be coerced into for a Case
    brief, so it is deliberately strict rather than permissive.

    `recommended_next_steps` is analyst guidance ONLY -- free-form
    investigative suggestions in the model's own words, never validated
    against a candidate registry (mirrors CopilotAssessment's own field of
    the same name). Step 13D does not introduce a Case-scoped
    recommended_actions candidate system (app.investigation_actions is
    alert-rule-scoped by design) -- see Known Limitations.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    summary: Annotated[str, Field(min_length=1, max_length=MAX_BRIEF_SUMMARY_LENGTH)]
    key_findings: list[CaseKeyFinding] = Field(default_factory=list, max_length=MAX_BRIEF_KEY_FINDINGS)
    supporting_evidence: list[CaseEvidenceItem] = Field(default_factory=list, max_length=MAX_BRIEF_EVIDENCE_ITEMS)
    mitre_analysis: list[MitreAnalysisEntry] = Field(default_factory=list, max_length=MAX_BRIEF_MITRE_ANALYSIS_ENTRIES)
    timeline_summary: Annotated[str, Field(min_length=1, max_length=MAX_TIMELINE_SUMMARY_LENGTH)]
    uncertainties: list[ShortStatement] = Field(default_factory=list, max_length=MAX_BRIEF_UNCERTAINTIES)
    recommended_next_steps: list[ShortStatement] = Field(default_factory=list, max_length=MAX_BRIEF_NEXT_STEPS)


class CaseCopilotQuestionRequest(BaseModel):
    """Input schema for POST /cases/{case_id}/copilot.

    Deliberately accepts ONLY `question` and an optional
    `focused_alert_id` -- no evidence/events/notes/audit/MITRE fields of
    any kind (Step 13D §5: "the client must NOT send arbitrary Case
    evidence as trusted context"). Everything the Copilot reasons about
    is reconstructed server-side from `case_id` (path) and
    `focused_alert_id` (this field, cross-checked against the case's own
    real linked alerts -- see CaseCopilotService) alone.
    """

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=MAX_CASE_QUESTION_LENGTH)
    focused_alert_id: uuid.UUID | None = None

    @field_validator("question")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("question must not be blank")
        return v


class CaseCopilotResponse(BaseModel):
    """Output schema for POST /cases/{case_id}/copilot."""

    model_config = ConfigDict(frozen=True)

    case_id: uuid.UUID
    provider: str
    model: str
    brief: CaseInvestigationBrief
    generated_at: datetime
    usage: dict[str, Any] | None = None
