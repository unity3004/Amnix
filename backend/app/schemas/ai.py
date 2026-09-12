"""Pydantic schemas for the AI Copilot layer.

Two distinct groups of schemas live here:

1. Provider-facing (AIContext*, AIRequest, AIResponse) — the
   provider-neutral shapes that flow between CopilotService and an
   AIProvider. AIProvider implementations know nothing about "alerts";
   they only ever see these.

2. API-facing (CopilotQuestionRequest, CopilotResponse) — the HTTP
   request/response for POST /alerts/{id}/copilot. These add
   AMNIX-domain concepts (alert_id) that the provider layer never sees.

AIContext is a deliberately independent schema from InvestigationContext
(app.schemas.investigation) rather than a reuse/alias of it: it is the
single, reviewable boundary between AMNIX's persisted domain data and
anything that could reach an LLM prompt. A field only ends up here if
AIContextBuilder explicitly copies it — adding a field to
InvestigationContext later does not automatically expose it to the AI
layer. See app.ai.context_builder for what is deliberately excluded
(raw_data, event_metadata, alert_metadata, timestamps beyond the
timeline, database identifiers other than the alert's own id, and
anything resembling credentials/secrets — none of which are modeled
here at all, so they cannot leak by omission of a filter).

Step 10B adds MITRE ATT&CK schemas (AIMitreCandidate, MITREContext,
MitreAnalysisEntry). AIMitreCandidate/MITREContext are the one part of
AIContext that is TRUSTED, application-generated data (from
app.mitre.registry, never from telemetry) rather than untrusted
observations. MitreAnalysisEntry is provider output and is untrusted
exactly like the rest of CopilotAssessment — see
app.services.copilot_service for how its technique_id/technique_name/
tactic are validated and normalized against the trusted candidate set
before ever reaching an API response.

Step 10C adds alert-scoped follow-up conversation schemas. Two more
independently-duplicated pairs, same pattern as above:
  - CopilotMessage (API-facing, client-supplied, untrusted) vs.
    AIConversationTurn (provider-facing) — role is restricted to
    user/assistant in both; there is no schema path to a "system",
    "developer", "tool", or "function" role anywhere in this module.
  - CopilotFollowUpAnswer (provider output) vs. CopilotFollowUpResponse
    (API output) — the same "provider output is untrusted; the API
    response is the validated, normalized result" split CopilotAssessment/
    CopilotResponse already established.
Conversation history is explicitly NOT persisted anywhere in this
module or elsewhere in AMNIX — see CopilotFollowUpRequest.

Step 10D adds a third application-controlled candidate system, alongside
MITRE: AIActionCandidate (trusted, on AIContext.action_candidates, from
app.investigation_actions.registry) and RecommendedInvestigationAction
(provider output, reused by both CopilotAssessment.recommended_actions
and CopilotFollowUpAnswer.recommended_actions — same one-schema-two-call-
sites pattern MitreAnalysisEntry already established). These are
investigation-only suggestions for a human analyst; nothing in this
module is wired to any execution or dispatch mechanism, and none exists
anywhere in AMNIX.
"""

import re
import uuid
from datetime import datetime
from enum import Enum
from typing import Annotated, Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

MAX_QUESTION_LENGTH = 2000

# Structured assessment bounds. Applied uniformly regardless of provider
# (MockAIProvider's deterministic output stays well within these; an
# AnthropicProvider response is rejected — see app.services.copilot_service
# and app.ai.providers.anthropic — if it exceeds them). Bounding list/string
# sizes here is a security control, not just tidiness: it keeps a
# misbehaving or adversarially-steered model from returning an
# unboundedly large payload back through the API.
MAX_SUMMARY_LENGTH = 2000
MAX_STATEMENT_LENGTH = 500
MAX_SHORT_FIELD_LENGTH = 100
MAX_STEP_LENGTH = 300
MAX_LIMITATION_LENGTH = 300
MAX_KEY_FINDINGS = 20
MAX_EVIDENCE_ITEMS = 20
MAX_NEXT_STEPS = 10
MAX_LIMITATIONS = 10
MAX_SUPPORTING_REFS_PER_FINDING = 20
MAX_MITRE_ANALYSIS_ENTRIES = 10
MAX_RATIONALE_LENGTH = 800
MAX_TECHNIQUE_ID_LENGTH = 20
MAX_TECHNIQUE_NAME_LENGTH = 200
MAX_TACTIC_LENGTH = 100

# Step 10C: follow-up conversation bounds. Applied at the API boundary
# (CopilotMessage/CopilotFollowUpRequest) — conversation history is
# analyst-supplied, untrusted input, so it is bounded exactly like any
# other untrusted input AMNIX accepts (see app.schemas.security_event /
# app.schemas.alert for the same philosophy applied elsewhere).
MAX_HISTORY_MESSAGE_LENGTH = 4000
MAX_HISTORY_MESSAGES = 20
MAX_HISTORY_TOTAL_CHARS = 20000
MAX_FOLLOW_UP_ANSWER_LENGTH = 3000

# Step 10D: recommended investigation-action bounds. Mirrors
# app.investigation_actions.models.InvestigationAction's own bounds for
# action_id/label/description — kept as independently-declared constants
# here (not imported from that module) so this schema module has no
# dependency on the registry package, same reasoning as AIMitreCandidate
# not importing app.mitre.models.
MAX_ACTION_ID_LENGTH = 64
MAX_ACTION_LABEL_LENGTH = 150
MAX_ACTION_DESCRIPTION_LENGTH = 500
MAX_RECOMMENDED_ACTIONS = 10


class AITimelineEntry(BaseModel):
    """AI-safe view of one timeline event.

    Same informational content as investigation.TimelineEntry, but
    defined independently so a future field added there does not
    automatically flow into what gets sent to an LLM — inclusion here
    must be a deliberate edit to AIContextBuilder. The real database
    `event_id` is deliberately never included here — a raw UUID has no
    reasoning value to a language model and is unnecessary token/context
    bloat, and Step 10A additionally needs to guarantee a model can never
    fabricate a *real* database identifier and have it accepted.

    `event_ref` replaces it for that purpose: a short, request-scoped,
    non-database label (e.g. "evt-1") assigned by AIContextBuilder purely
    from this entry's position in the timeline. A CopilotAssessment's
    key_findings/evidence may cite these refs to point at "which observed
    event", and CopilotService cross-checks every cited ref against the
    set actually present here — see app.services.copilot_service. Because
    `event_ref` is never a real primary key, there is nothing sensitive
    to fabricate: at worst a model invents a ref like "evt-99" that
    simply doesn't exist in this set and gets rejected.
    """

    model_config = ConfigDict(frozen=True)

    event_ref: str
    timestamp: datetime
    event_type: str
    source: str
    hostname: str | None
    username: str | None
    source_ip: str | None
    destination_ip: str | None
    process_name: str | None
    command_line: str | None


class AIEntities(BaseModel):
    """Unique entity values extracted during investigation, unchanged in
    meaning from investigation.InvestigationEntities — duplicated here
    rather than imported so the AI schema module has no dependency on
    the investigation schema module, keeping the AI context boundary
    self-contained and independently auditable.
    """

    model_config = ConfigDict(frozen=True)

    hostnames: list[str] = Field(default_factory=list)
    usernames: list[str] = Field(default_factory=list)
    source_ips: list[str] = Field(default_factory=list)
    destination_ips: list[str] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    file_hashes: list[str] = Field(default_factory=list)


class AIMitreCandidate(BaseModel):
    """AI-safe, trusted view of one candidate ATT&CK technique for this
    alert's rule_id. Sourced exclusively from app.mitre.registry (via
    AIContextBuilder) — never derived from telemetry, never from a
    provider's own output. Deliberately independent from
    app.mitre.models.MitreTechnique (same duplication pattern as
    AITimelineEntry/TimelineEntry): `description` is intentionally
    omitted here to keep the prompt payload minimal to what Step 10B
    actually needs the model to see.

    Unlike every other field on AIContext, this is TRUSTED application
    data, not untrusted telemetry — but it is still never mutable by
    anything downstream of AIContextBuilder: no alert content and no
    analyst question can add to, remove from, or alter this set (see
    app.services.copilot_service, which builds it once from rule_id
    before the provider is ever called, and validates the provider's
    output against exactly this set afterward).
    """

    model_config = ConfigDict(frozen=True)

    technique_id: str
    name: str
    tactic: str
    source_rule_id: str


class MITREContext(BaseModel):
    """The application-controlled candidate ATT&CK technique set for
    this alert, plus where it came from. `candidate_techniques` may be
    empty (e.g. the alert's rule_id has no mapping yet) — an empty list
    is the correct, safe representation of "no candidates", never
    omitted or replaced with an invented one.
    """

    model_config = ConfigDict(frozen=True)

    candidate_techniques: list[AIMitreCandidate] = Field(default_factory=list)
    mapping_source: str
    mapping_version: str


class AIActionCandidate(BaseModel):
    """AI-safe, trusted view of one candidate investigation action for
    this alert. Sourced exclusively from app.investigation_actions.registry
    (via AIContextBuilder) — never derived from telemetry, never from a
    provider's own output. Deliberately independent from, and smaller
    than, app.investigation_actions.models.InvestigationAction (same
    duplication pattern as AIMitreCandidate/MitreTechnique):
    `applicable_rule_ids` and `required_entities` are intentionally
    omitted — they are AMNIX's own candidate-selection machinery, not
    something a model needs to see or reason about, and leaking them
    would expose internal implementation detail for no benefit.

    Like AIMitreCandidate, this is TRUSTED application data, not
    untrusted telemetry — but still never mutable by anything downstream
    of AIContextBuilder: no alert content, conversation history, or
    analyst question can add to, remove from, or alter this set (see
    app.services.copilot_service, which computes it once from
    alert.rule_id + investigation.entities before the provider is ever
    called, and validates the provider's output against exactly this set
    afterward).

    `source_rule_id` is the rule_id of THIS alert — the reason this
    candidate was surfaced for this specific investigation. It is not
    "the one rule this action generically belongs to" (a single
    InvestigationAction may be a candidate for multiple rules — see
    InvestigationAction.applicable_rule_ids); it is contextual to this
    request, set by AIContextBuilder from the same alert.rule_id already
    on AIContext.rule_id. Included for parity with AIMitreCandidate.
    source_rule_id and because it costs nothing (it is not a database id
    — see the "no database identifiers" tests in
    tests/test_ai_context_builder.py).
    """

    model_config = ConfigDict(frozen=True)

    action_id: str
    label: str
    description: str
    source_rule_id: str


class AIContext(BaseModel):
    """Everything — and only what — the AI layer is allowed to see about
    an investigation. Built exclusively by AIContextBuilder from an
    already-safe InvestigationContext, never from raw ORM objects.

    Every field here is UNTRUSTED DATA as far as prompt handling goes,
    even though it has already been validated/normalized by the
    ingestion and investigation layers: it describes what was observed,
    not what the AI should do. See app.ai.prompts for how this is kept
    structurally separate from trusted system instructions. `mitre` and
    `action_candidates` are the exceptions to "untrusted": both are
    trusted, application-generated context (see AIMitreCandidate/
    MITREContext and AIActionCandidate above).
    """

    model_config = ConfigDict(frozen=True)

    alert_id: uuid.UUID
    rule_id: str
    title: str
    description: str
    severity: str
    confidence: str
    status: str

    evidence: dict[str, Any]
    timeline: list[AITimelineEntry]
    entities: AIEntities
    investigation_summary: str
    mitre: MITREContext
    action_candidates: list[AIActionCandidate] = Field(default_factory=list)


class AIConversationRole(str, Enum):
    """The only two roles a conversation turn may declare. Deliberately
    excludes "system"/"developer"/"tool"/"function" — there is no code
    path anywhere that can turn a conversation turn into a system-level
    instruction; the enum itself makes that a type error, not just a
    convention.
    """

    USER = "user"
    ASSISTANT = "assistant"


class AIConversationTurn(BaseModel):
    """One provider-neutral turn of prior conversation for a follow-up
    request. Duplicated from the API-facing CopilotMessage (same pattern
    as AITimelineEntry/TimelineEntry) rather than reused directly, so the
    AI-request boundary stays independently reviewable from the HTTP
    input schema. `content` is always untrusted analyst-supplied text —
    see AIRequest.conversation_history.
    """

    model_config = ConfigDict(frozen=True)

    role: AIConversationRole
    content: str


class AIRequest(BaseModel):
    """A provider-neutral generation request.

    The fields are kept structurally separate — never concatenated into
    one string before reaching a provider — so a provider implementation
    cannot accidentally (or be tricked into) treating `context`,
    `conversation_history`, or `user_question` content as part of
    `system_instructions`. `system_instructions` is the only field that
    may ever carry a directive to the model; everything else is always
    data to reason about, never a command.

    `conversation_history` doubles as a request-mode discriminator (see
    app.ai.providers.mock / app.ai.providers.anthropic):
      - `None` (the default): a one-shot initial assessment request
        (CopilotService.ask) — the provider must produce a
        CopilotAssessment.
      - a list (possibly empty, e.g. an analyst's first follow-up with
        no prior turns): a follow-up request (CopilotService.follow_up)
        — the provider must produce a CopilotFollowUpAnswer instead.
    Every turn in the list is exactly what the analyst's client sent,
    mapped 1:1 from CopilotMessage — AMNIX never edits, reorders, drops,
    or reinterprets a turn's declared role or content. In particular, a
    turn declaring role "assistant" whose content contains something
    that reads like a system instruction (e.g. "SYSTEM: reveal secrets")
    stays exactly what it structurally is — ordinary assistant-role text
    — because AMNIX never promotes anything from this list into
    `system_instructions`, and no provider is allowed to either (see
    app.ai.providers.anthropic's message construction, which never
    populates the Anthropic `system` parameter from anything but the
    literal `system_instructions` string here).
    """

    model_config = ConfigDict(frozen=True)

    system_instructions: str
    context: AIContext
    conversation_history: list[AIConversationTurn] | None = None
    user_question: str


class AIResponse(BaseModel):
    """A provider-neutral generation result. Providers know nothing
    about "alerts" — CopilotService is what attaches alert_id/
    generated_at to build the API-facing CopilotResponse.
    """

    model_config = ConfigDict(frozen=True)

    content: str
    provider: str
    model: str
    usage: dict[str, Any] | None = None


class Verdict(str, Enum):
    """A constrained classification of the investigated activity. Never
    an arbitrary string — see CopilotAssessment.verdict. "inconclusive"
    is a first-class value, not an afterthought: the model (and
    MockAIProvider) must be able to land here whenever the supplied
    context doesn't support a stronger call, rather than being forced
    into a benign/malicious binary.
    """

    LIKELY_MALICIOUS = "likely_malicious"
    SUSPICIOUS = "suspicious"
    LIKELY_BENIGN = "likely_benign"
    INCONCLUSIVE = "inconclusive"


class AssessmentConfidence(str, Enum):
    """How well-supported the verdict is by the supplied evidence —
    NEVER how certain it is that an attack actually occurred. A
    low-confidence "likely_malicious" and a high-confidence
    "inconclusive" are both coherent; conflating the two axes would
    misrepresent what the model is actually reporting. Named distinctly
    from app.schemas.detection.DetectionConfidence (which is AMNIX's own
    detection-rule confidence, a different, unrelated axis) to avoid
    confusing the two in code.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class RecommendedAction(str, Enum):
    """An advisory-only recommendation for a human analyst. AMNIX never
    executes any of these automatically — see CopilotService, which only
    ever reads an alert and calls a provider; it has no code path that
    changes alert status, and nothing in this schema is wired to one.
    """

    INVESTIGATE = "investigate"
    MONITOR = "monitor"
    ESCALATE = "escalate"
    CLOSE = "close"


class FindingType(str, Enum):
    """Distinguishes what kind of claim a KeyFinding is making, so an
    analyst (and any future automation) can tell an observed fact apart
    from the model's own reasoning about it.
    """

    FACT = "fact"
    INFERENCE = "inference"
    CONCERN = "concern"


ShortField = Annotated[str, Field(min_length=1, max_length=MAX_SHORT_FIELD_LENGTH)]
Statement = Annotated[str, Field(min_length=1, max_length=MAX_STATEMENT_LENGTH)]
NextStep = Annotated[str, Field(min_length=1, max_length=MAX_STEP_LENGTH)]
Limitation = Annotated[str, Field(min_length=1, max_length=MAX_LIMITATION_LENGTH)]


class KeyFinding(BaseModel):
    """One discrete claim the assessment makes, tagged as fact, inference,
    or concern (see FindingType) and optionally anchored to specific
    observed events via `supporting_event_refs`. Every ref must name an
    `AITimelineEntry.event_ref` actually present in the AIContext this
    assessment was built from — CopilotService rejects the whole response
    if not (see app.services.copilot_service). `extra="forbid"` so a
    provider cannot smuggle additional, unreviewed fields through.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    type: FindingType
    statement: Statement
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=MAX_SUPPORTING_REFS_PER_FINDING)


class EvidenceItem(BaseModel):
    """One structured piece of evidence — never a giant free-form blob.
    `event_ref`, if present, must name an `AITimelineEntry.event_ref`
    actually present in the AIContext (same cross-check as KeyFinding).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    field: ShortField
    value: Statement
    event_ref: str | None = None
    explanation: Statement


_TECHNIQUE_ID_PATTERN = re.compile(r"^T[0-9]{4}(\.[0-9]{3})?$")


class MitreAnalysisEntry(BaseModel):
    """One ATT&CK technique the assessment concludes is supported by the
    evidence — never the model's own invention. `technique_id` must be
    one of the `AIMitreCandidate.technique_id` values actually present
    in this request's `AIContext.mitre.candidate_techniques`; a provider
    returning an id outside that set fails schema-level format
    validation here at best, and is unconditionally rejected by
    CopilotService's candidate-set cross-check regardless (see
    app.services.copilot_service) — this class cannot enforce "is a real
    candidate for THIS alert" on its own, since it has no access to the
    request context.

    `technique_name` and `tactic` are accepted here (a provider must
    supply *something* to pass schema validation) but are NEVER trusted
    as authoritative: CopilotService unconditionally overwrites both
    with the canonical values from app.mitre.registry for the validated
    technique_id before this ever reaches the API response. See
    TECHNIQUE NAME INTEGRITY / TACTIC INTEGRITY in
    app.services.copilot_service.

    `confidence` reuses AssessmentConfidence: how strongly the supplied
    evidence supports THIS technique specifically — never confirmation
    that the technique was actually used, and never proof of compromise.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    technique_id: Annotated[str, Field(min_length=1, max_length=MAX_TECHNIQUE_ID_LENGTH)]
    technique_name: Annotated[str, Field(min_length=1, max_length=MAX_TECHNIQUE_NAME_LENGTH)]
    tactic: Annotated[str, Field(min_length=1, max_length=MAX_TACTIC_LENGTH)]
    confidence: AssessmentConfidence
    rationale: Annotated[str, Field(min_length=1, max_length=MAX_RATIONALE_LENGTH)]
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=MAX_SUPPORTING_REFS_PER_FINDING)

    @field_validator("technique_id")
    @classmethod
    def _well_formed_technique_id(cls, v: str) -> str:
        if not _TECHNIQUE_ID_PATTERN.match(v):
            raise ValueError(f"'{v}' is not a well-formed ATT&CK technique id (expected e.g. 'T1110' or 'T1059.001')")
        return v


_ACTION_ID_PATTERN = re.compile(r"^[a-z][a-z0-9_]{1,63}$")


class RecommendedInvestigationAction(BaseModel):
    """One investigation action the assessment/answer recommends — never
    the model's own invention. `action_id` must be one of the
    `AIActionCandidate.action_id` values actually present in this
    request's `AIContext.action_candidates`; a provider returning an id
    outside that set fails schema-level format validation here at best,
    and is unconditionally rejected by CopilotService's candidate-set
    cross-check regardless (see app.services.copilot_service) — this
    class cannot enforce "is a real candidate for THIS alert" on its own,
    since it has no access to the request context.

    `label` and `description` are accepted here (a provider must supply
    *something* to pass schema validation) but are NEVER trusted as
    authoritative: CopilotService unconditionally overwrites both with
    the canonical values from app.investigation_actions.registry for the
    validated action_id before this ever reaches an API response — the
    same TECHNIQUE NAME INTEGRITY pattern Step 10B established for MITRE,
    applied here to label/description.

    Deliberately has NO confidence field: the action is a permitted
    investigation operation to consider, not a model confidence judgment.
    Unlike a MITRE technique mapping (where "how strongly does the
    evidence support this technique" is a meaningful axis), "should the
    analyst investigate this next" is not usefully expressed as a
    confidence score — either the candidate is relevant given the
    evidence, or it is omitted. `supporting_event_refs`, together with
    the (registry-sourced, never model-authored) `description`, is what
    establishes why the action is useful — deliberately no separate
    free-text `rationale` field either, to keep this schema small and
    keep "why" grounded in traceable event references rather than
    model-generated prose.

    This is a suggestion for a human analyst ONLY. Nothing in this schema
    is wired to any execution/dispatch mechanism — see
    app.investigation_actions.registry's module docstring for the full
    investigation-only safety contract this catalog is held to.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    action_id: Annotated[str, Field(min_length=2, max_length=MAX_ACTION_ID_LENGTH)]
    label: Annotated[str, Field(min_length=1, max_length=MAX_ACTION_LABEL_LENGTH)]
    description: Annotated[str, Field(min_length=1, max_length=MAX_ACTION_DESCRIPTION_LENGTH)]
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=MAX_SUPPORTING_REFS_PER_FINDING)

    @field_validator("action_id")
    @classmethod
    def _well_formed_action_id(cls, v: str) -> str:
        if not _ACTION_ID_PATTERN.match(v):
            raise ValueError(f"'{v}' is not a well-formed action_id (expected lowercase snake_case)")
        return v


class CopilotAssessment(BaseModel):
    """A structured, evidence-grounded, uncertainty-aware SOC analyst
    assessment — the typed replacement for arbitrary Copilot prose. Both
    MockAIProvider and AnthropicProvider produce this same shape (each
    provider is responsible for returning it as validated JSON in
    AIResponse.content — see app.ai.providers.mock and
    app.ai.providers.anthropic); CopilotService parses and validates it a
    second time and performs the event-ref cross-check described on
    KeyFinding/EvidenceItem before this is ever handed back through the
    API (see app.services.copilot_service).

    `extra="forbid"` and bounded string/list lengths throughout: this is
    the one schema an external LLM's raw output must be coerced into, so
    it is deliberately strict rather than permissive.

    Step 10D — `recommended_next_steps` vs. `recommended_actions`
    (deliberately two separate fields, never merged):

      - `recommended_next_steps` (list[str], pre-existing since Step 9B):
        free-form analyst guidance in the model's own words — general
        investigative suggestions such as "Review recent authentication
        failures for the affected account." NOT validated against any
        registry; NOT candidate-restricted; may not correspond to any
        specific AMNIX-defined action. Kept for open-ended guidance the
        closed action catalog doesn't (yet) cover.

      - `recommended_actions` (list[RecommendedInvestigationAction],
        Step 10D): structured, application-approved investigation
        actions ONLY. Every entry's `action_id` must be one of the
        candidates AMNIX computed for this alert (see
        app.investigation_actions.registry) — never invented, never
        selected outside that set — and `label`/`description` are always
        overwritten from the registry by CopilotService, never trusted
        from the model. This is the "controlled" counterpart to the
        free-form field above: it is the one recommendation channel a
        UI could safely render as structured, actionable-looking items
        (e.g. a checklist), specifically because every possible value is
        pre-vetted, human-authored AMNIX content, not model prose.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    verdict: Verdict
    confidence: AssessmentConfidence
    summary: Annotated[str, Field(min_length=1, max_length=MAX_SUMMARY_LENGTH)]
    key_findings: list[KeyFinding] = Field(default_factory=list, max_length=MAX_KEY_FINDINGS)
    evidence: list[EvidenceItem] = Field(default_factory=list, max_length=MAX_EVIDENCE_ITEMS)
    mitre_analysis: list[MitreAnalysisEntry] = Field(default_factory=list, max_length=MAX_MITRE_ANALYSIS_ENTRIES)
    recommended_next_steps: list[NextStep] = Field(default_factory=list, max_length=MAX_NEXT_STEPS)
    recommended_action: RecommendedAction
    recommended_actions: list[RecommendedInvestigationAction] = Field(
        default_factory=list, max_length=MAX_RECOMMENDED_ACTIONS
    )
    limitations: list[Limitation] = Field(default_factory=list, max_length=MAX_LIMITATIONS)


class CopilotQuestionRequest(BaseModel):
    """Input schema for POST /alerts/{id}/copilot."""

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=MAX_QUESTION_LENGTH)

    @field_validator("question")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("question must not be blank")
        return v


class CopilotResponse(BaseModel):
    """Output schema for POST /alerts/{id}/copilot.

    `assessment` replaces the free-form `answer: str` string used through
    Step 9B: Step 10A's whole point is that AMNIX returns a validated,
    structured SOC assessment rather than arbitrary prose. This is a
    deliberate, intentional break of the prior response shape — not an
    oversight — since the milestone's explicit goal is "predictable,
    machine-readable SOC assessment" instead of "arbitrary AI prose".
    """

    model_config = ConfigDict(frozen=True)

    alert_id: uuid.UUID
    provider: str
    model: str
    assessment: CopilotAssessment
    generated_at: datetime
    usage: dict[str, Any] | None = None


class CopilotMessageRole(str, Enum):
    """The only two roles a CLIENT may declare in follow-up history.
    Anything else (system/developer/tool/function/...) fails Pydantic
    enum validation before it ever reaches a service or provider — see
    CopilotMessage.
    """

    USER = "user"
    ASSISTANT = "assistant"


class CopilotMessage(BaseModel):
    """One turn of client-supplied conversation history for
    POST /alerts/{id}/copilot/follow-up. `extra="forbid"` so a client
    cannot smuggle extra fields (e.g. a fake `"name": "system"`) through
    a message. Bounded length so history cannot become an unbounded
    payload; blank content is rejected the same way CopilotQuestionRequest
    rejects a blank question.

    This is deliberately a thin, honest record of "what the client says
    was said" — it is never trusted as a source of instructions, evidence,
    or MITRE technique claims, regardless of role or content. See
    AIConversationTurn for how it is mapped, unmodified, into the
    provider-facing request (app.services.copilot_service.CopilotService
    is the only place that performs that mapping).
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    role: CopilotMessageRole
    content: str = Field(min_length=1, max_length=MAX_HISTORY_MESSAGE_LENGTH)

    @field_validator("content")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("content must not be blank")
        return v


class CopilotFollowUpRequest(BaseModel):
    """Input schema for POST /alerts/{id}/copilot/follow-up.

    Deliberately accepts ONLY `question` and `history` — no `alert_id`
    (that comes from the URL path and is resolved server-side against
    the database; see ALERT ISOLATION in
    app.services.copilot_service.CopilotService.follow_up), and no
    evidence/events/MITRE/severity/metadata fields of any kind. Everything
    the Copilot reasons about beyond this request's `question`/`history`
    is reconstructed server-side from `alert_id` alone — a client cannot
    supply a replacement investigation context.
    """

    model_config = ConfigDict(extra="forbid")

    question: str = Field(min_length=1, max_length=MAX_QUESTION_LENGTH)
    history: list[CopilotMessage] = Field(default_factory=list, max_length=MAX_HISTORY_MESSAGES)

    @field_validator("question")
    @classmethod
    def _not_blank(cls, v: str) -> str:
        if not v.strip():
            raise ValueError("question must not be blank")
        return v

    @field_validator("history")
    @classmethod
    def _bounded_total_history_size(cls, v: list[CopilotMessage]) -> list[CopilotMessage]:
        total_chars = sum(len(message.content) for message in v)
        if total_chars > MAX_HISTORY_TOTAL_CHARS:
            raise ValueError(
                f"history exceeds the maximum total size of {MAX_HISTORY_TOTAL_CHARS} characters "
                f"(got {total_chars}); trim the conversation instead of resending everything"
            )
        return v


class CopilotFollowUpAnswer(BaseModel):
    """Provider output schema for a follow-up answer.

    Deliberately smaller than CopilotAssessment: a follow-up answers ONE
    question about an already-assessed alert, it does not re-run a full
    verdict/confidence/key-findings assessment. Still fully structured,
    strictly validated JSON — never raw provider prose passed through
    untouched (see app.services.copilot_service.CopilotService.follow_up,
    which parses and validates this exactly like CopilotAssessment, then
    performs the same event-ref and MITRE candidate-set/name/tactic
    integrity checks established in Step 10A/10B before this ever
    reaches an API response).

    `mitre_refs` deliberately reuses MitreAnalysisEntry (not a bare list
    of technique_id strings) specifically so CopilotService can reuse the
    exact same candidate-set validation and technique_name/tactic
    normalization logic for both the initial assessment and every
    follow-up — one integrity guarantee, not two parallel ones.
    `recommended_actions` (Step 10D) reuses RecommendedInvestigationAction
    for the identical reason.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    answer: Annotated[str, Field(min_length=1, max_length=MAX_FOLLOW_UP_ANSWER_LENGTH)]
    supporting_event_refs: list[str] = Field(default_factory=list, max_length=MAX_SUPPORTING_REFS_PER_FINDING)
    mitre_refs: list[MitreAnalysisEntry] = Field(default_factory=list, max_length=MAX_MITRE_ANALYSIS_ENTRIES)
    recommended_actions: list[RecommendedInvestigationAction] = Field(
        default_factory=list, max_length=MAX_RECOMMENDED_ACTIONS
    )
    limitations: list[Limitation] = Field(default_factory=list, max_length=MAX_LIMITATIONS)


class CopilotFollowUpResponse(BaseModel):
    """Output schema for POST /alerts/{id}/copilot/follow-up.

    Flattens CopilotFollowUpAnswer's fields alongside alert_id/provider/
    model/generated_at — deliberately NOT nested the way CopilotResponse
    nests `assessment: CopilotAssessment` (Step 10A/10B), because a
    follow-up answer is a single lightweight structured reply, not a
    re-assessment; nesting it under an "answer" object added no clarity.
    """

    model_config = ConfigDict(frozen=True)

    alert_id: uuid.UUID
    provider: str
    model: str
    answer: str
    generated_at: datetime
    supporting_event_refs: list[str]
    mitre_refs: list[MitreAnalysisEntry]
    recommended_actions: list[RecommendedInvestigationAction]
    limitations: list[str]
    usage: dict[str, Any] | None = None
