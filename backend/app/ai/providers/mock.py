"""Deterministic, offline AI provider.

Makes no network calls, needs no API key or credentials of any kind, and
never claims to be a real model. Exists so the Copilot pipeline
(CopilotService -> AIContextBuilder -> AIProvider) can be built, wired
into the API, and tested end to end before any real LLM integration
exists.

Step 10A: this now returns a deterministic, valid CopilotAssessment
(serialized as JSON in AIResponse.content, exactly like AnthropicProvider
does — see app.ai.providers.anthropic) instead of free-form prose. It is
still emphatically NOT a fake LLM: every field is derived by simple,
inspectable rules from AIContext's own already-validated data (the
alert's own severity/confidence, its evidence dict, its timeline) —
never by interpreting the free-text CONTENT of any telemetry string. It
therefore cannot be prompt-injected: it never looks for words like
"ignore" or "instructions" anywhere, so there is no free-text channel
for adversarial telemetry to influence its behavior through.

Security note: this provider never inspects `request.context` or
`request.user_question` for anything resembling instructions — it only
reads specific, known structured fields (severity, confidence, evidence,
entity lists, timeline length/refs) to build its canned response.

Step 10B: `mitre_analysis` is built purely from
`context.mitre.candidate_techniques` — the application-supplied,
already-vetted candidate list built by AIContextBuilder from
app.mitre.registry (see app.services.copilot_service). This provider
never invents a technique_id/name/tactic of its own: every
MitreAnalysisEntry it produces copies those three fields verbatim from a
supplied candidate. If no candidates were supplied (e.g. an alert whose
rule_id has no MITRE mapping yet), `mitre_analysis` is simply empty —
never a guess.

Step 10C: `generate()` branches on `request.conversation_history` (see
AIRequest's docstring for why that's the mode discriminator): `None`
means an initial assessment (unchanged from Step 10A/10B); a list means
a follow-up. The follow-up path never interprets conversation history
content either — it only reads its *length* (a structural fact about
the conversation, not its text) to make the deterministic answer
visibly depend on how many prior turns exist, without ever doing
free-text analysis of what was actually said. This keeps the mock
immune to injection through history for exactly the same reason it's
already immune through telemetry: there is no code path that branches
on the CONTENT of untrusted input.

Step 10D: `recommended_actions` is built purely from
`context.action_candidates` — the application-supplied, already-vetted
candidate list built by AIContextBuilder from
app.investigation_actions.registry (see app.services.copilot_service).
Exactly the same discipline as `mitre_analysis`: this provider never
invents an action_id/label/description of its own — every
RecommendedInvestigationAction it produces copies those three fields
verbatim from a supplied candidate. If no candidates were supplied (no
matching rule/entities), `recommended_actions` is simply empty — never
a guess.

Step 13E: `generate_case()` gains the identical Step 10C-style branch on
`request.conversation_history` (see AICaseRequest's own docstring) — a
Case-scoped follow-up never has a focused alert (the follow-up endpoint
accepts no focused_alert_id), so `_build_case_follow_up_answer` never has
any event_refs to offer and always returns an empty
`supporting_event_refs`. Same immunity-to-injection reasoning as
`_build_follow_up_answer`: only conversation *length*, never content, is
read.
"""

from app.ai.provider import AIProvider
from app.schemas.ai import (
    AIActionCandidate,
    AIContext,
    AIMitreCandidate,
    AIRequest,
    AIResponse,
    AssessmentConfidence,
    CopilotAssessment,
    CopilotFollowUpAnswer,
    EvidenceItem,
    FindingType,
    KeyFinding,
    MitreAnalysisEntry,
    RecommendedAction,
    RecommendedInvestigationAction,
    Verdict,
)
from app.schemas.case_ai import (
    AICaseContext,
    AICaseMitreCandidate,
    AICaseRequest,
    CaseEvidenceItem,
    CaseFollowUpAnswer,
    CaseInvestigationBrief,
    CaseKeyFinding,
)

MOCK_MODEL_NAME = "amnix-mock-v1"

# severity -> (verdict, confidence). Deliberately mirrors AMNIX's own
# DetectionSeverity axis rather than inventing new judgment: the mock
# reports what the alert's own deterministic severity already implies,
# it does not "analyze" anything.
_VERDICT_BY_SEVERITY: dict[str, tuple[Verdict, AssessmentConfidence]] = {
    "critical": (Verdict.LIKELY_MALICIOUS, AssessmentConfidence.HIGH),
    "high": (Verdict.SUSPICIOUS, AssessmentConfidence.HIGH),
    "medium": (Verdict.SUSPICIOUS, AssessmentConfidence.MEDIUM),
    "low": (Verdict.LIKELY_BENIGN, AssessmentConfidence.MEDIUM),
}

_ACTION_BY_VERDICT: dict[Verdict, RecommendedAction] = {
    Verdict.LIKELY_MALICIOUS: RecommendedAction.ESCALATE,
    Verdict.SUSPICIOUS: RecommendedAction.INVESTIGATE,
    Verdict.LIKELY_BENIGN: RecommendedAction.MONITOR,
    Verdict.INCONCLUSIVE: RecommendedAction.INVESTIGATE,
}

_MAX_EVIDENCE_FROM_ALERT_DICT = 5
_MAX_SUPPORTING_REFS = 5


class MockAIProvider(AIProvider):
    @property
    def name(self) -> str:
        return "mock"

    def generate(self, request: AIRequest) -> AIResponse:
        if request.conversation_history is None:
            payload = self._build_assessment(request.context)
        else:
            payload = self._build_follow_up_answer(request)
        return AIResponse(
            content=payload.model_dump_json(),
            provider=self.name,
            model=MOCK_MODEL_NAME,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )

    def generate_case(self, request: AICaseRequest) -> AIResponse:
        """Step 13D: deterministic Case brief, same discipline as
        generate() above — every field derived by simple, inspectable
        rules from AICaseContext's own already-bounded, already-validated
        data (case status/priority, each alert's own severity/status,
        note/audit counts, the optional focused alert's timeline) — never
        by interpreting the free-text CONTENT of any note, audit value,
        or the analyst's question. Immune to prompt injection for the
        same reason the alert-scoped mock is: no code path here branches
        on untrusted text content.

        Step 13E: branches on `request.conversation_history` exactly like
        generate() does for the alert-scoped pipeline (see AICaseRequest's
        own docstring for the None-vs-list mode discriminator) — `None`
        means the initial brief (unchanged from Step 13D); a list means a
        Case-scoped follow-up. The follow-up path never interprets
        conversation history content either — it only reads its *length*
        (a structural fact, not its text) to make the deterministic
        answer visibly depend on how many prior turns exist, exactly
        mirroring _build_follow_up_answer's own discipline.
        """
        if request.conversation_history is None:
            payload: CaseInvestigationBrief | CaseFollowUpAnswer = self._build_case_brief(request.context)
        else:
            payload = self._build_case_follow_up_answer(request)
        return AIResponse(
            content=payload.model_dump_json(),
            provider=self.name,
            model=MOCK_MODEL_NAME,
            usage={"input_tokens": 0, "output_tokens": 0, "total_tokens": 0},
        )

    @staticmethod
    def _verdict_and_confidence(context: AIContext) -> tuple[Verdict, AssessmentConfidence]:
        verdict, confidence = _VERDICT_BY_SEVERITY.get(
            context.severity, (Verdict.INCONCLUSIVE, AssessmentConfidence.LOW)
        )
        # DetectionConfidence "low" on the alert itself always weakens the
        # mock's own stated confidence, regardless of severity — a
        # low-confidence detection cannot justify a high-confidence
        # assessment of it.
        if context.confidence == "low" and confidence == AssessmentConfidence.HIGH:
            confidence = AssessmentConfidence.MEDIUM
        return verdict, confidence

    def _build_assessment(self, context: AIContext) -> CopilotAssessment:
        verdict, confidence = self._verdict_and_confidence(context)
        all_refs = [entry.event_ref for entry in context.timeline]

        return CopilotAssessment(
            verdict=verdict,
            confidence=confidence,
            summary=self._build_summary(context, verdict),
            key_findings=self._build_key_findings(context, verdict, all_refs),
            evidence=self._build_evidence(context),
            mitre_analysis=self._build_mitre_analysis(context, confidence, all_refs),
            recommended_actions=self._build_recommended_actions(context, all_refs),
            recommended_next_steps=self._build_next_steps(context),
            recommended_action=_ACTION_BY_VERDICT[verdict],
            limitations=self._build_limitations(context),
        )

    def _build_follow_up_answer(self, request: AIRequest) -> CopilotFollowUpAnswer:
        context = request.context
        history = request.conversation_history or []
        _, confidence = self._verdict_and_confidence(context)
        all_refs = [entry.event_ref for entry in context.timeline]

        return CopilotFollowUpAnswer(
            answer=self._build_follow_up_text(context, request.user_question, len(history)),
            supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
            mitre_refs=self._build_mitre_analysis(context, confidence, all_refs),
            recommended_actions=self._build_recommended_actions(context, all_refs),
            limitations=self._build_limitations(context),
        )

    @staticmethod
    def _build_follow_up_text(context: AIContext, question: str, history_length: int) -> str:
        # Fixed template + bounded excerpts of variable-length fields
        # (question/title are each bounded upstream, but only loosely —
        # 2000/500 chars respectively — so this truncates its own quoted
        # excerpts to stay safely under MAX_FOLLOW_UP_ANSWER_LENGTH
        # regardless of how long the untrusted inputs happen to be).
        question_excerpt = question if len(question) <= 300 else f"{question[:300]}…"
        title_excerpt = context.title if len(context.title) <= 150 else f"{context.title[:150]}…"
        return (
            f"[MOCK FOLLOW-UP ANSWER — generated by AMNIX's MockAIProvider, not a real language "
            f"model] Question: {question_excerpt} "
            f"(turn {history_length + 1} of this conversation about alert '{title_excerpt}', rule "
            f"'{context.rule_id}'). FACT: the alert has severity '{context.severity}' and detection "
            f"confidence '{context.confidence}', based on {len(context.timeline)} related security "
            f"event(s). INTERPRETATION: this is a deterministic placeholder answer derived solely "
            f"from the alert's own structured fields and the number of prior conversation turns; it "
            f"does not perform any language-model reasoning over the question or history content. "
            f"LIMITATION: no real conversational reasoning was performed. RECOMMENDATION: review "
            f"the full initial assessment via POST /alerts/{{alert_id}}/copilot for complete findings."
        )

    @staticmethod
    def _build_summary(context: AIContext, verdict: Verdict) -> str:
        return (
            f"[MOCK ASSESSMENT — generated by AMNIX's MockAIProvider, not a real language model] "
            f"Alert '{context.title}' (rule '{context.rule_id}') was raised with severity "
            f"'{context.severity}' and detection confidence '{context.confidence}', based on "
            f"{len(context.timeline)} related security event(s). This deterministic placeholder "
            f"maps that severity/confidence to verdict '{verdict.value}' using a fixed rule table; "
            f"it does not perform any language-model reasoning over the event content."
        )

    @staticmethod
    def _build_key_findings(context: AIContext, verdict: Verdict, all_refs: list[str]) -> list[KeyFinding]:
        findings = [
            KeyFinding(
                type=FindingType.FACT,
                statement=(
                    f"Alert '{context.title}' was raised by rule '{context.rule_id}' with "
                    f"severity '{context.severity}', referencing {len(context.timeline)} "
                    "related security event(s)."
                ),
                supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
            )
        ]
        if context.entities.usernames:
            findings.append(
                KeyFinding(
                    type=FindingType.FACT,
                    statement=f"Affected user(s) observed in related events: {', '.join(context.entities.usernames)}.",
                    supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
                )
            )
        if context.entities.hostnames:
            findings.append(
                KeyFinding(
                    type=FindingType.FACT,
                    statement=f"Affected host(s) observed in related events: {', '.join(context.entities.hostnames)}.",
                    supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
                )
            )
        findings.append(
            KeyFinding(
                type=FindingType.INFERENCE,
                statement=(
                    f"Given detection severity '{context.severity}' and confidence "
                    f"'{context.confidence}', this pattern is consistent with a "
                    f"'{verdict.value}' classification under AMNIX's fixed mock mapping."
                ),
                supporting_event_refs=[],
            )
        )
        return findings

    @staticmethod
    def _build_evidence(context: AIContext) -> list[EvidenceItem]:
        evidence: list[EvidenceItem] = []
        for key, value in list(context.evidence.items())[:_MAX_EVIDENCE_FROM_ALERT_DICT]:
            evidence.append(
                EvidenceItem(
                    field=str(key)[:100],
                    value=str(value)[:500],
                    event_ref=None,
                    explanation="Captured in the alert's own evidence at detection time.",
                )
            )
        if context.timeline:
            first = context.timeline[0]
            if first.source_ip:
                evidence.append(
                    EvidenceItem(
                        field="source_ip",
                        value=first.source_ip,
                        event_ref=first.event_ref,
                        explanation="Source IP observed on the earliest related event.",
                    )
                )
            if first.hostname:
                evidence.append(
                    EvidenceItem(
                        field="hostname",
                        value=first.hostname,
                        event_ref=first.event_ref,
                        explanation="Hostname observed on the earliest related event.",
                    )
                )
        return evidence

    @staticmethod
    def _build_mitre_analysis(
        context: AIContext, confidence: AssessmentConfidence, all_refs: list[str]
    ) -> list[MitreAnalysisEntry]:
        return [
            MockAIProvider._mitre_entry_for(candidate, context.rule_id, confidence, all_refs)
            for candidate in context.mitre.candidate_techniques
        ]

    @staticmethod
    def _mitre_entry_for(
        candidate: AIMitreCandidate, rule_id: str, confidence: AssessmentConfidence, all_refs: list[str]
    ) -> MitreAnalysisEntry:
        return MitreAnalysisEntry(
            # technique_id/technique_name/tactic are copied verbatim from
            # the supplied candidate — never invented.
            technique_id=candidate.technique_id,
            technique_name=candidate.name,
            tactic=candidate.tactic,
            confidence=confidence,
            rationale=(
                f"FACT: this alert was generated by AMNIX detection rule '{rule_id}'. "
                f"MAPPING: rule '{rule_id}' maps to ATT&CK technique {candidate.technique_id} "
                f"('{candidate.name}') under AMNIX's application-controlled mapping. "
                f"INTERPRETATION: the observed activity is consistent with the "
                f"{candidate.technique_id} technique pattern; this describes behavioral "
                "alignment only, not confirmed compromise."
            ),
            supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
        )

    @staticmethod
    def _build_recommended_actions(context: AIContext, all_refs: list[str]) -> list[RecommendedInvestigationAction]:
        return [MockAIProvider._action_entry_for(candidate, all_refs) for candidate in context.action_candidates]

    @staticmethod
    def _action_entry_for(candidate: AIActionCandidate, all_refs: list[str]) -> RecommendedInvestigationAction:
        return RecommendedInvestigationAction(
            # action_id/label/description are copied verbatim from the
            # supplied candidate — never invented. "Why" this action is
            # relevant is established by supporting_event_refs (real,
            # bounded timeline references) plus the candidate's own
            # registry-authored description — no separate free-text
            # rationale field exists on this schema (see
            # RecommendedInvestigationAction's docstring).
            action_id=candidate.action_id,
            label=candidate.label,
            description=candidate.description,
            supporting_event_refs=all_refs[:_MAX_SUPPORTING_REFS],
        )

    @staticmethod
    def _build_next_steps(context: AIContext) -> list[str]:
        steps: list[str] = []
        if context.entities.usernames:
            steps.append(
                f"Review recent authentication and access activity for {', '.join(context.entities.usernames[:3])}."
            )
        if context.entities.source_ips:
            steps.append(
                f"Check whether source IP {context.entities.source_ips[0]} appears elsewhere in the environment."
            )
        if context.entities.hostnames:
            steps.append(f"Inspect related activity on host {context.entities.hostnames[0]}.")
        steps.append("Confirm whether the observed activity matches expected business activity for this user/host.")
        return steps

    @staticmethod
    def _build_limitations(context: AIContext) -> list[str]:
        limitations = [
            "No IP reputation or threat-intelligence data was supplied to this assessment.",
            "No historical baseline for this user or host was supplied.",
        ]
        if not any(entry.event_type and "success" in entry.event_type.lower() for entry in context.timeline):
            limitations.append("No successful-authentication evidence was supplied in this context.")
        if not context.timeline:
            limitations.append("No related security events were supplied in this context.")
        if not context.mitre.candidate_techniques:
            limitations.append(
                f"No ATT&CK candidate techniques are mapped for rule '{context.rule_id}' in AMNIX's "
                f"current mapping ({context.mitre.mapping_version}), so no MITRE analysis is offered."
            )
        return limitations

    # ------------------------------------------------------------------
    # Step 13D: Case-scoped investigation brief
    # ------------------------------------------------------------------

    def _build_case_brief(self, context: AICaseContext) -> CaseInvestigationBrief:
        alert_refs = [a.alert_ref for a in context.alerts]
        event_refs = [e.event_ref for e in context.focused_alert.timeline] if context.focused_alert else []

        return CaseInvestigationBrief(
            summary=self._build_case_summary(context),
            key_findings=self._build_case_key_findings(context, alert_refs, event_refs),
            supporting_evidence=self._build_case_evidence(context),
            mitre_analysis=self._build_case_mitre_analysis(context, event_refs),
            timeline_summary=self._build_case_timeline_summary(context),
            uncertainties=self._build_case_uncertainties(context),
            recommended_next_steps=self._build_case_next_steps(context),
        )

    @staticmethod
    def _build_case_summary(context: AICaseContext) -> str:
        return (
            f"[MOCK CASE BRIEF — generated by AMNIX's MockAIProvider, not a real language model] "
            f"Case '{context.title}' is currently {context.status} with {context.priority} priority. "
            f"{len(context.alerts)} alert(s) are linked, {len(context.notes)} analyst note(s) and "
            f"{len(context.audit)} audit entr{'y' if len(context.audit) == 1 else 'ies'} have been "
            f"recorded in the supplied context. This deterministic placeholder is derived solely from "
            f"the case's own structured fields; it does not perform any language-model reasoning."
        )

    @staticmethod
    def _build_case_key_findings(
        context: AICaseContext, alert_refs: list[str], event_refs: list[str]
    ) -> list[CaseKeyFinding]:
        findings: list[CaseKeyFinding] = []
        if context.alerts:
            findings.append(
                CaseKeyFinding(
                    type=FindingType.FACT,
                    statement=(
                        f"{len(context.alerts)} alert(s) are linked to this case, referencing rule(s) "
                        + ", ".join(sorted({a.rule_id for a in context.alerts}))
                        + "."
                    ),
                    supporting_alert_refs=alert_refs[:_MAX_SUPPORTING_REFS],
                    supporting_event_refs=[],
                )
            )
        else:
            findings.append(
                CaseKeyFinding(
                    type=FindingType.FACT,
                    statement="No alerts are currently linked to this case.",
                    supporting_alert_refs=[],
                    supporting_event_refs=[],
                )
            )
        if context.focused_alert is not None:
            findings.append(
                CaseKeyFinding(
                    type=FindingType.FACT,
                    statement=(
                        f"Alert '{context.focused_alert.alert_ref}' was explicitly focused, providing "
                        f"{len(context.focused_alert.timeline)} related security event(s) for detailed review."
                    ),
                    supporting_alert_refs=[context.focused_alert.alert_ref] if context.focused_alert.alert_ref in alert_refs else [],
                    supporting_event_refs=event_refs[:_MAX_SUPPORTING_REFS],
                )
            )
        findings.append(
            CaseKeyFinding(
                type=FindingType.INFERENCE,
                statement=(
                    f"Given {len(context.alerts)} linked alert(s) and {len(context.notes)} recorded "
                    "note(s), this case's current documentation level is consistent with its "
                    f"'{context.status}' status under AMNIX's fixed mock mapping."
                ),
                supporting_alert_refs=[],
                supporting_event_refs=[],
            )
        )
        return findings

    @staticmethod
    def _build_case_evidence(context: AICaseContext) -> list[CaseEvidenceItem]:
        evidence: list[CaseEvidenceItem] = []
        for alert in context.alerts[:_MAX_EVIDENCE_FROM_ALERT_DICT]:
            if alert.evidence_keys:
                evidence.append(
                    CaseEvidenceItem(
                        field="evidence_keys",
                        value=", ".join(alert.evidence_keys)[:500],
                        alert_ref=alert.alert_ref,
                        event_ref=None,
                        explanation=f"Structured evidence fields recorded for alert '{alert.alert_ref}' at detection time.",
                    )
                )
        if context.focused_alert and context.focused_alert.timeline:
            first = context.focused_alert.timeline[0]
            if first.hostname:
                evidence.append(
                    CaseEvidenceItem(
                        field="hostname",
                        value=first.hostname,
                        alert_ref=context.focused_alert.alert_ref,
                        event_ref=first.event_ref,
                        explanation="Hostname observed on the earliest event of the focused alert.",
                    )
                )
        return evidence

    @staticmethod
    def _build_case_mitre_analysis(context: AICaseContext, event_refs: list[str]) -> list[MitreAnalysisEntry]:
        return [
            MockAIProvider._case_mitre_entry_for(candidate, event_refs) for candidate in context.mitre_candidates
        ]

    @staticmethod
    def _case_mitre_entry_for(candidate: AICaseMitreCandidate, event_refs: list[str]) -> MitreAnalysisEntry:
        return MitreAnalysisEntry(
            # technique_id/technique_name/tactic are copied verbatim from
            # the supplied candidate — never invented.
            technique_id=candidate.technique_id,
            technique_name=candidate.name,
            tactic=candidate.tactic,
            confidence=AssessmentConfidence.LOW,
            rationale=(
                f"FACT: this case includes an alert generated by AMNIX detection rule "
                f"'{candidate.source_rule_id}'. MAPPING: rule '{candidate.source_rule_id}' maps to "
                f"ATT&CK technique {candidate.technique_id} ('{candidate.name}') under AMNIX's "
                f"application-controlled mapping. INTERPRETATION: this describes behavioral alignment "
                "only, not confirmed compromise, and reflects a case-wide candidate, not a per-event "
                "confirmation."
            ),
            supporting_event_refs=event_refs[:_MAX_SUPPORTING_REFS],
        )

    @staticmethod
    def _build_case_timeline_summary(context: AICaseContext) -> str:
        if context.focused_alert is not None and context.focused_alert.timeline:
            return (
                f"Focused alert '{context.focused_alert.alert_ref}' contributes "
                f"{len(context.focused_alert.timeline)} observed security event(s) to this case's "
                "telemetry. No other linked alert's per-event timeline was supplied in this context."
            )
        if context.alerts:
            return (
                f"This case has {len(context.alerts)} linked alert(s); no alert was explicitly "
                "focused for this request, so no per-event telemetry timeline is available in this "
                "context — only each alert's own summary fields."
            )
        return "No alerts are linked to this case, so no telemetry timeline is available."

    @staticmethod
    def _build_case_uncertainties(context: AICaseContext) -> list[str]:
        uncertainties = [
            "No IP reputation or threat-intelligence data was supplied to this brief.",
        ]
        if context.focused_alert is None:
            uncertainties.append(
                "No alert was explicitly focused, so no per-event telemetry timeline was available "
                "for this brief -- only bounded per-alert summaries."
            )
        if not context.notes:
            uncertainties.append("No analyst notes have been recorded for this case.")
        if not context.mitre_candidates:
            uncertainties.append("No ATT&CK candidate techniques are mapped for this case's linked alert rule(s).")
        return uncertainties

    @staticmethod
    def _build_case_next_steps(context: AICaseContext) -> list[str]:
        steps: list[str] = []
        if not context.alerts:
            steps.append("Link relevant alerts to this case to begin building an evidence trail.")
        if context.focused_alert is None and context.alerts:
            steps.append("Select an alert to focus for a detailed telemetry review.")
        if not context.notes:
            steps.append("Record an analyst note documenting the current investigation state.")
        steps.append("Review each linked alert's own evidence and investigation timeline individually.")
        return steps

    # ------------------------------------------------------------------
    # Step 13E: Case-scoped follow-up
    # ------------------------------------------------------------------

    def _build_case_follow_up_answer(self, request: AICaseRequest) -> CaseFollowUpAnswer:
        context = request.context
        history = request.conversation_history or []
        # Step 13E Phase 2: a Case-scoped follow-up never receives a
        # focused alert (CaseCopilotService.ask_case_follow_up accepts no
        # focused_alert_id) -- context.focused_alert is therefore always
        # None here, so there are never any event_refs to offer.
        alert_refs = [a.alert_ref for a in context.alerts]

        return CaseFollowUpAnswer(
            answer=self._build_case_follow_up_text(context, request.user_question, len(history)),
            supporting_alert_refs=alert_refs[:_MAX_SUPPORTING_REFS],
            supporting_event_refs=[],
            mitre_analysis=self._build_case_mitre_analysis(context, []),
            uncertainties=self._build_case_uncertainties(context),
            recommended_next_steps=self._build_case_next_steps(context),
        )

    @staticmethod
    def _build_case_follow_up_text(context: AICaseContext, question: str, history_length: int) -> str:
        # Fixed template + bounded excerpts of variable-length fields,
        # mirroring _build_follow_up_text's own truncation discipline so
        # this always stays safely under MAX_CASE_FOLLOW_UP_ANSWER_LENGTH
        # regardless of how long the untrusted inputs happen to be.
        question_excerpt = question if len(question) <= 300 else f"{question[:300]}…"
        title_excerpt = context.title if len(context.title) <= 150 else f"{context.title[:150]}…"
        return (
            f"[MOCK CASE FOLLOW-UP ANSWER — generated by AMNIX's MockAIProvider, not a real "
            f"language model] Question: {question_excerpt} (turn {history_length + 1} of this "
            f"conversation about case '{title_excerpt}', status '{context.status}', priority "
            f"'{context.priority}'). FACT: {len(context.alerts)} alert(s) are linked and "
            f"{len(context.notes)} analyst note(s) have been recorded. INTERPRETATION: this is a "
            f"deterministic placeholder answer derived solely from the case's own structured fields "
            f"and the number of prior conversation turns; it does not perform any language-model "
            f"reasoning over the question or history content. LIMITATION: no real conversational "
            f"reasoning was performed, and no focused alert's telemetry is available in a follow-up "
            f"request. RECOMMENDATION: review the full investigation brief via "
            f"POST /cases/{{case_id}}/copilot for complete findings."
        )
