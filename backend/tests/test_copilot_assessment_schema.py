"""Unit tests for the CopilotAssessment schema family (Verdict,
AssessmentConfidence, RecommendedAction, FindingType, KeyFinding,
EvidenceItem, CopilotAssessment). Pure Pydantic validation — no database,
no provider, no network.
"""

import pytest
from pydantic import ValidationError

from app.schemas.ai import (
    MAX_EVIDENCE_ITEMS,
    MAX_KEY_FINDINGS,
    MAX_LIMITATIONS,
    MAX_NEXT_STEPS,
    MAX_SUMMARY_LENGTH,
    MAX_SUPPORTING_REFS_PER_FINDING,
    AssessmentConfidence,
    CopilotAssessment,
    EvidenceItem,
    FindingType,
    KeyFinding,
    RecommendedAction,
    Verdict,
)


def _valid_kwargs(**overrides) -> dict:
    defaults = dict(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="4 authentication failures for jdoe were observed.",
        key_findings=[KeyFinding(type=FindingType.FACT, statement="4 failures observed.", supporting_event_refs=["evt-1"])],
        evidence=[EvidenceItem(field="failure_count", value="4", event_ref="evt-1", explanation="From the alert.")],
        recommended_next_steps=["Review authentication activity for jdoe."],
        recommended_action=RecommendedAction.INVESTIGATE,
        limitations=["No IP reputation data was supplied."],
    )
    defaults.update(overrides)
    return defaults


# --- 1. valid assessment -----------------------------------------------------


def test_valid_assessment_constructs_successfully():
    assessment = CopilotAssessment(**_valid_kwargs())

    assert assessment.verdict == Verdict.SUSPICIOUS
    assert assessment.confidence == AssessmentConfidence.MEDIUM
    assert assessment.recommended_action == RecommendedAction.INVESTIGATE


def test_verdict_includes_inconclusive_and_does_not_force_a_conclusion():
    assessment = CopilotAssessment(**_valid_kwargs(verdict=Verdict.INCONCLUSIVE))
    assert assessment.verdict == Verdict.INCONCLUSIVE


# --- 2. invalid verdict -------------------------------------------------------


def test_invalid_verdict_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(verdict="definitely_malicious"))


# --- 3. invalid confidence ----------------------------------------------------


def test_invalid_confidence_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(confidence="certain"))


# --- 4. invalid recommended action --------------------------------------------


def test_invalid_recommended_action_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(recommended_action="disable_account"))


def test_recommended_action_never_permits_autonomous_verbs():
    valid_actions = {a.value for a in RecommendedAction}
    assert valid_actions == {"investigate", "monitor", "escalate", "close"}
    for forbidden in ("block_ip", "disable_account", "terminate_process", "delete_file", "execute", "remediate"):
        assert forbidden not in valid_actions


# --- 5. missing required fields -----------------------------------------------


def test_missing_verdict_rejected():
    kwargs = _valid_kwargs()
    del kwargs["verdict"]
    with pytest.raises(ValidationError):
        CopilotAssessment(**kwargs)


def test_missing_summary_rejected():
    kwargs = _valid_kwargs()
    del kwargs["summary"]
    with pytest.raises(ValidationError):
        CopilotAssessment(**kwargs)


def test_missing_recommended_action_rejected():
    kwargs = _valid_kwargs()
    del kwargs["recommended_action"]
    with pytest.raises(ValidationError):
        CopilotAssessment(**kwargs)


# --- 6. unexpected fields (extra="forbid") ------------------------------------


def test_unexpected_top_level_field_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(), extra_hallucinated_field="oops")


def test_unexpected_key_finding_field_rejected():
    with pytest.raises(ValidationError):
        KeyFinding(type=FindingType.FACT, statement="x", supporting_event_refs=[], tool_call="rm -rf /")


def test_unexpected_evidence_field_rejected():
    with pytest.raises(ValidationError):
        EvidenceItem(field="x", value="y", event_ref=None, explanation="z", confidence_score=0.99)


# --- 7. oversized strings ------------------------------------------------------


def test_oversized_summary_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(summary="x" * (MAX_SUMMARY_LENGTH + 1)))


def test_empty_summary_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(summary=""))


def test_oversized_finding_statement_rejected():
    with pytest.raises(ValidationError):
        KeyFinding(type=FindingType.FACT, statement="x" * 501, supporting_event_refs=[])


def test_oversized_evidence_field_name_rejected():
    with pytest.raises(ValidationError):
        EvidenceItem(field="x" * 101, value="y", event_ref=None, explanation="z")


# --- 8. oversized lists ---------------------------------------------------------


def test_too_many_key_findings_rejected():
    findings = [KeyFinding(type=FindingType.FACT, statement="x", supporting_event_refs=[]) for _ in range(MAX_KEY_FINDINGS + 1)]
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(key_findings=findings))


def test_too_many_evidence_items_rejected():
    items = [EvidenceItem(field="x", value="y", event_ref=None, explanation="z") for _ in range(MAX_EVIDENCE_ITEMS + 1)]
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(evidence=items))


def test_too_many_next_steps_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(recommended_next_steps=[f"step {i}" for i in range(MAX_NEXT_STEPS + 1)]))


def test_too_many_limitations_rejected():
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_kwargs(limitations=[f"limitation {i}" for i in range(MAX_LIMITATIONS + 1)]))


def test_too_many_supporting_refs_on_a_single_finding_rejected():
    with pytest.raises(ValidationError):
        KeyFinding(
            type=FindingType.FACT,
            statement="x",
            supporting_event_refs=[f"evt-{i}" for i in range(MAX_SUPPORTING_REFS_PER_FINDING + 1)],
        )


def test_at_bound_list_sizes_are_accepted():
    findings = [KeyFinding(type=FindingType.FACT, statement="x", supporting_event_refs=[]) for _ in range(MAX_KEY_FINDINGS)]
    assessment = CopilotAssessment(**_valid_kwargs(key_findings=findings))
    assert len(assessment.key_findings) == MAX_KEY_FINDINGS


# --- 9. evidence validation ------------------------------------------------------


def test_evidence_event_ref_is_optional():
    item = EvidenceItem(field="source_ip", value="10.0.0.5", event_ref=None, explanation="Observed on the alert.")
    assert item.event_ref is None


def test_evidence_requires_field_value_and_explanation():
    with pytest.raises(ValidationError):
        EvidenceItem(field="", value="10.0.0.5", event_ref=None, explanation="x")
    with pytest.raises(ValidationError):
        EvidenceItem(field="source_ip", value="", event_ref=None, explanation="x")
    with pytest.raises(ValidationError):
        EvidenceItem(field="source_ip", value="10.0.0.5", event_ref=None, explanation="")


def test_finding_type_enum_is_constrained():
    with pytest.raises(ValidationError):
        KeyFinding(type="opinion", statement="x", supporting_event_refs=[])
    assert {t.value for t in FindingType} == {"fact", "inference", "concern"}


# --- Frozen / immutability (security-sensitive schema, defense in depth) -------


def test_assessment_is_frozen():
    assessment = CopilotAssessment(**_valid_kwargs())
    with pytest.raises(ValidationError):
        assessment.verdict = Verdict.LIKELY_BENIGN
