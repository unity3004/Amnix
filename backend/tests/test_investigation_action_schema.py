"""Unit tests for RecommendedInvestigationAction, AIActionCandidate, and
CopilotAssessment/CopilotFollowUpAnswer.recommended_actions. Pure
Pydantic validation — no database, no provider, no network.
"""

import pytest
from pydantic import ValidationError

from app.schemas.ai import (
    MAX_ACTION_DESCRIPTION_LENGTH,
    MAX_ACTION_ID_LENGTH,
    MAX_ACTION_LABEL_LENGTH,
    MAX_RECOMMENDED_ACTIONS,
    MAX_SUPPORTING_REFS_PER_FINDING,
    AIActionCandidate,
    AssessmentConfidence,
    CopilotAssessment,
    CopilotFollowUpAnswer,
    EvidenceItem,
    FindingType,
    KeyFinding,
    RecommendedAction,
    RecommendedInvestigationAction,
    Verdict,
)


def _valid_action_entry(**overrides) -> RecommendedInvestigationAction:
    defaults = dict(
        action_id="review_host_activity",
        label="Review related activity on the affected host",
        description="Review other recent events recorded for this host.",
        supporting_event_refs=["evt-1"],
    )
    defaults.update(overrides)
    return RecommendedInvestigationAction(**defaults)


def _valid_assessment_kwargs(**overrides) -> dict:
    defaults = dict(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="A structured test assessment.",
        key_findings=[KeyFinding(type=FindingType.FACT, statement="x", supporting_event_refs=["evt-1"])],
        evidence=[EvidenceItem(field="x", value="y", event_ref="evt-1", explanation="z")],
        recommended_actions=[_valid_action_entry()],
        recommended_next_steps=["Review the activity."],
        recommended_action=RecommendedAction.INVESTIGATE,
        limitations=["No IP reputation data was supplied."],
    )
    defaults.update(overrides)
    return defaults


# --- valid action ------------------------------------------------------------


def test_valid_action_entry_constructs():
    entry = _valid_action_entry()
    assert entry.action_id == "review_host_activity"


def test_valid_assessment_with_recommended_actions_constructs():
    assessment = CopilotAssessment(**_valid_assessment_kwargs())
    assert len(assessment.recommended_actions) == 1


def test_empty_recommended_actions_is_valid():
    assessment = CopilotAssessment(**_valid_assessment_kwargs(recommended_actions=[]))
    assert assessment.recommended_actions == []


def test_recommended_actions_defaults_to_empty_list():
    kwargs = _valid_assessment_kwargs()
    del kwargs["recommended_actions"]
    assessment = CopilotAssessment(**kwargs)
    assert assessment.recommended_actions == []


def test_valid_follow_up_answer_with_recommended_actions():
    answer = CopilotFollowUpAnswer(answer="x", recommended_actions=[_valid_action_entry()])
    assert len(answer.recommended_actions) == 1


# --- missing fields -----------------------------------------------------------


@pytest.mark.parametrize("missing", ["action_id", "label", "description"])
def test_missing_required_field_rejected(missing):
    kwargs = dict(
        action_id="review_host_activity",
        label="Review related activity on the affected host",
        description="x",
    )
    del kwargs[missing]
    with pytest.raises(ValidationError):
        RecommendedInvestigationAction(**kwargs)


def test_supporting_event_refs_defaults_to_empty_list():
    entry = RecommendedInvestigationAction(action_id="review_host_activity", label="x", description="y")
    assert entry.supporting_event_refs == []


# --- malformed action_id -------------------------------------------------------


@pytest.mark.parametrize(
    "bad_id",
    ["T1110", "Review_Host_Activity", "review host activity", "review-host-activity", "1review_host", "", "a"],
)
def test_malformed_action_id_rejected(bad_id):
    with pytest.raises(ValidationError):
        _valid_action_entry(action_id=bad_id)


@pytest.mark.parametrize("good_id", ["review_host_activity", "collect_additional_event_context", "ab"])
def test_well_formed_action_id_accepted(good_id):
    entry = _valid_action_entry(action_id=good_id)
    assert entry.action_id == good_id


# --- oversized fields -----------------------------------------------------------


def test_oversized_action_id_rejected():
    with pytest.raises(ValidationError):
        _valid_action_entry(action_id="a" + "b" * MAX_ACTION_ID_LENGTH)


def test_oversized_label_rejected():
    with pytest.raises(ValidationError):
        _valid_action_entry(label="x" * (MAX_ACTION_LABEL_LENGTH + 1))


def test_oversized_description_rejected():
    with pytest.raises(ValidationError):
        _valid_action_entry(description="x" * (MAX_ACTION_DESCRIPTION_LENGTH + 1))


def test_too_many_supporting_refs_rejected():
    with pytest.raises(ValidationError):
        _valid_action_entry(supporting_event_refs=[f"evt-{i}" for i in range(MAX_SUPPORTING_REFS_PER_FINDING + 1)])


# --- oversized list ----------------------------------------------------------------


def test_too_many_recommended_actions_rejected():
    entries = [_valid_action_entry() for _ in range(MAX_RECOMMENDED_ACTIONS + 1)]
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_assessment_kwargs(recommended_actions=entries))


def test_at_bound_recommended_actions_accepted():
    entries = [_valid_action_entry() for _ in range(MAX_RECOMMENDED_ACTIONS)]
    assessment = CopilotAssessment(**_valid_assessment_kwargs(recommended_actions=entries))
    assert len(assessment.recommended_actions) == MAX_RECOMMENDED_ACTIONS


# --- extra fields forbidden ---------------------------------------------------------


def test_unexpected_field_on_action_entry_rejected():
    with pytest.raises(ValidationError):
        RecommendedInvestigationAction(
            action_id="review_host_activity",
            label="x",
            description="y",
            confidence="high",
        )


def test_no_confidence_field_on_action_entry_by_design():
    assert "confidence" not in RecommendedInvestigationAction.model_fields


def test_no_rationale_field_on_action_entry_by_design():
    """Deliberately no free-text rationale field: supporting_event_refs
    + the registry-sourced description establish why the action is
    useful, not model-generated prose (see the schema's own docstring).
    """
    assert "rationale" not in RecommendedInvestigationAction.model_fields


def test_ai_action_candidate_has_source_rule_id():
    candidate = AIActionCandidate(
        action_id="review_host_activity", label="x", description="y", source_rule_id="brute_force_authentication"
    )
    assert candidate.source_rule_id == "brute_force_authentication"


def test_ai_action_candidate_constructs_with_expected_fields_only():
    """AIActionCandidate does not need extra="forbid" — same as
    AIMitreCandidate (its 10B precedent) — because it is only ever
    constructed internally by AIContextBuilder from trusted registry
    data, never parsed from untrusted external JSON."""
    candidate = AIActionCandidate(
        action_id="review_host_activity", label="x", description="y", source_rule_id="brute_force_authentication"
    )
    assert candidate.action_id == "review_host_activity"


# --- immutability -----------------------------------------------------------------------


def test_action_entry_is_frozen():
    entry = _valid_action_entry()
    with pytest.raises(ValidationError):
        entry.action_id = "review_user_activity"


def test_ai_action_candidate_is_frozen():
    candidate = AIActionCandidate(
        action_id="review_host_activity", label="x", description="y", source_rule_id="brute_force_authentication"
    )
    with pytest.raises(ValidationError):
        candidate.action_id = "other"


def test_ai_action_candidate_omits_internal_registry_fields():
    """AIActionCandidate is intentionally smaller than
    InvestigationAction — no applicable_rule_ids/required_entities
    (AMNIX's own candidate-selection machinery, never sent to a model)."""
    assert "applicable_rule_ids" not in AIActionCandidate.model_fields
    assert "required_entities" not in AIActionCandidate.model_fields


def test_ai_action_candidate_source_rule_id_is_not_a_database_id():
    """source_rule_id is the alert's rule_id string (e.g.
    'brute_force_authentication'), never a database UUID — structural
    guarantee alongside the existing 'no database identifiers' checks."""
    assert "id" not in AIActionCandidate.model_fields
    assert "event_id" not in AIActionCandidate.model_fields
    assert "alert_id" not in AIActionCandidate.model_fields
