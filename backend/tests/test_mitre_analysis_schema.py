"""Unit tests for MitreAnalysisEntry and CopilotAssessment.mitre_analysis.
Pure Pydantic validation — no database, no provider, no network.
"""

import pytest
from pydantic import ValidationError

from app.schemas.ai import (
    MAX_MITRE_ANALYSIS_ENTRIES,
    MAX_RATIONALE_LENGTH,
    MAX_SUPPORTING_REFS_PER_FINDING,
    MAX_TACTIC_LENGTH,
    MAX_TECHNIQUE_ID_LENGTH,
    MAX_TECHNIQUE_NAME_LENGTH,
    AssessmentConfidence,
    CopilotAssessment,
    EvidenceItem,
    FindingType,
    KeyFinding,
    MitreAnalysisEntry,
    RecommendedAction,
    Verdict,
)


def _valid_mitre_entry(**overrides) -> MitreAnalysisEntry:
    defaults = dict(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        confidence=AssessmentConfidence.HIGH,
        rationale=(
            "FACT: PowerShell command-line activity was observed. MAPPING: rule "
            "suspicious_powershell_execution maps to T1059.001. INTERPRETATION: consistent "
            "with the PowerShell sub-technique."
        ),
        supporting_event_refs=["evt-1"],
    )
    defaults.update(overrides)
    return MitreAnalysisEntry(**defaults)


def _valid_assessment_kwargs(**overrides) -> dict:
    defaults = dict(
        verdict=Verdict.SUSPICIOUS,
        confidence=AssessmentConfidence.MEDIUM,
        summary="PowerShell command-line activity was observed.",
        key_findings=[KeyFinding(type=FindingType.FACT, statement="Observed.", supporting_event_refs=["evt-1"])],
        evidence=[EvidenceItem(field="process_name", value="powershell.exe", event_ref="evt-1", explanation="x")],
        mitre_analysis=[_valid_mitre_entry()],
        recommended_next_steps=["Review the activity."],
        recommended_action=RecommendedAction.INVESTIGATE,
        limitations=["No IP reputation data was supplied."],
    )
    defaults.update(overrides)
    return defaults


# --- 8. valid MITRE analysis --------------------------------------------------


def test_valid_mitre_analysis_entry_constructs():
    entry = _valid_mitre_entry()
    assert entry.technique_id == "T1059.001"


def test_valid_assessment_with_mitre_analysis_constructs():
    assessment = CopilotAssessment(**_valid_assessment_kwargs())
    assert len(assessment.mitre_analysis) == 1
    assert assessment.mitre_analysis[0].technique_id == "T1059.001"


def test_empty_mitre_analysis_is_valid():
    assessment = CopilotAssessment(**_valid_assessment_kwargs(mitre_analysis=[]))
    assert assessment.mitre_analysis == []


def test_mitre_analysis_field_defaults_to_empty_list():
    kwargs = _valid_assessment_kwargs()
    del kwargs["mitre_analysis"]
    assessment = CopilotAssessment(**kwargs)
    assert assessment.mitre_analysis == []


# --- 9. invalid technique ID ---------------------------------------------------


@pytest.mark.parametrize(
    "bad_id",
    ["T9999999", "not-a-technique", "1059.001", "t1059.001-", "T1059.0011", "T105.001", ""],
)
def test_malformed_technique_id_rejected(bad_id):
    with pytest.raises(ValidationError):
        _valid_mitre_entry(technique_id=bad_id)


@pytest.mark.parametrize("good_id", ["T1110", "T1059.001", "T1027.010", "T9999"])
def test_well_formed_technique_id_accepted(good_id):
    entry = _valid_mitre_entry(technique_id=good_id)
    assert entry.technique_id == good_id


# --- 10. missing technique fields -----------------------------------------------


@pytest.mark.parametrize("missing", ["technique_id", "technique_name", "tactic", "confidence", "rationale"])
def test_missing_required_field_rejected(missing):
    kwargs = dict(
        technique_id="T1059.001",
        technique_name="Command and Scripting Interpreter: PowerShell",
        tactic="Execution",
        confidence=AssessmentConfidence.HIGH,
        rationale="x",
    )
    del kwargs[missing]
    with pytest.raises(ValidationError):
        MitreAnalysisEntry(**kwargs)


# --- 11. invalid confidence -------------------------------------------------------


def test_invalid_mitre_confidence_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(confidence="certain")


# --- 12. fabricated event reference (schema-level: shape only) -------------------
#
# The schema itself cannot know which event_refs are "real" for a given
# alert (it has no access to AIContext) — that cross-check is
# CopilotService's job (see tests/test_copilot_service.py). What the
# schema DOES enforce is that supporting_event_refs is a bounded list of
# plain strings, never something structurally unbounded/unsafe.


def test_supporting_event_refs_accepts_arbitrary_strings_shape_only():
    entry = _valid_mitre_entry(supporting_event_refs=["evt-1", "evt-2"])
    assert entry.supporting_event_refs == ["evt-1", "evt-2"]


def test_too_many_supporting_refs_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(supporting_event_refs=[f"evt-{i}" for i in range(MAX_SUPPORTING_REFS_PER_FINDING + 1)])


# --- 13. oversized values ---------------------------------------------------------


def test_oversized_technique_id_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(technique_id="T" + "1" * MAX_TECHNIQUE_ID_LENGTH)


def test_oversized_technique_name_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(technique_name="x" * (MAX_TECHNIQUE_NAME_LENGTH + 1))


def test_oversized_tactic_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(tactic="x" * (MAX_TACTIC_LENGTH + 1))


def test_oversized_rationale_rejected():
    with pytest.raises(ValidationError):
        _valid_mitre_entry(rationale="x" * (MAX_RATIONALE_LENGTH + 1))


def test_too_many_mitre_analysis_entries_rejected():
    entries = [_valid_mitre_entry() for _ in range(MAX_MITRE_ANALYSIS_ENTRIES + 1)]
    with pytest.raises(ValidationError):
        CopilotAssessment(**_valid_assessment_kwargs(mitre_analysis=entries))


def test_at_bound_mitre_analysis_entries_accepted():
    entries = [_valid_mitre_entry() for _ in range(MAX_MITRE_ANALYSIS_ENTRIES)]
    assessment = CopilotAssessment(**_valid_assessment_kwargs(mitre_analysis=entries))
    assert len(assessment.mitre_analysis) == MAX_MITRE_ANALYSIS_ENTRIES


# --- 14. unexpected fields ---------------------------------------------------------


def test_unexpected_field_on_mitre_analysis_entry_rejected():
    with pytest.raises(ValidationError):
        MitreAnalysisEntry(
            technique_id="T1059.001",
            technique_name="Command and Scripting Interpreter: PowerShell",
            tactic="Execution",
            confidence=AssessmentConfidence.HIGH,
            rationale="x",
            proof_of_compromise=True,
        )


def test_mitre_analysis_entry_is_frozen():
    entry = _valid_mitre_entry()
    with pytest.raises(ValidationError):
        entry.technique_id = "T1110"
