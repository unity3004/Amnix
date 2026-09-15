"""Unit tests for AICaseContextBuilder. No database required.

Mirrors tests/test_ai_context_builder.py's own shape exactly: builds
real, transient Case/Alert/CaseNote/CaseAudit instances via
case_factory/alert_factory/case_note_factory/case_audit_factory (all
in-memory, never persisted) and feeds them through AICaseContextBuilder.
"""

from datetime import datetime, timezone

from app.ai.case_context_builder import AICaseContextBuilder
from app.services.investigation_service import InvestigationEngine

BUILDER = AICaseContextBuilder()
INVESTIGATION_ENGINE = InvestigationEngine()

START = datetime(2026, 8, 29, 10, 0, 0, tzinfo=timezone.utc)


def test_preserves_case_fields(case_factory):
    case = case_factory(title="Suspicious lateral movement", status="INVESTIGATING", priority="high")

    context = BUILDER.build(case=case, alerts=[], notes=[], audits=[])

    assert context.case_id == case.id
    assert context.title == "Suspicious lateral movement"
    assert context.status == "INVESTIGATING"
    assert context.priority == "high"


def test_maps_alerts_to_bounded_summaries_with_synthetic_refs(alert_factory, event_factory, case_factory):
    case = case_factory()
    event = event_factory()
    alert_a = alert_factory(
        rule_id="brute_force_authentication", severity="high", status="new", security_events=[event],
        evidence={"failure_count": 5, "username": "jdoe"},
    )
    alert_b = alert_factory(rule_id="suspicious_powershell_execution", severity="medium", status="investigating")

    context = BUILDER.build(case=case, alerts=[alert_a, alert_b], notes=[], audits=[])

    assert [a.alert_ref for a in context.alerts] == ["alert-1", "alert-2"]
    assert context.alerts[0].rule_id == "brute_force_authentication"
    assert context.alerts[0].severity == "high"
    assert context.alerts[0].status == "new"
    assert context.alerts[0].event_count == 1
    assert set(context.alerts[0].evidence_keys) == {"failure_count", "username"}
    # Evidence VALUES never reach AICaseAlertSummary -- only the keys.
    assert "jdoe" not in context.alerts[0].evidence_keys
    assert context.alerts[1].alert_ref == "alert-2"
    assert context.alerts[1].event_count == 0


def test_never_includes_a_real_alert_database_id(alert_factory, case_factory):
    case = case_factory()
    alert = alert_factory()

    context = BUILDER.build(case=case, alerts=[alert], notes=[], audits=[])

    serialized = context.model_dump_json()
    assert str(alert.id) not in serialized


def test_maps_notes_to_synthetic_refs(case_note_factory, case_factory):
    case = case_factory()
    note_a = case_note_factory(body="First observation.")
    note_b = case_note_factory(body="Second observation.")

    context = BUILDER.build(case=case, alerts=[], notes=[note_a, note_b], audits=[])

    assert [n.note_ref for n in context.notes] == ["note-1", "note-2"]
    assert context.notes[0].body == "First observation."
    assert context.notes[1].body == "Second observation."


def test_never_includes_a_real_note_or_author_database_id(case_note_factory, case_factory):
    case = case_factory()
    note = case_note_factory()

    context = BUILDER.build(case=case, alerts=[], notes=[note], audits=[])

    serialized = context.model_dump_json()
    assert str(note.id) not in serialized
    assert str(note.author_id) not in serialized


def test_maps_audit_entries_to_synthetic_refs(case_audit_factory, case_factory):
    case = case_factory()
    audit = case_audit_factory(action="CASE_STATUS_CHANGED", previous_value="OPEN", new_value="INVESTIGATING")

    context = BUILDER.build(case=case, alerts=[], notes=[], audits=[audit])

    assert context.audit[0].audit_ref == "audit-1"
    assert context.audit[0].action == "CASE_STATUS_CHANGED"
    assert context.audit[0].previous_value == "OPEN"
    assert context.audit[0].new_value == "INVESTIGATING"


def test_no_focused_alert_by_default(alert_factory, case_factory):
    case = case_factory()
    alert = alert_factory()

    context = BUILDER.build(case=case, alerts=[alert], notes=[], audits=[])

    assert context.focused_alert is None


def test_focused_alert_carries_real_timeline_with_synthetic_event_refs(alert_factory, event_factory, case_factory):
    case = case_factory()
    event_a = event_factory(event_timestamp=START, hostname="WKS-01")
    event_b = event_factory(event_timestamp=START, hostname="WKS-02")
    alert = alert_factory(security_events=[event_a, event_b])
    investigation = INVESTIGATION_ENGINE.build_context(alert)

    context = BUILDER.build(
        case=case, alerts=[alert], notes=[], audits=[],
        focused_alert_investigation=investigation, focused_alert_ref="alert-1",
    )

    assert context.focused_alert is not None
    assert context.focused_alert.alert_ref == "alert-1"
    assert [e.event_ref for e in context.focused_alert.timeline] == ["evt-1", "evt-2"]
    hostnames = {e.hostname for e in context.focused_alert.timeline}
    assert hostnames == {"WKS-01", "WKS-02"}
    # Real database event ids never reach the context.
    serialized = context.model_dump_json()
    assert str(event_a.id) not in serialized
    assert str(event_b.id) not in serialized


def test_mitre_candidates_are_mapped_verbatim_from_supplied_techniques(case_factory):
    from app.mitre.registry import get_techniques_for_rule

    case = case_factory()
    candidates = get_techniques_for_rule("brute_force_authentication")

    context = BUILDER.build(case=case, alerts=[], notes=[], audits=[], mitre_candidates=candidates)

    assert len(context.mitre_candidates) == len(candidates)
    if candidates:
        assert context.mitre_candidates[0].technique_id == candidates[0].technique_id
        assert context.mitre_candidates[0].name == candidates[0].name


def test_empty_case_produces_empty_bounded_lists(case_factory):
    case = case_factory()

    context = BUILDER.build(case=case, alerts=[], notes=[], audits=[])

    assert context.alerts == []
    assert context.notes == []
    assert context.audit == []
    assert context.mitre_candidates == []
