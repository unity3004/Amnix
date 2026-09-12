"""Unit tests for the investigation-action mapping layer
(app.investigation_actions.registry / .models). Pure in-code data — no
database, no network.
"""

from app.investigation_actions.models import InvestigationAction
from app.investigation_actions.registry import (
    ACTION_MAPPING_SOURCE,
    ACTION_MAPPING_VERSION,
    _CATALOG,
    get_candidate_actions,
)
from app.schemas.investigation import InvestigationEntities

# Defense in depth (see the registry module's own docstring): this list
# must never appear, as a substring, in any action_id/label/description
# anywhere in the catalog. If a developer ever adds a remediation-shaped
# action, this test fails the build.
_BLACKLISTED_REMEDIATION_VERBS = (
    "block",
    "disable",
    "kill",
    "terminate",
    "quarantine",
    "isolate",
    "revoke",
    "delete",
    "remediate",
    "patch",
    "deploy",
    "restart",
    "shutdown",
    "execute",
)


def test_known_rule_mapping_brute_force():
    entities = InvestigationEntities(usernames=["jdoe"])
    candidates = get_candidate_actions("brute_force_authentication", entities)

    action_ids = {a.action_id for a in candidates}
    assert "review_authentication_failures" in action_ids
    assert "collect_additional_event_context" in action_ids


def test_known_rule_mapping_suspicious_powershell():
    entities = InvestigationEntities(process_names=["powershell.exe"])
    candidates = get_candidate_actions("suspicious_powershell_execution", entities)

    action_ids = {a.action_id for a in candidates}
    assert "review_powershell_command" in action_ids
    assert "review_process_tree" in action_ids


def test_known_rule_mapping_encoded_powershell():
    entities = InvestigationEntities(process_names=["powershell.exe"], destination_ips=["10.0.0.9"])
    candidates = get_candidate_actions("encoded_powershell_command", entities)

    action_ids = {a.action_id for a in candidates}
    assert "review_powershell_command" in action_ids
    assert "review_network_connections" in action_ids


def test_entity_filtering_missing_required_entity_yields_no_candidate_for_that_action():
    entities = InvestigationEntities()  # no usernames
    candidates = get_candidate_actions("brute_force_authentication", entities)

    action_ids = {a.action_id for a in candidates}
    assert "review_authentication_failures" not in action_ids
    assert "review_user_activity" not in action_ids
    # But the entity-independent action is still offered.
    assert "collect_additional_event_context" in action_ids


def test_entity_filtering_matching_rule_and_entity_produces_candidate():
    entities = InvestigationEntities(source_ips=["10.0.0.5"])
    candidates = get_candidate_actions("brute_force_authentication", entities)

    assert any(a.action_id == "review_source_ip_history" for a in candidates)


def test_unknown_rule_returns_empty_list():
    entities = InvestigationEntities(usernames=["jdoe"], source_ips=["10.0.0.5"], hostnames=["WKS-01"])
    assert get_candidate_actions("some_rule_that_does_not_exist", entities) == []
    assert get_candidate_actions("", entities) == []


def test_no_entities_at_all_still_returns_entity_independent_actions():
    entities = InvestigationEntities()
    candidates = get_candidate_actions("brute_force_authentication", entities)

    assert candidates == [a for a in candidates if not a.required_entities]
    assert len(candidates) >= 1


def test_mapping_version_is_explicit_and_identifies_amnix():
    assert ACTION_MAPPING_VERSION
    assert "AMNIX" in ACTION_MAPPING_VERSION
    assert "latest" not in ACTION_MAPPING_VERSION.lower()


def test_mapping_source_identifies_itself_as_application_controlled_not_threat_intel():
    assert ACTION_MAPPING_SOURCE == "AMNIX investigation action mapping"
    lowered = ACTION_MAPPING_SOURCE.lower()
    assert "threat intelligence" not in lowered
    assert "live" not in lowered


def test_get_candidate_actions_returns_a_fresh_list_each_time():
    entities = InvestigationEntities(usernames=["jdoe"])
    first = get_candidate_actions("brute_force_authentication", entities)
    first.append(
        InvestigationAction(
            action_id="not_a_real_catalog_entry",
            label="x",
            description="y",
            applicable_rule_ids=frozenset({"brute_force_authentication"}),
        )
    )

    second = get_candidate_actions("brute_force_authentication", entities)

    assert "not_a_real_catalog_entry" not in {a.action_id for a in second}


def test_catalog_size_is_deliberately_small():
    assert 6 <= len(_CATALOG) <= 10


def test_catalog_entries_reference_only_known_rule_ids():
    known_rule_ids = {"brute_force_authentication", "suspicious_powershell_execution", "encoded_powershell_command"}
    for action in _CATALOG:
        assert action.applicable_rule_ids <= known_rule_ids


def test_catalog_entries_reference_only_known_entity_field_names():
    known_entity_fields = {"hostnames", "usernames", "source_ips", "destination_ips", "process_names", "file_hashes"}
    for action in _CATALOG:
        assert action.required_entities <= known_entity_fields


def test_action_ids_are_unique():
    action_ids = [a.action_id for a in _CATALOG]
    assert len(action_ids) == len(set(action_ids))


# --- Defense in depth: no remediation verbs anywhere in the catalog --------


def test_no_remediation_verbs_anywhere_in_the_catalog():
    for action in _CATALOG:
        for field_name in ("action_id", "label", "description"):
            text = getattr(action, field_name).lower()
            for verb in _BLACKLISTED_REMEDIATION_VERBS:
                assert verb not in text, (
                    f"Blacklisted remediation verb '{verb}' found in "
                    f"InvestigationAction.{field_name} for action_id='{action.action_id}': {text!r}"
                )


def test_no_remediation_verbs_in_mapping_source_or_version():
    for text in (ACTION_MAPPING_SOURCE.lower(), ACTION_MAPPING_VERSION.lower()):
        for verb in _BLACKLISTED_REMEDIATION_VERBS:
            assert verb not in text


# --- Defense in depth: no execution primitives in this subsystem -----------
#
# The actual security boundary for this milestone is the closed candidate
# set + validation + normalization + event-ref checking + the absence of
# any execution surface — never prompting. This is a static source-code
# guard proving the investigation_actions package itself contains none of
# the primitives that would make an "action" capable of doing anything:
# no subprocess, no eval/exec, no shell invocation, no outbound network
# call of any kind.


def test_no_execution_primitives_in_investigation_actions_subsystem():
    import pathlib

    forbidden_tokens = (
        "subprocess",
        "os.system",
        "eval(",
        "exec(",
        "shell=True",
        "socket.",
        "urllib",
        "requests.",
        "httpx",
    )
    package_dir = pathlib.Path(__file__).resolve().parents[1] / "app" / "investigation_actions"
    source_files = list(package_dir.glob("*.py"))
    assert source_files, "expected to find app/investigation_actions/*.py source files"

    for path in source_files:
        text = path.read_text(encoding="utf-8")
        for token in forbidden_tokens:
            assert token not in text, f"forbidden execution/network primitive '{token}' found in {path}"
