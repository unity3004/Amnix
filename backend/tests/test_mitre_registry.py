"""Unit tests for the MITRE mapping layer (app.mitre.registry /
app.mitre.models). Pure in-code data — no database, no network.
"""

from app.mitre.models import MitreTechnique
from app.mitre.registry import MAPPING_SOURCE, MITRE_ATTACK_VERSION, get_techniques_for_rule


def test_brute_force_authentication_maps_to_t1110():
    techniques = get_techniques_for_rule("brute_force_authentication")

    assert len(techniques) == 1
    technique = techniques[0]
    assert technique.technique_id == "T1110"
    assert technique.name == "Brute Force"
    assert technique.tactic == "Credential Access"
    assert technique.source_rule_id == "brute_force_authentication"


def test_suspicious_powershell_execution_maps_to_t1059_001():
    techniques = get_techniques_for_rule("suspicious_powershell_execution")

    assert len(techniques) == 1
    technique = techniques[0]
    assert technique.technique_id == "T1059.001"
    assert technique.name == "Command and Scripting Interpreter: PowerShell"
    assert technique.tactic == "Execution"
    assert technique.source_rule_id == "suspicious_powershell_execution"


def test_encoded_powershell_command_maps_to_t1059_001_and_t1027_010():
    techniques = get_techniques_for_rule("encoded_powershell_command")

    technique_ids = {t.technique_id for t in techniques}
    assert technique_ids == {"T1059.001", "T1027.010"}
    for technique in techniques:
        assert technique.source_rule_id == "encoded_powershell_command"

    obfuscation = next(t for t in techniques if t.technique_id == "T1027.010")
    assert obfuscation.name == "Obfuscated Files or Information: Command Obfuscation"
    assert obfuscation.tactic == "Stealth"


def test_unknown_rule_returns_empty_list_not_an_invented_mapping():
    assert get_techniques_for_rule("some_rule_that_does_not_exist") == []
    assert get_techniques_for_rule("") == []


def test_canonical_technique_metadata_is_well_formed():
    for rule_id in ("brute_force_authentication", "suspicious_powershell_execution", "encoded_powershell_command"):
        for technique in get_techniques_for_rule(rule_id):
            assert isinstance(technique, MitreTechnique)
            assert technique.technique_id.startswith("T")
            assert technique.name
            assert technique.tactic
            assert technique.description
            assert technique.source_rule_id == rule_id


def test_mapping_version_is_explicit_and_stable():
    assert MITRE_ATTACK_VERSION
    assert "MITRE ATT&CK" in MITRE_ATTACK_VERSION
    # Must not claim to be a live/dynamic lookup.
    assert "latest" not in MITRE_ATTACK_VERSION.lower()


def test_mapping_source_identifies_itself_as_application_controlled():
    assert MAPPING_SOURCE == "AMNIX detection-rule mapping"
    lowered = MAPPING_SOURCE.lower()
    assert "threat intelligence" not in lowered
    assert "live" not in lowered


def test_get_techniques_for_rule_returns_a_fresh_list_each_time():
    """Callers must not be able to mutate the registry's internal state
    through the returned list."""
    first = get_techniques_for_rule("brute_force_authentication")
    first.append(
        MitreTechnique(
            technique_id="T9999",
            name="Not Real",
            tactic="Nowhere",
            description="x",
            source_rule_id="brute_force_authentication",
        )
    )

    second = get_techniques_for_rule("brute_force_authentication")

    assert len(second) == 1
    assert second[0].technique_id == "T1110"
