"""The MITRE mapping layer: the single, deterministic, application-
controlled source of truth for "which ATT&CK techniques could this AMNIX
detection rule's alert be evidence of."

This is NOT threat intelligence and NOT a live lookup. It is a small,
version-controlled, hand-curated table living in code, reviewed exactly
like any other detection logic. get_techniques_for_rule() is the ONLY
supported way to read it — nothing else in AMNIX should hold its own
copy of a technique ID (see app.ai.context_builder and
app.services.copilot_service, the only two callers).

An unknown rule_id returns an empty list. It never invents a plausible-
looking mapping — "I don't have a mapping for this" is a correct and
expected answer, not an error.

--- Verified against MITRE ATT&CK, and why each mapping was chosen ---

MITRE_ATTACK_VERSION below records the specific ATT&CK release these
entries were checked against (technique names, tactic names, and IDs
looked up directly from attack.mitre.org rather than assumed from
memory). Re-verify and bump this constant whenever ATT&CK's taxonomy
changes in a way that could affect these entries — e.g. ATT&CK v19
(2026-04-28) split the long-standing "Defense Evasion" tactic into
"Stealth" (TA0005) and "Defense Impairment" (TA0112); T1027 and its
sub-techniques now fall under "Stealth", which is why that tactic name
below is "Stealth" and not "Defense Evasion".

brute_force_authentication -> T1110 "Brute Force" (Credential Access).
    AMNIX's rule correlates repeated authentication failures by
    (username, source_ip) within a window. It deliberately does NOT
    distinguish which specific brute-force method was used (e.g.
    T1110.001 Password Guessing vs. T1110.003 Password Spraying vs.
    T1110.004 Credential Stuffing all look identical to this rule) —
    only the parent technique T1110 is claimed, since mapping to a
    sub-technique the detection logic cannot actually establish would
    overstate what AMNIX observed.

suspicious_powershell_execution -> T1059.001 "Command and Scripting
    Interpreter: PowerShell" (Execution). Direct match: the rule only
    fires on a PowerShell process execution with malicious-use
    command-line indicators.

encoded_powershell_command -> T1059.001 (Execution) AND T1027.010
    "Obfuscated Files or Information: Command Obfuscation" (Stealth).
    An encoded (-EncodedCommand/-enc) PowerShell invocation is
    simultaneously "PowerShell execution" and "command-line
    obfuscation" — two behaviorally distinct techniques, both
    genuinely supported by what this rule detects. suspicious_
    powershell_execution is deliberately NOT also mapped to T1027.010:
    its indicators (hidden window, execution-policy bypass, download
    cradles, IEX) are execution/evasion behaviors, not command-line
    *obfuscation* specifically, so claiming T1027.010 there would not
    be supported by that rule's actual match logic.
"""

from app.mitre.models import MitreTechnique

MITRE_ATTACK_VERSION = "MITRE ATT&CK Enterprise v19.0 (2026-04-28)"
MAPPING_SOURCE = "AMNIX detection-rule mapping"

_BRUTE_FORCE = MitreTechnique(
    technique_id="T1110",
    name="Brute Force",
    tactic="Credential Access",
    description=(
        "Adversaries may use brute force techniques to gain access to accounts when "
        "passwords are unknown or when password hashes are obtained. AMNIX's "
        "brute_force_authentication rule detects a burst of repeated authentication "
        "failures for the same (username, source_ip) pair within a time window; it "
        "does not determine which specific brute-force method was used, so the "
        "parent technique is mapped rather than a sub-technique."
    ),
    source_rule_id="brute_force_authentication",
)

_POWERSHELL_SUSPICIOUS = MitreTechnique(
    technique_id="T1059.001",
    name="Command and Scripting Interpreter: PowerShell",
    tactic="Execution",
    description=(
        "Adversaries may abuse PowerShell commands and scripts for execution. "
        "AMNIX's suspicious_powershell_execution rule detects a PowerShell process "
        "execution whose command line contains indicators commonly associated with "
        "malicious use (hidden-window execution, execution-policy bypass, in-memory "
        "download-and-execute cradles)."
    ),
    source_rule_id="suspicious_powershell_execution",
)

_POWERSHELL_ENCODED = _POWERSHELL_SUSPICIOUS.model_copy(
    update={
        "description": (
            "Adversaries may abuse PowerShell commands and scripts for execution. "
            "AMNIX's encoded_powershell_command rule detects a PowerShell process "
            "execution using the -EncodedCommand/-enc flag to pass a base64-encoded "
            "command."
        ),
        "source_rule_id": "encoded_powershell_command",
    }
)

_COMMAND_OBFUSCATION = MitreTechnique(
    technique_id="T1027.010",
    name="Obfuscated Files or Information: Command Obfuscation",
    tactic="Stealth",
    description=(
        "Adversaries may obfuscate content during command execution to impede "
        "detection. AMNIX's encoded_powershell_command rule detects the "
        "-EncodedCommand/-enc flag, a common way to pass an obfuscated (base64-"
        "encoded) command to PowerShell to hide its content from casual log review."
    ),
    source_rule_id="encoded_powershell_command",
)

_RULE_TECHNIQUES: dict[str, list[MitreTechnique]] = {
    "brute_force_authentication": [_BRUTE_FORCE],
    "suspicious_powershell_execution": [_POWERSHELL_SUSPICIOUS],
    "encoded_powershell_command": [_POWERSHELL_ENCODED, _COMMAND_OBFUSCATION],
}


def get_techniques_for_rule(rule_id: str) -> list[MitreTechnique]:
    """The only supported lookup. Returns a fresh list (never a shared
    mutable reference) of candidate techniques for `rule_id`, or an
    empty list for any rule_id not in the mapping — including unknown,
    misspelled, or future rule_ids. Never invents a plausible-looking
    fallback.
    """
    return list(_RULE_TECHNIQUES.get(rule_id, []))
