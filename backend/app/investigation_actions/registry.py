"""The investigation-action mapping layer: the single, deterministic,
application-controlled source of truth for "which investigation steps
could AMNIX reasonably suggest for this alert."

This is NOT threat intelligence, NOT a live lookup, and NOT a remediation
or SOAR catalog. It is a small, version-controlled, hand-curated table
living in code, reviewed exactly like app.mitre.registry. Every entry is
investigation-only: reviewing/collecting/checking existing evidence,
never blocking, disabling, killing, terminating, quarantining, isolating,
revoking, deleting, remediating, patching, deploying, restarting,
shutting down, or executing anything. See
tests/test_investigation_action_registry.py for a static test that scans
this entire catalog for those verbs and fails if any appear — defense in
depth on top of manual review.

get_candidate_actions() is the ONLY supported way to read this catalog —
nothing else in AMNIX should hold its own copy of an action_id (see
app.ai.context_builder and app.services.copilot_service, the only two
callers). An unknown rule_id, or a matching rule whose required entity
type is missing from this alert's InvestigationEntities, both correctly
return fewer (or zero) candidates — never an invented one.

Candidate selection depends ONLY on `rule_id` and `entities`, both of
which are computed server-side before any provider is invoked (see
CopilotService.ask/follow_up) — there is no parameter here, and no code
path anywhere, through which client-supplied text (a question,
conversation history, or telemetry content) could influence which
actions are returned.
"""

from app.investigation_actions.models import InvestigationAction
from app.schemas.investigation import InvestigationEntities

ACTION_MAPPING_VERSION = "AMNIX investigation action mapping v1 (2026-09-02)"
ACTION_MAPPING_SOURCE = "AMNIX investigation action mapping"

_RULE_IDS = frozenset(
    {"brute_force_authentication", "suspicious_powershell_execution", "encoded_powershell_command"}
)
_POWERSHELL_RULE_IDS = frozenset({"suspicious_powershell_execution", "encoded_powershell_command"})

_REVIEW_AUTHENTICATION_FAILURES = InvestigationAction(
    action_id="review_authentication_failures",
    label="Review authentication failure history for the affected account",
    description=(
        "Review the account's recent authentication failure and success history to help "
        "determine whether the observed pattern is consistent with a genuine access attempt, "
        "a misconfigured client, or credential-guessing activity."
    ),
    applicable_rule_ids=frozenset({"brute_force_authentication"}),
    required_entities=frozenset({"usernames"}),
)

_REVIEW_SOURCE_IP_HISTORY = InvestigationAction(
    action_id="review_source_ip_history",
    label="Review source IP activity history across the environment",
    description=(
        "Review where else this source IP has appeared across AMNIX's recorded events to help "
        "assess whether the activity is limited to this alert or part of a broader pattern."
    ),
    applicable_rule_ids=_RULE_IDS,
    required_entities=frozenset({"source_ips"}),
)

_REVIEW_HOST_ACTIVITY = InvestigationAction(
    action_id="review_host_activity",
    label="Review related activity on the affected host",
    description=(
        "Review other recent events recorded for this host to help establish whether the "
        "observed activity fits a broader sequence on that system."
    ),
    applicable_rule_ids=_RULE_IDS,
    required_entities=frozenset({"hostnames"}),
)

_REVIEW_USER_ACTIVITY = InvestigationAction(
    action_id="review_user_activity",
    label="Review recent activity for the affected user account",
    description=(
        "Review other recent events associated with this user account to help assess whether "
        "the observed activity is consistent with the account's normal usage pattern."
    ),
    applicable_rule_ids=_RULE_IDS,
    required_entities=frozenset({"usernames"}),
)

_REVIEW_POWERSHELL_COMMAND = InvestigationAction(
    action_id="review_powershell_command",
    label="Review the PowerShell command line and process context",
    description=(
        "Review the full command line and parent process for the observed PowerShell activity "
        "to help determine what the command was intended to do."
    ),
    applicable_rule_ids=_POWERSHELL_RULE_IDS,
    required_entities=frozenset({"process_names"}),
)

_REVIEW_PROCESS_TREE = InvestigationAction(
    action_id="review_process_tree",
    label="Review the process tree around this event",
    description=(
        "Review the parent and child processes surrounding this event to help establish how "
        "the observed process was launched and what it spawned."
    ),
    applicable_rule_ids=_POWERSHELL_RULE_IDS,
    required_entities=frozenset({"process_names"}),
)

_REVIEW_NETWORK_CONNECTIONS = InvestigationAction(
    action_id="review_network_connections",
    label="Review outbound network connections associated with this activity",
    description=(
        "Review outbound network connections observed around this event to help determine "
        "whether the host communicated with any notable destinations."
    ),
    applicable_rule_ids=_POWERSHELL_RULE_IDS,
    required_entities=frozenset({"destination_ips"}),
)

_COLLECT_ADDITIONAL_EVENT_CONTEXT = InvestigationAction(
    action_id="collect_additional_event_context",
    label="Collect additional event context around the alert time window",
    description=(
        "Gather additional telemetry from the time window surrounding this alert to help fill "
        "gaps in the currently available evidence."
    ),
    applicable_rule_ids=_RULE_IDS,
    required_entities=frozenset(),
)

_CATALOG: tuple[InvestigationAction, ...] = (
    _REVIEW_AUTHENTICATION_FAILURES,
    _REVIEW_SOURCE_IP_HISTORY,
    _REVIEW_HOST_ACTIVITY,
    _REVIEW_USER_ACTIVITY,
    _REVIEW_POWERSHELL_COMMAND,
    _REVIEW_PROCESS_TREE,
    _REVIEW_NETWORK_CONNECTIONS,
    _COLLECT_ADDITIONAL_EVENT_CONTEXT,
)


def get_candidate_actions(rule_id: str, entities: InvestigationEntities) -> list[InvestigationAction]:
    """The only supported lookup. Returns a fresh list (never a shared
    mutable reference) of every catalog entry whose `applicable_rule_ids`
    contains `rule_id` AND whose `required_entities` are all non-empty on
    `entities`. An unknown rule_id, or a matching rule with a missing
    required entity type, both correctly yield fewer (or zero) results —
    never an invented candidate.
    """
    return [
        action
        for action in _CATALOG
        if rule_id in action.applicable_rule_ids
        and all(getattr(entities, field_name) for field_name in action.required_entities)
    ]
