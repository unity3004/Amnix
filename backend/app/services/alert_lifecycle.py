"""Alert status lifecycle: the explicit, testable state machine governing
which status transitions PATCH /alerts/{id}/status may perform.

    NEW ───────┬──────────────┬──────────────┐
     │         │              │              │
     ▼         ▼              ▼              ▼
ACKNOWLEDGED ─► INVESTIGATING ─► RESOLVED   ESCALATED ─► RESOLVED
     │                              ▲            ▲
     └──────────────────────────────┴────────────┘
                    (ESCALATED reachable from NEW/ACKNOWLEDGED/INVESTIGATING)

Design choices, spelled out because they're judgment calls, not the only
reasonable graph:

- NEW -> INVESTIGATING and NEW -> ESCALATED are both allowed: an analyst
  picking up a NEW alert directly, or a high-severity NEW alert needing
  immediate escalation, shouldn't be forced through a separate
  "acknowledge" step first.
- ACKNOWLEDGED -> ESCALATED is allowed for the same reason.
- ACKNOWLEDGED -> RESOLVED is deliberately NOT allowed: "acknowledged"
  only means "seen", not "investigated" — resolving requires having gone
  through INVESTIGATING or ESCALATED first, so RESOLVED always reflects
  substantive engagement.
- ESCALATED -> RESOLVED is allowed (an escalated investigation can
  still conclude), but ESCALATED -> INVESTIGATING (de-escalation) is not
  — kept out of this first version to keep the graph exactly as large as
  what's justified now; see the final report.
- RESOLVED is fully terminal: no outgoing transitions at all, including
  RESOLVED -> RESOLVED. Reopening a resolved alert is Incident-model
  territory, out of scope here.
- A same-state "transition" (e.g. NEW -> NEW) is not valid: PATCH must
  represent an actual state change.
"""

from app.schemas.alert import AlertStatus

ALERT_STATUS_TRANSITIONS: dict[AlertStatus, frozenset[AlertStatus]] = {
    AlertStatus.NEW: frozenset(
        {AlertStatus.ACKNOWLEDGED, AlertStatus.INVESTIGATING, AlertStatus.ESCALATED}
    ),
    AlertStatus.ACKNOWLEDGED: frozenset({AlertStatus.INVESTIGATING, AlertStatus.ESCALATED}),
    AlertStatus.INVESTIGATING: frozenset({AlertStatus.RESOLVED, AlertStatus.ESCALATED}),
    AlertStatus.ESCALATED: frozenset({AlertStatus.RESOLVED}),
    AlertStatus.RESOLVED: frozenset(),
}


class InvalidAlertStatusTransition(ValueError):
    def __init__(self, current: AlertStatus, requested: AlertStatus) -> None:
        self.current = current
        self.requested = requested
        super().__init__(f"Cannot transition alert status from '{current.value}' to '{requested.value}'")


def is_valid_transition(current: AlertStatus, requested: AlertStatus) -> bool:
    return requested in ALERT_STATUS_TRANSITIONS.get(current, frozenset())


def assert_valid_transition(current: AlertStatus, requested: AlertStatus) -> None:
    if not is_valid_transition(current, requested):
        raise InvalidAlertStatusTransition(current, requested)
