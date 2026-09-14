"""Case status lifecycle: the explicit, testable state machine governing
which status transitions PATCH /cases/{id}/status may perform (Step 12R,
architecture approved in Step 12Q).

Pure-Python, zero database dependency -- a direct structural mirror of
app.services.alert_lifecycle, deliberately kept as its own separate
module/table rather than merged with Alert's: Case and Alert lifecycles
are genuinely independent concepts (see the Step 12Q report's own
domain-boundary discussion) that happen to share this module's shape,
not the same state machine.

    OPEN ──────► INVESTIGATING ──────► RESOLVED ──────► CLOSED
                      ▲                    │  ▲             │
                      └────────────────────┘  └─────────────┘

Approved design (Step 12Q, unchanged from that proposal):
- OPEN -> INVESTIGATING is the only way out of OPEN. Unlike Alert (which
  allows NEW -> ESCALATED directly), a Case has no escalation-shortcut
  concept in this first version.
- INVESTIGATING -> RESOLVED: normal progression.
- RESOLVED -> INVESTIGATING: analyst determined more work is needed
  before final closure. Does NOT represent a "reopen" of a closed case
  (closed_at/closure_reason are never touched by this transition) --
  CaseService distinguishes this from CLOSED -> INVESTIGATING and
  records it as the generic CASE_STATUS_CHANGED audit action, not
  CASE_REOPENED.
- RESOLVED -> CLOSED: formal closure. CaseService requires a non-blank
  closure_reason for this specific transition and records CASE_CLOSED.
- CLOSED -> INVESTIGATING: reopening a closed case. Deliberately allowed
  here, unlike Alert.RESOLVED (which is fully terminal) -- a Case is a
  longer-lived, higher-stakes record where new information surfacing
  after closure is a normal SOC workflow, not an edge case to forbid.
  CaseService records this as CASE_REOPENED and clears closed_at/
  closure_reason.
- A same-state "transition" (e.g. OPEN -> OPEN) is not valid: PATCH must
  represent an actual state change, exactly like Alert's own rule.
"""

from app.schemas.case import CaseStatus

CASE_STATUS_TRANSITIONS: dict[CaseStatus, frozenset[CaseStatus]] = {
    CaseStatus.OPEN: frozenset({CaseStatus.INVESTIGATING}),
    CaseStatus.INVESTIGATING: frozenset({CaseStatus.RESOLVED}),
    CaseStatus.RESOLVED: frozenset({CaseStatus.INVESTIGATING, CaseStatus.CLOSED}),
    CaseStatus.CLOSED: frozenset({CaseStatus.INVESTIGATING}),
}


class InvalidCaseStatusTransition(ValueError):
    def __init__(self, current: CaseStatus, requested: CaseStatus) -> None:
        self.current = current
        self.requested = requested
        super().__init__(f"Cannot transition case status from '{current.value}' to '{requested.value}'")


def is_valid_transition(current: CaseStatus, requested: CaseStatus) -> bool:
    return requested in CASE_STATUS_TRANSITIONS.get(current, frozenset())


def assert_valid_transition(current: CaseStatus, requested: CaseStatus) -> None:
    if not is_valid_transition(current, requested):
        raise InvalidCaseStatusTransition(current, requested)
