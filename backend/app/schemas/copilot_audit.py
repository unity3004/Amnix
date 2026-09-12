"""Typed vocabulary for CopilotAudit records (see app.models.copilot_audit
and app.services.copilot_audit_service).

These three enums exist so CopilotAuditService.record() is called with
real Python values instead of raw strings that could silently drift from
app.models.copilot_audit's CHECK constraint vocabulary. There is no
single source of truth spanning both a database CHECK constraint string
and a Python enum — keeping the two in sync (values here must match the
CHECK constraints in app.models.copilot_audit exactly) is a manual
invariant; changing one without reviewing the other is a bug.

Kept separate from app.schemas.ai deliberately: these describe the audit
*record* of a Copilot call, not anything that is ever sent to or
received from an AI provider.

Step 10F.5 adds the two API-facing retrieval schemas at the bottom of
this file, CopilotAuditResponse and CopilotAuditListResponse — the one
and only place a CopilotAudit row is ever turned into an HTTP response
body. See CopilotAuditResponse's own docstring for the content-exposure
boundary it enforces.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class AuditRequestType(str, Enum):
    """Which CopilotService method produced this call: ask() (an initial
    structured assessment) or follow_up() (an alert-scoped follow-up
    question). Matches app.models.copilot_audit's ck_copilot_audits_
    request_type_valid.
    """

    ASK = "ask"
    FOLLOW_UP = "follow_up"


class AuditOutcome(str, Enum):
    """Top-level success/failure of the call. Matches
    ck_copilot_audits_outcome_valid.
    """

    SUCCESS = "success"
    FAILURE = "failure"


class AuditValidationStatus(str, Enum):
    """Finer-grained than `AuditOutcome`: distinguishes "the provider
    transport failed before validation ever ran" (NOT_APPLICABLE) from
    "the provider responded but AMNIX rejected the content" (FAILED).
    Matches ck_copilot_audits_validation_status_valid.
    """

    PASSED = "passed"
    FAILED = "failed"
    NOT_APPLICABLE = "not_applicable"


class CopilotAuditResponse(BaseModel):
    """API-facing view of one CopilotAudit row — safe metadata only.

    This is the content-exposure boundary for Step 10F.5's retrieval
    endpoint: every field here is a 1:1 copy of an existing
    CopilotAudit column (see app.models.copilot_audit), constructed via
    `model_validate(audit, from_attributes=True)` — never a dict a route
    hand-assembles field by field, so there is no code path here that
    could accidentally add a new field. There is deliberately no
    question/history/answer/response/context/system_instructions/
    rationale/exception field on this schema, because there is no such
    column on CopilotAudit to read one from (see that model's own
    docstring for the full list of what is never persisted in the first
    place — this schema cannot leak what was never stored).

    `extra="forbid"` is not needed here the way it is on request schemas
    (nothing ever constructs this from untrusted client input — it is
    always built from a trusted ORM row), but the field list itself is
    the real boundary and is kept exactly in sync with
    app.models.copilot_audit's columns.
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    alert_id: uuid.UUID
    request_type: AuditRequestType
    provider_name: str
    model_name: str | None
    outcome: AuditOutcome
    validation_status: AuditValidationStatus
    http_status: int
    question_fingerprint: str
    question_length: int
    history_turn_count: int | None
    duration_ms: int | None
    created_at: datetime


class CopilotAuditListResponse(BaseModel):
    """List envelope for GET /alerts/{alert_id}/copilot/audits. `items`
    preserves whatever order CopilotAuditRepository.list_for_alert
    already returned (newest-first, id DESC tie-break) — this schema
    does not, and must never, re-sort anything. `limit`/`offset` echo
    back exactly what was requested (post API-layer validation), not a
    total count — no COUNT(*) query is performed for this milestone.
    """

    model_config = ConfigDict(extra="forbid")

    items: list[CopilotAuditResponse]
    limit: int
    offset: int
