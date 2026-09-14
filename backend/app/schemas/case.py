"""Pydantic schemas for the Case domain (Step 12R, architecture approved
in Step 12Q).

Mirrors app.schemas.alert's own conventions: mutation-restricted fields
(status, owner, created_by, case_number, timestamps, closure fields)
are simply ABSENT from whichever input schema shouldn't accept them --
"a client cannot supply X" is true by construction (no field exists to
parse), not by a runtime check that could be forgotten. Every mutating
input schema uses `extra="forbid"`, exactly like AlertStatusUpdate's own
"deliberately a single-field, extra=forbid schema" precedent.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.schemas.detection import DetectionSeverity


class CaseStatus(str, Enum):
    """The complete, fixed Case lifecycle vocabulary (Step 12Q, approved).
    Matches app.models.case.CASE_STATUS_VALUES and that model's own CHECK
    constraint exactly. No CONTAINMENT state -- see the Step 12Q report.
    """

    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    CLOSED = "CLOSED"


class CasePriority(str, Enum):
    """The complete, fixed Case priority vocabulary -- an independent,
    analyst-set operational field, distinct from any alert's own
    severity (see CaseRead.severity, which is derived, never stored).
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def _not_blank(value: str) -> str:
    if not value.strip():
        raise ValueError("must not be blank")
    return value


class CaseCreate(BaseModel):
    """Input schema for POST /cases.

    `created_by` is deliberately NOT a field here -- it is always
    server-resolved from AuthenticatedUser (see CaseService.create_case),
    never accepted from a client. Likewise absent: `id`, `case_number`,
    `status`, `owner_id`, `created_at`, `updated_at`, `closed_at`,
    `closure_reason` -- every one of these is either server-controlled or
    only reachable through its own dedicated endpoint.
    """

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=500)
    description: str = Field(min_length=1)
    priority: CasePriority = CasePriority.MEDIUM

    @field_validator("title", "description")
    @classmethod
    def _validate_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class CaseUpdate(BaseModel):
    """Input schema for PATCH /cases/{case_id} -- title/description/
    priority ONLY. Status, ownership, case_number, severity, and closure
    fields each have no field here at all (status/ownership have their
    own dedicated endpoints; case_number/severity/closed_at/
    closure_reason are never client-settable through any endpoint).

    Every field defaults to None, meaning "do not change this field" --
    a field explicitly submitted as `null` is treated identically to an
    omitted field (both mean "no-op" for that field), since title/
    description can never legitimately be cleared to NULL and collapsing
    the two cases avoids an ambiguous "did they mean omit or clear"
    distinction for a column that has only one valid non-blank shape
    anyway.
    """

    model_config = ConfigDict(extra="forbid")

    title: str | None = Field(default=None, max_length=500)
    description: str | None = None
    priority: CasePriority | None = None

    @field_validator("title", "description")
    @classmethod
    def _validate_not_blank_if_provided(cls, v: str | None) -> str | None:
        if v is not None:
            return _not_blank(v)
        return v


class CaseStatusUpdate(BaseModel):
    """Input schema for PATCH /cases/{case_id}/status.

    `closure_reason` is accepted here (optionally) because CaseService
    needs it specifically for the transition into CLOSED -- it is
    ignored for every other transition, never persisted unless the
    requested transition is actually CLOSED. The service, not this
    schema, is the sole authority on whether a given transition is valid
    and what it requires: no `previous_status`/`actor`/`case_id`/
    `created_by`/`closed_at` field exists here, so none can be
    client-supplied.
    """

    model_config = ConfigDict(extra="forbid")

    status: CaseStatus
    closure_reason: str | None = None

    @field_validator("closure_reason")
    @classmethod
    def _validate_not_blank_if_provided(cls, v: str | None) -> str | None:
        if v is not None:
            return _not_blank(v)
        return v


class CaseOwnerUpdate(BaseModel):
    """Input schema for PATCH /cases/{case_id}/owner.

    `owner_id: None` means "release ownership" (case becomes unowned).
    Object-level authorization (self-assign vs. admin-only reassignment)
    is enforced entirely in CaseService using the AUTHENTICATED caller's
    own identity/role -- this schema carries no actor/role field of any
    kind, so neither can ever be spoofed through it.
    """

    model_config = ConfigDict(extra="forbid")

    owner_id: uuid.UUID | None = None


class CaseAlertLink(BaseModel):
    """Input schema for POST /cases/{case_id}/alerts.

    `linked_by`/`linked_at` are never accepted -- CaseService always
    resolves the actor from AuthenticatedUser and the timestamp from the
    database server default.
    """

    model_config = ConfigDict(extra="forbid")

    alert_id: uuid.UUID


class CaseNoteCreate(BaseModel):
    """Input schema for POST /cases/{case_id}/notes.

    `author_id`/`created_at` are never accepted -- always server-resolved.
    """

    model_config = ConfigDict(extra="forbid")

    body: str = Field(min_length=1)

    @field_validator("body")
    @classmethod
    def _validate_not_blank(cls, v: str) -> str:
        return _not_blank(v)


class CaseRead(BaseModel):
    """Output schema for a single Case.

    `severity` is NOT a 1:1 column copy (Case has no such column at all
    -- see app.models.case's own docstring): it is always populated by
    CaseService.derive_severity() as the max severity among this case's
    currently-linked alerts, or None if no alerts are linked. Never a
    stored, cacheable, or defaultable value -- constructing a CaseRead
    without explicitly supplying this field is a programming error, not
    an omission this schema silently tolerates (no default is given).
    """

    model_config = ConfigDict(extra="forbid")

    id: uuid.UUID
    case_number: int
    title: str
    description: str
    status: CaseStatus
    priority: CasePriority
    severity: DetectionSeverity | None
    created_at: datetime
    updated_at: datetime
    created_by: uuid.UUID
    owner_id: uuid.UUID | None
    closed_at: datetime | None
    closure_reason: str | None


class CaseListResponse(BaseModel):
    """List envelope for GET /cases. `items` preserves whatever order
    CaseRepository.list() already returned (newest-first, id DESC
    tie-break) -- never re-sorted here. `limit`/`offset` echo back
    exactly what was requested, not a total count -- no COUNT(*) query,
    mirroring every other list endpoint in AMNIX (AlertListResponse,
    AdminAuditListResponse, CopilotAuditListResponse).
    """

    model_config = ConfigDict(extra="forbid")

    items: list[CaseRead]
    limit: int
    offset: int


class CaseAuditAction(str, Enum):
    """The complete, fixed action vocabulary (Step 12Q, approved).
    Matches app.models.case_audit.CASE_AUDIT_ACTIONS and that model's own
    CHECK constraint exactly. No generic CASE_UPDATED -- see that
    module's own docstring for why.
    """

    CASE_CREATED = "CASE_CREATED"
    CASE_TITLE_CHANGED = "CASE_TITLE_CHANGED"
    CASE_DESCRIPTION_CHANGED = "CASE_DESCRIPTION_CHANGED"
    CASE_STATUS_CHANGED = "CASE_STATUS_CHANGED"
    CASE_PRIORITY_CHANGED = "CASE_PRIORITY_CHANGED"
    CASE_OWNER_CHANGED = "CASE_OWNER_CHANGED"
    CASE_ALERT_LINKED = "CASE_ALERT_LINKED"
    CASE_ALERT_UNLINKED = "CASE_ALERT_UNLINKED"
    CASE_CLOSED = "CASE_CLOSED"
    CASE_REOPENED = "CASE_REOPENED"


class CaseAuditResponse(BaseModel):
    """API-facing view of one CaseAudit row -- a 1:1 copy of the model's
    own columns, constructed via model_validate(..., from_attributes=True)
    exactly like AdminAuditResponse. There is no request-body/header/
    token/credential field on this schema because there is no such
    column on CaseAudit to read one from.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    case_id: uuid.UUID
    actor_user_id: uuid.UUID
    action: CaseAuditAction
    related_alert_id: uuid.UUID | None
    previous_value: str | None
    new_value: str | None
    created_at: datetime


class CaseAuditListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CaseAuditResponse]
    limit: int
    offset: int


class CaseNoteResponse(BaseModel):
    """API-facing view of one CaseNote row. No internal metadata beyond
    the note's own real columns.
    """

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    id: uuid.UUID
    case_id: uuid.UUID
    author_id: uuid.UUID
    body: str
    created_at: datetime


class CaseNoteListResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    items: list[CaseNoteResponse]
    limit: int
    offset: int
