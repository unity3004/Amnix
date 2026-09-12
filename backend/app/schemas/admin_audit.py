"""Pydantic schemas for AdminAudit (Step 11M).

Mirrors app.schemas.copilot_audit's own split: a typed vocabulary enum
plus the two API-facing retrieval schemas — the one and only place an
AdminAudit row is ever turned into an HTTP response body. See
AdminAuditResponse's own docstring for the content-exposure boundary it
enforces.

No create/write-facing schema exists here at all: AdminAudit rows are
never constructed from client input (see
app.services.admin_audit_service.AdminAuditService) — there is no
schema path a client could use to supply `action`, `actor_user_id`, or
any other audit field directly.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict


class AdminAuditAction(str, Enum):
    """The complete, fixed action vocabulary (Step 11M). Matches
    app.models.admin_audit.ADMIN_AUDIT_ACTIONS and that model's own
    CHECK constraint exactly. Widening this is a deliberate future
    decision — see that module's own docstring.
    """

    USER_STATUS_CHANGED = "USER_STATUS_CHANGED"


class AdminAuditResponse(BaseModel):
    """API-facing view of one AdminAudit row — safe metadata only.

    Every field here is a 1:1 copy of an existing AdminAudit column,
    constructed via `model_validate(audit, from_attributes=True)` —
    never a dict a route hand-assembles field by field, so there is no
    code path here that could accidentally add a new field. There is
    deliberately no request-body/header/token/credential field on this
    schema, because there is no such column on AdminAudit to read one
    from (see that model's own docstring for the full list of what is
    never persisted in the first place).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    actor_user_id: uuid.UUID
    target_user_id: uuid.UUID
    action: AdminAuditAction
    previous_is_active: bool
    new_is_active: bool
    created_at: datetime


class AdminAuditListResponse(BaseModel):
    """List envelope for GET /admin/audits. `items` preserves whatever
    order AdminAuditRepository.list() already returned (newest-first,
    id DESC tie-break) — this schema does not, and must never, re-sort
    anything. `limit`/`offset` echo back exactly what was requested
    (post API-layer validation), not a total count — no COUNT(*) query
    is performed for this milestone, mirroring CopilotAuditListResponse's
    own scope decision.
    """

    model_config = ConfigDict(extra="forbid")

    items: list[AdminAuditResponse]
    limit: int
    offset: int
