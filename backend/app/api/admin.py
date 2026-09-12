"""Administrative endpoints (Step 11G, extended in Step 11M with a
durable audit trail).

AMNIX's first real admin-only route. Every route in this router depends
on require_admin (Step 11F), never a hand-written `current_user.role ==
"admin"` check — require_admin already composes authentication
(get_current_user, Step 11E) and authorization (Step 11F) in one
reusable dependency, so declaring `Depends(require_admin)` alone gives a
route both: a missing/invalid/expired token or an inactive/deleted
caller still yields 401 (authentication), and a valid but non-admin
caller yields 403 (authorization) — see app.api.dependencies for the
full trust boundary neither this file nor app.services.user_service
re-implements.

Business logic (the self-target rule, the not-found check, the actual
mutation, and — Step 11M — the atomic audit-record write) lives
entirely in UserService/AdminAuditService; this file only translates
their typed errors into HTTP responses, exactly like app.api.alerts
does for AlertService.
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from sqlalchemy.orm import Session

from app.api.dependencies import AuthenticatedUser, get_client_ip, require_admin
from app.core.database import get_db
from app.core.security_events import SecurityEvent, SecurityEventType, log_security_event
from app.repositories.admin_audit import DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, AdminAuditRepository
from app.repositories.user import UserRepository
from app.schemas.admin_audit import AdminAuditAction, AdminAuditListResponse, AdminAuditResponse
from app.schemas.auth import UserRead, UserStatusUpdate
from app.services.admin_audit_service import AdminAuditService
from app.services.user_service import CannotModifyOwnAccountError, UserNotFoundError, UserService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/admin", tags=["admin"])


def get_admin_audit_service(db: Session = Depends(get_db)) -> AdminAuditService:
    return AdminAuditService(db, UserService(UserRepository(db)), AdminAuditRepository(db))


@router.patch("/users/{user_id}/status", response_model=UserRead)
def update_user_status(
    request: Request,
    user_id: uuid.UUID,
    payload: UserStatusUpdate,
    current_user: AuthenticatedUser = Depends(require_admin),
    service: AdminAuditService = Depends(get_admin_audit_service),
) -> UserRead:
    """Enable or disable a user account. Admin-only.

    An admin may not target their own account through this endpoint
    (see CannotModifyOwnAccountError's own docstring for why) — that
    request is rejected with 409, distinct from the 403 require_admin
    would raise for a non-admin caller: this is a business-rule
    conflict, not an authorization failure. A nonexistent target_user_id
    is 404, matching AlertNotFoundError's own convention in
    app.api.alerts. Response is UserRead — the same safe projection
    already used by /auth/register and /auth/login, so password_hash is
    never reachable here either. This response shape is completely
    unchanged from Step 11G/11J — Step 11M's new AdminAudit row is not
    reflected in this endpoint's response at all (see GET /admin/audits
    below for reading it back).

    Step 11M: service.change_user_status() atomically persists BOTH the
    User mutation and its AdminAudit row (see
    app.services.admin_audit_service's own docstring for the full
    transactional guarantee) — reaching the code below the try/except is
    proof both are durably committed, not merely attempted.

    Step 11J: still emits ADMIN_USER_STATUS_CHANGED, unchanged, only
    after the above has already succeeded. The 409 (self-target) and 404
    (nonexistent target) cases below deliberately create NO AdminAudit
    row and log NO security event (that would be recording a false
    success) — an already-authorized admin hitting an edge case of their
    own request is an ordinary business outcome, not unauthorized access
    (which is what AUTHORIZATION_DENIED, emitted by require_admin itself
    for a non-admin caller, already covers).
    """
    try:
        user, _audit = service.change_user_status(
            acting_admin_id=current_user.id, target_user_id=user_id, is_active=payload.is_active
        )
    except CannotModifyOwnAccountError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except UserNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc

    log_security_event(
        SecurityEvent(
            event_type=SecurityEventType.ADMIN_USER_STATUS_CHANGED,
            method=request.method,
            path=request.url.path,
            status_code=200,
            actor_user_id=str(current_user.id),
            target_user_id=str(user.id),
            target_is_active=user.is_active,
            client_ip=get_client_ip(request),
        )
    )
    return UserRead.model_validate(user)


@router.get("/audits", response_model=AdminAuditListResponse)
def list_admin_audits(
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    actor_user_id: uuid.UUID | None = Query(default=None),
    target_user_id: uuid.UUID | None = Query(default=None),
    action: AdminAuditAction | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(require_admin),
    service: AdminAuditService = Depends(get_admin_audit_service),
) -> AdminAuditListResponse:
    """Step 11M: read-only, bounded retrieval of AMNIX's durable
    administrative audit trail. Admin-only — the same require_admin
    dependency as the write endpoint above, so an analyst token gets 403
    exactly like it would on the status-change endpoint; there is no
    separate, weaker authorization path for reads.

    `limit`/`offset` are validated by FastAPI's own Query bounds
    (1..MAX_LIST_LIMIT / >=0) before this function body ever runs — an
    out-of-range value is a 422, never silently clamped. `action`, if
    supplied, must be a real AdminAuditAction member (FastAPI rejects
    anything else with 422 before this ever runs) — there is no code
    path here that could pass an arbitrary caller-supplied string
    through to the database as a filter value.

    No total count, no cursor — a plain bounded page, mirroring
    CopilotAuditListResponse's own scope decision (see
    app.schemas.copilot_audit).
    """
    audits = service.list_audits(
        limit=limit,
        offset=offset,
        actor_user_id=actor_user_id,
        target_user_id=target_user_id,
        action=action.value if action is not None else None,
    )
    return AdminAuditListResponse(
        items=[AdminAuditResponse.model_validate(audit) for audit in audits],
        limit=limit,
        offset=offset,
    )
