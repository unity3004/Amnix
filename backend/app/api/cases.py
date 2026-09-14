"""Case creation, retrieval, lifecycle, ownership, alert-linking, and
note endpoints (Step 12R, architecture approved in Step 12Q).

Every route requires an authenticated, active user (get_current_user) --
no additional role restriction: both AMNIX roles ('analyst' and 'admin')
may call every route here equally, exactly mirroring app.api.alerts'
own "shared SOC queue" model. The one place role actually matters is
owner reassignment, which is genuine OBJECT-level authorization
(depends on the case's current owner, not just the caller's role) and
therefore lives inside CaseService.change_owner(), not a route-level
Depends(require_admin) gate -- see that method's own docstring.

IDOR handling: every path-identified resource (case_id, alert_id,
note_id via its parent case_id) is validated to actually exist -- and,
for alert link/unlink, to actually belong to the case in question --
before any read or mutation; a missing/mismatched relationship is
always a 404, never a different error message that would let a caller
distinguish "case doesn't exist" from "alert isn't linked to it".
"""

import logging
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.api.dependencies import AuthenticatedUser, get_current_user
from app.core.database import get_db
from app.models.case import Case
from app.repositories.alert import AlertRepository
from app.repositories.case import DEFAULT_LIST_LIMIT as CASE_DEFAULT_LIST_LIMIT
from app.repositories.case import MAX_LIST_LIMIT as CASE_MAX_LIST_LIMIT
from app.repositories.case import CaseRepository
from app.repositories.case_alert import CaseAlertRepository
from app.repositories.case_audit import DEFAULT_LIST_LIMIT as AUDIT_DEFAULT_LIST_LIMIT
from app.repositories.case_audit import MAX_LIST_LIMIT as AUDIT_MAX_LIST_LIMIT
from app.repositories.case_audit import CaseAuditRepository
from app.repositories.case_note import DEFAULT_LIST_LIMIT as NOTE_DEFAULT_LIST_LIMIT
from app.repositories.case_note import MAX_LIST_LIMIT as NOTE_MAX_LIST_LIMIT
from app.repositories.case_note import CaseNoteRepository
from app.repositories.user import UserRepository
from app.schemas.alert import AlertListResponse, AlertRead
from app.schemas.case import (
    CaseAlertLink,
    CaseAuditListResponse,
    CaseAuditResponse,
    CaseCreate,
    CaseListResponse,
    CaseNoteCreate,
    CaseNoteListResponse,
    CaseNoteResponse,
    CaseOwnerUpdate,
    CasePriority,
    CaseRead,
    CaseStatus,
    CaseStatusUpdate,
    CaseUpdate,
)
from app.services.alert_service import AlertNotFoundError
from app.services.case_lifecycle import InvalidCaseStatusTransition
from app.services.case_service import (
    AlertAlreadyLinkedError,
    AlertNotLinkedError,
    CaseNotFoundError,
    CaseOwnerNotFoundError,
    CaseOwnershipAuthorizationError,
    CaseService,
    ClosureReasonRequiredError,
    InactiveCaseOwnerError,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/cases", tags=["cases"])


def get_case_service(db: Session = Depends(get_db)) -> CaseService:
    return CaseService(
        db,
        CaseRepository(db),
        CaseAlertRepository(db),
        CaseAuditRepository(db),
        CaseNoteRepository(db),
        AlertRepository(db),
        UserRepository(db),
    )


def case_to_case_read(case: Case, severity: str | None) -> CaseRead:
    """The one Case -> CaseRead projection, shared with app.api.alerts'
    GET /alerts/{id}/cases (Step 12V) so that endpoint's response shape
    can never silently drift from this one's -- `severity` is always
    supplied by the caller (from CaseService.derive_severity()), never
    computed here, so this function alone can never be the place a
    stored-vs-derived severity bug gets introduced.
    """
    return CaseRead(
        id=case.id,
        case_number=case.case_number,
        title=case.title,
        description=case.description,
        status=case.status,
        priority=case.priority,
        severity=severity,
        created_at=case.created_at,
        updated_at=case.updated_at,
        created_by=case.created_by,
        owner_id=case.owner_id,
        closed_at=case.closed_at,
        closure_reason=case.closure_reason,
    )


@router.post("", response_model=CaseRead, status_code=status.HTTP_201_CREATED)
def create_case(
    payload: CaseCreate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseRead:
    case = service.create_case(
        title=payload.title, description=payload.description, priority=payload.priority, created_by=current_user.id
    )
    return case_to_case_read(case, severity=None)  # a brand-new case has no linked alerts yet


@router.get("", response_model=CaseListResponse)
def list_cases(
    limit: int = Query(default=CASE_DEFAULT_LIST_LIMIT, ge=1, le=CASE_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    status_filter: CaseStatus | None = Query(default=None, alias="status"),
    priority: CasePriority | None = Query(default=None),
    owner_id: uuid.UUID | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseListResponse:
    """Read-only, bounded, newest-first retrieval of Cases -- shared SOC
    visibility, same as GET /alerts (no ownership-scoped filtering; any
    authenticated analyst/admin sees the same case queue). `limit`/
    `offset` are validated here by FastAPI's own Query bounds and again
    independently inside CaseRepository (defense in depth, matching
    every other bounded-list repository in this codebase).
    """
    cases = service.list_cases(limit=limit, offset=offset, status=status_filter, priority=priority, owner_id=owner_id)
    items = [case_to_case_read(case, severity=service.derive_severity(case.id)) for case in cases]
    return CaseListResponse(items=items, limit=limit, offset=offset)


@router.get("/{case_id}", response_model=CaseRead)
def get_case(
    case_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseRead:
    try:
        case = service.get_case(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    return case_to_case_read(case, severity=service.derive_severity(case_id))


@router.patch("/{case_id}", response_model=CaseRead)
def update_case(
    case_id: uuid.UUID,
    payload: CaseUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseRead:
    try:
        case = service.update_case(
            case_id,
            title=payload.title,
            description=payload.description,
            priority=payload.priority,
            actor_id=current_user.id,
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    return case_to_case_read(case, severity=service.derive_severity(case_id))


@router.patch("/{case_id}/status", response_model=CaseRead)
def update_case_status(
    case_id: uuid.UUID,
    payload: CaseStatusUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseRead:
    try:
        case = service.change_status(
            case_id, new_status=payload.status, closure_reason=payload.closure_reason, actor_id=current_user.id
        )
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    except InvalidCaseStatusTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    except ClosureReasonRequiredError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return case_to_case_read(case, severity=service.derive_severity(case_id))


@router.patch("/{case_id}/owner", response_model=CaseRead)
def update_case_owner(
    case_id: uuid.UUID,
    payload: CaseOwnerUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseRead:
    try:
        case = service.change_owner(case_id, new_owner_id=payload.owner_id, actor=current_user)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    except CaseOwnershipAuthorizationError as exc:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(exc)) from exc
    except CaseOwnerNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found") from exc
    except InactiveCaseOwnerError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return case_to_case_read(case, severity=service.derive_severity(case_id))


@router.get("/{case_id}/alerts", response_model=AlertListResponse)
def list_case_alerts(
    case_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> AlertListResponse:
    """Real, linked Alert rows for one Case -- reuses the existing
    AlertRead projection unmodified (no duplicate schema). Not paginated
    beyond the natural bound of "however many alerts are linked to this
    one case" -- there is no separate limit/offset here because a case's
    linked-alert count is operator-bounded by ordinary SOC usage, not an
    open-ended list like GET /alerts itself.
    """
    try:
        alerts = service.list_alerts(case_id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    items = [AlertRead.model_validate(alert) for alert in alerts]
    return AlertListResponse(items=items, limit=len(items), offset=0)


@router.post("/{case_id}/alerts", response_model=AlertRead, status_code=status.HTTP_201_CREATED)
def link_case_alert(
    case_id: uuid.UUID,
    payload: CaseAlertLink,
    current_user: AuthenticatedUser = Depends(get_current_user),
    db: Session = Depends(get_db),
    service: CaseService = Depends(get_case_service),
) -> AlertRead:
    try:
        service.link_alert(case_id, alert_id=payload.alert_id, actor_id=current_user.id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except AlertAlreadyLinkedError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    # link_alert() already proved this alert exists; re-fetch it fresh
    # (not via a private service attribute) purely to shape the response.
    alert = AlertRepository(db).get_by_id(payload.alert_id)
    return AlertRead.model_validate(alert)


@router.delete("/{case_id}/alerts/{alert_id}", status_code=status.HTTP_204_NO_CONTENT)
def unlink_case_alert(
    case_id: uuid.UUID,
    alert_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> None:
    try:
        service.unlink_alert(case_id, alert_id=alert_id, actor_id=current_user.id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    except AlertNotLinkedError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert is not linked to this case") from exc


@router.get("/{case_id}/audit", response_model=CaseAuditListResponse)
def list_case_audit(
    case_id: uuid.UUID,
    limit: int = Query(default=AUDIT_DEFAULT_LIST_LIMIT, ge=1, le=AUDIT_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseAuditListResponse:
    try:
        audits = service.list_audits(case_id, limit=limit, offset=offset)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    items = [CaseAuditResponse.model_validate(audit) for audit in audits]
    return CaseAuditListResponse(items=items, limit=limit, offset=offset)


@router.get("/{case_id}/notes", response_model=CaseNoteListResponse)
def list_case_notes(
    case_id: uuid.UUID,
    limit: int = Query(default=NOTE_DEFAULT_LIST_LIMIT, ge=1, le=NOTE_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseNoteListResponse:
    try:
        notes = service.list_notes(case_id, limit=limit, offset=offset)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    items = [CaseNoteResponse.model_validate(note) for note in notes]
    return CaseNoteListResponse(items=items, limit=limit, offset=offset)


@router.post("/{case_id}/notes", response_model=CaseNoteResponse, status_code=status.HTTP_201_CREATED)
def create_case_note(
    case_id: uuid.UUID,
    payload: CaseNoteCreate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CaseService = Depends(get_case_service),
) -> CaseNoteResponse:
    try:
        note = service.add_note(case_id, body=payload.body, actor_id=current_user.id)
    except CaseNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found") from exc
    return CaseNoteResponse.model_validate(note)
