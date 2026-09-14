"""Alert creation, retrieval, and status-transition endpoints.

Step 11E: every route in this router requires an authenticated, active
user (see app.api.dependencies.get_current_user) — the entire alert/
investigation/Copilot/Copilot-audit surface is no longer publicly
accessible. Authentication happens before any business logic runs;
nothing about alert creation, investigation, Copilot, or Copilot audit
behavior itself changes. No RBAC yet: any authenticated user (analyst or
admin) may call every route here equally — see Step 11F.

Step 12V: GET /{alert_id}/cases is the one route in this file that
depends on the Case domain (app.api.cases.get_case_service/
case_to_case_read, app.services.case_service.CaseService) -- the
authoritative Alert -> Case reverse relationship query. This does not
make Alert itself "Case-aware": app.models.alert.py and
app.repositories.alert.py remain completely untouched by this step; the
dependency is a router-level, read-only composition of the existing
Case domain, not a new field/column/relationship on Alert.
"""

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.ai.context_builder import AIContextBuilder
from app.ai.exceptions import AIProviderError
from app.ai.factory import get_ai_provider
from app.ai.provider import AIProvider
from app.api.cases import case_to_case_read, get_case_service
from app.api.dependencies import AuthenticatedUser, get_current_user
from app.core.database import get_db
from app.repositories.alert import (
    DEFAULT_LIST_LIMIT as ALERT_DEFAULT_LIST_LIMIT,
)
from app.repositories.alert import (
    MAX_LIST_LIMIT as ALERT_MAX_LIST_LIMIT,
)
from app.repositories.alert import AlertRepository
from app.repositories.case import DEFAULT_LIST_LIMIT as CASE_DEFAULT_LIST_LIMIT
from app.repositories.case import MAX_LIST_LIMIT as CASE_MAX_LIST_LIMIT
from app.repositories.copilot_audit import DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, CopilotAuditRepository
from app.schemas.ai import CopilotFollowUpRequest, CopilotFollowUpResponse, CopilotQuestionRequest, CopilotResponse
from app.schemas.alert import AlertCreate, AlertListResponse, AlertRead, AlertStatus, AlertStatusUpdate
from app.schemas.case import CaseListResponse
from app.schemas.copilot_audit import CopilotAuditListResponse, CopilotAuditResponse
from app.schemas.detection import DetectionSeverity
from app.schemas.investigation import InvestigationContext
from app.services.alert_lifecycle import InvalidAlertStatusTransition
from app.services.alert_service import AlertNotFoundError, AlertService, UnknownSourceEventsError
from app.services.case_service import CaseService
from app.services.copilot_audit_service import (
    CopilotAuditAlertNotFoundError,
    CopilotAuditPersistenceError,
    CopilotAuditService,
    CopilotAuditValidationError,
)
from app.services.copilot_service import CopilotService
from app.services.investigation_service import InvestigationEngine

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/alerts", tags=["alerts"])


def get_alert_service(db: Session = Depends(get_db)) -> AlertService:
    return AlertService(AlertRepository(db))


def get_copilot_audit_service(db: Session = Depends(get_db)) -> CopilotAuditService:
    return CopilotAuditService(CopilotAuditRepository(db), AlertRepository(db))


def get_copilot_service(
    db: Session = Depends(get_db),
    provider: AIProvider = Depends(get_ai_provider),
    copilot_audit_service: CopilotAuditService = Depends(get_copilot_audit_service),
) -> CopilotService:
    return CopilotService(
        alert_service=AlertService(AlertRepository(db)),
        investigation_engine=InvestigationEngine(),
        context_builder=AIContextBuilder(),
        provider=provider,
        copilot_audit_service=copilot_audit_service,
    )


@router.post("", response_model=AlertRead, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> AlertRead:
    try:
        alert = service.create(payload)
    except UnknownSourceEventsError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return AlertRead.model_validate(alert)


@router.get("", response_model=AlertListResponse)
def list_alerts(
    limit: int = Query(default=ALERT_DEFAULT_LIST_LIMIT, ge=1, le=ALERT_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    status_filter: AlertStatus | None = Query(default=None, alias="status"),
    severity: DetectionSeverity | None = Query(default=None),
    rule_id: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> AlertListResponse:
    """Dashboard Data Foundation: read-only, bounded, newest-first
    retrieval of recent Alerts. Same shared-SOC authentication as every
    other route in this router — no ownership/tenant filter, any
    authenticated analyst or admin sees the same queue (unchanged Step
    11N shared-SOC model).

    `limit`/`offset` are validated here, at the API layer, by FastAPI's
    own Query bounds (1..MAX_LIST_LIMIT / >=0) — an out-of-range value
    is rejected with 422 before this function body ever runs. The same
    bounds are still enforced independently inside AlertRepository
    (defense in depth, matching every other bounded-list repository in
    this codebase). `status`/`severity` reuse the existing AlertStatus/
    DetectionSeverity enums — an invalid value is a 422 from Pydantic's
    own enum validation, never a hand-rolled string check; `rule_id` is
    an exact-match filter; `since`/`until` bound `first_seen`. The query
    parameter is named `status` (via `alias=`) to match the public
    contract while avoiding shadowing the `status` module already
    imported for HTTP status codes in this file.
    """
    if since is not None and until is not None and until < since:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="'until' must not be before 'since'.")

    alerts = service.list_recent(
        limit=limit, offset=offset, status=status_filter, severity=severity, rule_id=rule_id, since=since, until=until
    )
    return AlertListResponse(
        items=[AlertRead.model_validate(alert) for alert in alerts],
        limit=limit,
        offset=offset,
    )


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> AlertRead:
    alert = service.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return AlertRead.model_validate(alert)


@router.patch("/{alert_id}/status", response_model=AlertRead)
def update_alert_status(
    alert_id: uuid.UUID,
    payload: AlertStatusUpdate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> AlertRead:
    try:
        alert = service.update_status(alert_id, payload.status)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except InvalidAlertStatusTransition as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return AlertRead.model_validate(alert)


@router.get("/{alert_id}/investigation", response_model=InvestigationContext)
def get_alert_investigation(
    alert_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: AlertService = Depends(get_alert_service),
) -> InvestigationContext:
    """Read-only: computes an InvestigationContext on demand. Does not
    change the alert's status — the analyst workflow stays explicit.
    """
    alert = service.get_with_events(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return InvestigationEngine().build_context(alert)


@router.get("/{alert_id}/cases", response_model=CaseListResponse)
def list_alert_cases(
    alert_id: uuid.UUID,
    limit: int = Query(default=CASE_DEFAULT_LIST_LIMIT, ge=1, le=CASE_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
    case_service: CaseService = Depends(get_case_service),
) -> CaseListResponse:
    """Step 12V: the authoritative reverse relationship Step 12U's
    discovery found missing -- which real, persisted Cases (if any)
    currently cite this Alert, via the exact same case_alerts join
    GET /cases/{id}/alerts already uses in the other direction. There is
    deliberately no `GET /cases?alert_id=...` anywhere in this codebase:
    that query parameter would not exist on CaseRepository.list()'s own
    signature, so FastAPI would silently ignore it and return every
    Case, unfiltered -- confirmed by live testing during Step 12U's own
    discovery. This route is the real, index-backed, authoritative
    replacement for that trap, not an alternate path to it.

    Read-only: never creates a CaseAudit row (or any other audit/
    mutation) merely because the analyst viewed this relationship, and
    never touches SecurityEvent/InvestigationContext/MITRE/Copilot --
    the response is CaseRead's own existing safe field set (reused
    verbatim via case_to_case_read(), the identical projection GET
    /cases and GET /cases/{id} already use), never a new schema
    invented to duplicate it.

    Same shared-SOC authentication as every other route in this file --
    no ownership/tenant filter, any authenticated analyst or admin sees
    the same relationship. `limit`/`offset` reuse Case's own bounds
    (this endpoint returns Cases, not Alerts) and are validated here by
    FastAPI's own Query bounds, then again independently inside
    CaseAlertRepository (defense in depth, matching every other bounded-
    list repository in this codebase).
    """
    try:
        cases = case_service.list_cases_for_alert(alert_id, limit=limit, offset=offset)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc

    items = [case_to_case_read(case, severity=case_service.derive_severity(case.id)) for case in cases]
    return CaseListResponse(items=items, limit=limit, offset=offset)


@router.post("/{alert_id}/copilot", response_model=CopilotResponse)
def ask_copilot(
    alert_id: uuid.UUID,
    payload: CopilotQuestionRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CopilotService = Depends(get_copilot_service),
) -> CopilotResponse:
    """Ask the AI Copilot a question about an alert's investigation
    context. Advisory only: never changes the alert's status or any
    other stored data. Uses whichever AIProvider AI_PROVIDER configures
    (MockAIProvider by default) — never a raw SecurityEvent query.
    """
    try:
        return service.ask(alert_id, payload.question)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except AIProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.post("/{alert_id}/copilot/follow-up", response_model=CopilotFollowUpResponse)
def ask_copilot_follow_up(
    alert_id: uuid.UUID,
    payload: CopilotFollowUpRequest,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: CopilotService = Depends(get_copilot_service),
) -> CopilotFollowUpResponse:
    """Ask a follow-up question within the same alert-scoped investigation
    conversation. Advisory only, strictly read-only — never changes the
    alert's status or any other stored data. Conversation history is
    supplied by the client on every call (see CopilotFollowUpRequest);
    AMNIX does not persist it. The investigation context, MITRE candidate
    set, and system instructions are always reconstructed server-side
    from `alert_id` alone — `payload` can supply only `question` and
    `history`, never a replacement context (see
    CopilotService.follow_up).
    """
    try:
        return service.follow_up(alert_id, payload.question, payload.history)
    except AlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except AIProviderError as exc:
        raise HTTPException(status_code=status.HTTP_502_BAD_GATEWAY, detail=str(exc)) from exc


@router.get("/{alert_id}/copilot/audits", response_model=CopilotAuditListResponse)
def list_copilot_audits(
    alert_id: uuid.UUID,
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
    alert_service: AlertService = Depends(get_alert_service),
    copilot_audit_service: CopilotAuditService = Depends(get_copilot_audit_service),
) -> CopilotAuditListResponse:
    """Step 10F.5: read-only, alert-scoped retrieval of this alert's
    Copilot audit trail (see app.services.copilot_audit_service /
    app.models.copilot_audit). Exposes safe metadata only — see
    CopilotAuditResponse's own docstring for exactly what that means and
    why nothing else can leak through it. Never creates, updates, or
    deletes an audit row; never touches Alert or SecurityEvent state;
    never invokes an AI provider and never reads any investigation
    context.

    `limit`/`offset` are validated here, at the API layer, by FastAPI's
    own Query bounds (1..MAX_LIST_LIMIT / >=0) — an out-of-range value
    is rejected with 422 before this function body ever runs, rather
    than being silently clamped to something the analyst didn't ask for.
    The same bounds are still enforced independently inside
    CopilotAuditRepository (see its own docstring) as defense in depth
    for any other caller of that layer.

    Alert existence uses AlertService.get() (not get_with_events) —
    audit retrieval never needs this alert's SecurityEvent collection,
    so there is no reason to load it.
    """
    alert = alert_service.get(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    try:
        audits = copilot_audit_service.list_for_alert(alert_id, limit=limit, offset=offset)
    except CopilotAuditAlertNotFoundError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found") from exc
    except CopilotAuditValidationError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    except CopilotAuditPersistenceError as exc:
        logger.exception("Failed to retrieve Copilot audit records for alert %s", alert_id)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Failed to retrieve Copilot audit records."
        ) from exc

    return CopilotAuditListResponse(
        items=[CopilotAuditResponse.model_validate(audit) for audit in audits],
        limit=limit,
        offset=offset,
    )
