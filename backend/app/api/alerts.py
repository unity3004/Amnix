"""Alert creation, retrieval, and status-transition endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.alert import AlertRepository
from app.schemas.alert import AlertCreate, AlertRead, AlertStatusUpdate
from app.schemas.investigation import InvestigationContext
from app.services.alert_lifecycle import InvalidAlertStatusTransition
from app.services.alert_service import AlertNotFoundError, AlertService, UnknownSourceEventsError
from app.services.investigation_service import InvestigationEngine

router = APIRouter(prefix="/alerts", tags=["alerts"])


def get_alert_service(db: Session = Depends(get_db)) -> AlertService:
    return AlertService(AlertRepository(db))


@router.post("", response_model=AlertRead, status_code=status.HTTP_201_CREATED)
def create_alert(
    payload: AlertCreate,
    service: AlertService = Depends(get_alert_service),
) -> AlertRead:
    try:
        alert = service.create(payload)
    except UnknownSourceEventsError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    return AlertRead.model_validate(alert)


@router.get("/{alert_id}", response_model=AlertRead)
def get_alert(
    alert_id: uuid.UUID,
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
    service: AlertService = Depends(get_alert_service),
) -> InvestigationContext:
    """Read-only: computes an InvestigationContext on demand. Does not
    change the alert's status — the analyst workflow stays explicit.
    """
    alert = service.get_with_events(alert_id)
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")
    return InvestigationEngine().build_context(alert)
