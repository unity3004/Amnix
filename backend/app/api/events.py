"""SecurityEvent ingestion and retrieval endpoints."""

import uuid

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.repositories.security_event import SecurityEventRepository
from app.schemas.security_event import SecurityEventCreate, SecurityEventRead
from app.services.security_event import SecurityEventService

router = APIRouter(prefix="/events", tags=["events"])


def get_security_event_service(db: Session = Depends(get_db)) -> SecurityEventService:
    return SecurityEventService(SecurityEventRepository(db))


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def create_event(
    payload: SecurityEventCreate,
    service: SecurityEventService = Depends(get_security_event_service),
) -> SecurityEventRead:
    event = service.ingest(payload)
    return SecurityEventRead.model_validate(event)


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: uuid.UUID,
    service: SecurityEventService = Depends(get_security_event_service),
) -> SecurityEventRead:
    event = service.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found")
    return SecurityEventRead.model_validate(event)
