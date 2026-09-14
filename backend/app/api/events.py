"""SecurityEvent ingestion and retrieval endpoints.

Step 11E: every route in this router requires an authenticated,
active user (see app.api.dependencies.get_current_user) — ingestion is
no longer publicly accessible. Authentication happens before any
business logic runs; nothing about ingestion, detection, or automatic
alert generation itself changes (see AlertGenerationService, unmodified).
"""

import logging
import uuid
from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import IPvAnyAddress
from sqlalchemy.orm import Session

from app.api.alerts import get_alert_service
from app.api.dependencies import AuthenticatedUser, get_current_user
from app.core.database import get_db
from app.repositories.alert import DEFAULT_LIST_LIMIT as ALERT_DEFAULT_LIST_LIMIT
from app.repositories.alert import MAX_LIST_LIMIT as ALERT_MAX_LIST_LIMIT
from app.repositories.alert import AlertRepository
from app.repositories.security_event import DEFAULT_LIST_LIMIT, MAX_LIST_LIMIT, SecurityEventRepository
from app.schemas.alert import AlertListResponse, AlertRead
from app.schemas.security_event import SecurityEventCreate, SecurityEventListResponse, SecurityEventRead
from app.services.alert_generation_service import AlertGenerationService
from app.services.alert_service import AlertService
from app.services.security_event import SecurityEventService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/events", tags=["events"])


def get_security_event_service(db: Session = Depends(get_db)) -> SecurityEventService:
    return SecurityEventService(SecurityEventRepository(db))


def get_alert_generation_service(db: Session = Depends(get_db)) -> AlertGenerationService:
    return AlertGenerationService(
        security_event_repository=SecurityEventRepository(db),
        alert_repository=AlertRepository(db),
        alert_service=AlertService(AlertRepository(db)),
    )


@router.post("", response_model=SecurityEventRead, status_code=status.HTTP_201_CREATED)
def create_event(
    payload: SecurityEventCreate,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: SecurityEventService = Depends(get_security_event_service),
    alert_generation_service: AlertGenerationService = Depends(get_alert_generation_service),
) -> SecurityEventRead:
    """Ingest one SecurityEvent, then run it (Step 10H) through the
    existing DetectionEngine to automatically create any Alerts it
    warrants. Alert generation is a best-effort side effect — see
    AlertGenerationService's own docstring — so a problem there can
    never turn a successful ingestion into a failed one; the response
    shape and status code are unchanged from before Step 10H.

    AlertGenerationService.generate_from_event() already promises never
    to raise, but this route does not rely on that promise alone -- like
    CopilotService's own audit write, a second, outer try/except here
    means even a bug in that promise (or a future dependency-override in
    a test) still cannot turn a successful ingestion into a failed one.
    """
    event = service.ingest(payload)
    try:
        alert_generation_service.generate_from_event(event)
    except Exception:
        logger.exception("Automatic alert generation failed for SecurityEvent %s", event.id)
    return SecurityEventRead.model_validate(event)


@router.get("", response_model=SecurityEventListResponse)
def list_events(
    limit: int = Query(default=DEFAULT_LIST_LIMIT, ge=1, le=MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    event_type: str | None = Query(default=None),
    source: str | None = Query(default=None),
    since: datetime | None = Query(default=None),
    until: datetime | None = Query(default=None),
    hostname: str | None = Query(default=None),
    username: str | None = Query(default=None),
    source_ip: IPvAnyAddress | None = Query(default=None),
    destination_ip: IPvAnyAddress | None = Query(default=None),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: SecurityEventService = Depends(get_security_event_service),
) -> SecurityEventListResponse:
    """Dashboard Data Foundation: read-only, bounded, newest-first
    retrieval of recently ingested SecurityEvents. Same shared-SOC
    authentication as every other route in this router — no ownership/
    tenant filter, any authenticated analyst or admin sees the same
    queue (see app.api.dependencies.get_current_user and Step 11N's
    confirmed shared-SOC model, unchanged here).

    `limit`/`offset` are validated here, at the API layer, by FastAPI's
    own Query bounds (1..MAX_LIST_LIMIT / >=0) — an out-of-range value
    is rejected with 422 before this function body ever runs, rather
    than being silently clamped. The same bounds are still enforced
    independently inside SecurityEventRepository (defense in depth,
    matching every other bounded-list repository in this codebase).
    `event_type`/`source`/`hostname`/`username` are exact-match string
    filters; `since`/`until` bound `event_timestamp`. All nine are
    optional and independent — every existing caller that omits the new
    four keeps its exact prior behavior unchanged.

    Step 12X: `source_ip`/`destination_ip` are typed as `IPvAnyAddress`
    (Pydantic validates the query string is a real IPv4/IPv6 address,
    rejecting anything else with the same 422 shape as an invalid
    `since`/`until`) — the identical validation SecurityEventCreate
    already applies at ingestion. Converted to `str` before reaching the
    service/repository so the comparison matches the same canonicalized
    string form SecurityEventService.ingest() already stores (see that
    method's own `str(data["source_ip"])` conversion) — never the raw,
    un-normalized query string.
    """
    if since is not None and until is not None and until < since:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail="'until' must not be before 'since'.")

    events = service.list_recent(
        limit=limit,
        offset=offset,
        event_type=event_type,
        source=source,
        since=since,
        until=until,
        hostname=hostname,
        username=username,
        source_ip=str(source_ip) if source_ip is not None else None,
        destination_ip=str(destination_ip) if destination_ip is not None else None,
    )
    return SecurityEventListResponse(
        items=[SecurityEventRead.model_validate(event) for event in events],
        limit=limit,
        offset=offset,
    )


@router.get("/{event_id}", response_model=SecurityEventRead)
def get_event(
    event_id: uuid.UUID,
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: SecurityEventService = Depends(get_security_event_service),
) -> SecurityEventRead:
    event = service.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found")
    return SecurityEventRead.model_validate(event)


@router.get("/{event_id}/alerts", response_model=AlertListResponse)
def list_event_alerts(
    event_id: uuid.UUID,
    limit: int = Query(default=ALERT_DEFAULT_LIST_LIMIT, ge=1, le=ALERT_MAX_LIST_LIMIT),
    offset: int = Query(default=0, ge=0),
    current_user: AuthenticatedUser = Depends(get_current_user),
    service: SecurityEventService = Depends(get_security_event_service),
    alert_service: AlertService = Depends(get_alert_service),
) -> AlertListResponse:
    """Step 12Y: the authoritative reverse relationship -- which real,
    persisted Alerts (if any) cite this SecurityEvent as evidence, via
    the exact same alert_security_events join AlertRepository already
    uses in the forward direction (Alert.security_events /
    AlertRead.source_event_ids). This is deliberately NOT derived from
    rule_id, timestamps, event_type, hostname, username, IP address, or
    any other heuristic matching -- the database join is the sole source
    of truth, mirroring Step 12V's GET /alerts/{id}/cases (the same
    "authoritative reverse relationship" pattern, one hop over in the
    Alert <-> Case join).

    `event_id` is the only resource selector this route accepts -- there
    is deliberately no `alert_id` query parameter to filter by; a client
    cannot inject or probe for an arbitrary alert through this endpoint,
    only ever see the alerts a SecurityEvent is genuinely linked to.

    Same shared-SOC authentication as every other route in this router --
    no ownership/tenant filter, any authenticated analyst or admin sees
    the same relationship. `limit`/`offset` reuse Alert's own bounds
    (this endpoint returns Alerts, not SecurityEvents) and are validated
    here by FastAPI's own Query bounds, then again independently inside
    AlertRepository (defense in depth, matching every other bounded-list
    repository in this codebase).

    Read-only: never creates, updates, or deletes anything -- viewing
    this relationship has no side effect of any kind.
    """
    event = service.get(event_id)
    if event is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Security event not found")

    alerts = alert_service.list_for_event(event_id, limit=limit, offset=offset)
    return AlertListResponse(
        items=[AlertRead.model_validate(alert) for alert in alerts],
        limit=limit,
        offset=offset,
    )
