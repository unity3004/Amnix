"""Registration, login, and refresh endpoints (Step 11C, extended in
Step 11D with JWT access tokens + rotating refresh tokens).

No authentication middleware, no route protection, and no RBAC
enforcement exist yet anywhere in AMNIX — see app.core.tokens and
app.services.token_service's own docstrings for exactly what this step
does and does not do. Every other existing route (/events, /alerts,
...) remains completely unauthenticated after this step; actually
validating an incoming access token on a protected route is Step 11E's
job, not this file's.
"""

import logging

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from app.api.dependencies import enforce_login_rate_limit, get_client_ip
from app.core.database import get_db
from app.core.security import PasswordTooShortError, normalize_email
from app.core.security_events import (
    SecurityEvent,
    SecurityEventType,
    fingerprint_login_identifier,
    log_security_event,
)
from app.core.tokens import JWTConfigurationError
from app.repositories.refresh_token import RefreshTokenRepository
from app.repositories.user import UserRepository
from app.schemas.auth import LoginRequest, LoginResponse, RefreshRequest, RegisterRequest, TokenResponse, UserRead
from app.services.auth_service import AuthService, EmailAlreadyRegisteredError, InvalidCredentialsError
from app.services.token_service import InvalidRefreshTokenError, TokenService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/auth", tags=["auth"])

# Step 11K: field names whose submitted VALUE must never be echoed back
# in a validation-error response — see redact_sensitive_validation_errors()
# below for why this is necessary at all. Fixed, small, and exhaustive:
# these are the only field names anywhere in AMNIX's schemas that ever
# carry a raw credential (grepped during this step's discovery).
_SENSITIVE_VALIDATION_FIELD_NAMES = frozenset({"password", "refresh_token"})


_REDACTED = "[redacted]"


def _redact_error_input(error: dict) -> dict:
    """Redact one validation error's `input` if it could contain a
    sensitive field's raw value, in any of the three shapes Pydantic
    actually produces (verified empirically — all three occur in real
    AMNIX responses, not just hypothetically):

    1. A FIELD-level error (e.g. "string_too_long" on `password` itself)
       — `loc` ends in the sensitive field name and `input` IS the raw
       scalar value. Handled by checking `loc[-1]`.
    2. A MODEL-level error for a DIFFERENT, unrelated field on the same
       request (e.g. "missing" on `email` when `password` was also
       submitted) — Pydantic's `input` for this error type is the
       *entire request body dict*, which can still contain a sensitive
       field's raw value under its own key even though this specific
       error has nothing to do with that field. Handled by checking
       whether `input` is itself a dict containing a sensitive key.
    3. A whole-BODY error (`loc == ("body",)`, type "model_attributes_
       type") raised when FastAPI cannot parse the request body into a
       dict at all — e.g. a syntactically-valid JSON body sent with a
       non-JSON Content-Type (such as `text/plain`). Pydantic's `input`
       for this error type is the *raw request body, as `bytes`* (not
       decoded to `str`, and not a dict), so neither check 1 nor check 2
       above can see inside it. Found during Step 11O discovery: POST
       /auth/login with `Content-Type: text/plain` and an otherwise-
       valid JSON body echoed the submitted password back verbatim in
       this raw body, bypassing Step 11K's redaction entirely — an
       earlier fix attempt that only checked `isinstance(input_value,
       str)` still missed it for exactly this reason, confirmed by
       inspecting `exc.errors()` directly rather than assuming Pydantic's
       documented shape. Since a sensitive value's exact position inside
       an arbitrary raw payload can't be reliably isolated, the whole
       value is redacted whenever it contains a sensitive field name at
       all (checked against both `str` and `bytes` forms) — the same
       "redact the whole payload rather than risk missing part of it"
       posture check 2 already takes for the dict case.

    All three checks are necessary; none alone is sufficient — case 2
    was found only by testing a request that violates two fields at once
    (an oversized password AND a missing email); case 3 was found only
    by testing a wrong Content-Type against an otherwise-valid body —
    neither was discoverable by reasoning about the schema alone.
    """
    loc = error.get("loc", ())
    if loc and loc[-1] in _SENSITIVE_VALIDATION_FIELD_NAMES:
        return {**error, "input": _REDACTED}

    input_value = error.get("input")
    if isinstance(input_value, dict) and any(key in input_value for key in _SENSITIVE_VALIDATION_FIELD_NAMES):
        redacted_input = {
            key: (_REDACTED if key in _SENSITIVE_VALIDATION_FIELD_NAMES else value)
            for key, value in input_value.items()
        }
        return {**error, "input": redacted_input}

    if isinstance(input_value, (str, bytes)):
        haystack = input_value if isinstance(input_value, str) else input_value.decode("utf-8", errors="replace")
        if any(name in haystack for name in _SENSITIVE_VALIDATION_FIELD_NAMES):
            return {**error, "input": _REDACTED}

    return error


async def redact_sensitive_validation_errors(request: Request, exc: RequestValidationError) -> JSONResponse:
    """Registered globally (see app.main) as the RequestValidationError
    handler for the whole application — not scoped to /auth/* routes,
    because the redaction rule is keyed on FIELD NAME, not on which
    route raised it, and 'password'/'refresh_token' are (verified by
    grep) the only field names anywhere in AMNIX's schemas that ever
    carry a raw credential. Applying this globally means no future
    schema anywhere in the app could introduce the same leak by
    accident without also being covered.

    WHY THIS EXISTS: FastAPI's own default RequestValidationError
    handler (fastapi.exception_handlers.request_validation_exception_
    handler) serializes `exc.errors()` as-is, and Pydantic v2 includes
    the actual submitted value in each error's `"input"` key by design
    — verified empirically during Step 11K discovery, for a plain
    `Field(max_length=...)` violation, a custom `field_validator`
    raising `ValueError`, AND (the case that actually required
    _redact_error_input's second branch) a request that fails
    validation on a DIFFERENT field entirely while still carrying a
    sensitive field's raw value in the same body — e.g. a missing
    `email` alongside an oversized `password` produces a "missing"
    error on `email` whose `input` is the *whole request body*,
    including the password, unless also redacted. Without this handler,
    a credential could be echoed verbatim back into the 422 response
    body — harmless to the submitter alone, but a real concern for
    anything downstream that captures HTTP responses (API gateways,
    error trackers, browser devtools, request/response logging
    middleware).

    WHAT IS PRESERVED, DELIBERATELY: `type`, `loc`, and `msg` are left
    completely untouched — a client still sees exactly
    "String should have at most 128 characters" (the Step 11K brief's
    own example of an acceptable response), including the numeric limit
    in `ctx`, since revealing the configured maximum itself was
    explicitly blessed by that same example. Every other field's own
    validation errors (email format/length, is_active, ...) and their
    own `input` values are completely unaffected — this mirrors exactly
    how the framework's own default handler behaves, including the
    exact response shape (status 422, `{"detail": [...]}`), for
    anything not matching the redaction rule.
    """
    redacted_errors = [_redact_error_input(error) for error in exc.errors()]
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(redacted_errors)})


def get_token_service(db: Session = Depends(get_db)) -> TokenService:
    return TokenService(RefreshTokenRepository(db), UserRepository(db))


def get_auth_service(
    db: Session = Depends(get_db),
    token_service: TokenService = Depends(get_token_service),
) -> AuthService:
    return AuthService(UserRepository(db), token_service)


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
def register(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> UserRead:
    """Register a new analyst account. Always creates role="analyst",
    is_active=True — RegisterRequest has no field a client could use to
    request anything else (see app.schemas.auth's own docstring). Issues
    no token — see app.services.auth_service's own docstring for why.
    """
    try:
        user = service.register(payload.email, payload.password)
    except PasswordTooShortError as exc:
        raise HTTPException(status_code=status.HTTP_422_UNPROCESSABLE_CONTENT, detail=str(exc)) from exc
    except EmailAlreadyRegisteredError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc
    return UserRead.model_validate(user)


@router.post("/login", response_model=LoginResponse, dependencies=[Depends(enforce_login_rate_limit)])
def login(
    request: Request,
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> LoginResponse:
    """Authenticate credentials and, on success, return a fresh
    access/refresh token pair plus the safe user representation. Every
    failure mode (nonexistent email, wrong password, inactive account)
    returns the identical 401 with the identical generic message — see
    AuthService.login()'s own docstring for the account-enumeration
    reasoning, which applies identically whether or not tokens are
    involved.

    Step 11H: rate-limited via enforce_login_rate_limit (see
    app.api.dependencies) — declared as a route-level `dependencies=`
    entry rather than a function parameter since its result is never
    used, only its side effect (raising 429) matters, exactly like
    FastAPI's own documented pattern for dependencies with no return
    value the endpoint needs.

    Step 11J: emits AUTH_LOGIN_SUCCESS (with the real, validated
    `result.user.id` as actor_user_id) or AUTH_LOGIN_FAILURE (with NO
    user id at all — see AuthService.login()'s own docstring on why a
    failed attempt must never be resolved to a real account; only a
    one-way fingerprint of the submitted, unverified email is logged,
    for cross-attempt correlation, never the email itself). Logged only
    AFTER service.login() has actually returned/raised — never logged as
    successful before the real outcome is known.
    """
    client_ip = get_client_ip(request)
    login_fingerprint = fingerprint_login_identifier(normalize_email(payload.email))

    try:
        result = service.login(payload.email, payload.password)
    except InvalidCredentialsError as exc:
        log_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_LOGIN_FAILURE,
                method=request.method,
                path=request.url.path,
                status_code=401,
                client_ip=client_ip,
                login_identifier_fingerprint=login_fingerprint,
            )
        )
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except JWTConfigurationError as exc:
        logger.exception("JWT signing key is not configured; cannot issue an access token")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication is not available."
        ) from exc

    log_security_event(
        SecurityEvent(
            event_type=SecurityEventType.AUTH_LOGIN_SUCCESS,
            method=request.method,
            path=request.url.path,
            status_code=200,
            actor_user_id=str(result.user.id),
            client_ip=client_ip,
            login_identifier_fingerprint=login_fingerprint,
        )
    )
    return LoginResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=result.expires_in,
        user=UserRead.model_validate(result.user),
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh(
    payload: RefreshRequest,
    service: TokenService = Depends(get_token_service),
) -> TokenResponse:
    """Rotate a refresh token: validate it, mint a fresh access/refresh
    pair in the same token family, and revoke the presented token (see
    app.services.token_service's own docstring for the full rotation /
    reuse-detection model). Every failure mode (unknown token, expired,
    already-rotated/reused, inactive account) returns the identical 401
    with the identical generic message, for the same enumeration-
    resistance reasoning as login().
    """
    try:
        result = service.refresh(payload.refresh_token)
    except InvalidRefreshTokenError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc)) from exc
    except JWTConfigurationError as exc:
        logger.exception("JWT signing key is not configured; cannot issue an access token")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail="Authentication is not available."
        ) from exc
    return TokenResponse(
        access_token=result.access_token,
        refresh_token=result.refresh_token,
        expires_in=result.expires_in,
    )
