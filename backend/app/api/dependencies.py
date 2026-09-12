"""Shared FastAPI dependencies (Step 11E): Bearer access-token
authentication.

Lives in app.api (not app.core) deliberately: this module is inherently
FastAPI-aware (Depends, HTTPBearer, HTTPException) and is shared across
multiple routers (app.api.events, app.api.alerts) the same way
app.api.alerts.get_alert_service etc. are already DI factory functions
colocated with the routes that use them — this is the one dependency
none of those individual router files exclusively owns, so it gets its
own small module rather than being force-fit into one of them. app.core
(config/database/redis/security/tokens) stays framework-agnostic, as it
already was before this step — nothing here is added to it.

Reuses Step 11D's app.core.tokens.decode_access_token() unmodified for
all JWT verification (signature, algorithm, issuer, audience,
expiration, required claims, subject/role/jti shape) — this module does
not parse or verify a JWT itself. It also reuses
app.repositories.user.UserRepository.get_by_id() unmodified — no new
User-lookup logic.

Trust boundary (see get_current_user()'s own docstring for the full
flow): the JWT's own `role` claim is validated for *shape* only
(decode_access_token() already rejects a structurally invalid role) and
is otherwise NEVER trusted as the authoritative identity — the
AuthenticatedUser returned here always carries the CURRENT User.role
freshly loaded from PostgreSQL, so a stale or forged token claim can
never diverge from the account's real, current state. This is what
makes "valid JWT + deleted/deactivated user -> 401" possible without any
access-token revocation storage (see this module's docstring for why
that is intentionally out of scope for Step 11E).

No RBAC: this module establishes WHO is calling (authentication) and
nothing about WHAT they may do (authorization) — every route that uses
get_current_user() accepts any active user's token equally, analyst or
admin. Role-based route restriction is Step 11F, not here.

Step 11F adds require_roles() / require_admin below: a small
authorization layer built strictly on top of the AuthenticatedUser
authentication already establishes. Authorization is intentionally a
second, separate dependency layered after get_current_user(), not a
change to it — decode_access_token() and get_current_user() are
untouched by this step. require_roles() reads only
AuthenticatedUser.role (the database-backed value get_current_user()
already resolved); it never inspects the request, decodes a JWT, or
queries the database itself. An authenticated user whose role is not
in the required set gets 403 (authorization failure), never 401
(reserved exclusively for authentication failure) — see require_roles()
for the fail-closed handling of any role value outside the fixed
'analyst'/'admin' vocabulary.
"""

import logging
import uuid
from dataclasses import dataclass

import redis
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import get_settings
from app.core.database import get_db
from app.core.rate_limit import check_and_increment
from app.core.redis import get_redis_client
from app.core.security_events import SecurityEvent, SecurityEventType, log_security_event
from app.core.tokens import InvalidAccessTokenError, decode_access_token
from app.repositories.user import UserRepository

logger = logging.getLogger(__name__)


def get_client_ip(request: Request) -> str:
    """The one safe client-IP concept used everywhere in AMNIX that logs
    or rate-limits by client address (this module's own
    enforce_login_rate_limit, get_current_user's AUTH_TOKEN_INVALID/
    AUTH_USER_INACTIVE events, and app.api.auth/app.api.admin's login/
    admin security events). Deliberately just `request.client.host` --
    no `X-Forwarded-For` or other proxy header is ever consulted, since
    AMNIX has no TrustedHostMiddleware or reverse-proxy trust
    configuration anywhere (verified during Step 11H/11J discovery): an
    arbitrary client-supplied `X-Forwarded-For` header is not
    authoritative unless a specific trusted proxy hop is configured to
    strip/validate it, which does not exist here. Trusting it anyway
    would let any caller forge whatever "client IP" they want in every
    downstream rate-limit key and security log.
    """
    return request.client.host if request.client is not None else "unknown"

# auto_error=False is required, not incidental: FastAPI's own default
# (auto_error=True) raises 403 for a missing/malformed Authorization
# header, which would silently violate the "every authentication
# failure is 401, never 403" invariant this step requires for the one
# case FastAPI would otherwise handle before this function's body ever
# runs. Handling it explicitly below is what makes every failure mode
# converge on the same 401 response.
_bearer_scheme = HTTPBearer(auto_error=False)

_UNAUTHENTICATED_DETAIL = "Could not validate credentials."


@dataclass(frozen=True)
class AuthenticatedUser:
    """The authenticated principal a protected route receives — a
    deliberately small, safe projection of the current User row (see
    this module's docstring for why it is always freshly loaded from
    the database, never taken from the token's own claims). No
    password/password_hash field exists on this type at all.
    """

    id: uuid.UUID
    email: str
    role: str
    is_active: bool


def _unauthenticated() -> HTTPException:
    """One constructor for the one response every authentication
    failure produces — see get_current_user()'s docstring for the full
    list of failure modes this covers. Never parameterized with any
    detail about *why* (missing token vs. expired vs. tampered vs.
    unknown user vs. inactive user are all externally identical), and
    always carries WWW-Authenticate: Bearer per the Bearer auth spec.
    """
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=_UNAUTHENTICATED_DETAIL,
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedUser:
    """The one reusable authentication dependency every protected route
    uses (Depends(get_current_user)). Flow: extract the Bearer
    credential (HTTPBearer, not manual header parsing) -> validate the
    JWT via Step 11D's decode_access_token() (signature, algorithm,
    issuer, audience, expiration, required claims, subject/role/jti
    shape — see that function's own docstring for the exact list) ->
    load the current User by the token's subject -> require it to exist
    and be active -> return a database-backed AuthenticatedUser.

    Every failure below raises the exact same _unauthenticated() 401 —
    missing/empty/wrong-scheme Authorization header (HTTPBearer with
    auto_error=False returns None for all of these, verified against
    FastAPI's actual runtime behavior rather than assumed), any
    JWT-validation failure decode_access_token() raises
    (InvalidAccessTokenError already collapses expired/tampered/
    malformed/alg=none/alternate-algorithm/wrong-issuer/wrong-audience/
    missing-or-invalid-claims into one type — see app.core.tokens), an
    unknown user id, and an inactive user. None of these are
    distinguishable from the response alone, by design (see this
    module's docstring on why the token claim is never trusted over the
    live database row).

    Step 11J: two distinct SECURITY events are logged internally for
    these externally-identical failures — AUTH_TOKEN_INVALID (missing
    header, or any JWT-validation failure: the token itself is bad, no
    validated identity exists) vs. AUTH_USER_INACTIVE (the token's
    signature/claims were cryptographically valid, but the user it names
    is missing or disabled). This distinction is deliberately never
    exposed in the HTTP response (see above) — it exists only in the
    logs, for a SOC analyst's benefit, and never becomes an
    externally-observable enumeration signal. AUTH_USER_INACTIVE logs
    `claims.user_id` as `actor_user_id` because it IS trustworthy here
    (the token's signature already proved it was legitimately issued for
    that id); AUTH_TOKEN_INVALID never logs any claimed subject, because
    an invalid/unsigned/tampered token's claims cannot be trusted at all
    — logging an attacker-supplied "user id" as if it were real would be
    logging fabricated data as fact.
    """
    client_ip = get_client_ip(request)

    if credentials is None:
        log_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_TOKEN_INVALID,
                method=request.method,
                path=request.url.path,
                status_code=401,
                client_ip=client_ip,
            )
        )
        raise _unauthenticated()

    try:
        claims = decode_access_token(credentials.credentials)
    except InvalidAccessTokenError as exc:
        log_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_TOKEN_INVALID,
                method=request.method,
                path=request.url.path,
                status_code=401,
                client_ip=client_ip,
            )
        )
        raise _unauthenticated() from exc

    user = UserRepository(db).get_by_id(claims.user_id)
    if user is None or not user.is_active:
        log_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_USER_INACTIVE,
                method=request.method,
                path=request.url.path,
                status_code=401,
                actor_user_id=str(claims.user_id),
                client_ip=client_ip,
            )
        )
        raise _unauthenticated()

    return AuthenticatedUser(id=user.id, email=user.email, role=user.role, is_active=user.is_active)


# =============================================================================
# Step 11F: authorization (RBAC)
# =============================================================================

# The fixed, small role vocabulary — mirrors the User.role CHECK
# constraint exactly (see app.models.user). Not configurable, not a
# permissions table: a role value outside this set can only mean a
# defensive-programming edge case (e.g. a future migration widening the
# DB constraint before this set is updated to match), and must never be
# treated as privileged — see require_roles() below.
_KNOWN_ROLES = frozenset({"analyst", "admin"})

_FORBIDDEN_DETAIL = "Insufficient permissions."


def _forbidden() -> HTTPException:
    """One constructor for the one response every authorization failure
    produces. Deliberately generic (never names the required role, the
    caller's actual role, or anything else about why) and deliberately
    403, not 401 — the caller already proved who they are via
    get_current_user(); this is a decision about what they may do.
    """
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=_FORBIDDEN_DETAIL)


def require_roles(*roles: str):
    """Dependency factory: build a FastAPI dependency that only lets an
    authenticated user through if AuthenticatedUser.role is one of
    `roles`. Usage: `Depends(require_roles("admin"))`, or bind once and
    reuse (see require_admin below).

    Authorization input is exclusively `current_user.role`, itself
    obtained by depending on get_current_user() — nothing here parses a
    JWT, reads a header, reads a query parameter, or reads a request
    body. That is what makes "role cannot be supplied through the
    request" true by construction rather than by convention: there is
    no code path in this function that ever looks at anything other
    than the AuthenticatedUser FastAPI already resolved via the
    authentication dependency.

    Fails closed: a role that is not in the fixed `_KNOWN_ROLES`
    vocabulary is never treated as satisfying any requirement, no
    matter what `roles` was called with — an unrecognized role is
    always denied, never implicitly privileged. This can only be
    reached defensively today (User.role is DB CHECK-constrained to
    'analyst'/'admin'), but the check costs nothing and removes any
    temptation for a future caller to assume "not explicitly denied"
    means "allowed".
    """
    if not roles:
        raise ValueError("require_roles() requires at least one role")
    allowed = frozenset(roles)
    unknown = allowed - _KNOWN_ROLES
    if unknown:
        raise ValueError(f"require_roles() received unknown role(s): {sorted(unknown)}")

    def _require_roles(
        request: Request, current_user: AuthenticatedUser = Depends(get_current_user)
    ) -> AuthenticatedUser:
        if current_user.role not in _KNOWN_ROLES or current_user.role not in allowed:
            log_security_event(
                SecurityEvent(
                    event_type=SecurityEventType.AUTHORIZATION_DENIED,
                    method=request.method,
                    path=request.url.path,
                    status_code=403,
                    actor_user_id=str(current_user.id),
                    client_ip=get_client_ip(request),
                )
            )
            raise _forbidden()
        return current_user

    return _require_roles


# Bound once and reused wherever an admin-only operation is introduced
# (see this module's docstring — no such production route exists yet in
# Step 11F; this primitive is established for future use, per the Step
# 11F brief's explicit instruction not to manufacture one prematurely).
require_admin = require_roles("admin")


# =============================================================================
# Step 11H: login rate limiting
# =============================================================================

_RATE_LIMIT_DETAIL = "Too many login attempts. Please try again later."


def enforce_login_rate_limit(request: Request) -> None:
    """Blunt, Redis-backed protection against scripted credential
    stuffing/brute force against POST /auth/login — the one route in
    AMNIX with no other throttle on repeated attempts (Argon2id's own
    per-attempt CPU cost is a weak, incidental brake at best; this is a
    deliberate one). Applied to /auth/login only — see the Step 11H
    final report for why no other route was judged to need this in this
    step.

    Keyed on the request's client IP alone, not the submitted email:
    keying (even partly) on attacker-controlled input the endpoint
    itself is validating would let an attacker learn something about
    which emails are "interesting" by observing whether their own limit
    tightens differently per email — the account-enumeration risk
    AuthService.login() already goes to deliberate lengths to avoid (see
    its own docstring). IP-based limiting adds no such oracle: every
    caller from the same source shares one budget regardless of which
    email they submit.

    Fails OPEN, not closed, if Redis itself is unreachable: a rate
    limiter that takes down all logins during a Redis outage would trade
    a availability incident for a marginal, already-mitigated-elsewhere
    security control. Every open-fail is logged (safe metadata only — no
    tokens, no request body) so a real Redis outage is still visible in
    the application logs, just not fatal to authentication. This is an
    explicit, documented trade-off, not an oversight — see the final
    report's security review for the alternative considered and why it
    was rejected for this step.
    """
    settings = get_settings()
    client_ip = get_client_ip(request)
    key = f"ratelimit:login:{client_ip}"

    try:
        redis_client = get_redis_client()
        result = check_and_increment(
            redis_client,
            key=key,
            max_attempts=settings.login_rate_limit_max_attempts,
            window_seconds=settings.login_rate_limit_window_seconds,
        )
    except redis.RedisError:
        logger.warning("Login rate limiter backend unavailable; allowing request without rate limiting.")
        return

    if not result.allowed:
        log_security_event(
            SecurityEvent(
                event_type=SecurityEventType.AUTH_RATE_LIMITED,
                method=request.method,
                path=request.url.path,
                status_code=429,
                client_ip=client_ip,
            )
        )
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=_RATE_LIMIT_DETAIL,
            headers={"Retry-After": str(result.retry_after_seconds)},
        )
