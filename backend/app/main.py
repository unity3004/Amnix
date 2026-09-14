"""AMNIX FastAPI application entrypoint.

============================================================
Step 11L: HTTP security boundary
============================================================

AMNIX has no reverse proxy, load balancer, or TLS-termination layer
defined anywhere in this repository (verified during Step 11L discovery
— only Postgres/Redis are containerized in infrastructure/docker-
compose.yml; the backend itself runs as a single `uvicorn` process, see
backend/Dockerfile). Because of that, this application-level boundary is
currently the ONLY place AMNIX can enforce Host validation, CORS policy,
and response security headers — none of it can be assumed to already be
handled upstream. Strict-Transport-Security is deliberately NOT among
these headers for exactly this reason: AMNIX cannot currently know
whether the connection it is serving is really HTTPS (no trusted-proxy
`X-Forwarded-Proto` handling exists), and sending HSTS over what might
be plain local-development HTTP would be actively wrong. Revisit HSTS
once a real deployment defines TLS termination and forwards a trustworthy
"this was HTTPS" signal to the application.

Middleware order (outermost to innermost — see `app.add_middleware`
calls below, added in the exact reverse of this list, since Starlette
makes the LAST-added middleware the OUTERMOST one):

    1. TrustedHostMiddleware   — reject an unrecognized Host header
                                  before anything else runs at all.
    2. RequestBodySizeLimitMiddleware (Step 11I) — reject an oversized
                                  body before Pydantic ever parses it.
    3. CORSMiddleware          — cross-origin policy decision.
    4. SecurityHeadersMiddleware — appended to every response, from any
                                  layer below this point, including
                                  error responses the other three
                                  produce.
    5. FastAPI routing → RequestValidationError handling (Step 11K) →
       authentication (Step 11E) → RBAC (Step 11F) → route handlers.

This exact order matches the Step 11L brief's own reference diagram.
"""

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.exceptions import RequestValidationError
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.ai.factory import get_ai_provider
from app.api.admin import router as admin_router
from app.api.alerts import router as alerts_router
from app.api.auth import redact_sensitive_validation_errors
from app.api.auth import router as auth_router
from app.api.cases import router as cases_router
from app.api.events import router as events_router
from app.api.health import router as health_router
from app.core.config import get_settings
from app.middleware.request_size_limit import RequestBodySizeLimitMiddleware
from app.middleware.security_headers import SecurityHeadersMiddleware

settings = get_settings()


@asynccontextmanager
async def _lifespan(_: FastAPI) -> AsyncIterator[None]:
    """Construct the configured AIProvider once at startup so a bad
    AI_PROVIDER value or missing Anthropic configuration fails the
    process immediately, rather than surfacing as a 502 on an analyst's
    first Copilot request. get_ai_provider() is cached, so this reuses
    the same instance the API layer will use.
    """
    get_ai_provider()
    yield


app = FastAPI(
    title="AMNIX",
    description="AI-powered Security Operations Copilot",
    debug=settings.debug,
    lifespan=_lifespan,
)

app.include_router(health_router)
app.include_router(auth_router)
app.include_router(events_router)
app.include_router(alerts_router)
app.include_router(cases_router)
app.include_router(admin_router)

# Step 11K: redacts the raw submitted value from any validation error on
# a "password" or "refresh_token" field (FastAPI's default handler would
# otherwise echo it verbatim in the 422 response body) -- see
# app.api.auth.redact_sensitive_validation_errors's own docstring for
# the full reasoning and for why this is applied globally rather than
# scoped to /auth/* routes.
app.add_exception_handler(RequestValidationError, redact_sensitive_validation_errors)

# ============================================================
# Step 11L: HTTP security boundary middleware stack
# ============================================================
# Registered in the EXACT REVERSE of the desired outer-to-inner order --
# see this module's own docstring above for the full order and
# reasoning. Starlette makes the LAST middleware added via
# add_middleware() the OUTERMOST layer, so TrustedHostMiddleware (meant
# to be outermost) is added LAST here, and SecurityHeadersMiddleware
# (meant to be innermost of the four) is added FIRST.

# Innermost of the four: appended to every response from any layer
# below this point, including error responses CORS/body-limit/host
# validation themselves produce.
app.add_middleware(SecurityHeadersMiddleware)

# CORS: no wildcard, no credentials (see app.core.config.Settings.
# cors_allowed_origins's own docstring for why the default is empty --
# no frontend exists in this repository to hard-code an origin for).
# allow_credentials=False is a deliberate, correct choice, not a
# placeholder: AMNIX authenticates via an explicit `Authorization:
# Bearer <token>` header (Step 11E), never cookies, so the CORS
# "credentials" mode (which governs cookie/HTTP-auth transmission) has
# no legitimate use case here -- omitting it entirely also sidesteps the
# classic wildcard-plus-credentials misconfiguration by construction,
# on top of the explicit "*" rejection already enforced at the config
# layer. allow_headers includes exactly the one non-safelisted header a
# cross-origin AMNIX client actually needs to send (Authorization);
# Content-Type is already in Starlette's own CORS safelist and does not
# need to be listed again. allow_methods matches AMNIX's actual route
# verbs -- GET/POST/PATCH plus DELETE (Step 12R: DELETE /cases/{id}/
# alerts/{alert_id}, the first DELETE route in AMNIX -- unlinks a
# case_alerts join row only, never deletes an Alert itself). OPTIONS
# itself is the preflight verb, not something routes need independent
# permission for.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_allowed_origins_list,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Authorization"],
    allow_credentials=False,
)

# Step 11I: rejects an oversized request body at the ASGI layer, before
# Pydantic ever parses it. Unmodified from Step 11I except for its
# position in this now-larger middleware stack -- see app.middleware.
# request_size_limit's own docstring for the control itself.
app.add_middleware(RequestBodySizeLimitMiddleware, max_bytes=settings.max_request_body_bytes)

# Outermost: reject an unrecognized Host header before any other
# middleware or application code runs at all. www_redirect=False --
# AMNIX has no "www." variant of anything and no reason to auto-redirect
# one; an unmatched Host is simply rejected, not speculatively
# redirected. See Settings.trusted_hosts's own docstring for exactly
# which hosts are allowed by default and why.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.trusted_hosts_list, www_redirect=False)
