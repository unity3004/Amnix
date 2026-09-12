"""Pydantic schemas for registration/login (Step 11C).

Deliberately minimal shape validation only — business rules (email
normalization, the 12-character password minimum, duplicate detection)
live in app.services.auth_service, not here, matching how AlertCreate's
schema validates shape/bounds while AlertService owns business logic
(see app.schemas.alert). `email`/`password` are plain bounded strings,
not a format-validating EmailStr: that would require a new dependency
(`pydantic[email]`) that nothing in this step's discovery showed is
actually required, and format validation was never asked for — only
normalization (see app.core.security.normalize_email) and uniqueness.

Step 11K: `password` (both RegisterRequest and LoginRequest) and
RefreshRequest.refresh_token below all gained an explicit `max_length`
— the central invariant this step establishes is that an oversized
credential must never reach Argon2 hashing/verification or refresh-
token hashing/database lookup at all. Pydantic rejects it with a 422
before the route function body ever runs, so
AuthService.register()/login() and TokenService.refresh() are never
even called for an over-limit value. The MINIMUM password length (12)
is deliberately NOT duplicated here — it stays exactly where it already
was, enforced once in app.core.security.validate_password_length() via
AuthService.register() — adding a second, redundant min_length=12 here
would be exactly the kind of multi-layer validation duplication this
step's own brief warns against, with no corresponding security benefit
(the minimum is a business rule about password strength, not an input-
size DoS boundary the way the maximum is). See app.api.auth's own
docstring for how FastAPI's default validation-error response would
otherwise echo the full rejected value back to the client, and why a
dedicated, narrowly-scoped exception handler prevents that specifically
for these two field names.

RegisterRequest uses `extra="forbid"` specifically so a client can never
submit `role`, `is_active`, `password_hash`, or `id` — those fields
simply do not exist on this schema, so submitting them is a 422 before
AuthService.register() is ever called. This is what makes "no privilege
escalation through registration" true by construction, exactly like
AlertCreate's own docstring describes for `status`.

UserRole mirrors app.models.user's `role` CHECK constraint
('analyst' | 'admin'), the same way AlertStatus/DetectionSeverity mirror
their own DB CHECK-constrained columns elsewhere in this codebase — it
exists purely for the API-facing schema/OpenAPI documentation; the ORM
model itself still stores a plain CHECK-constrained string.
"""

import uuid
from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class UserRole(str, Enum):
    ANALYST = "analyst"
    ADMIN = "admin"


class RegisterRequest(BaseModel):
    """Input schema for POST /auth/register. Only `email`/`password` are
    accepted — see this module's docstring for why that is itself the
    privilege-escalation mitigation, not an incidental detail.

    Step 11K: `password` gained `max_length=128` — the minimum (12) is
    still enforced only in AuthService.register(), unchanged; see this
    module's own docstring for why the maximum lives here instead.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class LoginRequest(BaseModel):
    """Input schema for POST /auth/login.

    Step 11K: `password` gained `max_length=128` (see this module's own
    docstring). No minimum is enforced here, unchanged from before this
    step — login checks a submitted password against a stored hash, it
    never had a length floor of its own.
    """

    model_config = ConfigDict(extra="forbid")

    email: str = Field(min_length=1, max_length=320)
    password: str = Field(min_length=1, max_length=128)


class UserRead(BaseModel):
    """Safe, public representation of a User — returned by both
    registration and login. Never includes password or password_hash;
    there is no field on this schema that could expose either even by
    accident, matching CopilotAuditResponse's own "the field list is the
    content-exposure boundary" design (see app.schemas.copilot_audit).
    """

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime
    updated_at: datetime


class TokenResponse(BaseModel):
    """Shared shape of both POST /auth/login's and POST /auth/refresh's
    token payload (Step 11D). Deliberately excludes anything about how
    the tokens are stored server-side — no token_hash, no refresh-token
    database id, no family_id (see app.models.refresh_token) — a client
    only ever needs the two raw token strings themselves. `token_type`
    is always "Bearer"; `expires_in` is seconds, matching OAuth2's
    conventional field name/units rather than inventing a new one.
    """

    model_config = ConfigDict(extra="forbid")

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int


class LoginResponse(TokenResponse):
    """POST /auth/login's response: the shared token payload plus the
    safe user representation (see the Step 11D brief's example response
    shape). Not returned by POST /auth/refresh, which has no reason to
    re-send the full user record on every token rotation.
    """

    user: UserRead


class UserStatusUpdate(BaseModel):
    """Input schema for PATCH /admin/users/{user_id}/status (Step 11G).

    Deliberately single-field, extra="forbid" -- mirrors
    AlertStatusUpdate's own reasoning (see app.schemas.alert): this is
    the only endpoint that can mutate an existing user's account state,
    and it can mutate exactly one thing. `role`, `email`, and
    `password_hash` are not reachable through this schema at all, not
    merely ignored -- there is no field here a client could use to
    request a role change or any other account modification.
    """

    model_config = ConfigDict(extra="forbid")

    is_active: bool


class RefreshRequest(BaseModel):
    """Input schema for POST /auth/refresh. `extra="forbid"` for the
    same reason every other request schema in this module uses it —
    there is no field here a client could use to influence anything
    beyond which refresh token is being presented.

    Step 11K: `refresh_token` gained `max_length=512` — real refresh
    tokens are ~43 characters (32 bytes of CSPRNG output, URL-safe
    base64-encoded; see app.core.tokens.generate_refresh_token()), so
    512 leaves very generous headroom while still guaranteeing an
    oversized value is rejected before app.core.tokens.
    hash_refresh_token() or any refresh-token repository lookup ever
    runs (see app.services.token_service.TokenService.refresh(), the
    only caller).
    """

    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=512)
