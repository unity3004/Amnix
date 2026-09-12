"""Token foundation utilities (Step 11D): JWT access-token issuance/
validation, and opaque refresh-token generation/hashing.

Foundation only — nothing here is wired into route authentication yet
(no FastAPI dependency reads an Authorization header or calls
decode_access_token()). That is Step 11E's job. app.services.
token_service (this same step) uses this module to mint/validate tokens
at login/refresh time.

Deliberately independent of app.models/app.schemas, exactly like
app.core.security (password hashing) and app.core.database/redis are:
create_access_token() takes a plain `user_id`/`role`, never a `User` ORM
instance, so this module has zero knowledge of the ORM layer. This
mirrors an existing, already-established layering invariant in
app.core.* — none of its other modules import from app.models or
app.schemas either.

JWT algorithm: HS256, explicitly pinned on both encode and decode. The
token's own `alg` header is NEVER trusted to select verification
behavior — `algorithms=["HS256"]` is passed explicitly to
jwt.decode() every time (see decode_access_token()), which is what
makes an `alg=none` or algorithm-confusion attack structurally
impossible here, not merely unlikely.

Secret: settings.jwt_secret_key, read fresh from get_settings() on
every call (never cached as a module-level global) so tests can
override Settings without reloading this module. Empty/missing secret
fails immediately via JWTConfigurationError rather than signing or
verifying with an empty/predictable key — fail safely, per the Step
11D brief.

Refresh tokens are NOT JWTs — see generate_refresh_token()/
hash_refresh_token() below.
"""

import hashlib
import secrets
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import jwt

from app.core.config import get_settings

ALGORITHM = "HS256"

# Must match app.models.user's `role` CHECK constraint / app.schemas.
# auth.UserRole's values exactly. Duplicated here (rather than imported)
# specifically to preserve app.core's existing independence from
# app.models/app.schemas — see this module's own docstring.
_VALID_ROLES = frozenset({"analyst", "admin"})

# 32 bytes (256 bits) of entropy, URL-safe encoded -- see
# generate_refresh_token()'s own docstring for why this, not uuid4() or
# anything timestamp/identity-derived, is used.
REFRESH_TOKEN_ENTROPY_BYTES = 32


class TokenError(Exception):
    """Base class for every error this module raises."""


class JWTConfigurationError(TokenError):
    """JWT_SECRET_KEY is missing/empty — token issuance/validation
    cannot proceed safely. Never includes the secret (there is none to
    include) or any other configuration detail.
    """

    def __init__(self) -> None:
        super().__init__("JWT signing key is not configured.")


class InvalidAccessTokenError(TokenError):
    """Raised for every access-token validation failure: expired,
    tampered, malformed, wrong/absent algorithm, wrong issuer/audience,
    missing or malformed required claims, invalid subject, invalid role,
    invalid jti — deliberately ONE generic type for all of these,
    exactly like AuthService.InvalidCredentialsError, so a caller never
    needs to distinguish *why* a token was rejected and so raw PyJWT
    exception text is never propagated to anything upstream.
    """

    def __init__(self) -> None:
        super().__init__("Invalid or expired access token.")


@dataclass(frozen=True)
class AccessTokenClaims:
    """Typed result of a successfully validated access token — a
    caller never touches a raw claims dict, so there is no risk of a
    KeyError/typo on an unvalidated field downstream.
    """

    user_id: uuid.UUID
    role: str
    jti: uuid.UUID
    issued_at: datetime
    expires_at: datetime


def create_access_token(*, user_id: uuid.UUID, role: str) -> str:
    """Mint a short-lived JWT access token for `user_id`/`role` — both
    must already be the persisted, authoritative values (see
    app.services.token_service, which always sources them from a freshly
    -loaded User row, never from client input or a prior token's
    claims). Every call produces a fresh, unique `jti`. Never includes a
    password, password_hash, refresh token, token hash, or any claim
    beyond the fixed set the Step 11D brief specifies.
    """
    settings = get_settings()
    if not settings.jwt_secret_key:
        raise JWTConfigurationError()

    now = datetime.now(timezone.utc)
    payload = {
        "sub": str(user_id),
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.jwt_access_token_expire_minutes),
        "jti": str(uuid.uuid4()),
        "iss": settings.jwt_issuer,
        "aud": settings.jwt_audience,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=ALGORITHM)


def decode_access_token(token: str) -> AccessTokenClaims:
    """Validate `token` and return its claims, or raise
    InvalidAccessTokenError for any failure whatsoever (see that
    exception's own docstring for the full list this collapses). Always
    passes `algorithms=[ALGORITHM]` explicitly — the token's own `alg`
    header is never consulted to decide how to verify it.
    """
    settings = get_settings()
    if not settings.jwt_secret_key:
        raise JWTConfigurationError()

    try:
        payload = jwt.decode(
            token,
            settings.jwt_secret_key,
            algorithms=[ALGORITHM],
            issuer=settings.jwt_issuer,
            audience=settings.jwt_audience,
            options={"require": ["sub", "role", "iat", "exp", "jti", "iss", "aud"]},
        )
    except jwt.PyJWTError as exc:
        raise InvalidAccessTokenError() from exc

    try:
        user_id = uuid.UUID(str(payload["sub"]))
    except (ValueError, TypeError) as exc:
        raise InvalidAccessTokenError() from exc

    role = payload.get("role")
    if role not in _VALID_ROLES:
        raise InvalidAccessTokenError()

    try:
        jti = uuid.UUID(str(payload["jti"]))
    except (ValueError, TypeError) as exc:
        raise InvalidAccessTokenError() from exc

    try:
        issued_at = datetime.fromtimestamp(float(payload["iat"]), tz=timezone.utc)
        expires_at = datetime.fromtimestamp(float(payload["exp"]), tz=timezone.utc)
    except (ValueError, TypeError, OverflowError, OSError) as exc:
        raise InvalidAccessTokenError() from exc

    return AccessTokenClaims(user_id=user_id, role=role, jti=jti, issued_at=issued_at, expires_at=expires_at)


def generate_refresh_token() -> str:
    """An opaque, cryptographically random refresh token — never a JWT,
    never derived from uuid4()/timestamps/email/user id or any other
    predictable or identity-linked value. Uses Python's `secrets`
    module (CSPRNG-backed), 32 bytes (256 bits) of entropy, URL-safe
    text encoding. The raw value returned here must exist only in
    memory long enough to return it to the client and hash it (see
    hash_refresh_token()) — it is never itself persisted.
    """
    return secrets.token_urlsafe(REFRESH_TOKEN_ENTROPY_BYTES)


def hash_refresh_token(raw_token: str) -> str:
    """SHA-256 of `raw_token`, as a lowercase hex digest — the only
    representation of a refresh token ever persisted (see
    app.models.refresh_token). Argon2id is deliberately NOT used here:
    it protects low-entropy, human-chosen secrets (passwords) against
    offline guessing, which is not the threat model for a value that is
    already 256 bits of CSPRNG output — a fast cryptographic hash loses
    nothing here and avoids adding needless Argon2 CPU cost to every
    refresh request.
    """
    return hashlib.sha256(raw_token.encode("utf-8")).hexdigest()
