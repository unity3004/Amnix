"""AuthService: registration and credential-authentication business
logic (Step 11C, extended in Step 11D to issue tokens on login).

Built entirely on Step 11B's foundation — this file reuses
normalize_email(), hash_password(), verify_password(), and
validate_password_length() from app.core.security, and User/
UserRepository from app.models.user / app.repositories.user, unmodified.
It does not implement its own cryptography, its own email-normalization
rule, or a second User repository.

Step 11D change: login() now returns a LoginResult (User + access/
refresh token pair) instead of a bare User — see that class's own
docstring. Token *issuance* itself is entirely TokenService's
responsibility (app.services.token_service); AuthService only decides
*whether* credentials are valid and, once they are, asks TokenService
for a fresh token pair. AuthService still performs no JWT
encoding/decoding and no refresh-token generation/hashing itself.
register() is unchanged — no token is issued at registration (nothing
in this step's discovery showed that's needed; see the final report).

Account-enumeration mitigation (see login()'s docstring for the exact
mechanism): a nonexistent email, a wrong password, and an inactive
account must all be externally indistinguishable. This module achieves
that by (a) always raising the exact same InvalidCredentialsError with
the exact same generic message for all three cases, and (b) always
performing one Argon2id verification per login attempt — against the
real stored hash when a user row exists, or against a fixed, precomputed
decoy hash when it doesn't — so a nonexistent-email attempt costs
roughly the same CPU time as a real one instead of returning instantly.
Token issuance only ever happens after all of that succeeds, so it adds
no new enumeration signal of its own.
"""

from typing import NamedTuple

from sqlalchemy.exc import IntegrityError

from app.core.security import hash_password, normalize_email, validate_password_length, verify_password
from app.models.user import User
from app.repositories.user import UserRepository
from app.schemas.auth import UserRole
from app.services.token_service import TokenService

# Step 11A/10: a fixed, precomputed-once Argon2id hash of a password that
# is never used for any real account — its only purpose is to give
# verify_password() something real to do when no User row exists, so the
# nonexistent-email login path costs roughly the same CPU time as a
# real-user path instead of returning immediately. Computed exactly once
# at import time (never regenerated per request) per the Step 11A
# roadmap's explicit instruction.
_DECOY_PASSWORD_HASH = hash_password("amnix-decoy-password-never-used-for-a-real-account-6f1c9a")


class AuthServiceError(Exception):
    """Base class for every error AuthService raises."""


class EmailAlreadyRegisteredError(AuthServiceError):
    """Raised when the normalized email is already registered — from
    either the pre-insert check or a concurrent-registration race
    against the database's own unique index (see register()'s
    docstring). The message is generic on purpose: registration
    conflicts are visible to the client by design (the client just
    submitted that email), so this is not an enumeration concern the way
    login() is, but it still must never include the password or any
    database/ORM detail.
    """

    def __init__(self) -> None:
        super().__init__("Email is already registered.")


class InvalidCredentialsError(AuthServiceError):
    """Raised for every login failure mode (nonexistent email, wrong
    password, inactive account) with the exact same generic message —
    see this module's docstring for why that uniformity is the point,
    not an oversight.
    """

    def __init__(self) -> None:
        super().__init__("Invalid email or password.")


class LoginResult(NamedTuple):
    """Everything a successful login produces: the authenticated User
    plus a fresh access/refresh token pair (Step 11D). Kept as one
    result type rather than returning a bare User and having the API
    route separately call TokenService itself, so "login" remains one
    atomic operation from AuthService's own callers' point of view —
    exactly matching the Step 11D brief's login flow diagram (credentials
    valid -> mint tokens -> return token pair + safe user, as a single
    sequence).
    """

    user: User
    access_token: str
    refresh_token: str
    expires_in: int


class AuthService:
    def __init__(self, user_repository: UserRepository, token_service: TokenService) -> None:
        self._user_repository = user_repository
        self._token_service = token_service

    def register(self, email: str, password: str) -> User:
        """Register a new analyst account. Role is always
        UserRole.ANALYST — there is no parameter here that could set it
        to anything else, matching RegisterRequest's own `extra="forbid"`
        guarantee that a client can never submit a role at all (see
        app.schemas.auth). Raises PasswordTooShortError (from
        app.core.security, unmodified) if `password` is too short, or
        EmailAlreadyRegisteredError if the normalized email is already
        registered.
        """
        normalized_email = normalize_email(email)
        # validate_password_length() raises PasswordTooShortError (a
        # ValueError subclass) — propagated as-is, not wrapped, since it
        # already has a safe __str__ that never echoes the password.
        validate_password_length(password)

        if self._user_repository.get_by_email(normalized_email) is not None:
            raise EmailAlreadyRegisteredError()

        user = User(
            email=normalized_email,
            password_hash=hash_password(password),
            role=UserRole.ANALYST.value,
            is_active=True,
        )
        try:
            return self._user_repository.create(user)
        except IntegrityError as exc:
            # Two concurrent registrations for the same normalized email
            # can both pass the get_by_email() check above before either
            # commits — the database's own unique index (see
            # app.models.user) is the real guarantee. Translate its
            # violation into the exact same typed conflict the pre-check
            # path already raises, never a raw IntegrityError.
            raise EmailAlreadyRegisteredError() from exc

    def login(self, email: str, password: str) -> LoginResult:
        """Authenticate credentials and, on success, return the User
        plus a fresh access/refresh token pair (see LoginResult). Tokens
        are only ever minted after every check below has already
        passed — issuing a token is never itself a code path that could
        leak whether an email exists (see this module's docstring).

        Deliberately verifies the password BEFORE checking `is_active`
        (a refinement of the naive "check active flag, then verify
        password" ordering): if an inactive account's login always
        skipped password verification, the response would return
        instantly instead of after one Argon2id verification, making
        "this email belongs to an inactive account" distinguishable from
        "this email belongs to an active account with a wrong password"
        by timing alone — exactly the enumeration risk this module
        exists to close. Verifying first means every outcome other than
        "nonexistent email" costs the same one real Argon2id
        verification, regardless of whether the account is active.
        """
        normalized_email = normalize_email(email)
        user = self._user_repository.get_by_email(normalized_email)

        if user is None:
            verify_password(password, _DECOY_PASSWORD_HASH)
            raise InvalidCredentialsError()

        password_matches = verify_password(password, user.password_hash)
        if not password_matches or not user.is_active:
            raise InvalidCredentialsError()

        token_pair = self._token_service.issue_new_login_tokens(user)
        return LoginResult(
            user=user,
            access_token=token_pair.access_token,
            refresh_token=token_pair.refresh_token,
            expires_in=token_pair.expires_in,
        )
