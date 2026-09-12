"""Centralized, structured security-event logging (Step 11J).

Framework-agnostic, exactly like app.core.security/app.core.tokens/
app.core.rate_limit: every field this module accepts is a plain typed
value (str/bool/int, never a Request object, an ORM row, a Pydantic
model, or a raw exception) — callers in app.api.* (FastAPI-aware) and
app.middleware.* (pure ASGI) both extract whatever context they have
into these plain fields before calling log_security_event(). This
module never imports FastAPI or Starlette.

WHY A NEW SUBSYSTEM, NOT AN EXTENSION OF EXISTING LOGGING:
    Discovery (see the Step 11J final report) found real logger usage
    throughout AMNIX (app.api.events, app.api.auth, app.api.alerts,
    app.api.admin, app.api.dependencies, app.ai.providers.anthropic,
    app.services.*) -- but every single call site is an unstructured,
    printf-style operational log line (`logger.exception("Failed to X
    for %s", id)`), not a machine-readable event with a controlled
    schema. None of it is replaced here (see each of those modules'
    unchanged logger.* calls) -- this module adds a second, clearly
    distinguishable logger ("amnix.security", not module __name__) for
    a specific, small taxonomy of security-relevant events, while every
    existing operational log line keeps its original meaning and owner.

TAXONOMY (exactly these eight, no more -- see the final report for why
each candidate from the brief's larger list either made the cut or was
deferred):
    AUTH_LOGIN_SUCCESS, AUTH_LOGIN_FAILURE, AUTH_TOKEN_INVALID,
    AUTH_USER_INACTIVE, AUTHORIZATION_DENIED, AUTH_RATE_LIMITED,
    ADMIN_USER_STATUS_CHANGED, REQUEST_BODY_TOO_LARGE.

EVERY EVENT TYPE HAS A FIXED, NON-CALLER-SUPPLIED OUTCOME:
    None of the eight event types above is ever legitimately logged
    with both a success and a failure meaning (e.g. AUTH_LOGIN_FAILURE
    is definitionally a failure; ADMIN_USER_STATUS_CHANGED is only ever
    emitted after a real successful mutation -- see app.api.admin).
    `outcome` is therefore a derived property, not a constructor
    argument -- there is no code path that can construct an
    AUTH_LOGIN_SUCCESS event with outcome="failure" by mistake.

FAILURE ISOLATION:
    log_security_event() never raises. The only try/except in this
    entire module wraps nothing but the act of emitting the log record
    itself -- never a decision about whether an event occurred, and
    never any business/security logic. See that function's own
    docstring for why this is the one deliberately broad except in
    AMNIX rather than a violation of the "no broad exception
    swallowing" rule.
"""

import hashlib
import json
import logging
import sys
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum

_logger = logging.getLogger("amnix.security")


def _configure_security_logger() -> None:
    """AMNIX has no global `logging.basicConfig()` call anywhere in the
    application (verified during Step 11J discovery — grepped the whole
    `app/` tree). Without one, Python's logging module falls back to
    `logging.lastResort`: a bare stderr handler that only emits WARNING
    and above. That happens to make WARNING-level security events
    (AUTH_TOKEN_INVALID, AUTHORIZATION_DENIED, AUTH_RATE_LIMITED, ...)
    already visible on stderr — but INFO-level ones (AUTH_LOGIN_SUCCESS,
    ADMIN_USER_STATUS_CHANGED) are silently dropped entirely. This was
    not assumed — it was discovered by live-testing a real login against
    a real running server and finding the AUTH_LOGIN_SUCCESS record
    simply never appeared anywhere (see the Step 11J final report's live
    verification section), then fixed here.

    The fix is deliberately narrow: attach one plain `StreamHandler`
    directly to the `amnix.security` logger ONLY — never the root
    logger, never any other AMNIX logger (`app.api.events`,
    `app.services.copilot_service`, ...), all of which keep their exact
    pre-existing, unrelated behavior untouched. Propagation to the root
    logger is left at its default (True) rather than disabled: nothing
    in AMNIX configures the root logger today (verified — the same
    discovery that found no `logging.basicConfig()` call at all), so
    propagating there is a no-op in practice (root has no handler of its
    own to double-print through) and it keeps this logger's behavior
    fully compatible with standard tools that capture via the root
    logger — including pytest's own `caplog` fixture, which is exactly
    how tests/test_security_events.py and
    tests/test_security_events_wiring.py verify these events (disabling
    propagation was tried first and broke `caplog.at_level(...,
    logger="amnix.security")` outright, which is what surfaced this
    reasoning). If the root logger is ever configured with its own
    handler in the future, revisit this. The handler's
    formatter is just `%(message)s` — the JSON payload from
    `SecurityEvent.to_json()` already carries its own timestamp and
    level-equivalent (`outcome`), so no extra prefix is added that would
    turn a clean, single-line JSON record into something a log consumer
    has to strip before parsing. Writes to stdout, not a file (no log
    rotation infrastructure is introduced) — compatible with container
    stdout/stderr collection out of the box.

    Idempotent: safe if this module is ever imported more than once
    (re-adding a handler on every import would duplicate every log line).
    """
    if _logger.handlers:
        return
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("%(message)s"))
    _logger.addHandler(handler)
    _logger.setLevel(logging.INFO)


_configure_security_logger()


class SecurityEventType(str, Enum):
    """The complete, fixed security-event taxonomy. Adding a ninth value
    here is a deliberate future decision, not something a caller can do
    implicitly -- see this module's own docstring for why exactly these
    eight and no others.
    """

    AUTH_LOGIN_SUCCESS = "AUTH_LOGIN_SUCCESS"
    AUTH_LOGIN_FAILURE = "AUTH_LOGIN_FAILURE"
    AUTH_TOKEN_INVALID = "AUTH_TOKEN_INVALID"
    AUTH_USER_INACTIVE = "AUTH_USER_INACTIVE"
    AUTHORIZATION_DENIED = "AUTHORIZATION_DENIED"
    AUTH_RATE_LIMITED = "AUTH_RATE_LIMITED"
    ADMIN_USER_STATUS_CHANGED = "ADMIN_USER_STATUS_CHANGED"
    REQUEST_BODY_TOO_LARGE = "REQUEST_BODY_TOO_LARGE"


class SecurityEventOutcome(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


_OUTCOME_BY_EVENT_TYPE: dict[SecurityEventType, SecurityEventOutcome] = {
    SecurityEventType.AUTH_LOGIN_SUCCESS: SecurityEventOutcome.SUCCESS,
    SecurityEventType.AUTH_LOGIN_FAILURE: SecurityEventOutcome.FAILURE,
    SecurityEventType.AUTH_TOKEN_INVALID: SecurityEventOutcome.FAILURE,
    SecurityEventType.AUTH_USER_INACTIVE: SecurityEventOutcome.FAILURE,
    SecurityEventType.AUTHORIZATION_DENIED: SecurityEventOutcome.FAILURE,
    SecurityEventType.AUTH_RATE_LIMITED: SecurityEventOutcome.FAILURE,
    SecurityEventType.ADMIN_USER_STATUS_CHANGED: SecurityEventOutcome.SUCCESS,
    SecurityEventType.REQUEST_BODY_TOO_LARGE: SecurityEventOutcome.FAILURE,
}


@dataclass(frozen=True)
class SecurityEvent:
    """One structured security event. Every field is a plain, small,
    already-safe value -- never a Request, an ORM row, a Pydantic model,
    or an exception object. See this module's own docstring for the
    full field-by-field privacy reasoning (also documented per call site
    in app.api.dependencies / app.api.auth / app.api.admin /
    app.middleware.request_size_limit, where each field is actually
    populated).

    Deliberately excluded, on purpose, not by oversight: submitted
    passwords, password hashes, JWTs (access or refresh), token hashes,
    Authorization/Cookie header values, API keys, request bodies,
    Copilot conversation contents, arbitrary query parameters, and full
    exception objects/tracebacks. None of these has a field here at
    all -- there is no code path in this dataclass that could carry one
    even if a caller tried.
    """

    event_type: SecurityEventType
    method: str
    path: str
    status_code: int
    actor_user_id: str | None = None
    target_user_id: str | None = None
    target_is_active: bool | None = None
    client_ip: str | None = None
    login_identifier_fingerprint: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.event_type, SecurityEventType):
            raise TypeError(f"SecurityEvent.event_type must be a SecurityEventType, got {self.event_type!r}")

    @property
    def outcome(self) -> SecurityEventOutcome:
        return _OUTCOME_BY_EVENT_TYPE[self.event_type]

    def to_json(self) -> str:
        """Deterministic, machine-readable serialization -- a real
        controlled schema (every key comes from this dataclass's own
        typed fields, never an arbitrary caller-supplied dict), not
        `json.dumps(some_dict)`. Optional fields that are None are
        omitted entirely rather than serialized as `null`, so a log
        consumer never has to distinguish "explicitly absent" from
        "present but empty". `sort_keys=True` makes output byte-
        deterministic for a given event (useful for tests and for log
        deduplication), not just "valid JSON".
        """
        payload: dict[str, object] = {
            "logger": "amnix.security",
            "event_type": self.event_type.value,
            "outcome": self.outcome.value,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "method": self.method,
            "path": self.path,
            "status_code": self.status_code,
        }
        optional_fields = {
            "actor_user_id": self.actor_user_id,
            "target_user_id": self.target_user_id,
            "target_is_active": self.target_is_active,
            "client_ip": self.client_ip,
            "login_identifier_fingerprint": self.login_identifier_fingerprint,
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = value
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def fingerprint_login_identifier(normalized_email: str) -> str:
    """A one-way, unkeyed SHA-256 fingerprint of an already-normalized
    login identifier (see app.core.security.normalize_email), truncated
    to 16 hex characters (64 bits).

    Purpose: let a SOC analyst correlate repeated login attempts against
    the SAME submitted identifier across log lines (e.g. "this
    fingerprint failed 40 times from 12 different IPs in the last hour")
    without ever storing or being able to recover the actual email
    address from the log. Used for BOTH AUTH_LOGIN_SUCCESS and
    AUTH_LOGIN_FAILURE -- deliberately not a real user id for the
    failure case, since a failed login may not correspond to any real
    account at all (see AuthService.login()'s own account-enumeration
    reasoning, which this mirrors: never treat a submitted, unverified
    email as if it were a confirmed identity).

    Unkeyed on purpose: this is a correlation aid for people who already
    have access to these logs, not a security boundary in itself, so
    there is no secret whose leakage would matter here -- a keyed HMAC
    would add a new secret to provision and rotate for no corresponding
    benefit. Never reversible: SHA-256 truncated to 64 bits cannot be
    inverted back to the original email, and no email->fingerprint
    lookup table is ever persisted anywhere.
    """
    return hashlib.sha256(normalized_email.encode("utf-8")).hexdigest()[:16]


def log_security_event(event: SecurityEvent) -> None:
    """The single point every security event flows through. Emits at
    INFO for a success outcome, WARNING for a failure outcome (matching
    the Step 11J brief's level guidance) -- never ERROR merely because
    an event is security-related; ERROR is reserved for AMNIX's existing
    operational logging (e.g. logger.exception(...) call sites
    elsewhere), untouched by this module.

    Never raises. The try/except below wraps ONLY the act of emitting
    the log record -- not the decision of whether an event occurred, and
    never any authentication/authorization/rate-limit/request-size
    logic (none of that lives in this module at all; every call site
    decides independently whether to call this function, after its own
    real security decision has already been made). This is the one
    deliberately broad `except Exception` in AMNIX: a security-relevant
    request must behave identically whether the logging backend is
    healthy or completely broken (a full disk, a misconfigured handler,
    ...) -- logging is observability, never a security decision point.
    See tests/test_security_events.py's logger-failure tests, which
    prove this holds for every wired-in call site, not just this
    function in isolation.
    """
    try:
        level = logging.INFO if event.outcome is SecurityEventOutcome.SUCCESS else logging.WARNING
        _logger.log(level, event.to_json())
    except Exception:  # noqa: BLE001 - deliberate, see this function's own docstring
        pass
