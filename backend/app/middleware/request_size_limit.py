"""Pure-ASGI request body size protection (Step 11I).

Rejects an oversized request body with HTTP 413 before Pydantic ever
parses it — see the module-level docstring section below on why this
has to be pure ASGI middleware, not a FastAPI dependency or
`request.body()` inside a Starlette `BaseHTTPMiddleware`.

Lives in its own top-level package (app.middleware), distinct from both
app.core (framework-agnostic business logic — password hashing, JWT
mechanics, the rate-limit counter primitive) and app.api (FastAPI
dependency-injection code — Depends()-based authentication/authorization).
This is neither: it is raw ASGI protocol handling that runs *outside*
FastAPI's own request/response cycle entirely, wired in via
app.add_middleware() in app.main, not via any route's dependency graph.
No other middleware exists anywhere else in AMNIX before this step
(verified during discovery) — this is the first, and this package is
where any future one belongs too.

WHY NOT `request.body()` THEN `len()`:
    That reads the entire body into memory first and only rejects
    afterward — exactly the "parse first, validate later" pattern this
    step exists to eliminate. It also cannot reject based on a
    Content-Length header without ever touching the socket, and it
    offers no way to abort a legitimately-oversized *streaming* body
    early, mid-transfer.

WHY NOT Starlette's BaseHTTPMiddleware:
    BaseHTTPMiddleware wraps the downstream ASGI app and constructs a
    `Request`/`StreamingResponse` pair around it — internally, calling
    `await request.body()` (or anything that triggers full body
    consumption) inside it exhibits the same "must fully receive before
    you can decide" behavior as the naive approach above, and
    historically BaseHTTPMiddleware has had its own edge cases around
    background tasks and early client disconnects. A raw ASGI middleware
    class, operating directly on `scope`/`receive`/`send`, is the only
    way to inspect Content-Length before ever calling `receive()` at
    all, and to abort a chunked body mid-stream without buffering it.

TWO INDEPENDENT LAYERS, NEITHER SUFFICIENT ALONE:
    1. Content-Length fast path: if the header is present and already
       exceeds the limit, reject immediately -- `receive()` is never
       called even once, so not one byte of the body is ever read from
       the connection.
    2. Incremental byte-counting via a wrapped `receive`: covers a
       missing Content-Length (chunked/streaming clients), a forged
       Content-Length that understates the real body, and is what
       actually enforces the limit against the downstream ASGI app
       (Starlette's own body-reading loop) chunk by chunk, aborting as
       soon as the running total crosses the limit -- never buffering a
       known-oversized body to completion first.

HOW THE ABORT ACTUALLY BECOMES A 413, NOT A 400 OR A 500:
    When the wrapped `receive` detects the limit has been crossed, it
    raises `_RequestBodyTooLarge` -- a real `starlette.exceptions.
    HTTPException(status_code=413)` subclass, not a bare internal signal
    type. That distinction was not cosmetic: an earlier version of this
    middleware used a plain `Exception` subclass here, which worked
    against a hand-written route calling `request.body()` directly, but
    against a REAL AMNIX route (a Pydantic body parameter, e.g. `payload:
    SecurityEventCreate`), FastAPI's own body-reading code in
    fastapi/routing.py wraps that read in a broad `except Exception` that
    converts *any* non-HTTPException into an unrelated, generic
    `HTTPException(400, "There was an error parsing the body")` -- silently
    losing the intended 413 and the size-limit signal entirely. This was
    only discovered by testing an actual oversized chunked-transfer
    request against a real route with a Pydantic body parameter (see the
    Step 11I final report's live verification section) -- no unit test
    using a hand-written `request.body()` call would have caught it,
    since that path bypasses fastapi/routing.py's wrapper altogether.
    Making `_RequestBodyTooLarge` a real HTTPException fixes this two
    ways at once: fastapi/routing.py has an explicit, intentional
    carve-out (`except HTTPException: raise`) for exactly this shape of
    middleware, and Starlette's own `ExceptionMiddleware` (already
    present downstream of this middleware in every FastAPI app's stack)
    knows how to turn any HTTPException into a correct `{"detail": ...}`
    JSON response on its own -- for any route shape, Pydantic body
    parameter or not. This middleware's own `except _RequestBodyTooLarge`
    in `__call__` is only a defensive fallback for the (no longer
    expected) case that the exception somehow reaches back here
    unhandled; the real mechanism is Starlette's own exception handling.
"""

from collections.abc import Awaitable, Callable

from starlette.exceptions import HTTPException

from app.core.security_events import SecurityEvent, SecurityEventType, log_security_event

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_DETAIL_BODY = b'{"detail":"Request body too large."}'


class _RequestBodyTooLarge(HTTPException):
    """Raised from within the wrapped `receive()` once the running byte
    total crosses the configured limit.

    Deliberately a real starlette.exceptions.HTTPException subclass
    (status_code=413, the exact fixed detail this middleware always
    returns) -- NOT a bare internal signal type. This matters more than
    it looks: FastAPI's own body-reading code, in fastapi/routing.py
    (the path a route with a Pydantic body parameter -- i.e. nearly
    every real AMNIX route -- goes through to read its request body),
    wraps that read in a broad `except Exception` that converts ANY
    exception into a generic, unrelated `HTTPException(400, "There was
    an error parsing the body")` -- EXCEPT it contains one explicit,
    intentional carve-out immediately above that: `except HTTPException:
    raise  # If a middleware raises an HTTPException, it should be
    raised again`. A bare internal exception type does NOT hit that
    carve-out and gets silently turned into an unrelated 400 instead of
    413 -- a real failure mode this class exists to avoid, discovered
    only by testing an actual oversized chunked-transfer request against
    a real route with a Pydantic body parameter (see the Step 11I final
    report's live verification section; no unit or boundary test using a
    hand-written `request.body()` route call would have caught this,
    since that code path doesn't go through fastapi/routing.py's wrapper
    at all).

    Being a real HTTPException also means Starlette's own
    ExceptionMiddleware -- already present in every FastAPI app's
    middleware stack, downstream of this one -- knows how to turn it
    into a correct `{"detail": ...}`-shaped 413 JSON response on its
    own, for any route shape, Pydantic body parameter or not. This
    module's own except clause in __call__ is only a defensive fallback
    for the case that never fires today.
    """

    def __init__(self) -> None:
        super().__init__(status_code=413, detail="Request body too large.")


def _get_content_length(scope: Scope) -> int | None:
    """Read Content-Length directly from the ASGI scope's raw header
    list (bytes, lowercase names per the ASGI spec) -- not via a
    Starlette Request/Headers object, since constructing one is
    unnecessary work for a single header lookup that must happen before
    any Request even exists. Returns None if absent OR malformed (a
    non-numeric value is treated as absent, not trusted -- the
    incremental byte-counting path is what actually enforces the limit
    either way, so there is no safety loss in not trying too hard to
    parse a garbled header here).
    """
    for name, value in scope.get("headers", []):
        if name == b"content-length":
            try:
                return int(value)
            except ValueError:
                return None
    return None


def _log_request_body_too_large(scope: Scope) -> None:
    """Step 11J: logs REQUEST_BODY_TOO_LARGE at the exact point the
    violation is DETECTED (called from both the Content-Length fast path
    and from inside receive_wrapper, right before it raises) -- not from
    inside the middleware's own except clause, since that clause no
    longer fires for the normal incremental/chunked case (Starlette's
    own ExceptionMiddleware now handles _RequestBodyTooLarge before it
    ever propagates back here — see that class's own docstring). Logging
    at the detection point instead of the response point means this
    fires exactly once per real violation regardless of which of the two
    code paths caught it.

    Reads method/path/client directly from the raw ASGI scope (never
    constructs a Starlette Request) -- this module has no Request object
    available at the point Content-Length is checked, before self.app()
    is ever called. Never logs the body, the real or forged
    Content-Length value, or the configured limit -- only method, path,
    and client IP.
    """
    client = scope.get("client")
    client_ip = client[0] if client else "unknown"
    log_security_event(
        SecurityEvent(
            event_type=SecurityEventType.REQUEST_BODY_TOO_LARGE,
            method=scope.get("method", "UNKNOWN"),
            path=scope.get("path", "unknown"),
            status_code=413,
            client_ip=client_ip,
        )
    )


async def _send_413(send: Send) -> None:
    """The one 413 response this middleware ever produces. Fixed,
    generic body -- never the configured limit, the received size, this
    middleware's name, or anything else about why. No headers beyond
    content-type; in particular, deliberately no echo of any
    request header.
    """
    await send(
        {
            "type": "http.response.start",
            "status": 413,
            "headers": [(b"content-type", b"application/json")],
        }
    )
    await send({"type": "http.response.body", "body": _DETAIL_BODY, "more_body": False})


class RequestBodySizeLimitMiddleware:
    """ASGI middleware enforcing `max_bytes` on every HTTP request body.

    Applies to every HTTP request indiscriminately (health, auth, SOC
    routes alike) -- see the Step 11I final report for why a single
    global policy was chosen over per-route limits: every measured
    legitimate AMNIX payload fits comfortably under one generous limit,
    so per-route configuration would add complexity with no
    corresponding safety or usability benefit. GET requests are
    unaffected in practice: they carry no body, so neither check ever
    finds anything to reject. Only `scope["type"] == "http"` is
    inspected; websocket and lifespan scopes pass through untouched
    (this middleware has nothing to say about either).
    """

    def __init__(self, app: ASGIApp, *, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        content_length = _get_content_length(scope)
        if content_length is not None and content_length > self.max_bytes:
            # Fast path: reject without ever calling receive() -- not
            # one byte of the body is read off the connection.
            _log_request_body_too_large(scope)
            await _send_413(send)
            return

        total_bytes = 0

        async def receive_wrapper() -> Message:
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                total_bytes += len(message.get("body", b""))
                if total_bytes > self.max_bytes:
                    _log_request_body_too_large(scope)
                    raise _RequestBodyTooLarge()
            return message

        try:
            await self.app(scope, receive_wrapper, send)
        except _RequestBodyTooLarge:
            await _send_413(send)
