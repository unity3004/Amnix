"""Pure-ASGI security response headers (Step 11L).

Appends a small, fixed, deliberately-justified set of HTTP response
headers to every HTTP response this application produces — including
error responses (401/403/404/413/422/...), as long as this middleware
sits outside whatever layer produced that response (see app.main for
registration order; this is registered as the OUTERMOST layer, wrapping
everything, precisely so it never misses a response).

Pure ASGI (wrapping `send`, not Starlette's BaseHTTPMiddleware) for the
same reason app.middleware.request_size_limit is pure ASGI: no new
Request/Response object construction, minimal overhead, and no
interaction with body streaming at all — this middleware only ever
touches the `http.response.start` message's headers, never the body.

WHY EXACTLY THESE THREE HEADERS, NO OTHERS (see the Step 11L final
report for the full per-header discovery/reasoning):

- X-Content-Type-Options: nosniff — prevents a browser from MIME-
  sniffing a response into executing as something other than its
  declared Content-Type. Costs nothing, breaks nothing, always correct
  for a JSON API.
- X-Frame-Options: DENY — prevents any AMNIX response (including the
  framework-generated /docs and /redoc HTML pages) from being framed by
  another site (clickjacking defense-in-depth). Neither Swagger UI nor
  ReDoc need to be framed for their own normal operation.
- Referrer-Policy: no-referrer — never leaks the current URL via the
  Referer header when a user navigates away or loads an external
  resource. No functional cost: nothing in AMNIX's own responses relies
  on Referer being sent onward.

Deliberately NOT implemented, each independently reasoned about rather
than reflexively added (see the Step 11L final report for the full
write-up):

- Content-Security-Policy — AMNIX is a JSON API; the only HTML surfaces
  are FastAPI's own auto-generated /docs and /redoc, which load their
  JS/CSS from an external CDN whose exact URL is a FastAPI
  implementation detail this project does not want to hardcode/couple
  itself to (fragile against a FastAPI/Starlette upgrade), for a page
  that renders no untrusted user content. Inventing a CSP here would be
  exactly the "complex CSP merely for the sake of adding one" the brief
  warns against.
- Permissions-Policy — no concrete AMNIX threat this addresses: nothing
  in this application's response surface (JSON API, or the two
  framework-owned docs pages) ever had access to camera/microphone/
  geolocation to begin with. Adding it would be a speculative policy
  with no corresponding risk it closes.
- Strict-Transport-Security — see app.main's own docstring section for
  why this is deferred, not merely omitted: AMNIX has no reverse-proxy/
  TLS-termination configuration anywhere in this repository, so the
  application cannot currently know whether the connection it is
  actually serving is HTTPS. Sending HSTS from a plain HTTP connection
  (real local development) would be actively wrong.
"""

from collections.abc import Awaitable, Callable

Scope = dict
Message = dict
Receive = Callable[[], Awaitable[Message]]
Send = Callable[[Message], Awaitable[None]]
ASGIApp = Callable[[Scope, Receive, Send], Awaitable[None]]

_SECURITY_HEADERS: list[tuple[bytes, bytes]] = [
    (b"x-content-type-options", b"nosniff"),
    (b"x-frame-options", b"DENY"),
    (b"referrer-policy", b"no-referrer"),
]


class SecurityHeadersMiddleware:
    """Appends `_SECURITY_HEADERS` to every HTTP response's
    `http.response.start` message. Non-HTTP scopes (websocket,
    lifespan) pass through untouched — this middleware has nothing to
    say about either.
    """

    def __init__(self, app: ASGIApp) -> None:
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_wrapper(message: Message) -> None:
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(_SECURITY_HEADERS)
                message = {**message, "headers": headers}
            await send(message)

        await self.app(scope, receive, send_wrapper)
