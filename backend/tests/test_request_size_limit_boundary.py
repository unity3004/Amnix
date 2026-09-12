"""HTTP-level boundary tests for RequestBodySizeLimitMiddleware, through
a real (throwaway) FastAPI app rather than raw ASGI scope/receive/send.

Deliberately NOT run against the real app.main:app: that app's
middleware is constructed once, at module-import time, with
`max_bytes=settings.max_request_body_bytes` (1 MiB by default) baked in
as a plain constructor argument -- unlike app.core.config-driven
per-request checks elsewhere in AMNIX (e.g. the Step 11H rate limiter,
which calls get_settings() fresh on every request), this middleware's
limit is fixed once at process startup, by design (a request-size cap is
not something that needs hot-reloading). That makes exact-boundary
testing (at the limit / one byte over) impractical against the real
app's 1 MiB constant without either allocating megabyte-scale test
payloads for no added coverage or fighting Starlette's internal
middleware-stack caching to swap it out. A small throwaway app with a
small, explicit limit gives the same real FastAPI-integrated behavior
(TestClient -> ASGI -> RequestBodySizeLimitMiddleware -> FastAPI routing
-> a real route handler) with fast, deterministic boundaries.

Legitimate AMNIX payloads, auth interaction, and the real app's actual
1 MiB limit are covered separately in tests/test_request_size_limit_api.py.
"""

from fastapi import FastAPI, Request
from fastapi.testclient import TestClient

from app.middleware.request_size_limit import RequestBodySizeLimitMiddleware

LIMIT = 200


def _build_app(max_bytes: int = LIMIT) -> FastAPI:
    app = FastAPI()

    @app.post("/echo")
    async def echo(request: Request) -> dict:
        body = await request.body()
        return {"received": len(body)}

    app.add_middleware(RequestBodySizeLimitMiddleware, max_bytes=max_bytes)
    return app


def test_body_below_the_limit_succeeds():
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=b"x" * (LIMIT - 1))

    assert response.status_code == 200
    assert response.json() == {"received": LIMIT - 1}


def test_body_exactly_at_the_limit_succeeds():
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=b"x" * LIMIT)

    assert response.status_code == 200
    assert response.json() == {"received": LIMIT}


def test_body_one_byte_over_the_limit_returns_413():
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=b"x" * (LIMIT + 1))

    assert response.status_code == 413
    assert response.json() == {"detail": "Request body too large."}


def test_content_length_above_limit_returns_413():
    """A plain bytes `content=` body causes httpx to set a real
    Content-Length header -- this exercises the fast Content-Length path.
    """
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=b"y" * (LIMIT * 5))

    assert response.status_code == 413


def test_missing_content_length_oversized_body_returns_413():
    """A generator `content=` causes httpx to omit Content-Length
    entirely (verified during Step 11I discovery) -- this exercises the
    incremental byte-counting fallback path instead of the fast path.
    """
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=(b"z" * 50 for _ in range(10)))  # 500 bytes, limit is 200

    assert response.status_code == 413


def test_413_response_has_no_stack_trace_or_internal_details():
    with TestClient(_build_app()) as client:
        response = client.post("/echo", content=b"x" * (LIMIT + 1))

    assert response.status_code == 413
    body_text = response.text.lower()
    for forbidden_term in ("traceback", "middleware", "asgi", "starlette", "fastapi", str(LIMIT), str(LIMIT + 1)):
        assert forbidden_term not in body_text


def test_malformed_json_below_the_limit_reaches_normal_json_error_not_413():
    """A body under the size limit but not valid JSON must be rejected by
    FastAPI's own body parsing (a 422 RequestValidationError, exactly
    like every other malformed-JSON case elsewhere in AMNIX), not by
    this middleware -- proof the middleware never inspects content, only
    size. Uses a real Pydantic body parameter (not a hand-written
    `request.json()` call) so FastAPI's own JSON-decode-error handling
    path is what actually runs, matching every real AMNIX route.
    """
    from pydantic import BaseModel

    class _Payload(BaseModel):
        value: str

    app = FastAPI()

    @app.post("/json-echo")
    async def json_echo(payload: _Payload) -> dict:
        return {"value": payload.value}

    app.add_middleware(RequestBodySizeLimitMiddleware, max_bytes=LIMIT)

    with TestClient(app) as client:
        response = client.post(
            "/json-echo", content=b"{not valid json", headers={"content-type": "application/json"}
        )

    assert response.status_code == 422
