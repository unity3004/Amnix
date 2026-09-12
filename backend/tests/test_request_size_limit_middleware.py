"""Unit tests for app.middleware.request_size_limit.RequestBodySizeLimitMiddleware.

Pure ASGI-protocol tests: scope/receive/send are constructed directly,
with no HTTP client and no FastAPI app involved. This is deliberate, not
a shortcut -- httpx's ASGITransport (what TestClient uses under the
hood) was verified during discovery to always collapse a request body
into a single `http.request` ASGI message regardless of how the request
was built (json=, content=<generator>, ...), so it cannot exercise true
multi-chunk streaming, a missing-but-actually-oversized body, or a
mid-stream disconnect. Those scenarios are exactly what this file tests
directly against the middleware's own ASGI contract. HTTP-level behavior
(status codes through a real FastAPI app, legitimate AMNIX payloads,
auth interaction) is covered separately in
tests/test_request_size_limit_api.py.

No pytest-asyncio dependency is added for this: each test is a plain
sync function that drives its own coroutine via asyncio.run().
"""

import asyncio

import pytest

from app.middleware.request_size_limit import RequestBodySizeLimitMiddleware

MAX_BYTES = 100


def _http_scope(headers: list[tuple[bytes, bytes]] | None = None) -> dict:
    return {"type": "http", "method": "POST", "path": "/test", "headers": headers or []}


def _content_length_header(n: int) -> list[tuple[bytes, bytes]]:
    return [(b"content-length", str(n).encode())]


class _RecordingSend:
    """Records every ASGI message sent, so tests can assert exactly what
    (if anything) was sent back -- including asserting nothing was sent
    at all for scenarios where the downstream app returns early.
    """

    def __init__(self) -> None:
        self.messages: list[dict] = []

    async def __call__(self, message: dict) -> None:
        self.messages.append(message)

    @property
    def status(self) -> int | None:
        for message in self.messages:
            if message["type"] == "http.response.start":
                return message["status"]
        return None

    @property
    def body(self) -> bytes:
        return b"".join(
            message.get("body", b"") for message in self.messages if message["type"] == "http.response.body"
        )


def _make_receive(messages: list[dict]):
    """An ASGI receive() that yields `messages` in order, one per call.
    Raising on exhaustion (rather than hanging or repeating the last
    message) turns "the middleware/downstream app pulled more messages
    than this test set up" into an immediate, loud test failure instead
    of a silent infinite loop.
    """
    iterator = iter(messages)

    async def _receive() -> dict:
        try:
            return next(iterator)
        except StopIteration:
            raise AssertionError("receive() called more times than this test provided messages for") from None

    return _receive


async def _echo_body_app(scope: dict, receive, send) -> None:
    """Minimal stand-in for Starlette/FastAPI's own body-reading loop:
    pulls http.request messages until more_body is False or a
    disconnect arrives, then responds 200 with the total byte count it
    saw -- the same *shape* of consumption Request.stream()/body()
    performs, without pulling in FastAPI at all.
    """
    total = 0
    while True:
        message = await receive()
        if message["type"] == "http.disconnect":
            return
        total += len(message.get("body", b""))
        if not message.get("more_body", False):
            break
    await send({"type": "http.response.start", "status": 200, "headers": []})
    await send({"type": "http.response.body", "body": str(total).encode(), "more_body": False})


def _run(coro):
    return asyncio.run(coro)


# =============================================================================
# Content-Length fast path
# =============================================================================


def test_content_length_over_limit_rejects_without_calling_receive():
    """The defining property of the fast path: not one byte is read off
    the connection. `_make_receive([])` raises if receive() is ever
    called even once.
    """
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()

    _run(
        middleware(
            _http_scope(_content_length_header(MAX_BYTES + 1)),
            _make_receive([]),
            send,
        )
    )

    assert send.status == 413
    assert send.body == b'{"detail":"Request body too large."}'


def test_content_length_at_limit_is_accepted():
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()
    body = b"x" * MAX_BYTES

    _run(
        middleware(
            _http_scope(_content_length_header(MAX_BYTES)),
            _make_receive([{"type": "http.request", "body": body, "more_body": False}]),
            send,
        )
    )

    assert send.status == 200
    assert send.body == str(MAX_BYTES).encode()


def test_malformed_content_length_header_falls_back_to_incremental_check():
    """A non-numeric Content-Length is never trusted -- treated as
    absent, not as a reason to reject or crash. The incremental
    byte-counting path still correctly accepts a legitimately small body.
    """
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()

    _run(
        middleware(
            _http_scope([(b"content-length", b"not-a-number")]),
            _make_receive([{"type": "http.request", "body": b"hello", "more_body": False}]),
            send,
        )
    )

    assert send.status == 200


# =============================================================================
# Incremental byte-counting (missing Content-Length / chunked / forged header)
# =============================================================================


def test_missing_content_length_small_body_is_accepted():
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()

    _run(
        middleware(
            _http_scope(),
            _make_receive([{"type": "http.request", "body": b"hello", "more_body": False}]),
            send,
        )
    )

    assert send.status == 200
    assert send.body == b"5"


def test_missing_content_length_one_byte_over_limit_rejects():
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()
    body = b"x" * (MAX_BYTES + 1)

    _run(
        middleware(
            _http_scope(),
            _make_receive([{"type": "http.request", "body": body, "more_body": False}]),
            send,
        )
    )

    assert send.status == 413
    assert send.body == b'{"detail":"Request body too large."}'


def test_many_small_chunks_exceeding_limit_rejects_without_full_buffering():
    """15-byte chunks against a 100-byte limit: after the 7th chunk the
    running total is 105 (> 100), so the middleware must raise right
    there. Critically, it must stop pulling further chunks at that point
    rather than consuming every chunk a real client might send -- proven
    by giving the receive() stand-in exactly 7 chunks; an 8th pull would
    fail the test immediately via _make_receive's own exhaustion guard.
    """
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()
    chunks = [{"type": "http.request", "body": b"x" * 15, "more_body": True} for _ in range(7)]

    _run(middleware(_http_scope(), _make_receive(chunks), send))

    assert send.status == 413
    assert send.body == b'{"detail":"Request body too large."}'


def test_forged_content_length_understating_the_real_body_still_rejects():
    """Content-Length claims 10 bytes (within budget), but the real
    streamed body is far larger -- the incremental check is what
    actually enforces the limit; the header is never trusted alone.
    """
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()
    body = b"x" * (MAX_BYTES + 50)

    _run(
        middleware(
            _http_scope(_content_length_header(10)),
            _make_receive([{"type": "http.request", "body": body, "more_body": False}]),
            send,
        )
    )

    assert send.status == 413


# =============================================================================
# Disconnect handling
# =============================================================================


def test_disconnect_mid_stream_does_not_raise_or_send_a_response():
    """A client disconnecting partway through an under-limit upload is
    not this middleware's concern to respond to -- it must pass the
    disconnect straight through to the downstream app (which, in this
    stand-in, simply returns without sending anything) without raising
    an exception of its own.
    """
    middleware = RequestBodySizeLimitMiddleware(_echo_body_app, max_bytes=MAX_BYTES)
    send = _RecordingSend()
    messages = [
        {"type": "http.request", "body": b"partial", "more_body": True},
        {"type": "http.disconnect"},
    ]

    _run(middleware(_http_scope(), _make_receive(messages), send))

    assert send.messages == []


# =============================================================================
# Non-HTTP scopes and unrelated exceptions
# =============================================================================


def test_non_http_scope_passes_through_untouched():
    calls = []

    async def _lifespan_app(scope, receive, send):
        calls.append(scope["type"])

    middleware = RequestBodySizeLimitMiddleware(_lifespan_app, max_bytes=MAX_BYTES)

    _run(middleware({"type": "lifespan"}, _make_receive([]), _RecordingSend()))

    assert calls == ["lifespan"]


def test_unrelated_downstream_exception_is_not_swallowed():
    """The middleware only catches its own internal size-limit signal --
    any other exception the downstream app raises must propagate
    unchanged, never get silently turned into a 413.
    """

    async def _broken_app(scope, receive, send):
        raise RuntimeError("unrelated failure")

    middleware = RequestBodySizeLimitMiddleware(_broken_app, max_bytes=MAX_BYTES)

    with pytest.raises(RuntimeError, match="unrelated failure"):
        _run(middleware(_http_scope(), _make_receive([]), _RecordingSend()))
