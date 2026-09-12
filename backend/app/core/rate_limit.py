"""Fixed-window rate limiting backed by Redis (Step 11H).

Framework-agnostic, exactly like app.core.security/app.core.tokens:
takes an already-constructed redis.Redis client plus a key and limit
parameters, and returns whether the caller is within budget. No FastAPI
import here at all — the HTTP-facing dependency that decides what to do
with the result (raise 429, which identity dimension to key on, how to
fail if Redis itself is unreachable) lives in app.api.dependencies,
mirroring how app.core.tokens owns JWT mechanics while
app.api.dependencies owns what an HTTP request does with them.

Algorithm: fixed window, not sliding window or a token bucket. A fixed
window is simpler, requires only one Redis key per (identity, window)
pair, and is precise enough for this threat (blunting scripted
credential-stuffing/brute-force traffic) — it is not attempting to be a
precise, fair-queuing rate shaper. The known fixed-window weakness (a
caller can send up to 2x the limit by clustering requests around a
window boundary) is an accepted trade-off for that simplicity; nothing
in AMNIX's threat model needs finer precision than this.

INCR-then-EXPIRE is used rather than a single atomic Lua script: Redis's
own INCR is atomic (no lost-update race on the counter itself), and the
only race this leaves is two concurrent *first* requests in a brand-new
window both observing count == 1 and both issuing EXPIRE — a harmless,
extremely rare double-write of the same TTL value, not a security gap
(it cannot cause the window to be un-expired or the counter to under-
count). A full Lua script would close even that, at the cost of an extra
moving part for a benefit that does not matter here.
"""

from dataclasses import dataclass

import redis


@dataclass(frozen=True)
class RateLimitResult:
    """Whether this request is within budget, and enough information
    for the caller to build a Retry-After response if not.
    """

    allowed: bool
    remaining: int
    retry_after_seconds: int


def check_and_increment(
    client: redis.Redis, *, key: str, max_attempts: int, window_seconds: int
) -> RateLimitResult:
    """Increment `key`'s counter for the current window and report
    whether it is still within `max_attempts`. The window is anchored to
    the first increment that creates the key (TTL is only set once, when
    the count is first observed to be 1) — later increments within the
    same window do not push the expiry back out, so a steady stream of
    requests cannot keep the window alive forever.

    Any redis.RedisError (connection failure, timeout, etc.) propagates
    to the caller unmodified — this function does not decide fail-open
    vs. fail-closed; see app.api.dependencies.enforce_login_rate_limit
    for that decision and its justification.
    """
    count = client.incr(key)
    if count == 1:
        client.expire(key, window_seconds)
    ttl = client.ttl(key)
    retry_after = ttl if ttl and ttl > 0 else window_seconds

    return RateLimitResult(
        allowed=count <= max_attempts,
        remaining=max(0, max_attempts - count),
        retry_after_seconds=retry_after,
    )
