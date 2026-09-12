"""Redis connection configuration."""

from functools import lru_cache

import redis

from app.core.config import get_settings

# Step 11H: this client's first real caller (app.api.dependencies.
# enforce_login_rate_limit) deliberately fails OPEN when Redis is
# unreachable (see that function's own docstring) -- but a fail-open
# path is only actually safe if it fails FAST. Without an explicit
# timeout, redis-py falls back to the OS's own TCP connect timeout
# (tens of seconds, verified live against an unreachable port), which
# would turn "Redis is down" into "every login takes tens of seconds
# before still succeeding" -- a real availability degradation, not the
# graceful degradation fail-open is meant to provide. One second is
# generous for a healthy connection (same-network Redis in every
# deployment shape AMNIX currently has) and still bounds the worst case
# tightly.
_SOCKET_TIMEOUT_SECONDS = 1.0


@lru_cache
def get_redis_client() -> redis.Redis:
    """Return a cached Redis client instance."""
    settings = get_settings()
    return redis.Redis.from_url(
        settings.redis_url,
        decode_responses=True,
        socket_connect_timeout=_SOCKET_TIMEOUT_SECONDS,
        socket_timeout=_SOCKET_TIMEOUT_SECONDS,
    )
