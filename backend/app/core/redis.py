"""Redis connection configuration."""

from functools import lru_cache

import redis

from app.core.config import get_settings


@lru_cache
def get_redis_client() -> redis.Redis:
    """Return a cached Redis client instance."""
    settings = get_settings()
    return redis.Redis.from_url(settings.redis_url, decode_responses=True)
