# -*- coding: utf-8 -*-
"""
core/cache.py - Unified Caching Layer (Redis with In-Memory Fallback)

Provides:
- Redis caching if redis-py is installed and server is reachable.
- In-memory dictionary cache with TTL expiration as resilient fallback.
- `@cached(ttl=300)` decorator for functions and methods.
- Caching for taxonomy, compiled regex patterns, and heavy analytics.
"""

import functools
import json
import os
import time
from typing import Any, Callable, Dict, Optional, Tuple

from core.logger import logger

# Optional Redis import
try:
    import redis
except ImportError:
    redis = None


import threading
from collections import OrderedDict


class InMemoryCache:
    """Thread-safe bounded in-memory LRU cache with TTL expiration."""

    def __init__(self, max_entries: int = 2048) -> None:
        self._store: OrderedDict[str, Tuple[Any, Optional[float]]] = OrderedDict()
        self._max_entries = max(16, int(max_entries))
        self._lock = threading.Lock()

    def get(self, key: str) -> Optional[Any]:
        with self._lock:
            item = self._store.get(key)
            if item is None:
                return None
            val, expiry = item
            if expiry is not None and time.time() > expiry:
                self._store.pop(key, None)
                return None
            self._store.move_to_end(key)
            return val

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        expiry = time.time() + ttl if ttl else None
        with self._lock:
            self._store[key] = (value, expiry)
            self._store.move_to_end(key)
            while len(self._store) > self._max_entries:
                self._store.popitem(last=False)

    def delete(self, key: str) -> bool:
        with self._lock:
            return self._store.pop(key, None) is not None

    def clear(self) -> None:
        with self._lock:
            self._store.clear()


class CacheManager:
    """
    Unified cache manager providing Redis or In-Memory caching.
    """

    def __init__(self, redis_url: Optional[str] = None) -> None:
        self.redis_client = None
        self.backend = "memory"
        self._memory = InMemoryCache()

        url = redis_url or os.environ.get("REDIS_URL", "redis://localhost:6379/0")
        if redis is not None and os.environ.get("ENABLE_REDIS", "false").lower() in ("true", "1", "yes"):
            try:
                client = redis.from_url(url, socket_connect_timeout=2)
                client.ping()
                self.redis_client = client
                self.backend = "redis"
                logger.info("Connected to Redis cache at %s", url)
            except Exception as e:
                logger.debug("Redis unavailable (%s), falling back to In-Memory cache.", e)

    def get(self, key: str) -> Optional[Any]:
        if self.backend == "redis" and self.redis_client:
            try:
                raw = self.redis_client.get(key)
                if raw is not None:
                    return json.loads(raw)
                return None
            except Exception as e:
                logger.debug("Redis get error for %s: %s, checking memory.", key, e)
        return self._memory.get(key)

    def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        if self.backend == "redis" and self.redis_client:
            try:
                serialized = json.dumps(value, ensure_ascii=False)
                if ttl:
                    self.redis_client.setex(key, ttl, serialized)
                else:
                    self.redis_client.set(key, serialized)
                return
            except Exception as e:
                logger.debug("Redis set error for %s: %s, saving to memory.", key, e)
        self._memory.set(key, value, ttl)

    def delete(self, key: str) -> bool:
        if self.backend == "redis" and self.redis_client:
            try:
                self.redis_client.delete(key)
            except Exception:
                pass
        return self._memory.delete(key)

    def clear(self) -> None:
        if self.backend == "redis" and self.redis_client:
            try:
                # Only remove scanner-namespaced keys instead of flushdb()
                keys = list(self.redis_client.scan_iter(match="ai_scanner:*", count=500))
                if keys:
                    self.redis_client.delete(*keys)
            except Exception:
                pass
        self._memory.clear()


# Global cache instance
cache = CacheManager()


def cached(ttl: int = 300, key_prefix: str = ""):
    """Decorator to cache function return values with a specific TTL (seconds)."""
    def decorator(func: Callable):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # Build key from function name and arguments
            arg_str = ":".join(str(a) for a in args)
            kwarg_str = ":".join(f"{k}={v}" for k, v in sorted(kwargs.items()))
            cache_key = f"{key_prefix or func.__name__}:{arg_str}:{kwarg_str}"

            result = cache.get(cache_key)
            if result is not None:
                return result

            result = func(*args, **kwargs)
            try:
                cache.set(cache_key, result, ttl=ttl)
            except Exception:
                pass
            return result
        return wrapper
    return decorator
