# -*- coding: utf-8 -*-
"""
tests/unit/test_cache.py - Unit tests for CacheManager and In-Memory cache
"""

import time
import pytest
from core.cache import InMemoryCache, CacheManager, cached


def test_in_memory_cache_basic():
    c = InMemoryCache()
    c.set("k1", "v1")
    assert c.get("k1") == "v1"
    assert c.get("non_existent") is None

    c.delete("k1")
    assert c.get("k1") is None


def test_in_memory_cache_ttl():
    c = InMemoryCache()
    c.set("temp", "val", ttl=0.1)
    assert c.get("temp") == "val"
    time.sleep(0.15)
    assert c.get("temp") is None


def test_cache_manager():
    cm = CacheManager()
    cm.set("test_key", {"foo": "bar"}, ttl=60)
    assert cm.get("test_key") == {"foo": "bar"}
    cm.clear()
    assert cm.get("test_key") is None


def test_cached_decorator():
    call_count = 0

    @cached(ttl=60)
    def expensive_func(x, y):
        nonlocal call_count
        call_count += 1
        return x + y

    res1 = expensive_func(2, 3)
    res2 = expensive_func(2, 3)
    assert res1 == 5
    assert res2 == 5
    assert call_count == 1  # Result was served from cache
