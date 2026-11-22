# -*- coding: utf-8 -*-
"""
tests/unit/test_sse_and_concurrency.py - Multi-Subscriber SSE, Concurrency & Resilience Tests
"""

from __future__ import annotations

import queue
import time
from unittest.mock import MagicMock, patch

import pytest

from core.cache import CacheManager, InMemoryCache
from core.llm_client import SimpleLLMClient
from core.resilience import CircuitBreaker
from web.services.scan_manager import ScanBroadcaster


# ==============================================================================
# 1. ScanBroadcaster Multi-Subscriber SSE Fan-Out & Scan #1 -> Scan #2 Lifecycle
# ==============================================================================

def test_sse_broadcaster_fanout_multiple_subscribers():
    """Two concurrent subscribers must BOTH receive every event (no single-queue stealing)."""
    bc = ScanBroadcaster(max_subscribers=8, max_queue_size=10)
    q1 = bc.subscribe()
    q2 = bc.subscribe()

    bc.put({"type": "status", "token": "tok-1", "data": {"msg": "start"}})
    bc.put({"type": "result", "token": "tok-1", "data": {"vuln": True}})
    bc.put({"type": "done", "token": "tok-1", "data": {}})

    ev1 = [q1.get_nowait()["type"] for _ in range(3)]
    ev2 = [q2.get_nowait()["type"] for _ in range(3)]
    assert ev1 == ["status", "result", "done"]
    assert ev2 == ["status", "result", "done"]

    bc.unsubscribe(q1)
    bc.unsubscribe(q2)


def test_sse_broadcaster_replay_backlog_and_scan2_isolation():
    """Late subscriber replays only events matching its scan_token; Scan #2 clears Scan #1 backlog."""
    bc = ScanBroadcaster()
    bc.put({"type": "status", "token": "scan-1", "data": {"n": 1}})
    bc.put({"type": "done", "token": "scan-1", "data": {"n": 2}})

    q_late = bc.subscribe(replay_token="scan-1")
    replayed = [q_late.get_nowait()["type"], q_late.get_nowait()["type"]]
    assert replayed == ["status", "done"]
    bc.unsubscribe(q_late)

    bc.clear_backlog()
    bc.put({"type": "status", "token": "scan-2", "data": {"n": 1}})
    q_s2 = bc.subscribe(replay_token="scan-2")
    msg = q_s2.get_nowait()
    assert msg["token"] == "scan-2"
    with pytest.raises(queue.Empty):
        q_s2.get_nowait()
    bc.unsubscribe(q_s2)


def test_sse_broadcaster_queue_overflow_and_max_subscribers():
    bc = ScanBroadcaster(max_subscribers=2, max_queue_size=2)
    q1 = bc.subscribe()
    q2 = bc.subscribe()
    q3 = bc.subscribe()  # evicts oldest subscriber q1

    bc.put({"type": "a", "token": "t"})
    bc.put({"type": "b", "token": "t"})
    bc.put({"type": "c", "token": "t"})  # drops oldest item 'a' in bounded queues

    assert [q2.get_nowait()["type"], q2.get_nowait()["type"]] == ["b", "c"]
    assert [q3.get_nowait()["type"], q3.get_nowait()["type"]] == ["b", "c"]
    assert q1.empty()


# ==============================================================================
# 2. CircuitBreaker HALF_OPEN Single-Probe Guard
# ==============================================================================

def test_circuit_breaker_half_open_single_probe():
    cb = CircuitBreaker(failure_threshold=2, recovery_timeout=0.05)

    assert cb.allow_request() is True
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitBreaker.STATE_OPEN
    assert cb.allow_request() is False

    # Wait for recovery_timeout -> enters HALF_OPEN; allow ONLY ONE probe at a time!
    time.sleep(0.08)
    assert cb.allow_request() is True
    assert cb.state == CircuitBreaker.STATE_HALF_OPEN
    # Second concurrent caller during HALF_OPEN probe MUST be rejected
    assert cb.allow_request() is False

    # Recording success closes the circuit
    cb.record_success()
    assert cb.state == CircuitBreaker.STATE_CLOSED
    assert cb.allow_request() is True


# ==============================================================================
# 3. Thread-Safe Bounded LRU InMemoryCache & Prefix-Scoped CacheManager.clear()
# ==============================================================================

def test_in_memory_cache_bounded_lru_and_ttl():
    cache = InMemoryCache(max_entries=16)
    for i in range(16):
        cache.set(f"k{i}", f"v{i}", ttl=60)
    # Touch k0 so k1 becomes least-recently-used
    assert cache.get("k0") == "v0"
    cache.set("k16", "v16", ttl=60)
    assert cache.get("k1") is None
    assert cache.get("k0") == "v0"
    assert cache.get("k16") == "v16"

    # Short TTL expiration
    cache.set("short", "val", ttl=0.01)
    time.sleep(0.03)
    assert cache.get("short") is None


def test_redis_cache_clear_deletes_prefix_only_not_flushdb():
    cm = CacheManager(redis_url=None)
    mock_redis = MagicMock()
    mock_redis.scan_iter.return_value = ["ai_scanner:a", "ai_scanner:b"]
    cm.backend = "redis"
    cm.redis_client = mock_redis

    cm.clear()
    mock_redis.flushdb.assert_not_called()
    mock_redis.scan_iter.assert_called_once_with(match="ai_scanner:*", count=500)
    assert mock_redis.delete.call_count >= 1


# ==============================================================================
# 4. SimpleLLMClient OpenAI URL Dedup, Redirect Guard & 404 raise_on_error
# ==============================================================================

def test_llm_client_openai_v1_dedup_and_redirect_disabled():
    c1 = SimpleLLMClient(api_url="https://api.openai.com/v1", model_name="gpt-4o", api_key="sk-test")
    assert c1._is_openai_compatible() is True
    assert c1._openai_v1_url("chat/completions") == "https://api.openai.com/v1/chat/completions"

    c2 = SimpleLLMClient(api_url="https://api.openai.com", model_name="gpt-4o", api_key="sk-test")
    assert c2._openai_v1_url("chat/completions") == "https://api.openai.com/v1/chat/completions"

    c_local = SimpleLLMClient(api_url="http://127.0.0.1:11434", model_name="missing-model")
    c_local._model_resolved = True
    mock_404 = MagicMock(status_code=404, text="model not found")
    with patch.object(c_local.session, "post", return_value=mock_404) as mpost:
        with pytest.raises(RuntimeError):
            c_local.send_prompt("hello", raise_on_error=True)
        assert mpost.call_args.kwargs.get("allow_redirects") is False
