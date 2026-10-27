# -*- coding: utf-8 -*-
"""
tests/unit/test_llm_client.py - Unit tests for SimpleLLMClient and Resilience
"""

import pytest
import requests
from unittest.mock import MagicMock, patch

from core.llm_client import SimpleLLMClient
from core.resilience import CircuitBreaker, CircuitBreakerOpenError, execute_with_retry, RateLimitError


def test_client_init_defaults():
    client = SimpleLLMClient()
    assert client.api_url.startswith("http")
    assert client.model_name is not None
    assert client.timeout > 0
    assert client.circuit_breaker is not None


def test_client_routing_detect():
    client_ollama = SimpleLLMClient(api_url="http://localhost:11434")
    client_openai = SimpleLLMClient(api_url="https://api.openai.com")

    with patch.object(client_ollama, "send_prompt_ollama", return_value="ollama_resp") as mock_ol:
        res = client_ollama.send_prompt("test")
        assert res == "ollama_resp"
        mock_ol.assert_called_once()

    with patch.object(client_openai, "send_prompt_openai", return_value="openai_resp") as mock_oa:
        res = client_openai.send_prompt("test")
        assert res == "openai_resp"
        mock_oa.assert_called_once()


def test_circuit_breaker_transitions():
    cb = CircuitBreaker(failure_threshold=3, recovery_timeout=0.2)
    assert cb.state == CircuitBreaker.STATE_CLOSED
    assert cb.allow_request() is True

    # Record 2 failures -> still CLOSED
    cb.record_failure()
    cb.record_failure()
    assert cb.state == CircuitBreaker.STATE_CLOSED

    # 3rd failure -> trips to OPEN
    cb.record_failure()
    assert cb.state == CircuitBreaker.STATE_OPEN
    assert cb.allow_request() is False

    # After recovery timeout -> transitions to HALF_OPEN
    import time
    time.sleep(0.25)
    assert cb.allow_request() is True
    assert cb.state == CircuitBreaker.STATE_HALF_OPEN

    # Success resets to CLOSED
    cb.record_success()
    assert cb.state == CircuitBreaker.STATE_CLOSED
    assert cb.failure_count == 0


def test_execute_with_retry_success_after_failure():
    attempts = [0]

    def flaky_func():
        attempts[0] += 1
        if attempts[0] < 2:
            raise requests.exceptions.ConnectionError("Temporary glitch")
        return "success"

    res = execute_with_retry(flaky_func, max_retries=3, backoff_factor=0.01)
    assert res == "success"
    assert attempts[0] == 2


def test_execute_with_retry_circuit_breaker_blocks():
    cb = CircuitBreaker(failure_threshold=1, recovery_timeout=60)
    cb.record_failure()  # trips to OPEN

    def dummy():
        return "never"

    with pytest.raises(CircuitBreakerOpenError):
        execute_with_retry(dummy, max_retries=1, circuit_breaker=cb)


def test_test_connection_success():
    client = SimpleLLMClient(api_url="http://localhost:11434")
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None

    with patch.object(client.session, "get", return_value=mock_resp):
        ok, msg = client.test_connection()
        assert ok is True
        assert msg == "Connected"


def test_test_connection_failure():
    client = SimpleLLMClient(api_url="http://localhost:11434")
    with patch.object(client.session, "get", side_effect=requests.exceptions.ConnectionError("Refused")):
        ok, msg = client.test_connection()
        assert ok is False
        assert "Connection error" in msg


def test_openai_connection_detects_exhausted_quota():
    client = SimpleLLMClient(api_url="https://api.openai.com", api_key="sk-fake")
    models_resp = MagicMock()
    models_resp.status_code = 200
    models_resp.json.return_value = {"data": [{"id": "gpt-4o-mini"}]}

    probe_resp = MagicMock()
    probe_resp.status_code = 429
    probe_resp.json.return_value = {
        "error": {
            "code": "credit_balance_exhausted",
            "type": "insufficient_quota",
            "message": "You have no credits remaining."
        }
    }

    with patch.object(client.session, "get", return_value=models_resp), \
         patch.object(client.session, "post", return_value=probe_resp):
        ok, msg = client.test_connection()
        assert ok is False
        assert "credit_balance_exhausted" in msg or "HẾT CREDIT" in msg


def test_openai_send_prompt_detects_quota_exhaustion():
    client = SimpleLLMClient(api_url="https://api.openai.com", api_key="sk-fake", model_name="gpt-4o-mini")
    err_resp = MagicMock()
    err_resp.status_code = 429
    err_resp.json.return_value = {
        "error": {
            "code": "credit_balance_exhausted",
            "type": "insufficient_quota",
            "message": "You have no credits remaining."
        }
    }

    with patch.object(client.session, "post", return_value=err_resp):
        res = client.send_prompt("hello")
        assert "credit_balance_exhausted" in res
        assert "hết credit" in res.lower() or "hạn mức" in res.lower()
