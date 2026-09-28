# -*- coding: utf-8 -*-
"""
core/resilience.py - Fault Tolerance, Circuit Breaker & Connection Pooling

Implements:
1. Circuit Breaker Pattern to prevent overwhelming unresponsive LLMs.
2. Connection Pooling with HTTPAdapter for fast socket reuse.
3. Exponential Backoff Retry with jitter for transient errors.
"""

import random
import threading
import time
from typing import Callable, Any, Optional
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from core.logger import logger


class ScannerError(Exception):
    """Base exception for scanner operations."""
    pass


class LLMTimeoutError(ScannerError):
    """Raised when an inference server call exceeds timeout limits."""
    pass


class LLMConnectionError(ScannerError):
    """Raised when inference server is unreachable."""
    pass


class CircuitBreakerOpenError(ScannerError):
    """Raised when circuit breaker is active and blocking calls."""
    pass


class RateLimitError(ScannerError):
    """Raised when upstream server returns HTTP 429."""
    pass


class CircuitBreaker:
    """
    Circuit breaker state machine:
    - CLOSED: Normal operation, requests flow through.
    - OPEN: Consecutive failures exceeded threshold; requests fail fast.
    - HALF_OPEN: Probe interval elapsed; allows a single trial request to test health.
    """

    STATE_CLOSED = "CLOSED"
    STATE_OPEN = "OPEN"
    STATE_HALF_OPEN = "HALF_OPEN"

    def __init__(self, failure_threshold: int = 5, recovery_timeout: float = 30.0) -> None:
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.state = self.STATE_CLOSED
        self.failure_count = 0
        self.last_failure_time: Optional[float] = None
        self._lock = threading.Lock()

    def record_success(self) -> None:
        with self._lock:
            self.failure_count = 0
            if self.state != self.STATE_CLOSED:
                logger.info("Circuit breaker reset: OPEN -> CLOSED (System recovered)")
                self.state = self.STATE_CLOSED

    def record_failure(self) -> None:
        with self._lock:
            self.failure_count += 1
            self.last_failure_time = time.time()
            if self.failure_count >= self.failure_threshold:
                if self.state != self.STATE_OPEN:
                    logger.warning(
                        "Circuit breaker TRIPPED: %d consecutive failures. State -> OPEN for %.1fs",
                        self.failure_count,
                        self.recovery_timeout,
                    )
                self.state = self.STATE_OPEN

    def allow_request(self) -> bool:
        with self._lock:
            if self.state == self.STATE_CLOSED:
                return True
            if self.state == self.STATE_OPEN:
                # Check if recovery timeout has passed
                if self.last_failure_time and (time.time() - self.last_failure_time) > self.recovery_timeout:
                    self.state = self.STATE_HALF_OPEN
                    logger.info("Circuit breaker test probe: State -> HALF_OPEN")
                    return True
                return False
            # HALF_OPEN allows probe
            return True


def create_resilient_session(
    pool_connections: int = 10,
    pool_maxsize: int = 20,
    max_retries: int = 2,
    backoff_factor: float = 0.5,
) -> requests.Session:
    """Creates a requests.Session with connection pooling and socket reuse."""
    session = requests.Session()
    retry_strategy = Retry(
        total=max_retries,
        backoff_factor=backoff_factor,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(
        pool_connections=pool_connections,
        pool_maxsize=pool_maxsize,
        max_retries=retry_strategy,
    )
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def execute_with_retry(
    func: Callable[[], Any],
    max_retries: int = 3,
    backoff_factor: float = 1.0,
    circuit_breaker: Optional[CircuitBreaker] = None,
) -> Any:
    """Executes a function with exponential backoff and jitter."""
    if circuit_breaker and not circuit_breaker.allow_request():
        raise CircuitBreakerOpenError(
            f"Circuit breaker is OPEN. Target server is failing; wait {circuit_breaker.recovery_timeout}s."
        )

    last_exc = None
    for attempt in range(max_retries + 1):
        try:
            result = func()
            if circuit_breaker:
                circuit_breaker.record_success()
            return result
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout, RateLimitError) as exc:
            last_exc = exc
            if circuit_breaker:
                circuit_breaker.record_failure()

            if attempt < max_retries:
                # Exponential backoff + full jitter
                sleep_time = (backoff_factor * (2 ** attempt)) + random.uniform(0.1, 0.5)
                logger.debug(
                    "Retry attempt %d/%d after %.2fs due to: %s",
                    attempt + 1,
                    max_retries,
                    sleep_time,
                    exc,
                )
                time.sleep(sleep_time)
            else:
                break
        except Exception as exc:
            if circuit_breaker:
                circuit_breaker.record_failure()
            raise exc

    if last_exc:
        raise last_exc
