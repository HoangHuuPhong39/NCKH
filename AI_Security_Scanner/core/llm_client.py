# -*- coding: utf-8 -*-
"""
core/llm_client.py - Resilient Unified LLM Client for AI Security Scanner

Supports:
- Ollama-compatible APIs and OpenAI-compatible APIs.
- Connection pooling with socket reuse.
- Exponential backoff retry logic.
- Circuit breaker pattern to fail fast during target downtime.
- Structured logging & explicit error discrimination.
"""

from typing import Optional, Tuple
import requests

from core.config import cfg
from core.logger import logger
from core.resilience import (
    CircuitBreaker,
    create_resilient_session,
    execute_with_retry,
    CircuitBreakerOpenError,
    RateLimitError,
)


class SimpleLLMClient:
    """
    Resilient, production-ready HTTP client for LLM inference APIs.

    Features:
    - Connection pooling (HTTPAdapter).
    - Automatic exponential backoff retry on network hiccups and 429/50x codes.
    - Circuit breaker to prevent hanging scans when targets crash.
    """

    def __init__(
        self,
        api_url: Optional[str] = None,
        model_name: Optional[str] = None,
        timeout: Optional[int] = None,
        api_key: Optional[str] = None,
    ) -> None:
        self.api_url = (api_url or cfg.get("scanner.target_url", "http://localhost:11434")).rstrip("/")
        self.model_name = model_name or cfg.get("scanner.target_model", "llama3")
        self.timeout = timeout if timeout is not None else cfg.get("scanner.timeout", 60)
        self.api_key = api_key if api_key is not None else cfg.get("scanner.api_key", "")

        # Resilience & Connection pooling
        pool_conn = cfg.get("scanner.pool_connections", 10)
        pool_max = cfg.get("scanner.pool_maxsize", 20)
        self.max_retries = cfg.get("scanner.max_retries", 3)
        self.backoff_factor = cfg.get("scanner.backoff_factor", 1.0)

        self.session = create_resilient_session(
            pool_connections=pool_conn,
            pool_maxsize=pool_max,
            max_retries=1,  # adapter level
        )

        cb_threshold = cfg.get("scanner.circuit_breaker.failure_threshold", 5)
        cb_timeout = cfg.get("scanner.circuit_breaker.recovery_timeout", 30)
        self.circuit_breaker = CircuitBreaker(
            failure_threshold=cb_threshold,
            recovery_timeout=cb_timeout,
        )

    # ------------------------------------------------------------------
    # Ollama
    # ------------------------------------------------------------------

    def list_models(self) -> list:
        """Queries the target server for available/installed models."""
        url_lower = self.api_url.lower()
        try:
            if "openai" in url_lower or "api.openai" in url_lower:
                headers = {}
                if self.api_key:
                    headers["Authorization"] = f"Bearer {self.api_key}"
                resp = self.session.get(f"{self.api_url}/v1/models", headers=headers, timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return [m["id"] for m in data.get("data", [])]
            else:
                resp = self.session.get(f"{self.api_url}/api/tags", timeout=5)
                if resp.status_code == 200:
                    data = resp.json()
                    return [m["name"] for m in data.get("models", [])]
        except Exception as exc:
            logger.debug("Failed to list models from %s: %s", self.api_url, exc)
        return []

    def resolve_model_name(self) -> str:
        """
        Attempts to match self.model_name against available models on target.
        Handles aliases like 'llama3:8b' -> 'llama3:latest' or 'llama3' -> 'llama3:latest'.
        """
        if getattr(self, "_model_resolved", False):
            return self.model_name

        available = self.list_models()
        self.discovered_models = available

        if not available:
            self._model_resolved = True
            return self.model_name

        # Exact match
        if self.model_name in available:
            self._model_resolved = True
            return self.model_name

        # Tag variations: e.g. 'llama3' -> 'llama3:latest'
        if f"{self.model_name}:latest" in available:
            logger.info("Auto-mapped model '%s' to '%s'", self.model_name, f"{self.model_name}:latest")
            self.model_name = f"{self.model_name}:latest"
            self._model_resolved = True
            return self.model_name

        # Base name match: e.g. 'llama3:8b' -> 'llama3:latest'
        base = self.model_name.split(":")[0].lower()
        matching = [m for m in available if m.lower().startswith(base)]
        if matching:
            preferred = next((m for m in matching if ":latest" in m), matching[0])
            logger.info("Auto-mapped requested model '%s' to installed target model '%s'", self.model_name, preferred)
            self.model_name = preferred
            self._model_resolved = True
            return self.model_name

        self._model_resolved = True
        return self.model_name

    def send_prompt_ollama(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        resolved_model = self.resolve_model_name()
        payload = {
            "model": resolved_model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "num_predict": cfg.get("scanner.max_tokens", 350),
            },
        }
        if system_prompt:
            payload["system"] = system_prompt

        def _do_request():
            resp = self.session.post(
                f"{self.api_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            if resp.status_code == 429:
                raise RateLimitError(f"HTTP 429 Too Many Requests from Ollama: {resp.text}")
            if resp.status_code == 404:
                err_text = ""
                try:
                    err_text = resp.json().get("error", resp.text)
                except Exception:
                    err_text = resp.text
                return f"[-] Model not found (Ollama): {err_text}"
            resp.raise_for_status()
            data = resp.json()
            return data.get("response", "")

        try:
            return execute_with_retry(
                _do_request,
                max_retries=self.max_retries,
                backoff_factor=self.backoff_factor,
                circuit_breaker=self.circuit_breaker,
            )
        except CircuitBreakerOpenError as exc:
            logger.error("Ollama request blocked: %s", exc)
            return f"[-] Circuit breaker open: {exc}"
        except requests.exceptions.ConnectionError as exc:
            logger.error("Ollama connection failed: %s", exc)
            return f"[-] Connection error (Ollama): {exc}"
        except requests.exceptions.Timeout:
            logger.warning("Ollama timed out after %ds", self.timeout)
            return f"[-] Request timed out after {self.timeout}s (Ollama)"
        except requests.exceptions.HTTPError as exc:
            logger.error("Ollama HTTP error: %s", exc)
            return f"[-] HTTP error (Ollama): {exc}"
        except Exception as exc:
            logger.error("Unexpected error in Ollama client: %s", exc)
            return f"[-] Unexpected error (Ollama): {exc}"

    # ------------------------------------------------------------------
    # OpenAI-compatible
    # ------------------------------------------------------------------

    def send_prompt_openai(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model_name,
            "messages": messages,
            "max_tokens": cfg.get("scanner.max_tokens", 350),
        }

        def _do_request():
            resp = self.session.post(
                f"{self.api_url}/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code == 429:
                raise RateLimitError(f"HTTP 429 Rate Limit from OpenAI: {resp.text}")
            resp.raise_for_status()
            data = resp.json()
            return data["choices"][0]["message"]["content"]

        try:
            return execute_with_retry(
                _do_request,
                max_retries=self.max_retries,
                backoff_factor=self.backoff_factor,
                circuit_breaker=self.circuit_breaker,
            )
        except CircuitBreakerOpenError as exc:
            logger.error("OpenAI request blocked: %s", exc)
            return f"[-] Circuit breaker open: {exc}"
        except requests.exceptions.ConnectionError as exc:
            logger.error("OpenAI connection failed: %s", exc)
            return f"[-] Connection error (OpenAI): {exc}"
        except requests.exceptions.Timeout:
            logger.warning("OpenAI timed out after %ds", self.timeout)
            return f"[-] Request timed out after {self.timeout}s (OpenAI)"
        except requests.exceptions.HTTPError as exc:
            logger.error("OpenAI HTTP error: %s", exc)
            return f"[-] HTTP error (OpenAI): {exc}"
        except (KeyError, IndexError) as exc:
            logger.error("Invalid OpenAI response schema: %s", exc)
            return f"[-] Unexpected response format (OpenAI): {exc}"
        except Exception as exc:
            logger.error("Unexpected error in OpenAI client: %s", exc)
            return f"[-] Unexpected error (OpenAI): {exc}"

    # ------------------------------------------------------------------
    # Auto-detect
    # ------------------------------------------------------------------

    def send_prompt(
        self,
        prompt: str,
        system_prompt: Optional[str] = None,
    ) -> str:
        url_lower = self.api_url.lower()
        if "openai" in url_lower or "api.openai" in url_lower:
            return self.send_prompt_openai(prompt, system_prompt)
        return self.send_prompt_ollama(prompt, system_prompt)

    # ------------------------------------------------------------------
    # Health-check
    # ------------------------------------------------------------------

    def test_connection(self) -> Tuple[bool, str]:
        url_lower = self.api_url.lower()
        if "openai" in url_lower or "api.openai" in url_lower:
            health_url = f"{self.api_url}/v1/models"
            headers = {}
            if self.api_key:
                headers["Authorization"] = f"Bearer {self.api_key}"
        else:
            health_url = f"{self.api_url}/api/tags"
            headers = {}

        try:
            resp = self.session.get(health_url, headers=headers, timeout=min(self.timeout, 10))
            resp.raise_for_status()
            self.circuit_breaker.record_success()

            # Inspect available models
            models = self.list_models()
            self.discovered_models = models
            resolved = self.resolve_model_name()
            self.resolved_model = resolved

            return True, "Connected"
        except requests.exceptions.ConnectionError as exc:
            self.circuit_breaker.record_failure()
            return False, f"Connection error: {exc}"
        except requests.exceptions.Timeout:
            self.circuit_breaker.record_failure()
            return False, f"Connection timed out after {self.timeout}s"
        except requests.exceptions.HTTPError as exc:
            self.circuit_breaker.record_failure()
            return False, f"HTTP error: {exc}"
        except Exception as exc:
            self.circuit_breaker.record_failure()
            return False, f"Unexpected error: {exc}"