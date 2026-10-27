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
    QuotaExhaustedError,
    ScannerError,
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
        self.timeout = timeout if timeout is not None else cfg.get("scanner.timeout", 90)
        self.api_key = api_key if api_key is not None else cfg.get("scanner.api_key", "")

        # Resilience & Connection pooling
        pool_conn = cfg.get("scanner.pool_connections", 10)
        pool_max = cfg.get("scanner.pool_maxsize", 20)
        self.max_retries = cfg.get("scanner.max_retries", 1)
        self.backoff_factor = cfg.get("scanner.backoff_factor", 1.0)

        self.session = create_resilient_session(
            pool_connections=pool_conn,
            pool_maxsize=pool_max,
            max_retries=0,  # adapter level
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
                    all_ids = [m["id"] for m in data.get("data", [])]
                    # Filter and prioritize chat-capable models
                    chat_priority = [
                        "gpt-4o-mini",
                        "gpt-4o",
                        "gpt-4-turbo",
                        "gpt-4",
                        "gpt-3.5-turbo",
                        "o1-mini",
                        "o1-preview",
                        "o3-mini",
                    ]
                    excluded_keywords = [
                        "transcribe", "realtime", "audio", "whisper",
                        "tts", "dall-e", "embedding", "moderation", "davinci", "babbage"
                    ]
                    chat_models = [
                        m for m in all_ids
                        if not any(k in m.lower() for k in excluded_keywords)
                        and any(p in m.lower() for p in ["gpt-", "o1", "o3", "chat"])
                    ]
                    ordered = [p for p in chat_priority if p in all_ids]
                    for m in sorted(chat_models):
                        if m not in ordered:
                            ordered.append(m)
                    return ordered if ordered else all_ids
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
                "num_predict": cfg.get("scanner.max_tokens", 80),
                "temperature": 0.1,
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
            "max_tokens": cfg.get("scanner.max_tokens", 80),
            "temperature": 0.1,
        }

        def _do_request():
            resp = self.session.post(
                f"{self.api_url}/v1/chat/completions",
                json=payload,
                headers=headers,
                timeout=self.timeout,
            )
            if resp.status_code == 429:
                err_data = {}
                try:
                    err_data = resp.json().get("error", {})
                except Exception:
                    pass
                err_code = err_data.get("code")
                err_type = err_data.get("type")
                err_msg = err_data.get("message", resp.text)
                if err_code == "credit_balance_exhausted" or err_type == "insufficient_quota":
                    raise QuotaExhaustedError(
                        f"Tài khoản OpenAI đã hết credit/số dư (credit_balance_exhausted). "
                        f"Chi tiết: {err_msg}"
                    )
                raise RateLimitError(f"HTTP 429 Rate Limit from OpenAI: {err_msg}")
            if resp.status_code == 401:
                err_data = {}
                try:
                    err_data = resp.json().get("error", {})
                except Exception:
                    pass
                raise ScannerError(f"OpenAI API Key không hợp lệ (401 Unauthorized): {err_data.get('message', resp.text)}")
            if resp.status_code == 404:
                err_data = {}
                try:
                    err_data = resp.json().get("error", {})
                except Exception:
                    pass
                return f"[-] Model '{self.model_name}' không hỗ trợ chat hoặc không tồn tại (404 Not Found): {err_data.get('message', resp.text)}"
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
        except QuotaExhaustedError as exc:
            logger.error("OpenAI Quota exhausted: %s", exc)
            return f"[-] Lỗi hạn mức/Số dư OpenAI: {exc}"
        except RateLimitError as exc:
            logger.error("OpenAI Rate limited: %s", exc)
            return f"[-] Lỗi giới hạn tần suất OpenAI (Rate Limit 429): {exc}"
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

            # Với OpenAI: Thử kiểm tra hạn mức (quota) bằng một probe request nhỏ
            if "openai" in url_lower or "api.openai" in url_lower:
                test_model = resolved if resolved and not any(resolved.startswith(k) for k in ["llama", "mistral", "qwen"]) else "gpt-4o-mini"
                try:
                    probe_resp = self.session.post(
                        f"{self.api_url}/v1/chat/completions",
                        json={
                            "model": test_model,
                            "messages": [{"role": "user", "content": "ping"}],
                            "max_tokens": 1,
                        },
                        headers=headers,
                        timeout=min(self.timeout, 5),
                    )
                    if probe_resp.status_code == 429:
                        p_data = probe_resp.json().get("error", {})
                        if p_data.get("code") == "credit_balance_exhausted" or p_data.get("type") == "insufficient_quota":
                            return False, (
                                "OpenAI API Key kết nối được nhưng tài khoản ĐÃ HẾT CREDIT (credit_balance_exhausted). "
                                "Vui lòng nạp thêm credit tại: https://platform.openai.com/settings/organization/billing"
                            )
                    elif probe_resp.status_code == 401:
                        return False, "OpenAI API Key không hợp lệ (401 Unauthorized)."
                except Exception:
                    pass

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