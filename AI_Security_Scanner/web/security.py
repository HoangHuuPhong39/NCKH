# -*- coding: utf-8 -*-
"""
web/security.py - Security Hardening, Authentication, Rate Limiting & Validation

Implements:
1. HMAC-SHA256 signed JWT authentication with algorithm verification and env/config secrets.
2. Thread-safe, endpoint-scoped sliding window rate limiter with TTL memory eviction.
3. Strict SSRF-hardened URL & RoE scope validation (client policies can only narrow, never bypass).
4. HTTP Security Headers middleware with smart static-asset caching.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import threading
import time
from functools import wraps
from typing import Any, Dict, List, Optional, Tuple

from flask import g, jsonify, request

from core.config import cfg
from core.logger import logger
from core.url_security import SAFE_SCHEMES, is_internal_ip, validate_target_url


# ==============================================================================
# 1. JWT / HMAC Token Authentication
# ==============================================================================

def _get_jwt_secret() -> bytes:
    secret = str(cfg.get("web.jwt_secret_key", "") or "").strip()
    if not secret:
        raise RuntimeError("web.jwt_secret_key is not configured.")
    return secret.encode("utf-8")


def _get_admin_api_key() -> str:
    return str(cfg.get("web.admin_api_key", "") or "").strip()


def generate_token(identity: str, expires_in_seconds: Optional[int] = None) -> str:
    """Generate a secure HMAC-SHA256 signed JWT token."""
    if expires_in_seconds is None:
        expires_in_seconds = int(cfg.get("web.jwt_access_token_expires_minutes", 1440)) * 60
    secret = _get_jwt_secret()
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": identity,
        "exp": now + int(expires_in_seconds),
        "iat": now,
    }
    header_b64 = base64.urlsafe_b64encode(json.dumps(header, separators=(",", ":")).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def _b64url_decode_json(segment: str) -> dict:
    padding = (-len(segment)) % 4
    padded = segment + ("=" * padding)
    return json.loads(base64.urlsafe_b64decode(padded).decode("utf-8"))


def verify_token(token: str) -> Optional[dict]:
    """Verify HMAC-SHA256 JWT token, validating header alg/typ, signature, and expiry."""
    try:
        if not isinstance(token, str) or not token.strip():
            return None
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts

        header_data = _b64url_decode_json(header_b64)
        if not isinstance(header_data, dict) or header_data.get("alg") != "HS256":
            return None

        secret = _get_jwt_secret()
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None

        payload_data = _b64url_decode_json(payload_b64)
        if not isinstance(payload_data, dict):
            return None
        if payload_data.get("exp", 0) < time.time():
            return None
        return payload_data
    except Exception as exc:
        logger.debug("Token verification failed: %s", exc)
        return None


def is_request_authenticated() -> Tuple[bool, Optional[str]]:
    """Check whether the current Flask request carries a valid API Key or Bearer JWT."""
    admin_key = _get_admin_api_key()
    api_key_header = request.headers.get("X-API-Key")
    if isinstance(api_key_header, str) and admin_key and hmac.compare_digest(api_key_header, admin_key):
        return True, "api_key_admin"

    auth_header = request.headers.get("Authorization")
    if isinstance(auth_header, str) and auth_header.startswith("Bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        payload = verify_token(token)
        if payload:
            return True, str(payload.get("sub", "authenticated_user"))

    # Native EventSource cannot attach custom Authorization headers; allow JWT via query param ONLY on SSE stream
    if request.path == "/api/scan/stream":
        q_token = request.args.get("token", "")
        if q_token:
            payload = verify_token(q_token)
            if payload:
                return True, str(payload.get("sub", "authenticated_user"))

    return False, None


def require_auth(f):
    """
    Decorator enforcing authentication when ``web.require_auth`` is enabled.
    Accepts:
    - ``Authorization: Bearer <jwt_token>``
    - ``X-API-Key: <admin_api_key>``
    - ``?token=<jwt_token>`` exclusively on ``/api/scan/stream`` (EventSource)
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not cfg.get("web.require_auth", False):
            return f(*args, **kwargs)

        ok, user = is_request_authenticated()
        if ok:
            g.user = user
            return f(*args, **kwargs)

        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required. Provide valid Bearer token or X-API-Key header.",
        }), 401

    return decorated


# ==============================================================================
# 2. Thread-Safe, Endpoint-Scoped Sliding Window Rate Limiter
# ==============================================================================

class RateLimiter:
    """Thread-safe sliding window in-memory rate limiter with bounded key eviction."""

    def __init__(self, max_keys: int = 5000) -> None:
        self.requests: Dict[str, List[float]] = {}
        self._lock = threading.Lock()
        self._max_keys = max_keys
        self._last_sweep = time.monotonic()

    def _sweep_stale(self, now: float, max_window: int = 300) -> None:
        if len(self.requests) < self._max_keys and (now - self._last_sweep) < 60:
            return
        stale_keys = [
            k for k, ts_list in self.requests.items()
            if not ts_list or (now - ts_list[-1]) > max_window
        ]
        for k in stale_keys:
            self.requests.pop(k, None)
        # Hard cap if still above max_keys under flood
        if len(self.requests) >= self._max_keys:
            oldest = sorted(self.requests.items(), key=lambda kv: kv[1][-1] if kv[1] else 0.0)
            for k, _ in oldest[: max(1, len(self.requests) // 4)]:
                self.requests.pop(k, None)
        self._last_sweep = now

    def is_allowed(
        self,
        client_id: str,
        limit: int,
        window_seconds: int = 60,
        bucket: str = "global",
    ) -> Tuple[bool, int]:
        now = time.time()
        key = f"{bucket}:{client_id}"
        with self._lock:
            self._sweep_stale(now, max_window=max(window_seconds, 60))
            timestamps = self.requests.get(key, [])
            timestamps = [t for t in timestamps if now - t < window_seconds]
            if len(timestamps) >= limit:
                self.requests[key] = timestamps
                return False, 0

            timestamps.append(now)
            self.requests[key] = timestamps
            return True, limit - len(timestamps)

    def reset(self) -> None:
        with self._lock:
            self.requests.clear()


_limiter = RateLimiter()


def rate_limit(limit: Optional[int] = None, window: int = 60, bucket: Optional[str] = None):
    """Decorator to limit request rate per (client IP, endpoint)."""
    def decorator(f):
        bucket_name = bucket or f.__name__

        @wraps(f)
        def wrapped(*args, **kwargs):
            if not cfg.get("web.rate_limit_enabled", True):
                return f(*args, **kwargs)

            effective_limit = (
                int(limit)
                if limit is not None
                else int(cfg.get("web.rate_limit_per_minute", 120))
            )

            if cfg.get("web.trust_proxy", False):
                forwarded = request.headers.get("X-Forwarded-For", "")
                client_ip = forwarded.split(",")[0].strip() if forwarded else (request.remote_addr or "127.0.0.1")
            else:
                client_ip = request.remote_addr or "127.0.0.1"

            allowed, _remaining = _limiter.is_allowed(
                client_ip, effective_limit, window, bucket=bucket_name
            )
            if not allowed:
                logger.warning("Rate limit exceeded for IP %s on %s", client_ip, request.path)
                return jsonify({
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Maximum {effective_limit} requests per {window}s.",
                }), 429
            return f(*args, **kwargs)

        return wrapped
    return decorator


# ==============================================================================
# 3. Input Validation (SSRF + Non-Bypassable Governance RoE)
# ==============================================================================

from modules.registry import ALLOWED_MODULES_SET as ALLOWED_MODULES_WHITELIST


def validate_scan_request(data: dict, allow_local_target: bool = True) -> Tuple[bool, Optional[str]]:
    """Strictly validate scan initiation payload (SSRF + non-bypassable server RoE)."""
    if not isinstance(data, dict):
        return False, "Payload must be a valid JSON object."

    target_url = data.get("target_url")
    url_ok, url_err = validate_target_url(target_url, allow_local_target=allow_local_target)
    if not url_ok:
        return False, url_err

    # Operational Governance: Rules of Engagement (RoE) Scope Whitelist
    # Step 1: ALWAYS enforce server-side RoE policy first (cannot be widened by client payload)
    from core.governance import check_target_scope
    server_ok, server_err = check_target_scope(target_url.strip())
    if not server_ok:
        return False, server_err

    # Step 2: Optional client-supplied authorized_targets may only NARROW scope further
    client_targets = data.get("authorized_targets")
    if client_targets is not None:
        if not isinstance(client_targets, list):
            return False, "Field 'authorized_targets' must be a list of host/CIDR rules."
        client_ok, client_err = check_target_scope(
            target_url.strip(),
            authorized_targets=client_targets,
            enforce=True,
        )
        if not client_ok:
            return False, client_err

    # Validate target_model
    model = data.get("target_model")
    if not model or not isinstance(model, str) or len(model.strip()) > 100:
        return False, "Field 'target_model' is required (max 100 characters)."

    # Validate module(s) if provided
    module = data.get("module")
    if module and module not in ALLOWED_MODULES_WHITELIST:
        return False, f"Unknown module '{module}'. Allowed: {sorted(list(ALLOWED_MODULES_WHITELIST))}"

    modules_list = data.get("modules")
    if modules_list is not None:
        if not isinstance(modules_list, list):
            return False, "Field 'modules' must be a list of module names."
        unknown = [m for m in modules_list if m not in ALLOWED_MODULES_WHITELIST]
        if unknown:
            return False, f"Unknown module(s) {unknown}. Allowed: {sorted(list(ALLOWED_MODULES_WHITELIST))}"

    # Validate timeout
    timeout = data.get("timeout")
    if timeout is not None:
        try:
            timeout_val = int(timeout)
            if not (1 <= timeout_val <= 300):
                return False, "Timeout must be an integer between 1 and 300 seconds."
        except (ValueError, TypeError):
            return False, "Field 'timeout' must be a valid integer."

    return True, None


def validate_config_request(data: dict) -> Tuple[bool, Optional[str]]:
    """Validate configuration updates."""
    if not isinstance(data, dict):
        return False, "Config data must be a JSON object."
    if "target_url" in data:
        url_ok, url_err = validate_target_url(data["target_url"], allow_local_target=True)
        if not url_ok:
            return False, url_err
    if "timeout" in data:
        try:
            val = int(data["timeout"])
            if not (1 <= val <= 300):
                return False, "Timeout must be between 1 and 300."
        except Exception:
            return False, "Timeout must be an integer."
    return True, None


def validate_custom_payloads(payloads: Any) -> Tuple[bool, Optional[str]]:
    """Validate custom payload input (accepts either list of payload dicts or {module: list})."""
    def _validate_list(items: Any) -> Tuple[bool, Optional[str]]:
        if not isinstance(items, list):
            return False, "Custom payloads must be a list."
        if len(items) > 50:
            return False, "Maximum 50 custom payloads allowed."
        for item in items:
            if not isinstance(item, dict):
                return False, "Each custom payload must be a dictionary."
            if "name" not in item or "payload" not in item:
                return False, "Each custom payload must have 'name' and 'payload' keys."
            if not isinstance(item["payload"], str):
                return False, "Payload must be a string."
            if len(item["payload"]) > 10000:
                return False, "Payload length must not exceed 10000 characters."
        return True, None

    if isinstance(payloads, dict):
        for mod_key, mod_items in payloads.items():
            if mod_key not in ALLOWED_MODULES_WHITELIST:
                return False, f"Unknown module '{mod_key}' in custom_payloads."
            ok, err = _validate_list(mod_items)
            if not ok:
                return False, err
        return True, None
    return _validate_list(payloads)


# ==============================================================================
# 4. Security Headers Middleware
# ==============================================================================

def add_security_headers(response):
    """Add security headers with appropriate cache policy per content type."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "script-src-elem 'self'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data: blob:; "
        "media-src 'self'; "
        "object-src 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "frame-ancestors 'self'"
    )
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"

    # Preserve SSE no-cache and allow caching of static assets (JS/CSS/images/video)
    is_sse = (response.mimetype == "text/event-stream")
    is_static = False
    try:
        is_static = request.path.startswith("/static/")
    except RuntimeError:
        is_static = False

    if is_sse:
        response.headers["Cache-Control"] = "no-cache"
    elif is_static:
        response.headers["Cache-Control"] = "public, max-age=86400"
    else:
        response.headers["Cache-Control"] = "no-store"

    return response
