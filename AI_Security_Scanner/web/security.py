# -*- coding: utf-8 -*-
"""
web/security.py - Security Hardening, Authentication, Rate Limiting & Validation

Implements:
1. Token / JWT-style authentication with HMAC-SHA256 signature.
2. In-memory sliding window rate limiter per client IP.
3. Strict input validation for scanner target URLs, models, and payloads.
4. HTTP Security Headers middleware (XSS, Clickjacking, MIME sniffing).
"""

import base64
import hashlib
import hmac
import json
import re
import time
from functools import wraps
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urlparse

from flask import request, jsonify, g
from core.config import cfg
from core.logger import logger


# ==============================================================================
# 1. JWT / HMAC Token Authentication
# ==============================================================================

def generate_token(identity: str, expires_in_seconds: int = 86400) -> str:
    """Generates a secure HMAC-SHA256 signed JWT-like token."""
    secret = cfg.get("web.jwt_secret_key", "default-fallback-secret-key").encode("utf-8")
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": identity,
        "exp": int(time.time()) + expires_in_seconds,
        "iat": int(time.time()),
    }
    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).decode().rstrip("=")
    return f"{header_b64}.{payload_b64}.{sig_b64}"


def verify_token(token: str) -> Optional[dict]:
    """Verifies HMAC-SHA256 token and returns payload if valid and not expired."""
    try:
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header_b64, payload_b64, sig_b64 = parts
        secret = cfg.get("web.jwt_secret_key", "default-fallback-secret-key").encode("utf-8")
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")

        # Recalculate signature
        expected_sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
        expected_sig_b64 = base64.urlsafe_b64encode(expected_sig).decode().rstrip("=")

        if not hmac.compare_digest(sig_b64, expected_sig_b64):
            return None

        # Pad payload if needed
        padding = 4 - (len(payload_b64) % 4)
        if padding and padding != 4:
            payload_b64 += "=" * padding
        payload_data = json.loads(base64.urlsafe_b64decode(payload_b64).decode())

        if payload_data.get("exp", 0) < time.time():
            return None  # Expired
        return payload_data
    except Exception as exc:
        logger.debug("Token verification failed: %s", exc)
        return None


def require_auth(f):
    """
    Decorator enforcing authentication if `web.require_auth` is enabled.
    Accepts:
    - Authorization: Bearer <jwt_token>
    - X-API-Key: <admin_api_key>
    """
    @wraps(f)
    def decorated(*args, **kwargs):
        if not cfg.get("web.require_auth", False):
            return f(*args, **kwargs)

        # Check API Key header
        admin_key = cfg.get("web.admin_api_key", "ai-scanner-admin-secret-token")
        api_key_header = request.headers.get("X-API-Key")
        if api_key_header and hmac.compare_digest(api_key_header, admin_key):
            g.user = "api_key_admin"
            return f(*args, **kwargs)

        # Check Bearer token
        auth_header = request.headers.get("Authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ", 1)[1]
            payload = verify_token(token)
            if payload:
                g.user = payload.get("sub", "authenticated_user")
                return f(*args, **kwargs)

        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required. Provide valid Bearer token or X-API-Key header.",
        }), 401

    return decorated


# ==============================================================================
# 2. In-Memory Sliding Window Rate Limiting
# ==============================================================================

class RateLimiter:
    """Sliding window in-memory rate limiter per IP address."""

    def __init__(self) -> None:
        self.requests: Dict[str, List[float]] = {}

    def is_allowed(self, client_id: str, limit: int, window_seconds: int = 60) -> Tuple[bool, int]:
        now = time.time()
        timestamps = self.requests.get(client_id, [])
        # Prune expired timestamps
        timestamps = [t for t in timestamps if now - t < window_seconds]
        if len(timestamps) >= limit:
            remaining = 0
            self.requests[client_id] = timestamps
            return False, remaining

        timestamps.append(now)
        self.requests[client_id] = timestamps
        remaining = limit - len(timestamps)
        return True, remaining


_limiter = RateLimiter()


def rate_limit(limit: int = 60, window: int = 60):
    """Decorator to limit request rate per IP."""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            if not cfg.get("web.rate_limit_enabled", True):
                return f(*args, **kwargs)

            client_ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
            allowed, remaining = _limiter.is_allowed(client_ip, limit, window)
            if not allowed:
                logger.warning("Rate limit exceeded for IP %s on %s", client_ip, request.path)
                return jsonify({
                    "error": "Too Many Requests",
                    "message": f"Rate limit exceeded. Maximum {limit} requests per {window}s.",
                }), 429
            response = f(*args, **kwargs)
            return response
        return wrapped
    return decorator


# ==============================================================================
# 3. Input Validation
# ==============================================================================

SAFE_SCHEMES = {"http", "https"}
ALLOWED_MODULES_WHITELIST = {
    "prompt_injection", "jailbreak", "sensitive_disclosure",
    "output_handling", "excessive_agency", "prompt_leak",
    "rag_security", "misinformation", "model_dos", "port_scan",
}


def validate_scan_request(data: dict) -> Tuple[bool, Optional[str]]:
    """Strictly validates scan initiation payload."""
    if not isinstance(data, dict):
        return False, "Payload must be a valid JSON object."

    # Validate target_url
    target_url = data.get("target_url")
    if not target_url or not isinstance(target_url, str):
        return False, "Field 'target_url' is required and must be a string."

    target_url = target_url.strip()
    try:
        parsed = urlparse(target_url)
        if parsed.scheme.lower() not in SAFE_SCHEMES:
            return False, f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed."
        if not parsed.netloc:
            return False, "Target URL must contain a valid host and port."
    except Exception as exc:
        return False, f"Malformed target URL: {exc}"

    # Validate target_model
    model = data.get("target_model")
    if not model or not isinstance(model, str) or len(model.strip()) > 100:
        return False, "Field 'target_model' is required (max 100 characters)."

    # Validate module if provided
    module = data.get("module")
    if module and module not in ALLOWED_MODULES_WHITELIST:
        return False, f"Unknown module '{module}'. Allowed: {sorted(list(ALLOWED_MODULES_WHITELIST))}"

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
    """Validates configuration updates."""
    if not isinstance(data, dict):
        return False, "Config data must be a JSON object."
    if "target_url" in data:
        url = data["target_url"]
        parsed = urlparse(url)
        if parsed.scheme.lower() not in SAFE_SCHEMES or not parsed.netloc:
            return False, "Invalid target_url scheme or host."
    if "timeout" in data:
        try:
            val = int(data["timeout"])
            if not (1 <= val <= 300):
                return False, "Timeout must be between 1 and 300."
        except Exception:
            return False, "Timeout must be an integer."
    return True, None


# ==============================================================================
# 4. Security Headers Middleware
# ==============================================================================

def add_security_headers(response):
    """Adds standard security headers to protect against common web attacks."""
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    return response
