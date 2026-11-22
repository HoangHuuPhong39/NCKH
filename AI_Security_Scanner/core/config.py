# -*- coding: utf-8 -*-
"""
core/config.py - Centralized Configuration Loader for AI Security Scanner

Loads settings from `config.yaml` with precedence given to environment variables
(e.g., `SCANNER_TARGET_URL`, `SCANNER_TIMEOUT`, `SCANNER_JWT_SECRET`, etc.).
Supports .env files automatically if present.
"""

import os
import sys
from pathlib import Path
from typing import Any, Dict

# Optional yaml loader with graceful dictionary fallback
try:
    import yaml
except ImportError:
    yaml = None


def _load_env_file(env_path: Path) -> None:
    """Lightweight .env loader without requiring external python-dotenv."""
    if not env_path.exists():
        return
    try:
        with open(env_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, val = line.split("=", 1)
                key = key.strip()
                val = val.strip().strip("\"'")
                if key and key not in os.environ:
                    os.environ[key] = val
    except Exception:
        pass


class Config:
    """Unified configuration manager with environment variable overrides."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(Config, cls).__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self, config_file: str | None = None) -> None:
        if self._initialized:
            return

        self.project_root = Path(__file__).resolve().parent.parent
        _load_env_file(self.project_root / ".env")

        self.config_path = (
            Path(config_file) if config_file else self.project_root / "config.yaml"
        )
        self.data: Dict[str, Any] = self._load_defaults()
        default_jwt = self.data["web"]["jwt_secret_key"]
        default_api_key = self.data["web"]["admin_api_key"]

        _INSECURE_PLACEHOLDERS = {
            "",
            "ai-security-scanner-secret-key-change-in-production",
            "ai-scanner-admin-secret-token",
            "default-fallback-secret-key",
            "changeme",
            "secret",
        }

        if self.config_path.exists() and yaml:
            try:
                with open(self.config_path, "r", encoding="utf-8") as f:
                    loaded = yaml.safe_load(f)
                    if isinstance(loaded, dict):
                        self._deep_update(self.data, loaded)
            except Exception as e:
                print(f"[!] Warning loading config.yaml: {e}, using defaults.", file=sys.stderr)

        # Treat empty / known-placeholder secrets in config.yaml as unset so random defaults apply
        if str(self.data["web"].get("jwt_secret_key") or "").strip() in _INSECURE_PLACEHOLDERS:
            self.data["web"]["jwt_secret_key"] = default_jwt
        if str(self.data["web"].get("admin_api_key") or "").strip() in _INSECURE_PLACEHOLDERS:
            self.data["web"]["admin_api_key"] = default_api_key

        self._apply_env_overrides()

        using_ephemeral = (
            self.data["web"]["jwt_secret_key"] == default_jwt
            or self.data["web"]["admin_api_key"] == default_api_key
        )
        strict_secrets = os.environ.get("SCANNER_STRICT_SECRETS", "").lower() in ("true", "1", "yes")
        if using_ephemeral:
            if strict_secrets and self.data["web"].get("require_auth", False):
                raise RuntimeError(
                    "SCANNER_STRICT_SECRETS is enabled with require_auth=true, "
                    "but SCANNER_JWT_SECRET and SCANNER_ADMIN_API_KEY are not configured."
                )
            print(
                "[WARNING] Using randomly generated ephemeral secrets for jwt_secret_key / admin_api_key. "
                "Set SCANNER_JWT_SECRET and SCANNER_ADMIN_API_KEY in environment or .env for persistence.",
                file=sys.stderr,
            )

        self._initialized = True

    def _load_defaults(self) -> Dict[str, Any]:
        import secrets
        return {
            "scanner": {
                "target_url": "http://localhost:11434",
                "target_model": "llama3",
                "judge_model": "qwen2.5",
                "provider": "auto",
                "timeout": 90,
                "max_tokens": 512,
                "api_key": "",
                "max_retries": 1,
                "backoff_factor": 1.0,
                "retry_status_codes": [429, 500, 502, 503, 504],
                "pool_connections": 10,
                "pool_maxsize": 20,
                "circuit_breaker": {
                    "failure_threshold": 5,
                    "recovery_timeout": 30,
                },
            },
            "web": {
                "host": "127.0.0.1",
                "port": 5000,
                "debug": False,
                "require_auth": True,
                "trust_proxy": False,
                "cors_origins": [
                    "http://localhost:5000",
                    "http://127.0.0.1:5000",
                    "https://localhost:5000",
                    "https://127.0.0.1:5000",
                ],
                "allowed_internal_hosts": ["ollama", "ai-guard-proxy"],
                "allowed_local_ports": [],
                "jwt_secret_key": secrets.token_hex(32),
                "jwt_access_token_expires_minutes": 1440,
                "admin_api_key": secrets.token_urlsafe(32),
                "rate_limit_enabled": True,
                "rate_limit_per_minute": 120,
                "rate_limit_scan_start_per_minute": 10,
            },
            "logging": {
                "level": "INFO",
                "format": "text",
                "log_file": "logs/scanner.log",
                "max_bytes": 10485760,
                "backup_count": 5,
            },
            "storage": {
                "database_path": "data/scanner.db",
                "reports_dir": "reports",
                "allowed_scan_roots": [],
            },
            "governance": {
                "enforce_scope_whitelist": False,
                "authorized_targets": ["localhost", "127.0.0.1", "::1"],
                "allow_destructive_actions": False,
                "redact_reports": True,
                "audit_log_path": "logs/governance_audit.jsonl",
                "budget": {
                    "max_requests": 200,
                    "max_tokens": 100000,
                    "max_duration_sec": 600,
                },
            },
        }

    def _deep_update(self, base: dict, override: dict) -> None:
        for k, v in override.items():
            if isinstance(v, dict) and k in base and isinstance(base[k], dict):
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def _apply_env_overrides(self) -> None:
        # Scanner overrides
        if "SCANNER_TARGET_URL" in os.environ:
            self.data["scanner"]["target_url"] = os.environ["SCANNER_TARGET_URL"]
        if "SCANNER_TARGET_MODEL" in os.environ:
            self.data["scanner"]["target_model"] = os.environ["SCANNER_TARGET_MODEL"]
        if "SCANNER_JUDGE_MODEL" in os.environ:
            self.data["scanner"]["judge_model"] = os.environ["SCANNER_JUDGE_MODEL"]
        if "SCANNER_TIMEOUT" in os.environ:
            try:
                self.data["scanner"]["timeout"] = int(os.environ["SCANNER_TIMEOUT"])
            except ValueError:
                pass
        if "SCANNER_API_KEY" in os.environ:
            self.data["scanner"]["api_key"] = os.environ["SCANNER_API_KEY"]
        if "SCANNER_MAX_RETRIES" in os.environ:
            try:
                self.data["scanner"]["max_retries"] = int(os.environ["SCANNER_MAX_RETRIES"])
            except ValueError:
                pass

        # Web & Auth overrides
        if "SCANNER_REQUIRE_AUTH" in os.environ:
            self.data["web"]["require_auth"] = os.environ["SCANNER_REQUIRE_AUTH"].lower() in (
                "true",
                "1",
                "yes",
            )
        if "SCANNER_JWT_SECRET" in os.environ:
            self.data["web"]["jwt_secret_key"] = os.environ["SCANNER_JWT_SECRET"]
        if "SCANNER_ADMIN_API_KEY" in os.environ:
            self.data["web"]["admin_api_key"] = os.environ["SCANNER_ADMIN_API_KEY"]
        if "WEB_PORT" in os.environ:
            try:
                self.data["web"]["port"] = int(os.environ["WEB_PORT"])
            except ValueError:
                pass
        if "WEB_HOST" in os.environ:
            self.data["web"]["host"] = os.environ["WEB_HOST"]

        # Logging & DB overrides
        if "LOG_LEVEL" in os.environ:
            self.data["logging"]["level"] = os.environ["LOG_LEVEL"].upper()
        if "DATABASE_PATH" in os.environ:
            self.data["storage"]["database_path"] = os.environ["DATABASE_PATH"]
        if "SCANNER_ALLOWED_SCAN_ROOTS" in os.environ:
            roots = [
                p.strip()
                for p in os.environ["SCANNER_ALLOWED_SCAN_ROOTS"].split(os.pathsep)
                if p.strip()
            ]
            self.data["storage"]["allowed_scan_roots"] = roots
        if "SCANNER_CORS_ORIGINS" in os.environ:
            origins = [
                o.strip()
                for o in os.environ["SCANNER_CORS_ORIGINS"].split(",")
                if o.strip()
            ]
            self.data["web"]["cors_origins"] = origins
        if "SCANNER_PROVIDER" in os.environ:
            self.data["scanner"]["provider"] = os.environ["SCANNER_PROVIDER"].strip().lower()

    def get(self, key_path: str, default: Any = None) -> Any:
        """Access nested config values via dot-notation, e.g. 'scanner.target_url'."""
        keys = key_path.split(".")
        val = self.data
        for k in keys:
            if isinstance(val, dict) and k in val:
                val = val[k]
            else:
                return default
        return val

    def set(self, key_path: str, value: Any) -> None:
        """Set nested config value at runtime via dot-notation."""
        keys = key_path.split(".")
        target = self.data
        for k in keys[:-1]:
            if k not in target or not isinstance(target[k], dict):
                target[k] = {}
            target = target[k]
        target[keys[-1]] = value


# Singleton instance for easy import
cfg = Config()
