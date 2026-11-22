# -*- coding: utf-8 -*-
"""
core/governance.py - Operational Governance, Safety Controls & Audit Trail

Implements Section 9 ("Yêu cầu an toàn và quản trị khi vận hành"):
  1. Rules of Engagement (RoE) / Authorized Target Scope Enforcement
  2. Campaign Resource Budgets (Max Requests, Max Tokens, Max Duration, Kill-Switch)
  3. Sensitive Data Redaction for Reports, Evidence & Logs (API keys, JWT/Bearer,
     Private Keys, Credentials URIs, Vietnamese CCCD, Phone, Credit Cards, Emails)
  4. Immutable JSONL Governance Audit Trail
"""

from __future__ import annotations

import copy
import fnmatch
import ipaddress
import json
import os
import re
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

from core.config import cfg
from core.logger import logger

_PROJECT_ROOT = Path(__file__).resolve().parent.parent

# ==============================================================================
# 1. Sensitive Data Redaction Engine
# ==============================================================================

_REDACTION_PATTERNS: List[Tuple[str, re.Pattern[str], str]] = [
    (
        "PRIVATE_KEY",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY-----"
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    (
        "CREDENTIAL_URI",
        re.compile(
            r"\b(?:https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|mssql)://[^\s:@\"']+:[^\s@\"']+@[^\s\"']+"
        ),
        "[REDACTED_CREDENTIAL_URI]",
    ),
    (
        "QUERY_SECRET",
        re.compile(
            r"([?&](?:api_key|apikey|token|access_token|secret|key)=)[^&\s\"']+",
            re.IGNORECASE,
        ),
        r"\1[REDACTED_SECRET]",
    ),
    (
        "API_KEY",
        re.compile(
            r"\b(?:sk-(?:proj-|ant-|live-|test-|prod-)?[A-Za-z0-9_\-]{12,}|hf_[A-Za-z0-9]{16,}|gsk_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z\-_]{20,}|AKIA[0-9A-Z]{16})\b"
        ),
        "[REDACTED_API_KEY]",
    ),
    (
        "BEARER_TOKEN",
        re.compile(
            r"\bBearer\s+[A-Za-z0-9\-._~+/]{12,}=*",
            re.IGNORECASE,
        ),
        "Bearer [REDACTED_TOKEN]",
    ),
    (
        "JWT_TOKEN",
        re.compile(r"\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b"),
        "[REDACTED_JWT]",
    ),
    (
        "CREDIT_CARD",
        re.compile(r"\b(?:4[0-9]{3}|5[1-5][0-9]{2}|3[47][0-9]{2}|6011)[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}[\s\-]?[0-9]{3,4}\b"),
        "[REDACTED_CARD]",
    ),
    (
        "CCCD",
        # Vietnamese 12-digit Citizen ID (starts with 0, province code 001..096)
        re.compile(r"(?<!\d)0(?:0[1-9]|[1-8]\d|9[0-6])\d{9}(?!\d)"),
        "[REDACTED_CCCD]",
    ),
    (
        "VN_PHONE",
        re.compile(r"(?<!\d)(?:\+84|0)(?:3[2-9]|5[2689]|7[06-9]|8[1-9]|9[0-9])[\s.\-]?\d{3}[\s.\-]?\d{4}(?!\d)"),
        "[REDACTED_PHONE]",
    ),
    (
        "EMAIL",
        re.compile(r"\b[A-Za-z0-9._%+\-]+@(?!example\.com\b|evil\.com\b|test\.local\b)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
]


def redact_sensitive_data(text: Optional[str]) -> Tuple[str, List[str]]:
    """
    Mask sensitive PII and credentials in *text*.

    Returns:
        (redacted_text, sorted list of redaction category labels applied)
    """
    if not text or not isinstance(text, str):
        return (text or ""), []

    redacted = text
    applied: List[str] = []
    for label, pattern, replacement in _REDACTION_PATTERNS:
        new_text, count = pattern.subn(replacement, redacted)
        if count > 0:
            redacted = new_text
            if label not in applied:
                applied.append(label)
    return redacted, applied


def _redact_recursive(obj: Any) -> Any:
    """Recursively redact sensitive data in strings, dicts, and lists."""
    if isinstance(obj, str):
        redacted, _ = redact_sensitive_data(obj)
        return redacted
    if isinstance(obj, dict):
        return {k: _redact_recursive(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_redact_recursive(item) for item in obj]
    return obj


def redact_finding(finding: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep-copied finding dict with payload/response/notes/target_url redacted."""
    clean = copy.deepcopy(finding)
    all_labels: List[str] = []
    for field_name in ("payload", "response", "notes", "target_url"):
        if field_name in clean and isinstance(clean[field_name], str):
            redacted_val, labels = redact_sensitive_data(clean[field_name])
            clean[field_name] = redacted_val
            for lbl in labels:
                if lbl not in all_labels:
                    all_labels.append(lbl)
    clean["redacted_fields"] = all_labels
    return clean


# ==============================================================================
# 2. Rules of Engagement (RoE) / Scope Enforcement
# ==============================================================================

def _host_matches_rule(hostname: str, netloc: str, rule: str) -> bool:
    rule = rule.strip().lower()
    host = hostname.strip().lower()
    net = netloc.strip().lower()
    if not rule:
        return False

    if rule == "*":
        return True

    # Direct IP address match (handles IPv4 and full IPv6 literals like 2001:db8::1)
    try:
        rule_ip = ipaddress.ip_address(rule.strip("[]"))
        host_ip = ipaddress.ip_address(host.strip("[]"))
        return rule_ip == host_ip
    except ValueError:
        pass

    # Exact host:port match (single colon, non-CIDR)
    if rule.count(":") == 1 and "/" not in rule:
        if net == rule:
            return True

    # CIDR match (e.g. 10.0.0.0/8)
    if "/" in rule:
        try:
            network = ipaddress.ip_network(rule, strict=False)
            ip_obj = ipaddress.ip_address(host.strip("[]"))
            return ip_obj in network
        except ValueError:
            return False

    # Wildcard hostname match (e.g. *.staging.local)
    if "*" in rule or "?" in rule:
        return fnmatch.fnmatch(host, rule)

    return host == rule


def check_target_scope(
    target_url: str,
    authorized_targets: Optional[List[str]] = None,
    enforce: Optional[bool] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Verify that *target_url* falls within authorized testing scope (RoE).

    When *enforce* is None, reads ``governance.enforce_scope_whitelist`` from config.
    When *authorized_targets* is None, reads ``governance.authorized_targets`` from config.
    """
    should_enforce = (
        bool(cfg.get("governance.enforce_scope_whitelist", False))
        if enforce is None
        else bool(enforce)
    )
    if not should_enforce:
        return True, None

    if not target_url or not isinstance(target_url, str):
        return False, "Target URL is empty."

    parsed = urlparse(target_url.strip())
    hostname = parsed.hostname
    netloc = parsed.netloc
    if not hostname:
        return False, "Could not parse target hostname for scope verification."

    rules = (
        authorized_targets
        if authorized_targets is not None
        else cfg.get("governance.authorized_targets", ["localhost", "127.0.0.1", "::1"])
    )
    if not isinstance(rules, list) or len(rules) == 0:
        return False, "RoE Scope Violation: authorized_targets whitelist is empty."

    for rule in rules:
        if isinstance(rule, str) and _host_matches_rule(hostname, netloc, rule):
            return True, None

    return (
        False,
        f"RoE Scope Violation: target '{hostname}' is not in authorized_targets ({rules}).",
    )


# ==============================================================================
# 3. Campaign Resource Budget & Kill-Switch
# ==============================================================================

def estimate_tokens(text: Optional[str]) -> int:
    """Fast deterministic token estimator (~4 chars per token)."""
    if not text:
        return 0
    return max(1, len(text) // 4)


class CampaignBudget:
    """
    Thread-safe resource guardrail for a scan or regression campaign.
    Enforces max_requests, max_tokens, max_duration_sec, and an optional kill-switch.
    """

    def __init__(
        self,
        max_requests: Optional[int] = None,
        max_tokens: Optional[int] = None,
        max_duration_sec: Optional[float] = None,
        kill_switch: Optional[threading.Event] = None,
    ) -> None:
        self.max_requests = int(
            max_requests if max_requests is not None else cfg.get("governance.budget.max_requests", 200)
        )
        self.max_tokens = int(
            max_tokens if max_tokens is not None else cfg.get("governance.budget.max_tokens", 100000)
        )
        self.max_duration_sec = float(
            max_duration_sec
            if max_duration_sec is not None
            else cfg.get("governance.budget.max_duration_sec", 600)
        )
        self.kill_switch = kill_switch or threading.Event()
        self._lock = threading.Lock()
        self._started_at = time.monotonic()
        self.requests_used = 0
        self.tokens_used = 0
        self.exceeded = False
        self.exceeded_reason: Optional[str] = None

    def trigger_kill_switch(self, reason: str = "Emergency kill-switch triggered") -> None:
        with self._lock:
            self.kill_switch.set()
            self.exceeded = True
            self.exceeded_reason = reason

    def check_allowed(self) -> Tuple[bool, Optional[str]]:
        """Check whether the campaign is still within budget before sending a request."""
        with self._lock:
            if self.kill_switch.is_set():
                self.exceeded = True
                self.exceeded_reason = self.exceeded_reason or "Kill-switch activated"
                return False, self.exceeded_reason
            if self.max_requests > 0 and self.requests_used >= self.max_requests:
                self.exceeded = True
                self.exceeded_reason = f"Request budget exceeded ({self.requests_used}/{self.max_requests})"
                return False, self.exceeded_reason
            if self.max_tokens > 0 and self.tokens_used >= self.max_tokens:
                self.exceeded = True
                self.exceeded_reason = f"Token budget exceeded ({self.tokens_used}/{self.max_tokens})"
                return False, self.exceeded_reason
            elapsed = time.monotonic() - self._started_at
            if self.max_duration_sec > 0 and elapsed >= self.max_duration_sec:
                self.exceeded = True
                self.exceeded_reason = (
                    f"Duration budget exceeded ({elapsed:.1f}s/{self.max_duration_sec:.0f}s)"
                )
                return False, self.exceeded_reason
            return True, None

    def record_usage(
        self,
        prompt_text: str = "",
        response_text: str = "",
        explicit_tokens: Optional[int] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Record one completed request and return whether budget remains available."""
        toks = (
            int(explicit_tokens)
            if explicit_tokens is not None
            else (estimate_tokens(prompt_text) + estimate_tokens(response_text))
        )
        with self._lock:
            self.requests_used += 1
            self.tokens_used += max(0, toks)
        return self.check_allowed()

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            elapsed = round(time.monotonic() - self._started_at, 2)
            return {
                "requests_used": self.requests_used,
                "max_requests": self.max_requests,
                "tokens_used": self.tokens_used,
                "max_tokens": self.max_tokens,
                "elapsed_sec": elapsed,
                "max_duration_sec": self.max_duration_sec,
                "exceeded": self.exceeded,
                "exceeded_reason": self.exceeded_reason,
                "kill_switch_active": self.kill_switch.is_set(),
            }


# ==============================================================================
# 4. Immutable JSONL Governance Audit Trail
# ==============================================================================

class GovernanceAuditLogger:
    """Append-only JSONL audit logger for security testing governance."""

    def __init__(self, log_path: Optional[str] = None) -> None:
        raw_path = log_path or cfg.get("governance.audit_log_path", "logs/governance_audit.jsonl")
        p = Path(raw_path)
        self.log_path = p if p.is_absolute() else (_PROJECT_ROOT / p)
        self._lock = threading.Lock()

    def log_event(
        self,
        event_type: str,
        actor: str = "system",
        target_url: str = "",
        scan_id: Optional[int] = None,
        outcome: str = "OK",
        details: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        safe_details: Dict[str, Any] = _redact_recursive(details) if details else {}
        safe_target_url, _ = redact_sensitive_data(target_url or "")

        record = {
            "timestamp": datetime.now().isoformat(),
            "event_type": event_type,
            "actor": actor,
            "target_url": safe_target_url,
            "scan_id": scan_id,
            "outcome": outcome,
            "details": safe_details,
        }
        try:
            with self._lock:
                self.log_path.parent.mkdir(parents=True, exist_ok=True)
                with open(self.log_path, "a", encoding="utf-8") as fh:
                    fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            logger.warning("Failed to write governance audit log: %s", exc)
        return record

    def read_recent(self, limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
        if not self.log_path.exists():
            return []
        entries: List[Dict[str, Any]] = []
        try:
            with open(self.log_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        obj = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    if event_type and obj.get("event_type") != event_type:
                        continue
                    entries.append(obj)
        except OSError as exc:
            logger.warning("Failed to read governance audit log: %s", exc)
            return []
        return list(reversed(entries[-limit:]))


_default_audit_logger = GovernanceAuditLogger()


def log_audit_event(
    event_type: str,
    actor: str = "system",
    target_url: str = "",
    scan_id: Optional[int] = None,
    outcome: str = "OK",
    details: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    return _default_audit_logger.log_event(
        event_type=event_type,
        actor=actor,
        target_url=target_url,
        scan_id=scan_id,
        outcome=outcome,
        details=details,
    )


def get_audit_logs(limit: int = 100, event_type: Optional[str] = None) -> List[Dict[str, Any]]:
    return _default_audit_logger.read_recent(limit=limit, event_type=event_type)


def get_governance_policy() -> Dict[str, Any]:
    """Return current effective governance policy settings."""
    return {
        "enforce_scope_whitelist": bool(cfg.get("governance.enforce_scope_whitelist", False)),
        "authorized_targets": list(cfg.get("governance.authorized_targets", ["localhost", "127.0.0.1", "::1"])),
        "allow_destructive_actions": bool(cfg.get("governance.allow_destructive_actions", False)),
        "redact_reports": bool(cfg.get("governance.redact_reports", True)),
        "budget": {
            "max_requests": int(cfg.get("governance.budget.max_requests", 200)),
            "max_tokens": int(cfg.get("governance.budget.max_tokens", 100000)),
            "max_duration_sec": int(cfg.get("governance.budget.max_duration_sec", 600)),
        },
    }
