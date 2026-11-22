# -*- coding: utf-8 -*-
"""
core/url_security.py - Centralized SSRF & Target URL Validation

Validates user-supplied HTTP(S) target URLs using IPv4 + IPv6 DNS resolution
(``socket.getaddrinfo``), blocks cloud metadata & private RFC1918 networks,
and enforces optional loopback port restrictions.
"""

from __future__ import annotations

import ipaddress
import socket
from typing import Optional, Set, Tuple
from urllib.parse import urlparse

from core.config import cfg

SAFE_SCHEMES: Set[str] = {"http", "https"}

FORBIDDEN_HOSTNAMES: Set[str] = {
    "localhost",
    "localhost.localdomain",
    "metadata.google.internal",
    "metadata.google",
    "metadata.azure.internal",
    "instance-data",
    "instance-data.ec2.internal",
}

LOCALHOST_ALIASES: Set[str] = {"localhost", "127.0.0.1", "::1"}


def _is_blocked_ip(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Return True if an IPv4/IPv6 address belongs to a non-public / restricted range."""
    if isinstance(ip_obj, ipaddress.IPv6Address) and ip_obj.ipv4_mapped is not None:
        ip_obj = ip_obj.ipv4_mapped
    return bool(
        ip_obj.is_loopback
        or ip_obj.is_private
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_unspecified
        or ip_obj.is_reserved
    )


def is_internal_ip(hostname: str) -> bool:
    """
    Resolve *hostname* across all IPv4 and IPv6 records and return True if ANY
    resolved address is loopback, private, link-local, multicast, unspecified,
    reserved, or if resolution fails (fail-closed).
    """
    if not hostname or not isinstance(hostname, str):
        return True

    host_clean = hostname.strip().lower().rstrip(".")
    if not host_clean or host_clean in FORBIDDEN_HOSTNAMES:
        return True

    # Direct IP literal check first (supports IPv4 & IPv6 without DNS)
    try:
        ip_literal = ipaddress.ip_address(host_clean)
        return _is_blocked_ip(ip_literal)
    except ValueError:
        pass

    # Full IPv4 + IPv6 resolution via getaddrinfo
    try:
        infos = socket.getaddrinfo(host_clean, None, type=socket.SOCK_STREAM)
        if not infos:
            return True
        for info in infos:
            sockaddr = info[4]
            ip_str = sockaddr[0]
            # Strip IPv6 scope ID if present (e.g. fe80::1%eth0)
            if "%" in ip_str:
                ip_str = ip_str.split("%", 1)[0]
            ip_obj = ipaddress.ip_address(ip_str)
            if _is_blocked_ip(ip_obj):
                return True
        return False
    except Exception:
        # Fail-closed on unresolvable hostnames
        return True


def validate_target_url(
    target_url: str,
    allow_local_target: bool = True,
    allowed_local_ports: Optional[Set[int]] = None,
) -> Tuple[bool, Optional[str]]:
    """
    Validate a target URL for scheme safety, hostname integrity, and SSRF protection.

    Returns:
        (is_valid, error_message_or_None)
    """
    if not target_url or not isinstance(target_url, str):
        return False, "Field 'target_url' is required and must be a string."

    url = target_url.strip()
    if any(ch in url for ch in ("\r", "\n", "\x00")):
        return False, "Target URL contains disallowed control characters."

    try:
        parsed = urlparse(url)
    except Exception as exc:
        return False, f"Malformed target URL: {exc}"

    if parsed.scheme.lower() not in SAFE_SCHEMES:
        return False, f"Invalid URL scheme '{parsed.scheme}'. Only http and https are allowed."

    if not parsed.netloc:
        return False, "Target URL must contain a valid host and port."

    hostname = parsed.hostname
    if not hostname:
        return False, "Could not extract hostname from URL."

    host_lower = hostname.lower()
    is_local = host_lower in LOCALHOST_ALIASES

    # Also honor explicit Docker/internal service hostnames configured in governance/config
    extra_allowed_hosts = {
        str(h).strip().lower()
        for h in (cfg.get("web.allowed_internal_hosts", []) or [])
        if str(h).strip()
    }
    if host_lower in extra_allowed_hosts:
        return True, None

    if is_local and allow_local_target:
        # Enforce optional local port allowlist if configured
        ports_cfg = allowed_local_ports
        if ports_cfg is None:
            raw_ports = cfg.get("web.allowed_local_ports", None)
            if isinstance(raw_ports, list) and raw_ports:
                ports_cfg = {int(p) for p in raw_ports}
        if ports_cfg:
            port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
            if port not in ports_cfg:
                return False, (
                    f"Localhost port {port} is not in web.allowed_local_ports "
                    f"({sorted(ports_cfg)})."
                )
        return True, None

    if is_internal_ip(hostname):
        return False, "Internal IP or hostname is not allowed (SSRF protection)."

    return True, None
