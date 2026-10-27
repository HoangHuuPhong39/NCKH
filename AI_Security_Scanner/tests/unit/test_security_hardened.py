# -*- coding: utf-8 -*-
"""
tests/unit/test_security_hardened.py - Verification tests for security hardening (SSRF, Auth, Rate Limiting, Headers)
"""

import pytest
from web.security import is_internal_ip, validate_scan_request, add_security_headers
from flask import Response


def test_ssrf_internal_ip_blocking():
    # Loopback
    assert is_internal_ip("127.0.0.1") is True
    assert is_internal_ip("localhost") is True
    assert is_internal_ip("127.0.0.99") is True

    # Cloud metadata
    assert is_internal_ip("169.254.169.254") is True
    assert is_internal_ip("instance-data") is True
    assert is_internal_ip("metadata.google.internal") is True

    # RFC 1918 Private Ranges
    assert is_internal_ip("10.0.0.1") is True
    assert is_internal_ip("192.168.1.1") is True
    assert is_internal_ip("172.16.0.1") is True

    # Public safe IPs / Hostnames
    assert is_internal_ip("8.8.8.8") is False
    assert is_internal_ip("api.openai.com") is False
    assert is_internal_ip("huggingface.co") is False


def test_validate_scan_request_ssrf_rejection():
    # Attempting to scan AWS metadata service should be rejected immediately
    data = {
        "target_url": "http://169.254.169.254/latest/meta-data/",
        "target_model": "llama3",
        "module": "prompt_injection"
    }
    valid, err = validate_scan_request(data)
    assert valid is False
    assert "internal" in err.lower() or "ssrf" in err.lower()


def test_validate_scan_request_private_lan_rejection():
    data = {
        "target_url": "http://192.168.1.100:11434",
        "target_model": "llama3",
        "module": "prompt_injection"
    }
    valid, err = validate_scan_request(data)
    assert valid is False
    assert "internal" in err.lower() or "ssrf" in err.lower()


def test_strict_security_headers():
    res = Response("OK")
    res = add_security_headers(res)

    assert "X-Content-Type-Options" in res.headers
    assert res.headers["X-Content-Type-Options"] == "nosniff"

    assert "Content-Security-Policy" in res.headers
    assert "Strict-Transport-Security" in res.headers
    assert "Permissions-Policy" in res.headers
