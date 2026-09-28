# -*- coding: utf-8 -*-
"""
tests/unit/test_async_scanner.py - Unit tests for ConcurrentScanner
"""

import threading
import pytest
from core.async_scanner import ConcurrentScanner


class DummyModule:
    name = "Dummy Exploit"
    owasp = "LLM01"
    mitre = "AML.T0051"
    payloads = [
        {"name": "P1", "payload": "Safe question 1"},
        {"name": "P2", "payload": "Safe question 2"},
        {"name": "P3", "payload": "Safe question 3"},
    ]


class MockClient:
    def send_prompt(self, p):
        return "I cannot answer this request as an AI."


def test_concurrent_scanner_execution():
    scanner = ConcurrentScanner(max_workers=2)
    mod = DummyModule()
    client = MockClient()

    progress_events = []

    def on_prog(curr, tot, pct):
        progress_events.append((curr, tot, pct))

    results = scanner.run_module_concurrently(
        module=mod,
        llm_client=client,
        scan_id=1,
        on_progress=on_prog,
    )

    assert len(results) == 3
    assert len(progress_events) == 3
    for r in results:
        assert r["is_vuln"] is False
        assert r["severity"] == "INFO"
