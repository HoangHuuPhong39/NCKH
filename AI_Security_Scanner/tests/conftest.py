# -*- coding: utf-8 -*-
"""
tests/conftest.py - Pytest shared fixtures for AI Security Scanner test suite
"""

import os
import sys
import tempfile
from pathlib import Path
import pytest

# Add project root to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from core.config import cfg
from core.db import init_db
from web.app import app


@pytest.fixture(autouse=True)
def temp_database(monkeypatch):
    """Provides an isolated temporary SQLite database for each test."""
    temp_dir = tempfile.mkdtemp()
    db_path = os.path.join(temp_dir, "test_scanner.db")
    monkeypatch.setattr("core.db.DB_PATH", db_path)
    init_db()
    yield db_path
    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except Exception:
            pass


@pytest.fixture
def client():
    """Provides a Flask test client with test configuration."""
    app.config["TESTING"] = True
    with app.test_client() as client:
        yield client


class DummyLLMClient:
    """Mock LLM client for predictable testing without real inference calls."""

    def __init__(self, canned_response="Hello, this is a safe test response."):
        self.canned_response = canned_response
        self.call_count = 0
        self.last_prompt = None

    def send_prompt(self, prompt, system_prompt=None):
        self.call_count += 1
        self.last_prompt = prompt
        return self.canned_response

    def test_connection(self):
        return True, "Connected (Dummy)"


@pytest.fixture
def dummy_llm():
    return DummyLLMClient()
