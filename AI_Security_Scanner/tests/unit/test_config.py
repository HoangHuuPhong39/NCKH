# -*- coding: utf-8 -*-
"""
tests/unit/test_config.py - Unit tests for Config loader
"""

import os
from unittest.mock import patch
from core.config import Config, cfg


def test_config_defaults():
    assert cfg.get("scanner.target_url") is not None
    assert cfg.get("scanner.target_model") is not None
    assert cfg.get("scanner.timeout") == 60
    assert cfg.get("web.port") == 5000


def test_config_env_override():
    with patch.dict(os.environ, {"SCANNER_TIMEOUT": "99", "SCANNER_TARGET_MODEL": "mistral"}):
        test_cfg = Config()
        test_cfg._apply_env_overrides()
        assert test_cfg.get("scanner.timeout") == 99
        assert test_cfg.get("scanner.target_model") == "mistral"
