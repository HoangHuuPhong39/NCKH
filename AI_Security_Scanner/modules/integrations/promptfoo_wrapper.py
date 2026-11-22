# -*- coding: utf-8 -*-
"""
modules/integrations/promptfoo_wrapper.py - Promptfoo LLM Testing Integration

Hardened wrapper for Promptfoo (https://github.com/promptfoo/promptfoo):
1. Checks for a locally installed ``promptfoo`` binary (or ``npx --no-install``).
2. Serializes YAML configuration safely via ``yaml.safe_dump()`` with strict
   plugin allowlisting and provider prefix validation (prevents YAML/exec injection).
3. Validates target URLs and confines explicit ``config_path`` to allowed scan roots.
4. Returns explicit UNAVAILABLE status instead of fabricated simulated vulnerabilities.
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

_TEST_TYPE_META: Dict[str, Dict[str, str]] = {
    "prompt_injection":    {"owasp": "LLM01", "mitre": "AML.T0051", "severity": "HIGH"},
    "jailbreak":           {"owasp": "LLM01", "mitre": "AML.T0054", "severity": "CRITICAL"},
    "pii_extraction":      {"owasp": "LLM02", "mitre": "AML.T0024", "severity": "HIGH"},
    "hallucination":       {"owasp": "LLM09", "mitre": "N/A",       "severity": "MEDIUM"},
    "insecure_output":     {"owasp": "LLM05", "mitre": "AML.T0020", "severity": "HIGH"},
    "excessive_agency":    {"owasp": "LLM06", "mitre": "AML.T0048", "severity": "HIGH"},
    "overreliance":        {"owasp": "LLM09", "mitre": "N/A",       "severity": "MEDIUM"},
    "system_prompt_leak":  {"owasp": "LLM07", "mitre": "AML.T0054", "severity": "CRITICAL"},
}

_DEFAULT_TEST_TYPES = ["prompt_injection", "jailbreak", "pii_extraction"]
_DISALLOWED_PROVIDER_PREFIXES = ("exec:", "file:", "python:", "script:", "webhook:")


class PromptfooWrapper:
    """Hardened integration wrapper around the Promptfoo LLM red-team CLI."""

    def __init__(self, timeout: int = 300):
        self.timeout = timeout
        self._available: Optional[bool] = None

    def is_available(self) -> bool:
        """
        Check whether a locally installed ``promptfoo`` CLI is available without
        triggering remote npm downloads.
        """
        if self._available is not None:
            return self._available

        pf_bin = shutil.which("promptfoo")
        if pf_bin:
            cmd = [pf_bin, "--version"]
        elif shutil.which("npx"):
            cmd = ["npx", "--no-install", "promptfoo", "--version"]
        else:
            logger.debug("Neither promptfoo nor npx found on PATH.")
            self._available = False
            return False

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=8,
            )
            self._available = proc.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.debug("Promptfoo availability check failed: %s", exc)
            self._available = False

        return self._available

    @staticmethod
    def get_install_instructions() -> str:
        return "npm install -g promptfoo"

    def generate_config(
        self,
        target_url: str,
        model_name: str,
        test_types: Optional[List[str]] = None,
    ) -> str:
        """
        Safely generate a Promptfoo YAML configuration using ``yaml.safe_dump()``.
        Validates test types against ``_TEST_TYPE_META``, blocks arbitrary code
        provider prefixes (``exec:``, ``file:``, ``python:``), and validates URL.
        """
        from core.path_security import validate_safe_identifier
        from core.url_security import validate_target_url

        types = test_types or _DEFAULT_TEST_TYPES
        clean_types: List[str] = []
        for ttype in types:
            key = str(ttype).strip()
            if key not in _TEST_TYPE_META:
                raise ValueError(
                    f"Unsupported Promptfoo test type '{key}'. Allowed: {sorted(_TEST_TYPE_META.keys())}"
                )
            clean_types.append(key)

        clean_model = validate_safe_identifier(str(model_name), "model_name")
        if any(clean_model.lower().startswith(prefix) for prefix in _DISALLOWED_PROVIDER_PREFIXES):
            raise ValueError(f"Disallowed Promptfoo provider prefix in model_name: '{clean_model}'.")

        clean_url = str(target_url).strip()
        url_ok, url_err = validate_target_url(clean_url)
        if not url_ok:
            raise ValueError(url_err or "Invalid target URL for Promptfoo.")

        config_obj = {
            "targets": [
                {
                    "id": clean_model,
                    "config": {"apiBaseUrl": clean_url},
                }
            ],
            "redteam": {
                "purpose": f"AI Security Scanner red-team evaluation against {clean_model}.",
                "plugins": [{"id": t} for t in clean_types],
            },
            "defaultTest": {
                "options": {
                    "provider": {
                        "id": clean_model,
                        "config": {"apiBaseUrl": clean_url},
                    }
                }
            },
        }
        return yaml.safe_dump(config_obj, sort_keys=False, allow_unicode=True)

    def run_redteam(
        self,
        target_url: str,
        model_name: str,
        config_path: Optional[str] = None,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Execute Promptfoo when installed; otherwise return explicit UNAVAILABLE status."""
        if not self.is_available():
            logger.warning("Promptfoo not available. Run: %s", self.get_install_instructions())
            return self._simulate_results(target_url, model_name, test_types)

        from core.path_security import resolve_safe_path

        tmp_config: Optional[str] = None
        if config_path is None:
            yaml_content = self.generate_config(target_url, model_name, test_types)
            with tempfile.NamedTemporaryFile(
                mode="w",
                suffix=".yaml",
                prefix="promptfoo_",
                delete=False,
                encoding="utf-8",
            ) as f:
                f.write(yaml_content)
                tmp_config = f.name
            config_path = tmp_config
        else:
            config_path = str(resolve_safe_path(config_path, must_exist=True))

        output_fd, output_path = tempfile.mkstemp(suffix=".json", prefix="promptfoo_output_")
        os.close(output_fd)

        pf_bin = shutil.which("promptfoo")
        base_cmd = [pf_bin] if pf_bin else ["npx", "--no-install", "promptfoo"]
        cmd = [
            *base_cmd, "eval",
            "--config", config_path,
            "--output", output_path,
            "--output-format", "json",
            "--no-progress-bar",
        ]

        raw_output = ""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw_output = (proc.stdout or "") + "\n" + (proc.stderr or "")
            if os.path.exists(output_path) and os.path.getsize(output_path) > 0:
                with open(output_path, "r", encoding="utf-8") as f:
                    file_content = f.read().strip()
                if file_content:
                    raw_output = file_content
        except subprocess.TimeoutExpired:
            logger.error("Promptfoo timed out after %d s.", self.timeout)
            raw_output = f"TIMEOUT after {self.timeout} seconds"
        except Exception as exc:
            logger.error("Promptfoo subprocess error: %s", exc)
            raw_output = str(exc)
        finally:
            if tmp_config and os.path.exists(tmp_config):
                os.unlink(tmp_config)
            if os.path.exists(output_path):
                os.unlink(output_path)

        return self.parse_promptfoo_output(raw_output, test_types or _DEFAULT_TEST_TYPES)

    def parse_promptfoo_output(
        self,
        output: str,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Parse Promptfoo JSON or text output into framework findings format."""
        findings: List[Dict[str, Any]] = []

        try:
            data = json.loads(output)
            raw_results = (
                data.get("results", {}).get("results", [])
                or data.get("results", [])
                or []
            )
            for r in raw_results:
                passed = r.get("pass", True)
                plugin_id = (
                    r.get("testCase", {}).get("metadata", {}).get("pluginId", "unknown")
                    or r.get("metadata", {}).get("pluginId", "unknown")
                )
                meta = _TEST_TYPE_META.get(plugin_id, {"owasp": "N/A", "mitre": "N/A", "severity": "MEDIUM"})
                findings.append({
                    "probe": plugin_id,
                    "result": "PASS" if passed else "FAIL",
                    "severity": "INFO" if passed else meta["severity"],
                    "owasp_code": meta["owasp"],
                    "mitre_code": meta["mitre"],
                    "prompt": r.get("prompt", {}).get("raw", "")[:200],
                    "response": r.get("response", {}).get("output", "")[:200],
                    "detail": f"Promptfoo plugin '{plugin_id}': {'PASS' if passed else 'FAIL'}",
                })
            if findings:
                return findings
        except (json.JSONDecodeError, KeyError, TypeError):
            pass

        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            result = None
            if "PASS" in line.upper():
                result = "PASS"
            elif "FAIL" in line.upper() or "ERROR" in line.upper():
                result = "FAIL"
            if result:
                findings.append({
                    "probe": "promptfoo",
                    "result": result,
                    "severity": "INFO" if result == "PASS" else "HIGH",
                    "owasp_code": "LLM01",
                    "mitre_code": "AML.T0051",
                    "detail": line[:300],
                    "prompt": "",
                    "response": "",
                })

        if not findings:
            types_used = test_types or _DEFAULT_TEST_TYPES
            findings.append({
                "probe": "promptfoo",
                "result": "UNKNOWN",
                "severity": "INFO",
                "owasp_code": "N/A",
                "mitre_code": "N/A",
                "detail": output[:500].strip() or "No output from Promptfoo.",
                "prompt": "",
                "response": "",
                "test_types": types_used,
            })

        return findings

    def _simulate_results(
        self,
        target_url: str,
        model_name: str,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return explicit UNAVAILABLE status when Promptfoo is not installed (no fake findings)."""
        types = test_types or _DEFAULT_TEST_TYPES
        clean_model = str(model_name).replace("\n", "").replace("\r", "")
        clean_url = str(target_url).replace("\n", "").replace("\r", "")
        results: List[Dict[str, Any]] = []
        for ttype in types:
            meta = _TEST_TYPE_META.get(ttype, {"owasp": "N/A", "mitre": "N/A", "severity": "INFO"})
            results.append({
                "probe": ttype,
                "result": "UNAVAILABLE",
                "simulated": False,
                "severity": "INFO",
                "owasp_code": meta["owasp"],
                "mitre_code": meta["mitre"],
                "detail": (
                    f"Promptfoo not available (run: {self.get_install_instructions()}). "
                    f"No live test executed for '{ttype}' against {clean_model} @ {clean_url}."
                ),
                "prompt": "",
                "response": "",
            })
        return results

    def __repr__(self) -> str:
        return f"<PromptfooWrapper available={self.is_available()} timeout={self.timeout}s>"
