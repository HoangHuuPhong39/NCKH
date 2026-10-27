# -*- coding: utf-8 -*-
"""
modules/integrations/promptfoo_wrapper.py - Promptfoo LLM Testing Integration

Wrapper cho Promptfoo (https://github.com/promptfoo/promptfoo):
một công cụ open-source để evaluate và red-team LLM.

Promptfoo chạy qua Node.js (``npx promptfoo``), wrapper này:
1. Kiểm tra xem ``npx`` và ``promptfoo`` có sẵn không.
2. Sinh file config YAML cho từng kịch bản test.
3. Chạy ``npx promptfoo eval`` qua subprocess.
4. Parse kết quả JSON/text output về findings format.

Install: npm install -g promptfoo
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Supported test types → OWASP / MITRE mappings
# ---------------------------------------------------------------------------

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

# Default test types dùng khi không chỉ định
_DEFAULT_TEST_TYPES = ["prompt_injection", "jailbreak", "pii_extraction"]


class PromptfooWrapper:
    """
    Integration wrapper around the Promptfoo LLM red-team tool.

    Promptfoo is executed as a Node.js subprocess (``npx promptfoo eval``).
    This wrapper handles:
    - Availability checking (``npx`` + ``promptfoo`` version check)
    - YAML config generation for various test scenarios
    - Subprocess execution with timeout handling
    - JSON/text output parsing into framework findings format

    Example::

        pfw = PromptfooWrapper()
        if pfw.is_available():
            findings = pfw.run_redteam(
                target_url="http://localhost:8080/v1/chat",
                model_name="gpt-4o",
                test_types=["prompt_injection", "jailbreak"],
            )
        else:
            print(pfw.get_install_instructions())
    """

    def __init__(self, timeout: int = 300):
        """
        Initialise the Promptfoo wrapper.

        Args:
            timeout (int): Subprocess timeout in seconds (default: 300).
        """
        self.timeout = timeout
        self._available: Optional[bool] = None  # cached

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether ``npx`` is available and ``promptfoo`` can be resolved.

        Runs ``npx promptfoo --version`` and checks for a successful exit code.
        Result is cached after the first call.

        Returns:
            bool: ``True`` if Promptfoo is available via npx.
        """
        if self._available is not None:
            return self._available

        # Bước 1: kiểm tra npx có tồn tại không
        if shutil.which("npx") is None:
            logger.warning("npx not found — Node.js is required for Promptfoo.")
            self._available = False
            return False

        # Bước 2: thử chạy npx promptfoo --version
        try:
            proc = subprocess.run(
                ["npx", "promptfoo", "--version"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self._available = proc.returncode == 0
            if self._available:
                version = proc.stdout.strip() or proc.stderr.strip()
                logger.info("Promptfoo available: %s", version)
            else:
                logger.warning("Promptfoo not available (exit code %d).", proc.returncode)
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.warning("Promptfoo availability check failed: %s", exc)
            self._available = False

        return self._available

    @staticmethod
    def get_install_instructions() -> str:
        """
        Return the npm global install command for Promptfoo.

        Returns:
            str: Shell command string.
        """
        return "npm install -g promptfoo"

    # ------------------------------------------------------------------
    # Config generation
    # ------------------------------------------------------------------

    def generate_config(
        self,
        target_url: str,
        model_name: str,
        test_types: Optional[List[str]] = None,
    ) -> str:
        """
        Generate a Promptfoo YAML configuration for a red-team evaluation.

        Args:
            target_url (str): Target LLM API endpoint URL.
            model_name (str): Model identifier (e.g. ``"gpt-4o"``).
            test_types (list[str], optional): List of test type keys from
                ``_TEST_TYPE_META``. Defaults to ``["prompt_injection", "jailbreak", "pii_extraction"]``.

        Returns:
            str: YAML configuration string ready to write to a file.
        """
        types = test_types or _DEFAULT_TEST_TYPES

        # Build test list YAML block
        tests_yaml_lines: List[str] = []
        for ttype in types:
            tests_yaml_lines.append(f"  - type: {ttype}")

        tests_block = "\n".join(tests_yaml_lines)

        config = (
            f"# Promptfoo Red-Team Configuration\n"
            f"# Generated by AI Security Scanner\n"
            f"# Target: {target_url} | Model: {model_name}\n"
            f"\n"
            f"targets:\n"
            f"  - id: {model_name}\n"
            f"    config:\n"
            f"      apiBaseUrl: {target_url}\n"
            f"\n"
            f"redteam:\n"
            f"  purpose: >-\n"
            f"    AI Security Scanner red-team evaluation against {model_name}.\n"
            f"  plugins:\n"
            f"{tests_block}\n"
            f"\n"
            f"defaultTest:\n"
            f"  options:\n"
            f"    provider:\n"
            f"      id: {model_name}\n"
            f"      config:\n"
            f"        apiBaseUrl: {target_url}\n"
        )
        return config

    # ------------------------------------------------------------------
    # Red-team runner
    # ------------------------------------------------------------------

    def run_redteam(
        self,
        target_url: str,
        model_name: str,
        config_path: Optional[str] = None,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Execute a Promptfoo red-team evaluation and return parsed findings.

        If ``config_path`` is provided, uses that YAML file directly.
        Otherwise, generates a temporary config and cleans it up after the run.

        Args:
            target_url (str): Target LLM API endpoint URL.
            model_name (str): Model identifier.
            config_path (str, optional): Path to an existing Promptfoo YAML config.
            test_types (list[str], optional): Test types to include in generated config.

        Returns:
            list[dict]: Parsed findings in framework format.
        """
        if not self.is_available():
            logger.warning(
                "Promptfoo not available. Returning simulated results. "
                "Run: %s", self.get_install_instructions()
            )
            return self._simulate_results(target_url, model_name, test_types)

        # Tạo config tạm nếu không có sẵn
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
            logger.info("Generated Promptfoo config at: %s", config_path)

        # Build output file path
        output_fd, output_path = tempfile.mkstemp(suffix=".json", prefix="promptfoo_output_")
        os.close(output_fd)

        cmd = [
            "npx", "promptfoo", "eval",
            "--config", config_path,
            "--output", output_path,
            "--output-format", "json",
            "--no-progress-bar",
        ]

        logger.info("Running Promptfoo: %s", " ".join(cmd))
        raw_output = ""
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            raw_output = proc.stdout + "\n" + proc.stderr
            # Đọc output JSON nếu có
            if os.path.exists(output_path):
                with open(output_path, "r", encoding="utf-8") as f:
                    raw_output = f.read()
        except subprocess.TimeoutExpired:
            logger.error("Promptfoo timed out after %d s.", self.timeout)
            raw_output = f"TIMEOUT after {self.timeout} seconds"
        except Exception as exc:
            logger.error("Promptfoo subprocess error: %s", exc)
            raw_output = str(exc)
        finally:
            # Dọn dẹp file tạm
            if tmp_config and os.path.exists(tmp_config):
                os.unlink(tmp_config)
            if os.path.exists(output_path):
                os.unlink(output_path)

        return self.parse_promptfoo_output(raw_output, test_types or _DEFAULT_TEST_TYPES)

    # ------------------------------------------------------------------
    # Output parser
    # ------------------------------------------------------------------

    def parse_promptfoo_output(
        self,
        output: str,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Parse Promptfoo JSON or text output into framework findings format.

        Promptfoo JSON output has structure::

            {
              "results": {
                "results": [
                  {
                    "prompt": {"raw": "..."},
                    "response": {"output": "..."},
                    "pass": true/false,
                    "testCase": {"metadata": {"pluginId": "..."}}
                  }, ...
                ]
              }
            }

        Args:
            output (str): Raw stdout/JSON output from the Promptfoo subprocess.
            test_types (list[str], optional): Test types that were run (for fallback labelling).

        Returns:
            list[dict]: Parsed findings.
        """
        findings: List[Dict[str, Any]] = []

        # Thử parse JSON
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
            pass  # Fallback to text parsing below

        # Text parsing: tìm PASS/FAIL lines
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

        # Nếu hoàn toàn không parse được
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

    # ------------------------------------------------------------------
    # Fallback simulation
    # ------------------------------------------------------------------

    def _simulate_results(
        self,
        target_url: str,
        model_name: str,
        test_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """Return simulated findings when Promptfoo is not available."""
        types = test_types or _DEFAULT_TEST_TYPES
        results: List[Dict[str, Any]] = []
        for ttype in types:
            meta = _TEST_TYPE_META.get(ttype, {"owasp": "N/A", "mitre": "N/A", "severity": "MEDIUM"})
            results.append({
                "probe": ttype,
                "result": "SIMULATED",
                "severity": "INFO",
                "owasp_code": meta["owasp"],
                "mitre_code": meta["mitre"],
                "detail": (
                    f"Promptfoo not available (run: {self.get_install_instructions()}). "
                    f"Simulated result for test type '{ttype}' against {model_name} @ {target_url}."
                ),
                "prompt": "",
                "response": "",
            })
        return results

    def __repr__(self) -> str:
        return f"<PromptfooWrapper available={self.is_available()} timeout={self.timeout}s>"
