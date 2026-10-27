# -*- coding: utf-8 -*-
"""
modules/integrations/deepteam_wrapper.py - DeepTeam LLM Red-Teaming Integration

Wrapper cho DeepTeam (https://github.com/confident-ai/deepteam):
một framework red-teaming cho LLM với các attack types khác nhau.

DeepTeam hỗ trợ: prompt injection, jailbreak, RAG injection và nhiều hơn nữa.

DeepTeam License: Apache 2.0
Install: pip install deepteam
"""

import importlib.util
import logging
import subprocess
import sys
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Supported attack types → OWASP / MITRE mappings
# ---------------------------------------------------------------------------

_ATTACK_META: Dict[str, Dict[str, str]] = {
    "prompt_injection": {
        "owasp": "LLM01",
        "mitre": "AML.T0051",
        "severity": "HIGH",
        "description": "Prompt injection attempts to hijack LLM behaviour via malicious input.",
    },
    "jailbreak": {
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "description": "Jailbreak attempts to bypass LLM safety guardrails.",
    },
    "rag_injection": {
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "severity": "HIGH",
        "description": "RAG injection poisons the retrieval context to manipulate LLM output.",
    },
    "pii_exfiltration": {
        "owasp": "LLM02",
        "mitre": "AML.T0024",
        "severity": "HIGH",
        "description": "Attempts to extract personally identifiable information from the model.",
    },
    "excessive_agency": {
        "owasp": "LLM06",
        "mitre": "AML.T0048",
        "severity": "HIGH",
        "description": "Tests whether the agent takes unauthorized high-impact actions.",
    },
}

_SUPPORTED_ATTACK_TYPES = list(_ATTACK_META.keys())
_DEFAULT_ATTACK_TYPE = "prompt_injection"


class DeepTeamWrapper:
    """
    Integration wrapper around the DeepTeam LLM red-teaming framework.

    DeepTeam is invoked via subprocess (``python -m deepteam``) if the package
    is installed, otherwise falls back to structured simulation.

    Supports attack types: ``prompt_injection``, ``jailbreak``, ``rag_injection``,
    ``pii_exfiltration``, ``excessive_agency``.

    Example::

        dt = DeepTeamWrapper()
        if dt.is_available():
            findings = dt.run_attack(
                target_url="http://localhost:8080",
                model_name="llama3",
                attack_type="jailbreak",
            )
        else:
            print(dt.get_install_instructions())
    """

    def __init__(self, timeout: int = 300):
        """
        Initialise the DeepTeam wrapper.

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
        Check whether the ``deepteam`` package is importable.

        The result is cached after the first call.

        Returns:
            bool: ``True`` if deepteam is installed and importable.
        """
        if self._available is not None:
            return self._available

        try:
            spec = importlib.util.find_spec("deepteam")
            self._available = spec is not None
        except Exception:
            self._available = False

        if not self._available:
            logger.warning(
                "DeepTeam is not installed. Run: %s", self.get_install_instructions()
            )
        return self._available

    @staticmethod
    def get_install_instructions() -> str:
        """
        Return the pip install command for DeepTeam.

        Returns:
            str: Shell command string.
        """
        return "pip install deepteam"

    # ------------------------------------------------------------------
    # Attack runner
    # ------------------------------------------------------------------

    def run_attack(
        self,
        target_url: str,
        model_name: str,
        attack_type: str = _DEFAULT_ATTACK_TYPE,
    ) -> List[Dict[str, Any]]:
        """
        Run a DeepTeam attack against the specified target.

        If DeepTeam is installed, executes it via subprocess.
        Otherwise, returns simulated findings.

        Args:
            target_url (str): Target LLM API endpoint URL.
            model_name (str): Model identifier (e.g. ``"llama3"``).
            attack_type (str): One of the supported attack types:
                ``prompt_injection``, ``jailbreak``, ``rag_injection``,
                ``pii_exfiltration``, ``excessive_agency``.

        Returns:
            list[dict]: Findings in framework format.

        Raises:
            ValueError: If ``attack_type`` is not in supported types.
        """
        if attack_type not in _SUPPORTED_ATTACK_TYPES:
            raise ValueError(
                f"Unsupported attack_type: '{attack_type}'. "
                f"Supported types: {_SUPPORTED_ATTACK_TYPES}"
            )

        if not self.is_available():
            logger.warning(
                "DeepTeam not available — returning simulated results for '%s'.", attack_type
            )
            return self._simulate_results(target_url, model_name, attack_type)

        # Chạy qua subprocess
        raw_output = self._run_subprocess(target_url, model_name, attack_type)
        return self.parse_results(raw_output, attack_type)

    def _run_subprocess(
        self,
        target_url: str,
        model_name: str,
        attack_type: str,
    ) -> str:
        """
        Execute DeepTeam via subprocess and return raw output.

        Command structure::

            python -m deepteam attack
                --target-url <url>
                --model <model>
                --attack-type <type>

        Args:
            target_url (str): Target URL.
            model_name (str): Model name.
            attack_type (str): Attack type identifier.

        Returns:
            str: Combined stdout + stderr output.
        """
        cmd = [
            sys.executable, "-m", "deepteam", "attack",
            "--target-url", target_url,
            "--model", model_name,
            "--attack-type", attack_type,
        ]

        logger.info("Running DeepTeam: %s", " ".join(cmd))
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.timeout,
            )
            return proc.stdout + "\n" + proc.stderr
        except subprocess.TimeoutExpired:
            logger.error("DeepTeam timed out after %d s.", self.timeout)
            return f"TIMEOUT after {self.timeout} seconds"
        except FileNotFoundError:
            logger.error("Python executable not found: %s", sys.executable)
            return "ERROR: Python executable not found"
        except Exception as exc:
            logger.error("DeepTeam subprocess error: %s", exc)
            return f"ERROR: {exc}"

    # ------------------------------------------------------------------
    # Batch attacks
    # ------------------------------------------------------------------

    def run_all_attacks(
        self,
        target_url: str,
        model_name: str,
        attack_types: Optional[List[str]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Run multiple DeepTeam attack types and combine results.

        Args:
            target_url (str): Target URL.
            model_name (str): Model name.
            attack_types (list[str], optional): Attack types to run.
                Defaults to all supported types.

        Returns:
            list[dict]: Combined findings from all attacks.
        """
        types = attack_types or _SUPPORTED_ATTACK_TYPES
        all_results: List[Dict[str, Any]] = []
        for atype in types:
            try:
                results = self.run_attack(target_url, model_name, atype)
                all_results.extend(results)
            except ValueError as exc:
                logger.warning("Skipping unsupported attack type '%s': %s", atype, exc)
        return all_results

    # ------------------------------------------------------------------
    # Output parser
    # ------------------------------------------------------------------

    def parse_results(
        self,
        output: str,
        attack_type: str = _DEFAULT_ATTACK_TYPE,
    ) -> List[Dict[str, Any]]:
        """
        Parse DeepTeam subprocess output into framework findings format.

        DeepTeam outputs structured text or JSON. This parser handles both.

        Expected text format::

            [PASS] Test 1: Prompt injection attempt 1 — model refused
            [FAIL] Test 2: Prompt injection attempt 2 — model complied

        Args:
            output (str): Raw output from the DeepTeam subprocess.
            attack_type (str): Attack type that was run (used for metadata).

        Returns:
            list[dict]: Parsed findings.
        """
        import json as json_mod

        findings: List[Dict[str, Any]] = []
        meta = _ATTACK_META.get(attack_type, {
            "owasp": "N/A", "mitre": "N/A", "severity": "MEDIUM", "description": attack_type
        })

        # Thử parse JSON
        try:
            data = json_mod.loads(output)
            raw_results = data.get("results", data.get("findings", []))
            for r in raw_results:
                passed = r.get("passed", r.get("pass", r.get("success", True)))
                findings.append({
                    "tool": "deepteam",
                    "attack_type": attack_type,
                    "result": "PASS" if passed else "FAIL",
                    "severity": "INFO" if passed else meta["severity"],
                    "owasp_code": meta["owasp"],
                    "mitre_code": meta["mitre"],
                    "detail": r.get("detail", r.get("message", str(r)))[:300],
                    "raw": r,
                })
            if findings:
                return findings
        except (json_mod.JSONDecodeError, TypeError, AttributeError):
            pass

        # Text line-by-line parsing
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            result = None
            if line.upper().startswith("[PASS]") or "PASS" in line.upper():
                result = "PASS"
            elif (line.upper().startswith("[FAIL]") or "FAIL" in line.upper()
                  or "FAIL" in line.upper() or "TIMEOUT" in line.upper()):
                result = "FAIL"

            if result:
                findings.append({
                    "tool": "deepteam",
                    "attack_type": attack_type,
                    "result": result,
                    "severity": "INFO" if result == "PASS" else meta["severity"],
                    "owasp_code": meta["owasp"],
                    "mitre_code": meta["mitre"],
                    "detail": line[:300],
                    "raw": {},
                })

        # Nếu không parse được gì
        if not findings:
            findings.append({
                "tool": "deepteam",
                "attack_type": attack_type,
                "result": "UNKNOWN",
                "severity": "INFO",
                "owasp_code": meta["owasp"],
                "mitre_code": meta["mitre"],
                "detail": output[:500].strip() or "No output from DeepTeam.",
                "raw": {},
            })

        return findings

    # ------------------------------------------------------------------
    # Fallback simulation
    # ------------------------------------------------------------------

    def _simulate_results(
        self,
        target_url: str,
        model_name: str,
        attack_type: str,
    ) -> List[Dict[str, Any]]:
        """Return simulated findings when DeepTeam is not available."""
        meta = _ATTACK_META.get(attack_type, {
            "owasp": "N/A", "mitre": "N/A", "severity": "MEDIUM", "description": attack_type
        })
        return [{
            "tool": "deepteam",
            "attack_type": attack_type,
            "result": "SIMULATED",
            "severity": "INFO",
            "owasp_code": meta["owasp"],
            "mitre_code": meta["mitre"],
            "detail": (
                f"DeepTeam not available (run: {self.get_install_instructions()}). "
                f"Simulated result for attack type '{attack_type}' "
                f"against {model_name} @ {target_url}. "
                f"Description: {meta.get('description', '')}"
            ),
            "raw": {},
        }]

    def __repr__(self) -> str:
        return (
            f"<DeepTeamWrapper available={self.is_available()} "
            f"supported_attacks={_SUPPORTED_ATTACK_TYPES}>"
        )
