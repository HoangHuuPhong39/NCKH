# -*- coding: utf-8 -*-
"""
modules/integrations/garak_wrapper.py - Garak Open Source LLM Scanner Integration

Garak (https://github.com/leondz/garak) is an open-source LLM vulnerability
scanner by NVIDIA. This wrapper integrates Garak's probes with our framework
to fulfill Nội dung 5 (Open-source tool integration).

Garak License: Apache 2.0
Install: pip install garak
"""

import logging
import re
import subprocess
import sys

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Probe → OWASP LLM Top 10 mapping
# ---------------------------------------------------------------------------
_PROBE_OWASP_MAP: dict[str, str] = {
    "promptinject": "LLM01",
    "knownbadsignatures": "LLM01",
    "malwaregen": "LLM01",
    "xss": "LLM05",
    "dan": "LLM01",
}

# Default severity when a probe fires
_PROBE_SEVERITY: dict[str, str] = {
    "promptinject": "HIGH",
    "knownbadsignatures": "CRITICAL",
    "malwaregen": "CRITICAL",
    "xss": "HIGH",
    "dan": "CRITICAL",
}

# Standard probes to run when run_standard_probes() is called
_STANDARD_PROBES = [
    "knownbadsignatures",
    "malwaregen",
    "promptinject",
    "xss",
]


class GarakWrapper:
    """
    Integration wrapper around the Garak LLM security scanner.

    Garak is run as a subprocess (``python -m garak ...``) so that it does
    not need to be imported directly — this avoids version-pinning conflicts
    with the rest of the project.  Results are parsed from Garak's text output
    and returned as standardised dicts compatible with our framework's findings
    schema.

    Example::

        gw = GarakWrapper(
            target_url="http://localhost:11434",
            model_name="llama3",
        )
        if gw.is_available():
            findings = gw.run_standard_probes()
            for f in findings:
                print(f["probe"], f["result"], f["severity"])
        else:
            print(gw.get_install_instructions())
    """

    def __init__(self, target_url: str, model_name: str):
        """
        Initialise the Garak wrapper.

        Args:
            target_url (str): Base URL of the target LLM API
                (e.g. ``"http://localhost:11434"``).
            model_name (str): Name of the model to probe
                (e.g. ``"llama3"``).
        """
        self.target_url = target_url
        self.model_name = model_name
        self._available: bool | None = None  # cached after first check

    # ------------------------------------------------------------------
    # Availability
    # ------------------------------------------------------------------

    def is_available(self) -> bool:
        """
        Check whether the ``garak`` package is importable in the current
        Python environment.

        The result is cached after the first call.

        Returns:
            bool: ``True`` if garak is installed and importable.
        """
        if self._available is not None:
            return self._available

        try:
            import importlib.util
            spec = importlib.util.find_spec("garak")
            self._available = spec is not None
        except Exception:
            self._available = False

        if not self._available:
            logger.warning(
                "Garak is not installed. Run: %s", self.get_install_instructions()
            )
        return self._available

    @staticmethod
    def get_install_instructions() -> str:
        """
        Return the pip install command for Garak.

        Returns:
            str: Shell command string.
        """
        return "pip install garak"

    # ------------------------------------------------------------------
    # OWASP mapping helpers
    # ------------------------------------------------------------------

    def map_to_owasp(self, probe_name: str) -> str:
        """
        Map a Garak probe name to an OWASP LLM Top 10 category code.

        Args:
            probe_name (str): Garak probe name (e.g. ``"promptinject"``).

        Returns:
            str: OWASP code (e.g. ``"LLM01"``) or ``"N/A"`` if unknown.
        """
        return _PROBE_OWASP_MAP.get(probe_name.lower(), "N/A")

    # ------------------------------------------------------------------
    # Single probe runner
    # ------------------------------------------------------------------

    def run_probe(
        self,
        probe_name: str,
        generator_uri: str = None,
    ) -> list[dict]:
        """
        Run a single Garak probe via subprocess CLI and return structured results.

        The command executed is::

            python -m garak \\
                --model_type rest \\
                --model_name <model> \\
                --probes <probe_name> \\
                --parallel_requests 1

        Args:
            probe_name (str): The Garak probe to run (e.g. ``"promptinject"``).
            generator_uri (str, optional): Override generator URI.  Defaults to
                ``self.target_url``.

        Returns:
            list[dict]: List of finding dicts, each containing:
                - ``probe`` (str): Probe name
                - ``result`` (str): ``"PASS"`` or ``"FAIL"``
                - ``severity`` (str): Severity level
                - ``owasp_code`` (str): OWASP LLM category code
                - ``detail`` (str): Raw output line that triggered the finding
        """
        uri = generator_uri or self.target_url

        cmd = [
            sys.executable, "-m", "garak",
            "--model_type", "rest",
            "--model_name", self.model_name,
            "--probes", probe_name,
            "--parallel_requests", "1",
        ]

        logger.info("Running Garak probe '%s': %s", probe_name, " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,  # 5 min timeout per probe
            )
            combined_output = proc.stdout + "\n" + proc.stderr
        except subprocess.TimeoutExpired:
            logger.error("Garak probe '%s' timed out after 300 s.", probe_name)
            return [
                {
                    "probe": probe_name,
                    "result": "TIMEOUT",
                    "severity": "INFO",
                    "owasp_code": self.map_to_owasp(probe_name),
                    "detail": "Probe timed out after 300 seconds.",
                }
            ]
        except FileNotFoundError:
            logger.error("Python executable not found: %s", sys.executable)
            return []
        except Exception as exc:
            logger.error("Unexpected error running Garak probe '%s': %s", probe_name, exc)
            return []

        return self.parse_garak_output(combined_output, probe_name)

    # ------------------------------------------------------------------
    # Standard probe batch
    # ------------------------------------------------------------------

    def run_standard_probes(self) -> list[dict]:
        """
        Run the standard suite of Garak probes and combine their results.

        Standard probes: ``knownbadsignatures``, ``malwaregen``,
        ``promptinject``, ``xss``.

        Returns:
            list[dict]: Combined list of findings from all probes.
        """
        all_results: list[dict] = []
        for probe in _STANDARD_PROBES:
            logger.info("Running standard Garak probe: %s", probe)
            results = self.run_probe(probe)
            all_results.extend(results)
        return all_results

    # ------------------------------------------------------------------
    # Output parser
    # ------------------------------------------------------------------

    def parse_garak_output(self, stdout: str, probe_name: str = "unknown") -> list[dict]:
        """
        Parse Garak's text output into structured finding dicts.

        Garak outputs lines like::

            ✗ FAILED  probe.promptinject.HijackHateHumans: 4/5 (80.00%)
            ✓ PASSED  probe.xss.MarkdownImageExfil: 5/5 (100.00%)

        Args:
            stdout (str): Combined stdout + stderr from the Garak subprocess.
            probe_name (str): The probe that was run (used as fallback label).

        Returns:
            list[dict]: Parsed findings.
        """
        findings: list[dict] = []
        owasp_code = self.map_to_owasp(probe_name)
        severity = _PROBE_SEVERITY.get(probe_name.lower(), "MEDIUM")

        for line in stdout.splitlines():
            line = line.strip()
            if not line:
                continue

            # Pattern: ✗ FAILED  probe.<name>: N/M (X%)
            # Pattern: FAIL  probe.<name>  N/M
            fail_match = re.search(
                r"(?:✗|FAIL(?:ED)?)\s+(?:probe\.)?(\S+)(?::\s*(\d+/\d+))?",
                line,
                re.IGNORECASE,
            )
            if fail_match:
                detail_probe = fail_match.group(1)
                fraction = fail_match.group(2) or "?"
                findings.append(
                    {
                        "probe": detail_probe,
                        "result": "FAIL",
                        "severity": severity,
                        "owasp_code": owasp_code,
                        "detail": f"Probe failed: {fraction} attempts succeeded — {line}",
                    }
                )
                continue

            # Pattern: ✓ PASSED  probe.<name>
            pass_match = re.search(
                r"(?:✓|PASS(?:ED)?)\s+(?:probe\.)?(\S+)",
                line,
                re.IGNORECASE,
            )
            if pass_match:
                detail_probe = pass_match.group(1)
                findings.append(
                    {
                        "probe": detail_probe,
                        "result": "PASS",
                        "severity": "INFO",
                        "owasp_code": owasp_code,
                        "detail": f"Probe passed — {line}",
                    }
                )

        # If no structured lines were found, emit a single raw result
        if not findings:
            findings.append(
                {
                    "probe": probe_name,
                    "result": "UNKNOWN",
                    "severity": "INFO",
                    "owasp_code": owasp_code,
                    "detail": (
                        stdout[:500].strip()
                        if stdout.strip()
                        else "No output from Garak."
                    ),
                }
            )

        return findings
