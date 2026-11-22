# -*- coding: utf-8 -*-
"""
core/owasp_mapper.py - OWASP LLM Top 10 / MITRE ATLAS Taxonomy Mapper

Provides a convenience layer over taxonomy.json so that findings can be
enriched with standardised remediation guidance and human-readable
category descriptions without hard-coding strings throughout the codebase.
"""

import json
from pathlib import Path


# ---------------------------------------------------------------------------
# Module → OWASP code mapping (mirrors risk_scorer.py)
# ---------------------------------------------------------------------------
_MODULE_TO_OWASP: dict[str, str] = {
    # LLM01 – Prompt Injection (includes jailbreak as sub-technique)
    "prompt_injection":     "LLM01",
    "jailbreak":            "LLM01",
    # LLM02 – Sensitive Information Disclosure (≠ LLM06!)
    "sensitive_disclosure": "LLM02",
    # LLM03 – Supply Chain & Open-Source Code/Model Vulnerabilities
    "code_scanner":         "LLM03",
    "oss_security":         "LLM03",
    # LLM05 – Improper Output Handling
    "output_handling":      "LLM05",
    # LLM06 – Excessive Agency
    "excessive_agency":     "LLM06",
    # LLM07 – System Prompt Disclosure (≠ LLM06!)
    "prompt_leak":          "LLM07",
    # LLM08 – Vector and Embedding Weaknesses / RAG Poisoning
    "rag_security":         "LLM08",
    # LLM09 – Misinformation
    "misinformation":       "LLM09",
    "agent_testing":        "LLM06",
    "ml_adversarial":       "LLM01",
    # LLM10 – Unbounded Consumption (≠ LLM04 which is Data Poisoning!)
    "model_dos":            "LLM10",
    # Infrastructure & Auxiliary – not in OWASP scope
    "port_scan":            "N/A",
    "multiturn_jailbreak":  "LLM01",
    "model_fingerprint":    "N/A",
}


class OWASPMapper:
    """
    Look up OWASP LLM Top 10 category metadata from the project taxonomy.

    The mapper reads ``data/taxonomy.json`` on initialisation and indexes
    categories by their ``owasp_code`` field.  Multiple categories may share
    the same OWASP code (e.g. LLM01 covers both general prompt injection and
    jailbreaks); in that case ``get_category_info`` returns the *first* match
    while ``get_remediation`` merges all unique remediation steps.
    """

    def __init__(self) -> None:
        # Index: owasp_code → list[category_dict]
        self._by_owasp: dict[str, list[dict]] = {}
        self._standards_metadata: dict[str, dict] = {}
        self._load_taxonomy()

    def _load_taxonomy(self) -> None:
        project_root = Path(__file__).resolve().parent.parent
        taxonomy_path = project_root / "data" / "taxonomy.json"

        if not taxonomy_path.exists():
            return

        from core.cache import cache

        cached_data = cache.get("taxonomy_full_v21")
        if cached_data is not None:
            data = cached_data
        else:
            try:
                with open(taxonomy_path, encoding="utf-8") as fh:
                    data = json.load(fh)
                    cache.set("taxonomy_full_v21", data, ttl=3600)
            except (json.JSONDecodeError, OSError):
                return

        self._standards_metadata = data.get("standards_metadata", {})
        for category in data.get("categories", []):
            code = category.get("owasp_code", "")
            if code:
                self._by_owasp.setdefault(code, []).append(category)

    def _resolve_owasp_code(self, owasp_code: str) -> str:
        """Normalise *owasp_code*, treating module names as aliases."""
        if owasp_code in _MODULE_TO_OWASP:
            return _MODULE_TO_OWASP[owasp_code]
        return owasp_code

    def get_remediation(self, owasp_code: str) -> list[str]:
        code = self._resolve_owasp_code(owasp_code)
        categories = self._by_owasp.get(code, [])

        seen: set[str] = set()
        steps: list[str] = []
        for cat in categories:
            for step in cat.get("remediation", []):
                if step not in seen:
                    seen.add(step)
                    steps.append(step)
        return steps

    def get_category_info(self, owasp_code: str) -> dict:
        code = self._resolve_owasp_code(owasp_code)
        categories = self._by_owasp.get(code, [])
        return categories[0] if categories else {}

    def format_finding_description(self, module_name: str, severity: str) -> str:
        owasp_code = _MODULE_TO_OWASP.get(module_name, "N/A")
        info = self.get_category_info(owasp_code)

        if not info:
            return (
                f"[{severity}] Module: {module_name} "
                f"(OWASP: {owasp_code} | MITRE: N/A)\n"
                "No taxonomy entry found for this module."
            )

        name = info.get("name", module_name)
        mitre = info.get("mitre_code", "N/A")
        desc_vi = info.get("description_vi", info.get("description", ""))

        return (
            f"[{severity}] {name} ({owasp_code} | {mitre})\n"
            f"{desc_vi}"
        )

    def get_owasp_code_for_module(self, module_name: str) -> str:
        return _MODULE_TO_OWASP.get(module_name, "N/A")

    def get_mitre_code_for_module(self, module_name: str) -> str:
        owasp_code = _MODULE_TO_OWASP.get(module_name, "")
        info = self.get_category_info(owasp_code)
        return info.get("mitre_code", "N/A")

    def get_nist_rmf_for_module(self, module_name: str) -> list[str]:
        """Return NIST AI RMF 1.0 subcategory mappings for a module or OWASP code."""
        code = self._resolve_owasp_code(module_name)
        info = self.get_category_info(code)
        rmf = info.get("nist_ai_rmf", [])
        return list(rmf) if isinstance(rmf, list) else []

    def get_nist_aml_for_module(self, module_name: str) -> str:
        """Return NIST AML (AI 100-2) attack taxonomy label for a module or OWASP code."""
        code = self._resolve_owasp_code(module_name)
        info = self.get_category_info(code)
        return info.get("nist_aml", "N/A")

    def get_standards_metadata(self) -> dict[str, dict]:
        """Return versioned reference standards metadata (OWASP 2025, MITRE ATLAS, NIST AI RMF, NIST AML)."""
        return dict(self._standards_metadata)
