# -*- coding: utf-8 -*-
"""
core/threat_model.py - Threat Model / System Profiler

Phân tích và mô hình hóa hệ thống AI đích thành đối tượng kiểm thử thống nhất.
Hỗ trợ tự động phát hiện loại hệ thống (LLM / RAG / Agent / ML_Model) và
map attack surface sang MITRE ATLAS techniques.

Usage::

    from core.threat_model import ThreatModel, SystemProfiler, SystemType

    model = ThreatModel()
    profile = model.profile_target(
        target_url="http://localhost:8000/chat",
        model_name="gpt-4o",
        system_type="auto",
    )
    surface = model.generate_attack_surface()
    mitre = model.map_to_mitre_atlas()
    report = model.export_threat_model()
"""

from __future__ import annotations

import json
import os
import time
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Optional HTTP client — dùng try/except để không crash nếu thiếu
# ---------------------------------------------------------------------------
try:
    import urllib.request as _urllib_request
    import urllib.error as _urllib_error
    _HAS_URLLIB = True
except ImportError:  # pragma: no cover
    _HAS_URLLIB = False


class SystemType(str, Enum):
    """Enum phân loại loại hệ thống AI đích."""

    LLM = "LLM"
    RAG = "RAG"
    AGENT = "AGENT"
    ML_MODEL = "ML_MODEL"
    UNKNOWN = "UNKNOWN"


# ---------------------------------------------------------------------------
# MITRE ATLAS technique catalog (subset relevant to LLM/AI systems)
# ---------------------------------------------------------------------------
_MITRE_ATLAS_TECHNIQUES: Dict[str, Dict[str, str]] = {
    "AML.T0051": {
        "name": "LLM Prompt Injection",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0051",
    },
    "AML.T0054": {
        "name": "LLM Jailbreak",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0054",
    },
    "AML.T0024": {
        "name": "Exfiltration via ML Inference API",
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0024",
    },
    "AML.T0048": {
        "name": "Backdoor ML Model",
        "tactic": "Persistence",
        "url": "https://atlas.mitre.org/techniques/AML.T0048",
    },
    "AML.T0048.001": {
        "name": "Backdoor Model via Excessive Agency",
        "tactic": "Persistence",
        "url": "https://atlas.mitre.org/techniques/AML.T0048.001",
    },
    "AML.T0010": {
        "name": "ML Model Inference API Access",
        "tactic": "Initial Access",
        "url": "https://atlas.mitre.org/techniques/AML.T0010",
    },
    "AML.T0020": {
        "name": "Poison Training Data",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0020",
    },
    "AML.T0029": {
        "name": "Denial of ML Service",
        "tactic": "Impact",
        "url": "https://atlas.mitre.org/techniques/AML.T0029",
    },
    "AML.T0040": {
        "name": "ML Model Inference API Theft",
        "tactic": "Exfiltration",
        "url": "https://atlas.mitre.org/techniques/AML.T0040",
    },
    "AML.T0043": {
        "name": "Craft Adversarial Data",
        "tactic": "ML Attack Staging",
        "url": "https://atlas.mitre.org/techniques/AML.T0043",
    },
}

# ---------------------------------------------------------------------------
# Attack surface definitions per system type
# ---------------------------------------------------------------------------
_ATTACK_SURFACE_BY_TYPE: Dict[str, List[Dict[str, Any]]] = {
    SystemType.LLM: [
        {
            "component": "Chat/Completion Endpoint",
            "vectors": ["prompt_injection", "jailbreak", "sensitive_disclosure",
                        "model_dos", "prompt_leak"],
            "mitre_techniques": ["AML.T0051", "AML.T0054", "AML.T0024", "AML.T0029", "AML.T0010"],
            "owasp_codes": ["LLM01", "LLM02", "LLM07", "LLM10"],
        },
        {
            "component": "System Prompt",
            "vectors": ["prompt_leak", "prompt_injection"],
            "mitre_techniques": ["AML.T0010", "AML.T0051"],
            "owasp_codes": ["LLM07", "LLM01"],
        },
        {
            "component": "Output Handler",
            "vectors": ["output_handling", "misinformation"],
            "mitre_techniques": ["AML.T0048", "AML.T0043"],
            "owasp_codes": ["LLM05", "LLM09"],
        },
    ],
    SystemType.RAG: [
        {
            "component": "Vector Database",
            "vectors": ["rag_security", "prompt_injection"],
            "mitre_techniques": ["AML.T0020", "AML.T0043", "AML.T0051"],
            "owasp_codes": ["LLM08", "LLM01"],
        },
        {
            "component": "Document Retrieval Pipeline",
            "vectors": ["rag_security", "sensitive_disclosure"],
            "mitre_techniques": ["AML.T0020", "AML.T0024"],
            "owasp_codes": ["LLM08", "LLM02"],
        },
        {
            "component": "Embedding Model",
            "vectors": ["rag_security"],
            "mitre_techniques": ["AML.T0043", "AML.T0040"],
            "owasp_codes": ["LLM08"],
        },
        {
            "component": "LLM Generation Layer",
            "vectors": ["prompt_injection", "jailbreak", "prompt_leak"],
            "mitre_techniques": ["AML.T0051", "AML.T0054", "AML.T0010"],
            "owasp_codes": ["LLM01", "LLM07"],
        },
    ],
    SystemType.AGENT: [
        {
            "component": "Tool/Plugin Interface",
            "vectors": ["excessive_agency", "prompt_injection"],
            "mitre_techniques": ["AML.T0048.001", "AML.T0051"],
            "owasp_codes": ["LLM06", "LLM01"],
        },
        {
            "component": "Action Planner",
            "vectors": ["excessive_agency", "prompt_injection"],
            "mitre_techniques": ["AML.T0048.001", "AML.T0051"],
            "owasp_codes": ["LLM06", "LLM01"],
        },
        {
            "component": "Memory/State Store",
            "vectors": ["sensitive_disclosure", "rag_security"],
            "mitre_techniques": ["AML.T0024", "AML.T0020"],
            "owasp_codes": ["LLM02", "LLM08"],
        },
        {
            "component": "External API Calls",
            "vectors": ["excessive_agency", "output_handling"],
            "mitre_techniques": ["AML.T0048.001", "AML.T0048"],
            "owasp_codes": ["LLM06", "LLM05"],
        },
    ],
    SystemType.ML_MODEL: [
        {
            "component": "Inference API",
            "vectors": ["model_dos", "model_fingerprint", "sensitive_disclosure"],
            "mitre_techniques": ["AML.T0029", "AML.T0040", "AML.T0024"],
            "owasp_codes": ["LLM10", "LLM02"],
        },
        {
            "component": "Model Weights / Architecture",
            "vectors": ["model_fingerprint"],
            "mitre_techniques": ["AML.T0040", "AML.T0010"],
            "owasp_codes": ["LLM02"],
        },
    ],
}


class SystemProfiler:
    """Auto-detect AI system type based on endpoint behavior and response patterns.

    Gửi probe requests đến target endpoint và phân tích response để xác định
    loại hệ thống (LLM / RAG / Agent / ML_Model).
    """

    # Các indicator trong response để nhận dạng loại hệ thống
    _RAG_INDICATORS = [
        "retrieved", "document", "context", "source", "reference",
        "knowledge base", "vector", "embedding", "chunk",
    ]
    _AGENT_INDICATORS = [
        "tool", "function_call", "action", "step", "thought",
        "observation", "plan", "execute", "tool_calls",
    ]

    def __init__(self, timeout: int = 10) -> None:
        """Initialize SystemProfiler.

        Args:
            timeout: HTTP request timeout in seconds.
        """
        self.timeout = timeout

    def detect(
        self,
        target_url: str,
        probe_response: Optional[str] = None,
    ) -> SystemType:
        """Detect system type from URL pattern and probe response.

        Args:
            target_url:     Endpoint URL to analyze.
            probe_response: Optional pre-fetched response text to analyze.

        Returns:
            Detected :class:`SystemType`.
        """
        # Phân tích URL pattern trước
        url_lower = target_url.lower()
        if any(kw in url_lower for kw in ["/rag", "/retriev", "/search", "/documents"]):
            return SystemType.RAG
        if any(kw in url_lower for kw in ["/agent", "/tool", "/function", "/action"]):
            return SystemType.AGENT
        if any(kw in url_lower for kw in ["/predict", "/infer", "/score", "/classify"]):
            return SystemType.ML_MODEL

        # Phân tích response nếu có
        if probe_response:
            resp_lower = probe_response.lower()
            if any(ind in resp_lower for ind in self._RAG_INDICATORS):
                return SystemType.RAG
            if any(ind in resp_lower for ind in self._AGENT_INDICATORS):
                return SystemType.AGENT

        # Thử probe endpoint nếu có urllib
        if _HAS_URLLIB and target_url.startswith("http"):
            detected = self._probe_endpoint(target_url)
            if detected != SystemType.UNKNOWN:
                return detected

        # Default: assume LLM chat
        return SystemType.LLM

    def _probe_endpoint(self, url: str) -> SystemType:
        """Send a lightweight probe to the endpoint and analyze response.

        Args:
            url: Target endpoint URL.

        Returns:
            Detected :class:`SystemType` or ``UNKNOWN`` on failure.
        """
        probe_payload = json.dumps({"messages": [{"role": "user", "content": "hello"}]}).encode()
        try:
            req = _urllib_request.Request(
                url,
                data=probe_payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with _urllib_request.urlopen(req, timeout=self.timeout) as resp:
                body = resp.read().decode("utf-8", errors="ignore")
                resp_lower = body.lower()
                if any(ind in resp_lower for ind in self._RAG_INDICATORS):
                    return SystemType.RAG
                if any(ind in resp_lower for ind in self._AGENT_INDICATORS):
                    return SystemType.AGENT
                return SystemType.LLM
        except Exception:
            return SystemType.UNKNOWN


class ThreatModel:
    """Model and profile an AI target system into a unified threat model object.

    Tích hợp với OWASP LLM Top 10 và MITRE ATLAS để sinh báo cáo
    threat model đầy đủ cho hệ thống AI đích.

    Attributes:
        profiler:    :class:`SystemProfiler` instance for auto-detection.
        _profile:    Internal profile dict, populated by :meth:`profile_target`.
        _taxonomy:   OWASP taxonomy loaded from ``data/taxonomy.json``.
    """

    def __init__(self) -> None:
        self.profiler = SystemProfiler()
        self._profile: Dict[str, Any] = {}
        self._taxonomy: Dict[str, Any] = {}
        self._load_taxonomy()

    # ------------------------------------------------------------------
    # Taxonomy loading
    # ------------------------------------------------------------------

    def _load_taxonomy(self) -> None:
        """Load OWASP taxonomy from data/taxonomy.json."""
        project_root = Path(__file__).resolve().parent.parent
        taxonomy_path = project_root / "data" / "taxonomy.json"
        if not taxonomy_path.exists():
            return
        try:
            with open(taxonomy_path, encoding="utf-8") as fh:
                data = json.load(fh)
            for cat in data.get("categories", []):
                cat_id = cat.get("id", "")
                if cat_id:
                    self._taxonomy[cat_id] = cat
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def profile_target(
        self,
        target_url: str,
        model_name: str = "unknown",
        system_type: str = "auto",
        extra_metadata: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """Build a profile dict describing the target AI system.

        Args:
            target_url:     URL of the target AI endpoint.
            model_name:     Name/identifier of the AI model (e.g. ``'gpt-4o'``).
            system_type:    ``'auto'`` for auto-detection, or one of
                            ``'LLM'``, ``'RAG'``, ``'AGENT'``, ``'ML_MODEL'``.
            extra_metadata: Optional additional key-value metadata.

        Returns:
            Profile dict with keys: ``target_url``, ``model_name``,
            ``system_type``, ``components``, ``timestamp``, etc.
        """
        # Xác định system type
        if system_type.upper() == "AUTO":
            detected_type = self.profiler.detect(target_url)
        else:
            try:
                detected_type = SystemType(system_type.upper())
            except ValueError:
                detected_type = SystemType.UNKNOWN

        # Xây dựng danh sách components theo system type
        components = self._build_components(detected_type)

        self._profile = {
            "target_url": target_url,
            "model_name": model_name,
            "system_type": detected_type.value,
            "components": components,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
            "attack_surface": [],      # sẽ được điền bởi generate_attack_surface()
            "mitre_techniques": [],    # sẽ được điền bởi map_to_mitre_atlas()
            "risk_level": "UNKNOWN",
            "recommended_tests": [],
            "metadata": extra_metadata or {},
        }

        # Tự động sinh attack surface và MITRE mappings
        self._profile["attack_surface"] = self.generate_attack_surface()
        self._profile["mitre_techniques"] = self.map_to_mitre_atlas()
        self._profile["risk_level"] = self._calculate_risk_level()
        self._profile["recommended_tests"] = self._recommend_tests(detected_type)

        return self._profile

    def generate_attack_surface(self) -> List[Dict[str, Any]]:
        """List the attack surface based on the profiled system type.

        Must be called after :meth:`profile_target` (or manually set
        ``self._profile['system_type']``).

        Returns:
            List of attack surface component dicts.
        """
        system_type_str = self._profile.get("system_type", SystemType.LLM.value)
        try:
            st = SystemType(system_type_str)
        except ValueError:
            st = SystemType.LLM

        surfaces = _ATTACK_SURFACE_BY_TYPE.get(st, _ATTACK_SURFACE_BY_TYPE[SystemType.LLM])
        return list(surfaces)

    def map_to_mitre_atlas(self) -> List[Dict[str, Any]]:
        """Map the attack surface to MITRE ATLAS techniques.

        Returns:
            List of MITRE ATLAS technique dicts with ``id``, ``name``,
            ``tactic``, and ``url``.
        """
        attack_surface = self._profile.get("attack_surface") or self.generate_attack_surface()

        # Thu thập tất cả unique MITRE technique IDs từ attack surface
        seen_ids: set = set()
        techniques: List[Dict[str, Any]] = []
        for component in attack_surface:
            for tech_id in component.get("mitre_techniques", []):
                if tech_id in seen_ids:
                    continue
                seen_ids.add(tech_id)
                tech_info = _MITRE_ATLAS_TECHNIQUES.get(tech_id, {})
                techniques.append({
                    "id": tech_id,
                    "name": tech_info.get("name", tech_id),
                    "tactic": tech_info.get("tactic", "Unknown"),
                    "url": tech_info.get("url", ""),
                })

        return techniques

    def export_threat_model(self) -> Dict[str, Any]:
        """Export the full threat model as a JSON-serializable dict.

        Returns:
            Complete threat model report dict. Can be serialized with
            ``json.dumps(model.export_threat_model(), indent=2)``.

        Raises:
            RuntimeError: If :meth:`profile_target` has not been called yet.
        """
        if not self._profile:
            raise RuntimeError(
                "No profile available. Call profile_target() before export_threat_model()."
            )

        # Bổ sung thông tin taxonomy OWASP vào report
        owasp_coverage: List[Dict[str, Any]] = []
        covered_codes: set = set()
        for surface in self._profile.get("attack_surface", []):
            for code in surface.get("owasp_codes", []):
                if code in covered_codes:
                    continue
                covered_codes.add(code)
                tax_entry = self._taxonomy.get(code, {})
                owasp_coverage.append({
                    "owasp_code": code,
                    "name": tax_entry.get("name", code),
                    "severity": tax_entry.get("severity", "UNKNOWN"),
                    "base_risk_score": tax_entry.get("base_risk_score"),
                    "remediation": tax_entry.get("remediation", []),
                })

        report = dict(self._profile)
        report["owasp_coverage"] = owasp_coverage
        report["schema_version"] = "1.0"
        report["generator"] = "AI_Security_Scanner/ThreatModel"

        return report

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_components(self, system_type: SystemType) -> List[str]:
        """Return a list of high-level component names for a system type."""
        _components_map: Dict[str, List[str]] = {
            SystemType.LLM:      ["LLM Core", "Tokenizer", "System Prompt", "Output Handler"],
            SystemType.RAG:      ["LLM Core", "Embedding Model", "Vector DB", "Document Store",
                                  "Retrieval Pipeline", "Output Handler"],
            SystemType.AGENT:    ["LLM Core", "Tool Executor", "Action Planner", "Memory Store",
                                  "External APIs", "Output Handler"],
            SystemType.ML_MODEL: ["ML Model", "Inference API", "Preprocessing", "Postprocessing"],
            SystemType.UNKNOWN:  ["Unknown Component"],
        }
        return _components_map.get(system_type, ["Unknown"])

    def _calculate_risk_level(self) -> str:
        """Estimate overall risk level from attack surface coverage."""
        num_surfaces = len(self._profile.get("attack_surface", []))
        if num_surfaces >= 4:
            return "HIGH"
        if num_surfaces >= 2:
            return "MEDIUM"
        return "LOW"

    def _recommend_tests(self, system_type: SystemType) -> List[str]:
        """Recommend test modules based on system type.

        Args:
            system_type: Detected :class:`SystemType`.

        Returns:
            List of recommended module name strings.
        """
        _recommendations: Dict[str, List[str]] = {
            SystemType.LLM:      ["prompt_injection", "jailbreak", "multiturn_jailbreak",
                                  "prompt_leak", "sensitive_disclosure", "model_dos",
                                  "misinformation"],
            SystemType.RAG:      ["rag_security", "prompt_injection", "sensitive_disclosure",
                                  "prompt_leak"],
            SystemType.AGENT:    ["excessive_agency", "prompt_injection", "output_handling",
                                  "sensitive_disclosure"],
            SystemType.ML_MODEL: ["model_dos", "model_fingerprint", "sensitive_disclosure"],
            SystemType.UNKNOWN:  ["prompt_injection", "sensitive_disclosure", "model_dos"],
        }
        return _recommendations.get(system_type, _recommendations[SystemType.UNKNOWN])
