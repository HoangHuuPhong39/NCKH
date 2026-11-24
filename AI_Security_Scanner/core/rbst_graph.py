# -*- coding: utf-8 -*-
"""
core/rbst_graph.py - RBST-AI Layer 1 & Layer 2: Context Profiler & Threat Modeler

Implements Sections 4.1, 4.2, and 5.1 (Context Profiler & Threat Modeler) of the
RBST-AI framework:
  - Directed component/data-flow system graph S = (C, D)                 [Eq. (1)]
  - Trust boundary detection (untrusted source -> trusted component)
  - Transitive tool privilege propagation a_2 along directed data flows
  - Agentic amplification factor M(c) in [1, 2]:
        M(c) = 1 + w1*a1 + w2*a2 + w3*a3 + w4*a4                        [Eq. (2)]
  - Attacker model (NIST AI 100-2e2025) & Threat catalog covering:
        OWASP LLM Top 10 (2025), OWASP Top 10 for Agentic Applications (ASI01-ASI10),
        and MITRE ATLAS.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from enum import Enum
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import yaml


# ==============================================================================
# Enums & Constants
# ==============================================================================

class ComponentType(str, Enum):
    """Component types in the RBST-AI system graph S = (C, D) (Section 4.1)."""

    TRAINING_DATA = "training_data"
    TRAINING_PIPELINE = "training_pipeline"
    MODEL = "model"
    ORCHESTRATOR = "orchestrator"        # system prompt, planner, guardrails
    CONTEXT_SOURCE = "context_source"    # RAG, web search, email/review feed, memory
    TOOL = "tool"                        # executable tools / plugins / external APIs
    USER_INTERFACE = "user_interface"    # chat UI / web UI
    API = "api"                          # prediction / completion API endpoint


class PrivilegeLevel(str, Enum):
    """Component privilege tiers mapped to normalized scale {0, 1/3, 2/3, 1}."""

    NONE = "none"          # 0.0
    READ = "read"          # 1/3
    WRITE = "write"        # 2/3
    EXECUTE = "execute"    # 1.0 (execute / financial transaction / irreversible action)

    @property
    def numeric(self) -> float:
        return _PRIVILEGE_NUMERIC[self]


_PRIVILEGE_NUMERIC: Dict[PrivilegeLevel, float] = {
    PrivilegeLevel.NONE: 0.0,
    PrivilegeLevel.READ: 1.0 / 3.0,
    PrivilegeLevel.WRITE: 2.0 / 3.0,
    PrivilegeLevel.EXECUTE: 1.0,
}

_KNOWLEDGE_RANK: Dict[str, int] = {
    "black_box": 0,
    "gray_box": 1,
    "white_box": 2,
}

DEFAULT_AMPLIFICATION_WEIGHTS: Tuple[float, float, float, float] = (0.25, 0.25, 0.25, 0.25)


# ==============================================================================
# Graph & Attacker Data Structures
# ==============================================================================

@dataclass
class ComponentNode:
    """A component c in C of system graph S = (C, D)."""

    id: str
    name: str
    component_type: ComponentType
    privilege: PrivilegeLevel = PrivilegeLevel.NONE
    is_untrusted_source: bool = False
    receives_untrusted_external: bool = False
    data_sensitivity: float = 0.0          # a4 in [0, 1]
    human_approval_rate: float = 1.0       # autonomy a1 = 1 - human_approval_rate
    autonomy_override: Optional[float] = None
    existing_control_E: float = 0.0        # baseline control effectiveness E in [0, 1]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if isinstance(self.component_type, str):
            self.component_type = ComponentType(self.component_type.lower())
        if isinstance(self.privilege, str):
            self.privilege = PrivilegeLevel(self.privilege.lower())
        self.data_sensitivity = _clamp01(self.data_sensitivity)
        self.human_approval_rate = _clamp01(self.human_approval_rate)
        self.existing_control_E = _clamp01(self.existing_control_E)
        if self.autonomy_override is not None:
            self.autonomy_override = _clamp01(self.autonomy_override)

    @property
    def autonomy(self) -> float:
        """a1: autonomy level = 1 - fraction of critical actions requiring human approval."""
        if self.autonomy_override is not None:
            return self.autonomy_override
        return round(1.0 - self.human_approval_rate, 6)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "component_type": self.component_type.value,
            "privilege": self.privilege.value,
            "is_untrusted_source": self.is_untrusted_source,
            "receives_untrusted_external": self.receives_untrusted_external,
            "data_sensitivity": self.data_sensitivity,
            "human_approval_rate": self.human_approval_rate,
            "autonomy": self.autonomy,
            "existing_control_E": self.existing_control_E,
            "metadata": dict(self.metadata),
        }


@dataclass
class DataFlowEdge:
    """Directed data-flow edge (c -> c') in D of S = (C, D)."""

    source: str
    target: str
    label: str = ""
    untrusted_channel: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "label": self.label,
            "untrusted_channel": self.untrusted_channel,
        }


@dataclass
class AmplificationProfile:
    """Computed attribute vector (a1, a2, a3, a4) and amplification factor M(c)."""

    component_id: str
    a1_autonomy: float
    a2_propagated_privilege: float
    a3_untrusted_input_ratio: float
    a4_data_sensitivity: float
    weights: Tuple[float, float, float, float]
    M: float
    reachable_tools: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "component_id": self.component_id,
            "a1": round(self.a1_autonomy, 4),
            "a2": round(self.a2_propagated_privilege, 4),
            "a3": round(self.a3_untrusted_input_ratio, 4),
            "a4": round(self.a4_data_sensitivity, 4),
            "weights": [round(w, 4) for w in self.weights],
            "M": round(self.M, 4),
            "reachable_tools": list(self.reachable_tools),
        }


@dataclass
class AttackerModel:
    """Attacker capabilities & goals following NIST AI 100-2e2025 [21]."""

    name: str = "External Black-Box Attacker"
    objectives: Set[str] = field(
        default_factory=lambda: {"confidentiality", "integrity", "availability", "abuse"}
    )
    knowledge: str = "black_box"           # black_box | gray_box | white_box
    access_points: Set[str] = field(default_factory=lambda: {"*"})

    def can_reach_component(self, component_id: str) -> bool:
        return "*" in self.access_points or component_id in self.access_points

    def meets_knowledge(self, required_knowledge: str) -> bool:
        return _KNOWLEDGE_RANK.get(self.knowledge, 0) >= _KNOWLEDGE_RANK.get(required_knowledge, 0)


@dataclass
class ThreatDefinition:
    """Threat entry t aligned with OWASP LLM Top 10:2025, OWASP Agentic ASI01-ASI10, MITRE ATLAS."""

    id: str
    name: str
    owasp_code: str
    mitre_atlas: str
    nist_aml_objective: str                        # confidentiality | integrity | availability | abuse
    required_knowledge: str = "black_box"          # black_box | gray_box | white_box
    applicable_component_types: Set[ComponentType] = field(default_factory=set)
    requires_untrusted_input: bool = False
    requires_tool_reachability: bool = False
    default_impact: float = 3.0                    # I in [1, 5]
    prior_mu0: float = 0.20                        # published ASR prior mu_0 in (0, 1)
    prior_n0: float = 4.0                          # virtual sample size n_0 > 0
    scanner_module: str = "prompt_injection"
    owasp_rank: int = 10                           # ordering for B1 (OWASP list)
    rbt_qualitative_tier: int = 2                  # 1=High, 2=Medium, 3=Low (for B4)
    description: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "owasp_code": self.owasp_code,
            "mitre_atlas": self.mitre_atlas,
            "nist_aml_objective": self.nist_aml_objective,
            "required_knowledge": self.required_knowledge,
            "applicable_component_types": sorted(ct.value for ct in self.applicable_component_types),
            "requires_untrusted_input": self.requires_untrusted_input,
            "requires_tool_reachability": self.requires_tool_reachability,
            "default_impact": self.default_impact,
            "prior_mu0": self.prior_mu0,
            "prior_n0": self.prior_n0,
            "scanner_module": self.scanner_module,
            "owasp_rank": self.owasp_rank,
            "rbt_qualitative_tier": self.rbt_qualitative_tier,
            "description": self.description,
        }


@dataclass
class ApplicableThreatPair:
    """An applicable (threat t, component c) pair produced by Threat Modeler."""

    threat: ThreatDefinition
    component: ComponentNode
    amplification: AmplificationProfile
    impact: float
    control_effectiveness: float
    prior_mu0: float
    prior_n0: float
    crosses_trust_boundary: bool = False
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def pair_id(self) -> str:
        return f"{self.threat.id}@{self.component.id}"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pair_id": self.pair_id,
            "threat_id": self.threat.id,
            "threat_name": self.threat.name,
            "component_id": self.component.id,
            "component_name": self.component.name,
            "owasp_code": self.threat.owasp_code,
            "mitre_atlas": self.threat.mitre_atlas,
            "I": round(self.impact, 4),
            "M": round(self.amplification.M, 4),
            "E": round(self.control_effectiveness, 4),
            "mu0": round(self.prior_mu0, 4),
            "n0": round(self.prior_n0, 4),
            "crosses_trust_boundary": self.crosses_trust_boundary,
            "scanner_module": self.threat.scanner_module,
            "amplification": self.amplification.to_dict(),
        }


# ==============================================================================
# Helper Functions
# ==============================================================================

def _clamp01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def validate_weights(weights: Sequence[float]) -> Tuple[float, float, float, float]:
    """Validate amplification weights: 4 non-negative floats with sum <= 1.0."""
    if len(weights) != 4:
        raise ValueError(f"Expected 4 weights (w1..w4), got {len(weights)}.")
    w = tuple(float(x) for x in weights)
    if any(x < 0.0 for x in w):
        raise ValueError(f"Amplification weights must be non-negative: {w}")
    if sum(w) > 1.0 + 1e-9:
        raise ValueError(f"Sum of amplification weights must be <= 1.0, got {sum(w):.6f}")
    return (w[0], w[1], w[2], w[3])


# ==============================================================================
# SystemGraph S = (C, D) & Context Profiler
# ==============================================================================

class SystemGraph:
    """
    Directed system graph S = (C, D) with RBST-AI Context Profiler methods.

    Computes:
      - Trust boundaries (edges from untrusted source/channel into trusted node)
      - Reachable downstream components and propagated tool privilege a2(c)
      - Untrusted input ratio a3(c)
      - Agentic amplification factor M(c) = 1 + w1*a1 + w2*a2 + w3*a3 + w4*a4  [Eq. (2)]
    """

    def __init__(
        self,
        name: str = "AI System",
        version: str = "1.0",
        description: str = "",
        weights: Sequence[float] = DEFAULT_AMPLIFICATION_WEIGHTS,
        pair_overrides: Optional[Dict[str, Dict[str, Any]]] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.name = name
        self.version = version
        self.description = description
        self.weights = validate_weights(weights)
        self.nodes: Dict[str, ComponentNode] = {}
        self.edges: List[DataFlowEdge] = []
        self._outgoing: Dict[str, List[DataFlowEdge]] = {}
        self._incoming: Dict[str, List[DataFlowEdge]] = {}
        self.pair_overrides: Dict[str, Dict[str, Any]] = dict(pair_overrides or {})
        self.metadata: Dict[str, Any] = dict(metadata or {})

    # ------------------------------------------------------------------
    # Graph construction
    # ------------------------------------------------------------------

    def add_component(self, node: ComponentNode) -> None:
        self.nodes[node.id] = node
        self._outgoing.setdefault(node.id, [])
        self._incoming.setdefault(node.id, [])

    def add_flow(
        self,
        source: str,
        target: str,
        label: str = "",
        untrusted_channel: bool = False,
    ) -> DataFlowEdge:
        if source not in self.nodes:
            raise KeyError(f"Source component '{source}' not found in graph '{self.name}'.")
        if target not in self.nodes:
            raise KeyError(f"Target component '{target}' not found in graph '{self.name}'.")
        edge = DataFlowEdge(
            source=source,
            target=target,
            label=label,
            untrusted_channel=untrusted_channel,
        )
        self.edges.append(edge)
        self._outgoing[source].append(edge)
        self._incoming[target].append(edge)
        return edge

    # ------------------------------------------------------------------
    # Graph traversal & Context Profiler calculations (Section 4.1–4.2)
    # ------------------------------------------------------------------

    def get_reachable_nodes(self, start_id: str) -> Set[str]:
        """Return all component IDs reachable from start_id (including start_id)."""
        if start_id not in self.nodes:
            raise KeyError(f"Component '{start_id}' not found.")
        visited: Set[str] = {start_id}
        queue: deque[str] = deque([start_id])
        while queue:
            cur = queue.popleft()
            for edge in self._outgoing.get(cur, []):
                if edge.target not in visited:
                    visited.add(edge.target)
                    queue.append(edge.target)
        return visited

    def get_trust_boundaries(self) -> List[DataFlowEdge]:
        """
        Return directed edges crossing a trust boundary:
        an untrusted source (or untrusted channel) flowing into a trusted component.
        """
        boundaries: List[DataFlowEdge] = []
        for edge in self.edges:
            src = self.nodes[edge.source]
            dst = self.nodes[edge.target]
            if (src.is_untrusted_source or edge.untrusted_channel) and not dst.is_untrusted_source:
                boundaries.append(edge)
        return boundaries

    def has_untrusted_upstream(self, component_id: str) -> bool:
        """Return True if component_id is untrusted, directly receives untrusted input,
        or lies downstream of an untrusted source / untrusted channel."""
        node = self.nodes[component_id]
        if node.is_untrusted_source or node.receives_untrusted_external:
            return True
        visited: Set[str] = {component_id}
        queue: deque[str] = deque([component_id])
        while queue:
            cur = queue.popleft()
            for edge in self._incoming.get(cur, []):
                if edge.untrusted_channel:
                    return True
                src = self.nodes[edge.source]
                if src.is_untrusted_source or src.receives_untrusted_external:
                    return True
                if edge.source not in visited:
                    visited.add(edge.source)
                    queue.append(edge.source)
        return False

    def compute_propagated_privilege(self, component_id: str) -> Tuple[float, List[str]]:
        """
        Compute a2(c): maximum privilege among c and all downstream components/tools
        reachable from c via directed data flows D.
        """
        reachable = self.get_reachable_nodes(component_id)
        max_priv = 0.0
        reachable_tools: List[str] = []
        for nid in sorted(reachable):
            node = self.nodes[nid]
            priv_val = node.privilege.numeric
            if priv_val > max_priv:
                max_priv = priv_val
            if node.component_type == ComponentType.TOOL and priv_val > 0.0:
                reachable_tools.append(nid)
        return max_priv, reachable_tools

    def compute_untrusted_input_ratio(self, component_id: str) -> float:
        """
        Compute a3(c): ratio of untrusted incoming sources to total incoming sources.
        If c itself is an untrusted source (e.g., external web context), a3 = 1.0.
        If c has no incoming graph edges, falls back to 1.0 if receives_untrusted_external
        else 0.0.
        """
        node = self.nodes[component_id]
        if node.is_untrusted_source:
            return 1.0

        incoming = self._incoming.get(component_id, [])
        total_sources = len(incoming)
        untrusted_sources = sum(
            1
            for e in incoming
            if e.untrusted_channel
            or self.nodes[e.source].is_untrusted_source
            or self.nodes[e.source].receives_untrusted_external
        )
        if node.receives_untrusted_external:
            # Explicit external feed not modeled as a separate node
            total_sources += 1
            untrusted_sources += 1

        if total_sources == 0:
            return 0.0
        return _clamp01(untrusted_sources / total_sources)

    def compute_amplification(
        self,
        component_id: str,
        weights: Optional[Sequence[float]] = None,
    ) -> AmplificationProfile:
        """Compute (a1, a2, a3, a4) and M(c) = 1 + sum(w_i * a_i) in [1, 2] [Eq. (2)]."""
        if component_id not in self.nodes:
            raise KeyError(f"Component '{component_id}' not found.")
        w = validate_weights(weights) if weights is not None else self.weights
        node = self.nodes[component_id]

        a1 = node.autonomy
        a2, reachable_tools = self.compute_propagated_privilege(component_id)
        a3 = self.compute_untrusted_input_ratio(component_id)
        a4 = node.data_sensitivity

        m_val = 1.0 + w[0] * a1 + w[1] * a2 + w[2] * a3 + w[3] * a4
        m_val = max(1.0, min(2.0, m_val))

        return AmplificationProfile(
            component_id=component_id,
            a1_autonomy=a1,
            a2_propagated_privilege=a2,
            a3_untrusted_input_ratio=a3,
            a4_data_sensitivity=a4,
            weights=w,
            M=m_val,
            reachable_tools=reachable_tools,
        )

    def profile_all_components(
        self,
        weights: Optional[Sequence[float]] = None,
    ) -> Dict[str, AmplificationProfile]:
        """Compute AmplificationProfile for every component c in C."""
        return {cid: self.compute_amplification(cid, weights=weights) for cid in self.nodes}

    # ------------------------------------------------------------------
    # Serialization (YAML / JSON / Dict)
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict[str, Any]:
        profiles = self.profile_all_components()
        return {
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "weights": list(self.weights),
            "components": [n.to_dict() for n in self.nodes.values()],
            "flows": [e.to_dict() for e in self.edges],
            "trust_boundaries": [e.to_dict() for e in self.get_trust_boundaries()],
            "amplification_profiles": {k: v.to_dict() for k, v in profiles.items()},
            "pair_overrides": dict(self.pair_overrides),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "SystemGraph":
        graph = cls(
            name=str(data.get("name", "AI System")),
            version=str(data.get("version", "1.0")),
            description=str(data.get("description", "")),
            weights=data.get("weights", DEFAULT_AMPLIFICATION_WEIGHTS),
            pair_overrides=data.get("pair_overrides", {}),
            metadata=data.get("metadata", {}),
        )
        for comp in data.get("components", []):
            node = ComponentNode(
                id=str(comp["id"]),
                name=str(comp.get("name", comp["id"])),
                component_type=ComponentType(str(comp["component_type"]).lower()),
                privilege=PrivilegeLevel(str(comp.get("privilege", "none")).lower()),
                is_untrusted_source=bool(comp.get("is_untrusted_source", False)),
                receives_untrusted_external=bool(comp.get("receives_untrusted_external", False)),
                data_sensitivity=float(comp.get("data_sensitivity", 0.0)),
                human_approval_rate=float(comp.get("human_approval_rate", 1.0)),
                autonomy_override=(
                    float(comp["autonomy"]) if "autonomy" in comp and comp["autonomy"] is not None else None
                ),
                existing_control_E=float(comp.get("existing_control_E", 0.0)),
                metadata=dict(comp.get("metadata", {})),
            )
            graph.add_component(node)

        for flow in data.get("flows", []):
            graph.add_flow(
                source=str(flow["source"]),
                target=str(flow["target"]),
                label=str(flow.get("label", "")),
                untrusted_channel=bool(flow.get("untrusted_channel", False)),
            )
        return graph

    @classmethod
    def from_file(cls, path: str | Path) -> "SystemGraph":
        p = Path(path)
        raw = p.read_text(encoding="utf-8")
        if p.suffix.lower() in (".yaml", ".yml"):
            data = yaml.safe_load(raw)
        else:
            data = json.loads(raw)
        if not isinstance(data, dict):
            raise ValueError(f"Invalid system graph file: {p}")
        return cls.from_dict(data)


# ==============================================================================
# Default Threat Catalog (OWASP LLM Top 10:2025 + OWASP Agentic ASI + ATLAS)
# ==============================================================================

def get_default_threat_catalog() -> List[ThreatDefinition]:
    """
    Return the standard RBST-AI threat catalog T aligned with:
      - OWASP Top 10 for LLM Applications 2025 [23]
      - OWASP Top 10 for Agentic Applications (ASI01-ASI10) [22]
      - MITRE ATLAS [24]
      - Published empirical ASR priors mu_0 from [2, 6, 7, 14, 15, 27, 28].
    """
    return [
        ThreatDefinition(
            id="T_IPI",
            name="Indirect Prompt Injection",
            owasp_code="LLM01",
            mitre_atlas="AML.T0051.001",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.CONTEXT_SOURCE,
                ComponentType.ORCHESTRATOR,
                ComponentType.MODEL,
            },
            requires_untrusted_input=True,
            requires_tool_reachability=False,
            default_impact=4.5,
            prior_mu0=0.24,   # InjecAgent GPT-4 ReAct baseline ASR [15]
            prior_n0=4.0,
            scanner_module="rag_security",
            owasp_rank=1,
            rbt_qualitative_tier=1,
            description="Untrusted external content (web, email, reviews, docs) injects instructions hijacking AI behavior [1, 2, 15].",
        ),
        ThreatDefinition(
            id="T_DPI",
            name="Direct Prompt Injection",
            owasp_code="LLM01",
            mitre_atlas="AML.T0051.000",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.USER_INTERFACE,
                ComponentType.ORCHESTRATOR,
                ComponentType.MODEL,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=3.5,
            prior_mu0=0.25,   # Open-Prompt-Injection [2]
            prior_n0=4.0,
            scanner_module="prompt_injection",
            owasp_rank=1,
            rbt_qualitative_tier=1,
            description="User prompt directly overrides system instructions or hijacks task goal [2, 26].",
        ),
        ThreatDefinition(
            id="T_JB",
            name="Jailbreak / Safety Alignment Bypass",
            owasp_code="LLM01",
            mitre_atlas="AML.T0054",
            nist_aml_objective="abuse",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.MODEL,
                ComponentType.ORCHESTRATOR,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=3.8,
            prior_mu0=0.30,   # PAIR / HarmBench empirical range [13, 28]
            prior_n0=4.0,
            scanner_module="jailbreak",
            owasp_rank=1,
            rbt_qualitative_tier=1,
            description="Bypassing safety policies via iterative black-box (PAIR) or transferable suffixes (GCG) [27, 28].",
        ),
        ThreatDefinition(
            id="T_DATA_LEAK",
            name="Sensitive Information & Training Data Extraction",
            owasp_code="LLM02",
            mitre_atlas="AML.T0024",
            nist_aml_objective="confidentiality",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.MODEL,
                ComponentType.CONTEXT_SOURCE,
                ComponentType.TRAINING_DATA,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=4.2,
            prior_mu0=0.18,   # Training data / PII memorization & context leakage [7]
            prior_n0=4.0,
            scanner_module="sensitive_disclosure",
            owasp_rank=2,
            rbt_qualitative_tier=1,
            description="Exfiltrating PII, chat history, retrieved secrets, or memorized training data [7, 23].",
        ),
        ThreatDefinition(
            id="T_SUPPLY_BACKDOOR",
            name="Model Supply-Chain & Backdoor Poisoning",
            owasp_code="LLM03",
            mitre_atlas="AML.T0048",
            nist_aml_objective="integrity",
            required_knowledge="gray_box",
            applicable_component_types={
                ComponentType.TRAINING_DATA,
                ComponentType.TRAINING_PIPELINE,
                ComponentType.MODEL,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=4.4,
            prior_mu0=0.15,   # BadNets / supply-chain backdoor [5]
            prior_n0=4.0,
            scanner_module="oss_security",
            owasp_rank=3,
            rbt_qualitative_tier=2,
            description="Hidden backdoor triggers or malicious artifacts introduced during training/packaging [5].",
        ),
        ThreatDefinition(
            id="T_OUT_HANDLE",
            name="Improper Output Handling",
            owasp_code="LLM05",
            mitre_atlas="AML.T0048",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.USER_INTERFACE,
                ComponentType.TOOL,
                ComponentType.API,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=3.6,
            prior_mu0=0.20,
            prior_n0=4.0,
            scanner_module="output_handling",
            owasp_rank=5,
            rbt_qualitative_tier=2,
            description="Unsanitized LLM outputs trigger XSS, SQLi, SSRF, or command execution downstream [23].",
        ),
        ThreatDefinition(
            id="T_TOOL_ABUSE",
            name="Excessive Agency & Unauthorized Tool Execution",
            owasp_code="LLM06",
            mitre_atlas="AML.T0048.001",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.ORCHESTRATOR,
                ComponentType.TOOL,
                ComponentType.CONTEXT_SOURCE,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=True,
            default_impact=4.8,
            prior_mu0=0.24,   # InjecAgent & AgentDojo (<25% strongest agent) [14, 15]
            prior_n0=4.0,
            scanner_module="agent_testing",
            owasp_rank=6,
            rbt_qualitative_tier=1,
            description="Agent executes unauthorized high-privilege tool calls (email, financial transfer, booking) [14, 15, 22].",
        ),
        ThreatDefinition(
            id="T_ASI01_GOAL_HIJACK",
            name="Agent Goal Hijacking (OWASP Agentic ASI01)",
            owasp_code="ASI01",
            mitre_atlas="AML.T0051.001",
            nist_aml_objective="abuse",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.ORCHESTRATOR,
                ComponentType.CONTEXT_SOURCE,
            },
            requires_untrusted_input=True,
            requires_tool_reachability=True,
            default_impact=4.7,
            prior_mu0=0.25,   # AgentDojo / InjecAgent [14, 15, 22]
            prior_n0=4.0,
            scanner_module="excessive_agency",
            owasp_rank=6,
            rbt_qualitative_tier=1,
            description="Hijacking autonomous agent planning loop via untrusted context to pursue attacker objectives [22].",
        ),
        ThreatDefinition(
            id="T_PROMPT_LEAK",
            name="System Prompt Leakage",
            owasp_code="LLM07",
            mitre_atlas="AML.T0056",
            nist_aml_objective="confidentiality",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.ORCHESTRATOR,
                ComponentType.MODEL,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=2.8,
            prior_mu0=0.28,   # Perez & Ribeiro [26], OWASP 2025 [23]
            prior_n0=4.0,
            scanner_module="prompt_leak",
            owasp_rank=7,
            rbt_qualitative_tier=3,
            description="Extracting confidential system instructions, rules, or embedded secrets [23, 26].",
        ),
        ThreatDefinition(
            id="T_RAG_POISON",
            name="Vector & Embedding / Knowledge Base Weakness",
            owasp_code="LLM08",
            mitre_atlas="AML.T0020",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.CONTEXT_SOURCE,
            },
            requires_untrusted_input=True,
            requires_tool_reachability=False,
            default_impact=3.9,
            prior_mu0=0.22,
            prior_n0=4.0,
            scanner_module="rag_security",
            owasp_rank=8,
            rbt_qualitative_tier=2,
            description="Poisoning retrieval corpus or abusing embedding/access-control gaps in RAG [23].",
        ),
        ThreatDefinition(
            id="T_MODEL_EXTRACT",
            name="Model Extraction via Prediction API",
            owasp_code="AML_EXT",
            mitre_atlas="AML.T0044",
            nist_aml_objective="confidentiality",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.API,
                ComponentType.MODEL,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=4.5,
            prior_mu0=0.35,   # Tramèr et al. near-100% fidelity on MLaaS APIs [6]
            prior_n0=4.0,
            scanner_module="model_extraction",
            owasp_rank=4,
            rbt_qualitative_tier=1,
            description="Stealing proprietary ML model parameters/functionality via prediction API queries [6].",
        ),
        ThreatDefinition(
            id="T_ML_EVASION",
            name="Adversarial Evasion Attack (FGSM / C&W / Perturbation)",
            owasp_code="AML_EVA",
            mitre_atlas="AML.T0043",
            nist_aml_objective="integrity",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.API,
                ComponentType.MODEL,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=4.0,
            prior_mu0=0.30,   # Goodfellow / Carlini-Wagner [3, 4]
            prior_n0=4.0,
            scanner_module="ml_adversarial",
            owasp_rank=9,
            rbt_qualitative_tier=2,
            description="Crafting adversarial perturbations causing misclassification or filter evasion [3, 4].",
        ),
        ThreatDefinition(
            id="T_DOS",
            name="Unbounded Consumption / Denial of ML Service",
            owasp_code="LLM10",
            mitre_atlas="AML.T0029",
            nist_aml_objective="availability",
            required_knowledge="black_box",
            applicable_component_types={
                ComponentType.API,
                ComponentType.MODEL,
                ComponentType.USER_INTERFACE,
            },
            requires_untrusted_input=False,
            requires_tool_reachability=False,
            default_impact=2.6,
            prior_mu0=0.15,
            prior_n0=4.0,
            scanner_module="model_dos",
            owasp_rank=10,
            rbt_qualitative_tier=3,
            description="Resource exhaustion through excessive token/compute consumption [23].",
        ),
    ]


# ==============================================================================
# Threat Modeler (Layer 2)
# ==============================================================================

class RBSTThreatModeler:
    """
    Layer 2 Threat Modeler: combines SystemGraph S=(C, D), Threat Catalog T,
    and AttackerModel (NIST AI 100-2e2025) to enumerate applicable (t, c) pairs.
    """

    def __init__(self, threat_catalog: Optional[List[ThreatDefinition]] = None) -> None:
        self.catalog: List[ThreatDefinition] = (
            list(threat_catalog) if threat_catalog is not None else get_default_threat_catalog()
        )
        self._by_id: Dict[str, ThreatDefinition] = {t.id: t for t in self.catalog}

    def get_threat(self, threat_id: str) -> Optional[ThreatDefinition]:
        return self._by_id.get(threat_id)

    def enumerate_applicable_pairs(
        self,
        graph: SystemGraph,
        attacker: Optional[AttackerModel] = None,
        weights: Optional[Sequence[float]] = None,
        threat_ids: Optional[Iterable[str]] = None,
    ) -> List[ApplicableThreatPair]:
        """
        Determine all feasible (t, c) pairs given S = (C, D) and attacker model.
        Applies graph.pair_overrides (if any) for custom I, E, mu0, n0 per pair_id.
        """
        attacker = attacker or AttackerModel()
        profiles = graph.profile_all_components(weights=weights)
        boundary_targets = {e.target for e in graph.get_trust_boundaries()}
        boundary_sources = {e.source for e in graph.get_trust_boundaries()}

        allowed_threats = set(threat_ids) if threat_ids is not None else None
        pairs: List[ApplicableThreatPair] = []

        for threat in self.catalog:
            if allowed_threats is not None and threat.id not in allowed_threats:
                continue
            if threat.nist_aml_objective not in attacker.objectives:
                continue
            if not attacker.meets_knowledge(threat.required_knowledge):
                continue

            for comp_id, node in graph.nodes.items():
                if not attacker.can_reach_component(comp_id):
                    continue
                if threat.applicable_component_types and node.component_type not in threat.applicable_component_types:
                    continue

                amp = profiles[comp_id]
                if threat.requires_untrusted_input and not graph.has_untrusted_upstream(comp_id):
                    continue
                if threat.requires_tool_reachability and not amp.reachable_tools:
                    continue

                pair_key = f"{threat.id}@{comp_id}"
                override = graph.pair_overrides.get(pair_key, {})
                if override.get("exclude", False):
                    continue

                impact = float(override.get("I", threat.default_impact))
                impact = max(1.0, min(5.0, impact))

                control_e = _clamp01(float(override.get("E", node.existing_control_E)))
                mu0 = max(1e-4, min(1.0 - 1e-4, float(override.get("mu0", threat.prior_mu0))))
                n0 = max(1e-3, float(override.get("n0", threat.prior_n0)))

                crosses_tb = (comp_id in boundary_targets) or (comp_id in boundary_sources)
                pairs.append(
                    ApplicableThreatPair(
                        threat=threat,
                        component=node,
                        amplification=amp,
                        impact=impact,
                        control_effectiveness=control_e,
                        prior_mu0=mu0,
                        prior_n0=n0,
                        crosses_trust_boundary=crosses_tb,
                        metadata=dict(override.get("metadata", {})),
                    )
                )

        return pairs
