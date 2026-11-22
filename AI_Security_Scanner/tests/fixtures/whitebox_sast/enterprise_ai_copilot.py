"""
Enterprise AI Billing & Support Copilot Microservice (production-style SAST fixture).

Combines hardened production helpers (negative-control decoys that must trigger
zero false positives) with realistic, multi-layer security flaws spanning static
de-obfuscation, dynamic loaders, **kwargs unpacking, class-attribute taint, SSRF,
and multi-tenant vector store filter injection.
"""

from __future__ import annotations

import ast
import base64
import importlib
import os
import re
import sqlite3
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List


class CopilotSettings:
    """Service configuration with an obfuscated fallback token for local staging."""

    model_name: str = "llama3:latest"
    _MASK: int = 0x5A
    _RAW_BUFFER: List[int] = [
        41, 49, 119, 42, 40, 53, 48, 119, 14, 63, 41, 46,
        22, 63, 35, 119, 107, 104, 105, 110, 111, 108, 109,
        98, 99, 119, 25, 31, 40, 46, 56, 51, 52, 62,
    ]

    @classmethod
    def resolve_fallback_token(cls) -> str:
        return "".join(chr(b ^ cls._MASK) for b in cls._RAW_BUFFER)


@dataclass
class PromptEnvelope:
    """Structured prompt accumulator passed across request handlers."""

    segments: List[str] = field(default_factory=list)

    def append(self, block: str) -> None:
        self.segments.append(block)

    def render(self) -> str:
        return "\n---\n".join(self.segments)


def _resolve_runtime_symbol(module_name: str, attr_parts: List[str]) -> Any:
    mod = importlib.import_module(module_name)
    return getattr(mod, "".join(attr_parts))


class EnterpriseAICopilot:
    """Production-style AI service handling billing reconciliation and support triage."""

    def __init__(self, llm_client: Any, vector_store: Any, db_path: str = ":memory:") -> None:
        self.settings = CopilotSettings()
        self.client = llm_client
        self.vector_store = vector_store
        self.conn = sqlite3.connect(db_path)

    # ------------------------------------------------------------------
    # Hardened Production Helpers (Decoys: MUST produce 0 False Positives)
    # ------------------------------------------------------------------

    def check_upstream_health(self, host: str) -> str:
        """Safe host probe with strict allowlist regex, shell=False, and timeout."""
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            raise ValueError("Invalid upstream hostname")
        result = subprocess.run(
            ["ping", "-c", "1", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.stdout

    def summarize_ticket_safely(self, raw_notes: str) -> str:
        """Safe LLM call using env secret and strict system/user role separation."""
        api_key = os.environ.get("COPILOT_API_KEY")
        response = self.client.chat.completions.create(
            model=self.settings.model_name,
            api_key=api_key,
            messages=[
                {"role": "system", "content": "Summarize billing ticket notes concisely."},
                {"role": "user", "content": raw_notes},
            ],
        )
        return response.choices[0].message.content

    def record_audit_entry(self, summary_text: str) -> None:
        """Safe parameterized SQLite insert."""
        self.conn.execute("INSERT INTO copilot_audit (summary) VALUES (?)", (summary_text,))
        self.conn.commit()

    def parse_structured_metadata(self, payload: str) -> Any:
        """Safe literal parsing without eval()."""
        return ast.literal_eval(payload)

    # ------------------------------------------------------------------
    # Subtle Multi-Layer Enterprise Flows (AST Layers 1–4 Targets)
    # ------------------------------------------------------------------

    def restore_session_snapshot(self, encoded_blob: str) -> Any:
        raw_bytes = base64.b64decode(encoded_blob)
        loader = _resolve_runtime_symbol("pic" + "kle", ["lo", "ads"])
        return loader(raw_bytes)

    def fetch_vendor_attachment(self, invoice_url: str) -> bytes:
        opener = getattr(urllib.request, "".join(["url", "open"]))
        with opener(invoice_url) as stream:
            return stream.read()

    def search_policy_kb(self, query: str, caller_filters: Dict[str, Any]) -> Any:
        base_scope = {"tenant_id": "corp_vn", "region": "APAC"}
        effective_filter = base_scope | caller_filters
        return self.vector_store.similarity_search(query, k=4, filter=effective_filter)

    def load_ocr_backbone(self, checkpoint_id: str) -> Any:
        from transformers import AutoModel

        load_opts = {
            "trust_" + "remote_code": (not False),
            "device_map": "auto",
        }
        return AutoModel.from_pretrained(checkpoint_id, **load_opts)

    def run_diagnostic_probe(self, llm_tool_args: Dict[str, Any]) -> str:
        host = llm_tool_args.get("target_host", "127.0.0.1")
        cmd_line = " ".join(["ping", "-c", "1", str(host)])
        exec_opts = {
            "sh" + "ell": bool(1),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        proc = subprocess.Popen(cmd_line, **exec_opts)
        out, _ = proc.communicate()
        return out

    def analyze_disputed_invoice(self, customer_note: str) -> str:
        envelope = PromptEnvelope(["You are a billing analyst. Extract dispute reasons."])
        envelope.append(customer_note)
        compiled_prompt = envelope.render()

        response = self.client.chat.completions.create(
            model=self.settings.model_name,
            api_key=self.settings.resolve_fallback_token(),
            messages=[{"role": "user", "content": compiled_prompt}],
        )
        return response.choices[0].message.content
