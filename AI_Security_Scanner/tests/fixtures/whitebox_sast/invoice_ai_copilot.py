import os
import re
import subprocess
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Dict, List


@dataclass
class BillingAIConfig:
    """Cấu hình kết nối dịch vụ AI đối soát hóa đơn."""

    model_name: str = "llama3:latest"
    # [LỖ HỔNG 1 - AI-SAST-002]: Hardcoded API Key mã hóa bằng hex
    _hex_token: str = (
        "736b2d70726f6a2d426c696e6454657374"
        "39383736353433323130616263646566313233343536"
    )

    def get_bearer_key(self) -> str:
        return bytes.fromhex(self._hex_token).decode("utf-8")


@dataclass
class InvoicePromptBuilder:
    """Đệm gom ngữ cảnh hóa đơn trước khi gửi sang LLM."""

    blocks: List[str] = field(default_factory=list)

    def push(self, text: str) -> None:
        self.blocks.append(text)

    def render(self) -> str:
        return "\n".join(self.blocks)


class InvoiceAutomationService:
    """Microservice tự động phân loại, đối soát và tính chiết khấu hóa đơn."""

    def __init__(self, llm_client, vector_store):
        self.cfg = BillingAIConfig()
        self.client = llm_client
        self.vector_store = vector_store

    # --- DECOY AN TOÀN 1: Không được báo Command Injection ---
    def check_gateway_health(self, host: str) -> str:
        if not re.fullmatch(r"[a-zA-Z0-9.-]+", host):
            raise ValueError("Invalid host format")
        res = subprocess.run(
            ["ping", "-c", "1", host],
            shell=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
        return res.stdout

    # --- DECOY AN TOÀN 2: Không được báo Prompt Injection / Secret ---
    def summarize_invoice_safely(self, raw_notes: str) -> str:
        env_key = os.environ.get("BILLING_LLM_KEY")
        resp = self.client.chat.completions.create(
            model=self.cfg.model_name,
            api_key=env_key,
            messages=[
                {"role": "system", "content": "Summarize invoice notes concisely."},
                {"role": "user", "content": raw_notes},
            ],
        )
        return resp.choices[0].message.content

    # [LỖ HỔNG 2 & 3 - SSRF + Missing Timeout]
    def download_vendor_invoice(self, invoice_url: str) -> bytes:
        fetcher = getattr(urllib.request, "".join(["url", "open"]))
        with fetcher(invoice_url) as stream:
            return stream.read()

    # [LỖ HỔNG 4 - Vector DB Filter Injection qua toán tử gộp dict '|']
    def lookup_tax_policies(self, query: str, caller_filters: Dict[str, Any]):
        base_scope = {"tenant_id": "corp_vn", "region": "APAC"}
        effective_filter = base_scope | caller_filters
        return self.vector_store.similarity_search(
            query, k=4, filter=effective_filter
        )

    # [LỖ HỔNG 5 - Supply Chain RCE dùng 'not False' và **opts]
    def init_local_ocr_model(self, checkpoint_id: str):
        from transformers import AutoModel

        opts = {
            "trust_" + "remote_code": (not False),
            "device_map": "auto",
        }
        return AutoModel.from_pretrained(checkpoint_id, **opts)

    # [LỖ HỔNG 6 & 7 - Indirect Prompt Injection + RCE qua compile/exec]
    def compute_dynamic_discount(self, customer_note: str) -> Any:
        builder = InvoicePromptBuilder()
        builder.push("Return a Python assignment: discount = <number>")
        builder.push(customer_note)
        combined = builder.render()

        resp = self.client.chat.completions.create(
            model=self.cfg.model_name,
            api_key=self.cfg.get_bearer_key(),
            messages=[{"role": "user", "content": combined}],
        )
        formula_code = resp.choices[0].message.content

        local_ns: Dict[str, Any] = {}
        bytecode = compile(formula_code, "<discount_rule>", "exec")
        exec(bytecode, {}, local_ns)
        return local_ns.get("discount", 0)