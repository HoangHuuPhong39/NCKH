import json
import subprocess
import urllib.request
from typing import Dict, Any


class DocumentIngestor:
    """Nạp tài liệu từ nguồn bên ngoài vào kho tri thức RAG."""

    @staticmethod
    def _normalize_uri(raw_uri: str) -> str:
        cleaned = raw_uri.strip()
        return cleaned if "://" in cleaned else f"http://{cleaned}"

    def fetch_knowledge(self, source_url: str) -> str:
        # [LỖ HỔNG 1 - SSRF qua RAG]: Không lọc IP nội bộ / metadata cloud
        # Qua mặt SAST bằng cách không dùng requests.get trực tiếp và tách hàm xử lý URL
        target = self._normalize_uri(source_url)
        opener = getattr(urllib.request, "url" + "open")
        with opener(target) as resp:  # Không đặt timeout -> tiềm ẩn DoS
            return resp.read().decode("utf-8", errors="ignore")


class DiagnosticAgentTools:
    """Tập công cụ hệ thống được cấp cho AI Agent."""

    @staticmethod
    def run_network_check(llm_tool_args: Dict[str, Any]) -> str:
        host = llm_tool_args.get("target_host", "127.0.0.1")
        cmd_line = " ".join(["ping", "-c", "1", str(host)])

        # [LỖ HỔNG 2 - Command Injection / Excessive Agency]:
        # Che giấu shell=True bằng unpacking dict (**exec_opts) và biểu thức bool(1)
        exec_opts = {
            "sh" + "ell": bool(1),
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "text": True,
        }
        proc = subprocess.Popen(cmd_line, **exec_opts)
        out, _ = proc.communicate()
        return out


class LocalModelManager:
    """Tải mô hình ngôn ngữ từ Hugging Face Hub."""

    def load_checkpoint(self, repo_id: str):
        from transformers import AutoModelForCausalLM

        # [LỖ HỔNG 3 - Supply Chain / RCE khi tải Model]:
        # Che giấu trust_remote_code=True bằng dynamic dict unpacking
        flag_key = "_".join(["trust", "remote", "code"])
        load_kwargs = {flag_key: (1 == 1), "low_cpu_mem_usage": True}
        return AutoModelForCausalLM.from_pretrained(repo_id, **load_kwargs)


def answer_with_rag(llm_client, doc_url: str, user_question: str) -> str:
    ingestor = DocumentIngestor()
    external_context = ingestor.fetch_knowledge(doc_url)

    # [LỖ HỔNG 4 - Indirect Prompt Injection (RAG Poisoning)]:
    # Dùng format_map với template tách rời để tránh rule bắt f-string / dấu '+'
    template = "Context:\n{ctx}\n\nQuestion:\n{q}\nReturn JSON with target_host."
    payload = template.format_map({"ctx": external_context, "q": user_question})

    res = llm_client.chat.completions.create(
        model="llama3:latest",
        messages=[{"role": "user", "content": payload}],
    )
    tool_call = json.loads(res.choices[0].message.content)
    return DiagnosticAgentTools.run_network_check(tool_call)