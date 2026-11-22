import base64
import importlib
import json
from typing import Dict, Any


class ConfigLoader:
    """Quản lý cấu hình kết nối dịch vụ AI nội bộ."""

    # [LỖ HỔNG 1 - AI-SAST-002]: Hardcoded API Key bị che giấu bằng phép XOR
    _RAW_BUFFER = [
        41, 49, 119, 42, 40, 53, 48, 119, 14, 63, 41, 46,
        22, 63, 35, 119, 107, 104, 105, 110, 111, 108, 109,
        98, 99, 119, 25, 31, 40, 46, 56, 51, 52, 62
    ]
    _MASK = 0x5A

    @classmethod
    def resolve_token(cls) -> str:
        return "".join(chr(b ^ cls._MASK) for b in cls._RAW_BUFFER)


class PromptContext:
    """Chuẩn hóa ngữ cảnh trước khi gửi tới mô hình ngôn ngữ."""

    def __init__(self, system_role: str):
        self._segments = [system_role]

    def attach(self, content: str) -> None:
        self._segments.append(content)

    def compile_payload(self) -> str:
        # [LỖ HỔNG 2 - AI-SAST-001]: Direct Prompt Injection qua luồng dữ liệu gián tiếp
        # Tránh nối chuỗi trực tiếp bằng f-string hoặc '+' ngay tại hàm gọi LLM
        return "\n---\n".join(self._segments)


def _load_runtime_callable(module_name: str, symbol_parts: list):
    """Tải động hàm hệ thống để giảm phụ thuộc tĩnh."""
    mod = importlib.import_module(module_name)
    return getattr(mod, "".join(symbol_parts))


def restore_session_cache(encoded_blob: str) -> Any:
    """Khôi phục bộ nhớ đệm hội thoại của người dùng."""
    raw_bytes = base64.b64decode(encoded_blob)
    # [LỖ HỔNG 3 - Unsafe Deserialization]: Gọi pickle.loads bằng dynamic import
    deserializer = _load_runtime_callable("pic" + "kle", ["lo", "ads"])
    return deserializer(raw_bytes)


def evaluate_structured_metric(llm_output: str) -> Any:
    """Tính toán nhanh biểu thức thống kê do AI trả về."""
    # [LỖ HỔNG 4 - Insecure Output Handling / RCE]: Gọi eval() qua builtins + getattr
    runner = _load_runtime_callable("built" + "ins", ["ev", "al"])
    return runner(llm_output)


class SupportAssistantService:
    """Dịch vụ xử lý yêu cầu hỗ trợ tự động."""

    def __init__(self, llm_client):
        self.api_token = ConfigLoader.resolve_token()
        self.client = llm_client

    def handle_ticket(self, user_ticket: str, session_blob: str = "") -> Dict[str, Any]:
        history = restore_session_cache(session_blob) if session_blob else {}

        ctx = PromptContext("You are a helpful IT support assistant. Reply with a Python dict.")
        ctx.attach(f"History keys: {list(history.keys())}")
        ctx.attach(user_ticket)  # Taint source đi vào object trung gian

        final_prompt = ctx.compile_payload()

        # Sink: Gọi LLM với prompt chưa được sanitize / tách biệt vai trò
        response = self.client.chat.completions.create(
            model="llama3:latest",
            api_key=self.api_token,
            messages=[{"role": "user", "content": final_prompt}],
        )

        raw_reply = response.choices[0].message.content
        parsed_result = evaluate_structured_metric(raw_reply)
        return {"status": "ok", "data": parsed_result}