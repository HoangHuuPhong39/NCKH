from typing import Dict


def build_prompt_payload(raw_input: str) -> Dict[str, str]:
    """Đóng gói dữ liệu đầu vào vào cấu trúc từ điển mà không lọc nội dung."""
    template = "Generate a concise response for: {content}"
    return {
        "formatted_prompt": template.format(content=raw_input),
        "raw": raw_input,
    }