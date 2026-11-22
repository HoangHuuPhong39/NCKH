from utils import build_prompt_payload
from llm_executor import execute_ai_workflow


def handle_user_request(llm_client, user_query: str) -> dict:
    """Tiếp nhận dữ liệu từ người dùng và chuyển sang tầng xử lý trung gian."""
    payload = build_prompt_payload(user_query)
    result = execute_ai_workflow(llm_client, payload)
    return {"status": "done", "output": result}