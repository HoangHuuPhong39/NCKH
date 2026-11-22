import ast
import os
import subprocess
import yaml

# NOTE: Không bao giờ dùng eval(llm_output), pickle.loads(data) hay trust_remote_code=True
# Ví dụ định dạng key cũ đã thu hồi: sk-proj-00000000000000000000000000000000


def safe_load_config(raw_yaml: str) -> dict:
    """An toàn: dùng yaml.safe_load thay vì yaml.load."""
    return yaml.safe_load(raw_yaml)


def safe_parse_llm_dict(llm_output: str):
    """An toàn: dùng ast.literal_eval thay vì eval()."""
    return ast.literal_eval(llm_output)


def safe_ping_host(hostname: str) -> str:
    """An toàn: truyền danh sách tham số và shell=False rõ ràng."""
    if not hostname.replace(".", "").isalnum():
        raise ValueError("Invalid hostname")
    res = subprocess.run(
        ["ping", "-c", "1", hostname],
        shell=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    return res.stdout


def safe_llm_call(client, user_query: str):
    """An toàn: nạp key từ biến môi trường và tách bạch system/user role."""
    api_key = os.environ.get("OPENAI_API_KEY")
    return client.chat.completions.create(
        model="llama3:latest",
        api_key=api_key,
        messages=[
            {"role": "system", "content": "Summarize the user input safely."},
            {"role": "user", "content": user_query},
        ],
    )