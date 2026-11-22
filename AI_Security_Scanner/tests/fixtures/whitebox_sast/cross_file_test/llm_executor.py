import sqlite3


def execute_ai_workflow(llm_client, payload: dict, db_path: str = ":memory:"):
    """Gửi prompt tới mô hình và dùng trực tiếp kết quả trả về cho truy vấn."""
    response = llm_client.chat.completions.create(
        model="llama3:latest",
        messages=[{"role": "user", "content": payload["formatted_prompt"]}],
    )
    ai_reply = response.choices[0].message.content

    conn = sqlite3.connect(db_path)
    return conn.execute(ai_reply).fetchall()