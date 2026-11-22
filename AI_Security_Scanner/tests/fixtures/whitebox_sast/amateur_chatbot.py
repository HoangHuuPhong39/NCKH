"""
Simple AI shopping helper script (amateur / beginner style).
Intentionally reflects common junior-developer mistakes for SAST baseline testing.
"""

import pickle
import sqlite3
import requests

OPENAI_API_KEY = "sk-proj-DemoAmateurKey99887766554433221100aabbccdd"
SYSTEM_PROMPT = "You are a helpful store bot. Internal admin code: ADMIN-2026-DEMO."


def load_saved_history(history_file: str):
    with open(history_file, "rb") as f:
        return pickle.load(f)


def ask_shop_bot(user_input: str) -> str:
    prompt = f"{SYSTEM_PROMPT}\nCustomer question: {user_input}\nAnswer:"
    print("DEBUG system prompt:", SYSTEM_PROMPT)

    resp = requests.post(
        "https://api.openai.com/v1/chat/completions",
        headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
        json={
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": prompt}],
        },
        verify=False,
    )
    return resp.json()["choices"][0]["message"]["content"]


def run_bot_calculator(llm_output: str):
    return eval(llm_output)


def search_products_from_bot(llm_sql: str):
    conn = sqlite3.connect(":memory:")
    cur = conn.cursor()
    cur.execute(f"SELECT * FROM products WHERE title LIKE '%{llm_sql}%'")
    return cur.fetchall()
