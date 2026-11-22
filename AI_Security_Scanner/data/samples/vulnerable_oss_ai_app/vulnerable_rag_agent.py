# -*- coding: utf-8 -*-
"""
data/samples/vulnerable_oss_ai_app/vulnerable_rag_agent.py
Ứng dụng AI Mã nguồn mở Mẫu (LangChain + Ollama + ChromaDB + PyTorch)
Phục vụ thực nghiệm kiểm thử Quét Mã Nguồn Tĩnh (SAST - Static Application Security Testing).
"""

import os
import pickle
import sqlite3
import requests
import torch
from transformers import AutoModelForCausalLM, AutoTokenizer
from langchain_experimental.tools import PythonREPLTool

# [AI-SAST-002] Lộ khóa API OpenAI & HuggingFace trực tiếp trong mã nguồn
OPENAI_API_KEY = "sk-proj-9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b"
HF_TOKEN = "hf_AbCdEfGhIjKlMnOpQrStUvWxYz12345678"

# [AI-SAST-005] Nạp model mã nguồn mở với trust_remote_code=True không ghim commit hash
tokenizer = AutoTokenizer.from_pretrained("open-llm-community/viet-agent-7b", trust_remote_code=True)


def load_finetuned_lora_weights(model_path: str):
    """[AI-SAST-003] Giải tuần tự hóa model checkpoint không an toàn (Pickle RCE)."""
    state_dict = torch.load(model_path)
    with open("embedding_index.pkl", "rb") as f:
        vec_cache = pickle.load(f)
    return state_dict, vec_cache


def query_ollama_rag(user_input: str, retrieved_context: str) -> str:
    """[AI-SAST-001, AI-SAST-007, AI-SAST-009] Nối chuỗi trực tiếp vào Prompt & thiếu timeout/SSL."""
    prompt = f"System: Bạn là trợ lý tài chính nội bộ. Context: {retrieved_context}. Hãy trả lời yêu cầu: {user_input}"

    response = requests.post(
        "http://localhost:11434/api/generate",
        json={"model": "llama3:latest", "prompt": prompt, "stream": False},
        verify=False,
    )
    return response.json().get("response", "")


def run_agent_tool_and_db(llm_output: str):
    """[AI-SAST-004, AI-SAST-006] Thực thi eval() và truyền thẳng output LLM vào SQL."""
    repl = PythonREPLTool()
    computed = eval(llm_output)

    conn = sqlite3.connect("customers.db")
    cursor = conn.cursor()
    cursor.execute(llm_output)
    return computed
