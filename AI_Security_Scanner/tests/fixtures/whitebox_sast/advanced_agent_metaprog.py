import sqlite3
import types
from functools import wraps
from typing import Dict, Any


def _auto_commit_query(fn):
    """Decorator giấu Sink SQL Injection tách biệt hoàn toàn khỏi hàm gọi LLM."""
    @wraps(fn)
    def wrapper(self, *args, **kwargs):
        generated_sql = fn(self, *args, **kwargs)
        # [LỖ HỔNG 1 - Text-to-SQL Injection]: Thực thi trực tiếp SQL do LLM sinh ra
        return self.db_conn.execute(generated_sql).fetchall()
    return wrapper


def run_dynamic_policy(llm_expression: str, context: Dict[str, Any]) -> Any:
    """Thực thi biểu thức luật nghiệp vụ từ LLM mà không dùng eval/exec."""
    # [LỖ HỔNG 2 - RCE bậc cao]: Dùng compile() + types.FunctionType thay cho eval()
    code_obj = compile(f"def _p(ctx): return {llm_expression}", "<policy>", "exec")
    fn_code = next(c for c in code_obj.co_consts if isinstance(c, types.CodeType))
    dynamic_fn = types.FunctionType(fn_code, {"__builtins__": __builtins__})
    return dynamic_fn(context)


class EnterpriseRAGAgent:
    def __init__(self, llm_client, vector_db, db_path: str):
        self.client = llm_client
        self.vdb = vector_db
        self.db_conn = sqlite3.connect(db_path)

    def retrieve_docs(self, query: str, user_filters: Dict[str, Any]):
        # [LỖ HỔNG 3 - OWASP LLM08 Vector DB Filter Injection / Cross-Tenant Leak]:
        # Trộn trực tiếp filter từ user vào truy vấn Vector DB mà không khóa cứng tenant_id
        merged_where = {"department": "general", **user_filters}
        return self.vdb.query(query_texts=[query], n_results=5, where=merged_where)

    @_auto_commit_query
    def ask_database(self, user_question: str) -> str:
        res = self.client.chat.completions.create(
            model="llama3:latest",
            messages=[
                {"role": "system", "content": "Convert question to raw SQLite query."},
                {"role": "user", "content": user_question},
            ],
        )
        return res.choices[0].message.content