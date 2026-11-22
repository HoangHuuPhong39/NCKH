import json
import os
import sqlite3
from string import Template
from typing import Any, Dict


class IncidentBotConfig:
    """Cấu hình bot ứng phó sự cố tự động."""

    # [LỖ HỔNG 1 - AI-SAST-002]: API Key bị đảo ngược chuỗi (không dùng XOR/Hex/Base64)
    _REVERSED_TOKEN = "778899yeKterceS6202hcneBdirbyH-jorp-ks"

    @classmethod
    def get_key(cls) -> str:
        return cls._REVERSED_TOKEN[::-1]


class IncidentAutoResponder:
    """Tự động phân loại cảnh báo, chạy lệnh khắc phục và xuất báo cáo."""

    def __init__(self, llm_client, db_path: str = ":memory:"):
        self.client = llm_client
        self.conn = sqlite3.connect(db_path)
        self._state_bus: Dict[str, str] = {}

        # [LỖ HỔNG 2 - AI-SAST-004]: Bảng điều phối lambda giấu lệnh thực thi OS (os.popen)
        self._tool_registry = {
            "net_diag": lambda cmd: os.popen(cmd).read(),
            "noop": lambda _: "ok",
        }

    def ingest_webhook_alert(self, webhook_payload: Dict[str, Any]) -> None:
        """Nhận cảnh báo từ nguồn bên ngoài và đẩy vào state bus."""
        self._state_bus["latest_raw"] = str(webhook_payload.get("body", ""))

    # [LỖ HỔNG 3 - AI-SAST-001]: Prompt Injection gián tiếp qua state bus + string.Template
    def triage_and_remediate(self) -> Dict[str, Any]:
        alert_text = self._state_bus.get("latest_raw", "")
        tpl = Template("You are a DevOps bot. Return JSON {action, cmd, html}.\nAlert: $data")
        prompt = tpl.safe_substitute(data=alert_text)

        resp = self.client.chat.completions.create(
            model="llama3:latest",
            api_key=IncidentBotConfig.get_key(),
            messages=[{"role": "user", "content": prompt}],
        )
        plan = json.loads(resp.choices[0].message.content)

        # Gọi tool từ dispatch table bằng dữ liệu LLM sinh ra (không kiểm duyệt / sandbox)
        handler = self._tool_registry.get(plan.get("action", "noop"))
        cmd_output = handler(plan.get("cmd", "")) if handler else ""

        # [LỖ HỔNG 4 - AI-SAST-006]: SSTI / XSS khi render trực tiếp đầu ra LLM bằng Jinja2
        from jinja2 import Template as JinjaTemplate
        rendered_report = JinjaTemplate(plan.get("html", "")).render(output=cmd_output)

        self.save_audit_safely(rendered_report)
        return {"report": rendered_report}

    # [LỖ HỔNG 5 - AI-SAST-007]: Vòng lặp Agent vô hạn không giới hạn vòng/token/timeout (DoS)
    def autonomous_root_cause_loop(self, initial_symptom: str) -> str:
        history = [{"role": "user", "content": initial_symptom}]
        while True:
            resp = self.client.chat.completions.create(
                model="llama3:latest",
                messages=history,
            )
            answer = resp.choices[0].message.content
            if "FINAL_RCA:" in answer:
                return answer
            history.append({"role": "assistant", "content": answer})
            history.append({"role": "user", "content": "Dig deeper into the logs."})

    # --- DECOY AN TOÀN: Không được báo SQL Injection ---
    def save_audit_safely(self, summary_text: str) -> None:
        self.conn.execute(
            "INSERT INTO incident_audit (summary) VALUES (?)",
            (summary_text,),
        )
        self.conn.commit()