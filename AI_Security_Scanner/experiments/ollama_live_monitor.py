# -*- coding: utf-8 -*-
"""
experiments/ollama_live_monitor.py
Split-Screen Live Ollama Monitor for Real-Time Demonstration

Run this script in the RIGHT terminal window while running `demo_live_replay.py`
or `main.py --rbst cs2 --rbst-live` in the LEFT terminal window.

Every prompt sent to Ollama (`127.0.0.1:11434`) is displayed immediately on this
screen, and Ollama's real-time token generation streams word-by-word live on screen
before returning the exact unmodified response to the scanner.

Usage (Right Terminal Window):
    .\\venv\\Scripts\\python.exe experiments\\ollama_live_monitor.py
"""

from __future__ import annotations

import argparse
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import sys
import time
import urllib.request

from rich.console import Console
from rich.panel import Panel

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

console = Console(legacy_windows=False)
_REQ_COUNTER = 0


class OllamaLiveMonitorHandler(BaseHTTPRequestHandler):
    upstream_url: str = "http://127.0.0.1:11434"

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        # Suppress default HTTP access log noise to keep live token view clean
        return

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/_monitor_ping":
            body = b'{"status":"ollama_live_monitor_ok"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        target = f"{self.upstream_url.rstrip('/')}{self.path}"
        try:
            with urllib.request.urlopen(target, timeout=15) as resp:
                data = resp.read()
                self.send_response(resp.status)
                self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)
        except Exception as exc:
            err = json.dumps({"error": str(exc)}).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err)))
            self.end_headers()
            self.wfile.write(err)

    def do_POST(self) -> None:  # noqa: N802
        global _REQ_COUNTER
        length = int(self.headers.get("Content-Length", "0"))
        raw_body = self.rfile.read(length) if length > 0 else b"{}"

        if self.path not in ("/api/chat", "/api/generate"):
            self._forward_raw_post(raw_body)
            return

        try:
            req_json = json.loads(raw_body.decode("utf-8"))
        except Exception:
            self._forward_raw_post(raw_body)
            return

        _REQ_COUNTER += 1
        req_id = _REQ_COUNTER
        model = req_json.get("model", "unknown")
        caller_wants_stream = bool(req_json.get("stream", False))
        now_str = datetime.now().strftime("%H:%M:%S")

        if self.path == "/api/chat":
            msgs = req_json.get("messages", [])
            sys_txt = next((m.get("content", "") for m in msgs if m.get("role") == "system"), "")
            usr_txt = next((m.get("content", "") for m in reversed(msgs) if m.get("role") == "user"), "")
        else:
            sys_txt = req_json.get("system", "") or ""
            usr_txt = req_json.get("prompt", "") or ""

        console.print(f"\n[bold yellow]━━━ 📥 [LƯỢT #{req_id} | {now_str}] NHẬN PROMPT TỪ SCANNER ━━━[/bold yellow]")
        console.print(f"[bold cyan]• Endpoint:[/bold cyan] POST {self.path}   [bold cyan]• Mô hình đích:[/bold cyan] [bold green]{model}[/bold green]")
        if sys_txt:
            sys_preview = sys_txt[:160] + ("..." if len(sys_txt) > 160 else "")
            console.print(f"[dim]• System Prompt: {sys_preview}[/dim]")
        console.print(Panel(usr_txt, title="[bold red]Câu Prompt Tấn Công Gửi Vào[/bold red]", border_style="red"))

        # Stream from upstream real Ollama so viewers watch tokens appear live!
        upstream_payload = dict(req_json)
        upstream_payload["stream"] = True

        t0 = time.perf_counter()
        req = urllib.request.Request(
            f"{self.upstream_url.rstrip('/')}{self.path}",
            data=json.dumps(upstream_payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        console.print(f"[bold green]🤖 [{model} đang suy luận & gõ trả lời trực tiếp]:[/bold green] ", end="")
        sys.stdout.flush()

        chunks_text: list[str] = []
        last_chunk_obj: dict = {}

        try:
            with urllib.request.urlopen(req, timeout=180) as resp:
                if caller_wants_stream:
                    self.send_response(200)
                    self.send_header("Content-Type", "application/x-ndjson")
                    self.end_headers()

                for raw_line in resp:
                    line = raw_line.decode("utf-8", errors="replace").strip()
                    if not line:
                        continue
                    obj = json.loads(line)
                    last_chunk_obj = obj
                    piece = (
                        obj.get("message", {}).get("content", "")
                        if self.path == "/api/chat"
                        else obj.get("response", "")
                    )
                    if piece:
                        chunks_text.append(piece)
                        sys.stdout.write(piece)
                        sys.stdout.flush()
                    if caller_wants_stream:
                        self.wfile.write(raw_line)
                        self.wfile.flush()

            elapsed = time.perf_counter() - t0
            full_text = "".join(chunks_text)
            sys.stdout.write("\n")
            console.print(
                f"[bold cyan]📤 [HOÀN TẤT LƯỢT #{req_id} trong {elapsed:.2f}s | {len(full_text)} ký tự → Đã trả về Scanner][/bold cyan]"
            )

            if not caller_wants_stream:
                final_resp = dict(last_chunk_obj)
                if self.path == "/api/chat":
                    final_resp["message"] = {"role": "assistant", "content": full_text}
                else:
                    final_resp["response"] = full_text
                final_resp["done"] = True
                out_bytes = json.dumps(final_resp, ensure_ascii=False).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(out_bytes)))
                self.end_headers()
                self.wfile.write(out_bytes)

        except Exception as exc:
            sys.stdout.write("\n")
            console.print(f"[bold red]❌ Lỗi kết nối tới Ollama ({self.upstream_url}): {exc}[/bold red]")
            err_bytes = json.dumps({"error": str(exc)}).encode("utf-8")
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_bytes)))
            self.end_headers()
            self.wfile.write(err_bytes)

    def _forward_raw_post(self, raw_body: bytes) -> None:
        req = urllib.request.Request(
            f"{self.upstream_url.rstrip('/')}{self.path}",
            data=raw_body,
            headers={"Content-Type": self.headers.get("Content-Type", "application/json")},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=120) as resp:
            data = resp.read()
            self.send_response(resp.status)
            self.send_header("Content-Type", resp.headers.get("Content-Type", "application/json"))
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)


def main() -> int:
    parser = argparse.ArgumentParser(description="Split-Screen Live Ollama Monitor")
    parser.add_argument("--port", type=int, default=11435, help="Local monitor port (default: 11435)")
    parser.add_argument("--upstream", default="http://127.0.0.1:11434", help="Real Ollama URL (default: http://127.0.0.1:11434)")
    args = parser.parse_args()

    OllamaLiveMonitorHandler.upstream_url = args.upstream
    server = ThreadingHTTPServer(("127.0.0.1", args.port), OllamaLiveMonitorHandler)

    console.print(
        Panel(
            f"[bold green]🟢 MÀN HÌNH QUAN SÁT TRỰC TIẾP MÔ HÌNH OLLAMA (LIVE STREAM MONITOR)[/bold green]\n"
            f"• Cổng đón trung gian: [bold cyan]http://127.0.0.1:{args.port}[/bold cyan]  ──▶  Ollama thật: [bold yellow]{args.upstream}[/bold yellow]\n"
            f"• Trạng thái: [bold white]Đang chờ câu Prompt tấn công từ cửa sổ bên trái...[/bold white]\n"
            f"[dim](Giữ nguyên cửa sổ này mở ở nửa phải màn hình. Bấm Ctrl+C khi muốn tắt)[/dim]",
            border_style="green",
        )
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("\n[yellow]Đã tắt màn hình quan sát Ollama.[/yellow]")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
