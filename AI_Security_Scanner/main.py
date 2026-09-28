"""
AI Security Scanner - Enhanced CLI (Metasploit-style)
Giao diện dòng lệnh nâng cao cho bộ công cụ kiểm thử an toàn AI.
"""

import sys
import os
import time
from datetime import datetime

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.text import Text
from rich.columns import Columns
from rich import box

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Thêm thư mục gốc để import
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.config import cfg
from core.db import init_db, save_finding, get_findings, get_stats, clear_findings, start_scan, complete_scan
from core.llm_client import SimpleLLMClient
from core.risk_scorer import RiskScorer
from core.report import generate_html_report, export_json_report

console = Console(legacy_windows=False)

BANNER = """
[bold red]  ██████╗ ██████╗ ██████╗ ██████╗     [/bold red][bold blue]     █████╗ ██╗    [/bold blue]
[bold red]  ██╔══██╗██╔══██╗╚════██╗╚════██╗    [/bold red][bold blue]    ██╔══██╗██║    [/bold blue]
[bold red]  ██║  ██║██║  ██║ █████╔╝ █████╔╝    [/bold red][bold blue]    ███████║██║    [/bold blue]
[bold red]  ██║  ██║██║  ██║ ╚═══██╗ ╚═══██╗    [/bold red][bold blue]    ██╔══██║██║    [/bold blue]
[bold red]  ██████╔╝██████╔╝██████╔╝██████╔╝    [/bold red][bold blue]    ██║  ██║██║    [/bold blue]
[bold red]  ╚═════╝ ╚═════╝ ╚═════╝ ╚═════╝     [/bold red][bold blue]    ╚═╝  ╚═╝╚═╝   [/bold blue]

[bold yellow]       Bộ Công Cụ Kiểm Thử An Toàn Hệ Thống AI[/bold yellow]
[dim]       OWASP LLM Top 10 · MITRE ATLAS · Research Edition v2.0[/dim]
"""

MODULES_METADATA = {
    "prompt_injection": {
        "name": "Prompt Injection",
        "description": "Kiểm tra khả năng mô hình bỏ qua hướng dẫn hệ thống bằng các câu lệnh ghi đè trực tiếp/gián tiếp.",
        "owasp": "LLM01",
        "mitre": "AML.T0051",
        "severity": "HIGH",
        "payloads_count": 12,
        "icon": "🎯",
        "category": "exploits",
    },
    "jailbreak": {
        "name": "Jailbreak / Safety Bypass",
        "description": "Sử dụng kịch bản nhập vai (DAN, AIM, STAN) để ép AI bỏ qua các quy tắc an toàn.",
        "owasp": "LLM01",
        "mitre": "AML.T0054",          # ← sửa: T0054 = Jailbreak ML Model
        "severity": "CRITICAL",
        "payloads_count": 6,
        "icon": "🔓",
        "category": "exploits",
    },
    "prompt_leak": {
        "name": "System Prompt Disclosure",
        "description": "Trích xuất System Prompt ẩn bằng cách yêu cầu AI lặp lại hoặc dịch hướng dẫn nội bộ.",
        "owasp": "LLM07",              # ← sửa: LLM07 (không phải LLM06)
        "mitre": "AML.T0010",
        "severity": "MEDIUM",
        "payloads_count": 7,
        "icon": "📤",
        "category": "exploits",
    },
    "sensitive_disclosure": {
        "name": "Sensitive Information Disclosure",
        "description": "Kiểm thử rò rỉ PII, thông tin xác thực, dữ liệu huấn luyện nhạy cảm.",
        "owasp": "LLM02",              # ← sửa: LLM02 (không phải LLM06)
        "mitre": "AML.T0024",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "🔍",
        "category": "exploits",
    },
    "model_dos": {
        "name": "Unbounded Consumption (DoS)",
        "description": "Kiểm thử tiêu thụ tài nguyên không giới hạn bằng prompt cực dài, tác vụ đệ quy.",
        "owasp": "LLM10",              # ← sửa: LLM10 (LLM04 là Data Poisoning, khác!)
        "mitre": "AML.T0029",
        "severity": "MEDIUM",
        "payloads_count": 4,
        "icon": "💥",
        "category": "exploits",
    },
    "output_handling": {
        "name": "Improper Output Handling",
        "description": "Kiểm tra xem AI có tạo ra output nguy hiểm (XSS, SQL injection, SSRF) khi được yêu cầu.",
        "owasp": "LLM05",
        "mitre": "AML.T0048",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "⚠️",
        "category": "exploits",
    },
    "misinformation": {
        "name": "Misinformation / Hallucination",
        "description": "Kiểm thử khả năng AI tạo ra thông tin sai lệch có độ tin cậy cao, bịa đặt trích dẫn.",
        "owasp": "LLM09",
        "mitre": "AML.T0048.003",
        "severity": "MEDIUM",
        "payloads_count": 6,
        "icon": "🌀",
        "category": "exploits",
    },
    "excessive_agency": {
        "name": "Excessive Agency",
        "description": "Kiểm tra khả năng mô hình tự ý thực thi các hành vi vượt thẩm quyền nguy hiểm (giao dịch, xóa dữ liệu).",
        "owasp": "LLM06",
        "mitre": "AML.T0048.001",
        "severity": "CRITICAL",
        "payloads_count": 6,
        "icon": "🤖",
        "category": "exploits",
    },
    "rag_security": {
        "name": "Vector & Embedding Weaknesses",
        "description": "Kiểm thử khả năng mô hình bị thao túng gián tiếp qua ngữ cảnh RAG nhiễm độc (Indirect Injection / Delimiter Breakout).",
        "owasp": "LLM08",
        "mitre": "AML.T0020",
        "severity": "HIGH",
        "payloads_count": 6,
        "icon": "📚",
        "category": "exploits",
    },
    "multiturn_jailbreak": {
        "name": "Multi-Turn Jailbreak Escalation",
        "description": "Kiểm thử khả năng bẻ khóa an toàn qua chuỗi hội thoại nhiều lượt (Crescendo / PAIR).",
        "owasp": "LLM01",
        "mitre": "AML.T0054",
        "severity": "CRITICAL",
        "payloads_count": 3,
        "icon": "🪜",
        "category": "exploits",
    },
    "model_fingerprint": {
        "name": "Model Architecture Fingerprinting",
        "description": "Nhận diện họ mô hình AI (LLaMA, Mistral, GPT, Claude, Qwen, DeepSeek) và chữ ký bảo vệ.",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🧬",
        "category": "auxiliary",
    },
    "port_scan": {
        "name": "AI Service Port Scanner",
        "description": "Quét các cổng mạng phổ biến của dịch vụ AI/ML (Ollama, MLflow, Ray, Qdrant...).",
        "owasp": "N/A",
        "mitre": "AML.T0008",
        "severity": "INFO",
        "payloads_count": 6,
        "icon": "🔭",
        "category": "auxiliary",
    },
}

SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH": "bold orange1",
    "MEDIUM": "bold yellow",
    "LOW": "bold cyan",
    "INFO": "bold blue",
}


class AIScannerCLI:
    def __init__(self):
        self.current_module = None
        self.target_url = cfg.get("scanner.target_url", "http://localhost:11434")
        self.target_model = cfg.get("scanner.target_model", "llama3")
        self.timeout = cfg.get("scanner.timeout", 60)
        self.api_key = cfg.get("scanner.api_key", "")
        self.risk_scorer = RiskScorer()
        self.current_scan_id = None

    # ──────────────────────────────────────────
    # Command: show modules
    # ──────────────────────────────────────────
    def cmd_show_modules(self):
        table = Table(
            title="📦 Danh sách Attack Modules",
            box=box.ROUNDED, border_style="blue",
            show_header=True, header_style="bold blue",
        )
        table.add_column("#", style="dim", width=3)
        table.add_column("Module ID", style="bold cyan", min_width=20)
        table.add_column("Tên", min_width=26)
        table.add_column("Severity", width=10)
        table.add_column("OWASP", width=8)
        table.add_column("Payloads", width=9, justify="center")
        table.add_column("Mô tả", min_width=35)

        for i, (mid, m) in enumerate(MODULES_METADATA.items(), 1):
            sev_color = SEVERITY_COLORS.get(m["severity"], "white")
            table.add_row(
                str(i),
                f"{m['icon']} {mid}",
                m["name"],
                f"[{sev_color}]{m['severity']}[/{sev_color}]",
                m["owasp"],
                str(m["payloads_count"]),
                m["description"],
            )
        console.print(table)

    # ──────────────────────────────────────────
    # Command: show options
    # ──────────────────────────────────────────
    def cmd_show_options(self):
        table = Table(
            title="⚙️  Cấu hình hiện tại",
            box=box.SIMPLE_HEAD, border_style="dim",
        )
        table.add_column("Tùy chọn", style="bold yellow")
        table.add_column("Giá trị", style="green")
        table.add_column("Mô tả")

        table.add_row("target_url", self.target_url, "URL của LLM API endpoint")
        table.add_row("target_model", self.target_model, "Tên model AI cần kiểm thử")
        table.add_row("timeout", str(self.timeout), "Thời gian chờ phản hồi (giây)")
        table.add_row("api_key", "***" if self.api_key else "(trống)", "API Key (nếu dùng OpenAI)")
        table.add_row("module", self.current_module or "(chưa chọn)", "Module đang chọn")

        console.print(table)

    # ──────────────────────────────────────────
    # Command: info [module]
    # ──────────────────────────────────────────
    def cmd_info(self, args):
        target = args[0] if args else self.current_module
        if not target or target not in MODULES_METADATA:
            console.print("[red]Dùng: info <module_name> hoặc chọn module trước.[/red]")
            return
        m = MODULES_METADATA[target]
        panel_text = Text()
        panel_text.append(f"  {m['icon']} {m['name']}\n\n", style="bold")
        panel_text.append(f"  Module ID  : {target}\n", style="cyan")
        panel_text.append(f"  Mô tả      : {m['description']}\n")
        panel_text.append(f"  OWASP      : {m['owasp']}\n", style="yellow")
        panel_text.append(f"  MITRE      : {m['mitre']}\n", style="yellow")
        sev_color = SEVERITY_COLORS.get(m["severity"], "white")
        panel_text.append(f"  Severity   : [{sev_color}]{m['severity']}[/{sev_color}]\n")
        panel_text.append(f"  Payloads   : {m['payloads_count']}\n")
        panel_text.append(f"  Category   : {m['category']}\n")
        console.print(Panel(panel_text, title="Module Info", border_style="blue"))

    # ──────────────────────────────────────────
    # Command: use <module>
    # ──────────────────────────────────────────
    def cmd_use(self, args):
        if len(args) != 1:
            console.print("[red]Sử dụng: use <module_name>[/red]")
            self.cmd_show_modules()
            return
        module_name = args[0]
        if module_name in MODULES_METADATA:
            self.current_module = module_name
            m = MODULES_METADATA[module_name]
            console.print(f"[green][+] Đã load module:[/green] {m['icon']} [bold]{module_name}[/bold] ({m['name']})")
            console.print(f"[dim]    OWASP: {m['owasp']} | MITRE: {m['mitre']} | Payloads: {m['payloads_count']}[/dim]")
        else:
            console.print(f"[red]Module không tồn tại.[/red]")
            console.print(f"Gõ [bold yellow]show modules[/bold yellow] để xem danh sách.")

    # ──────────────────────────────────────────
    # Command: set
    # ──────────────────────────────────────────
    def cmd_set(self, args):
        if len(args) != 2:
            console.print("[red]Dùng: set <key> <value>[/red]")
            console.print("  Các key: target_url, target_model, timeout, api_key")
            return
        key, val = args[0].lower(), args[1]
        if key == "target_url":
            self.target_url = val
        elif key == "target_model":
            self.target_model = val
        elif key == "timeout":
            try:
                self.timeout = int(val)
            except ValueError:
                console.print("[red]timeout phải là số nguyên.[/red]"); return
        elif key == "api_key":
            self.api_key = val
        else:
            console.print(f"[red]Key không hợp lệ: {key}[/red]"); return
        console.print(f"[green][+] Đã cập nhật[/green] {key} = [bold]{val if key != 'api_key' else '***'}[/bold]")

    # ──────────────────────────────────────────
    # Command: run / run all
    # ──────────────────────────────────────────
    def cmd_run(self, args):
        if args and args[0].lower() == "all":
            self._run_all_modules()
            return

        if not self.current_module:
            console.print("[red]Bạn chưa chọn module. Dùng lệnh 'use <module>'[/red]")
            return
        self._run_module(self.current_module)

    def _run_all_modules(self):
        console.print(Panel(
            "[bold yellow]⚡ Chạy tất cả modules...[/bold yellow]\n"
            f"[dim]Target: {self.target_url} | Model: {self.target_model}[/dim]",
            border_style="yellow"
        ))
        for mod_name in MODULES_METADATA:
            console.print(f"\n[bold blue]{'─'*50}[/bold blue]")
            console.print(f"[bold blue][>>] Module: {MODULES_METADATA[mod_name]['icon']} {mod_name}[/bold blue]")
            self._run_module(mod_name)
        self._show_summary_table()

    def _run_module(self, module_name: str):
        from modules.detectors.pattern_match import PatternDetector
        from modules.detectors.llm_judge import LLMJudge
        m_meta = MODULES_METADATA[module_name]
        console.print(f"\n[bold blue][*] Khởi chạy:[/bold blue] {m_meta['icon']} {module_name} → {self.target_url}")

        try:
            client = SimpleLLMClient(
                api_url=self.target_url,
                model_name=self.target_model,
                timeout=self.timeout,
            )
            if self.api_key:
                client.api_key = self.api_key

            detector = PatternDetector()
            # LLM-as-Judge: dùng cùng client làm judge (có thể đổi thành model khác)
            judge = LLMJudge(judge_client=client)
            self.current_scan_id = start_scan(self.target_url, self.target_model)

            if module_name == "port_scan":
                from modules.auxiliary.scanner.port_scan import PortScanner
                scanner = PortScanner()
                host = self.target_url.split("://")[-1].split(":")[0]
                if host == "localhost":
                    host = "127.0.0.1"
                services = scanner.run(host)
                if services:
                    for port, name in services:
                        risk_score = self.risk_scorer.calculate_score("port_scan", True, 0)
                        severity = self.risk_scorer.score_to_severity(risk_score)
                        console.print(f"[bold red][+] Cổng mở: {port} ({name})[/bold red]")
                        save_finding(self.current_scan_id, self.target_url, "port_scan",
                                     f"Port {port}", f"Service: {name}", severity, risk_score, "N/A", "AML.T0008")
                else:
                    console.print("[dim][-] Không tìm thấy dịch vụ AI nào đang mở.[/dim]")
                complete_scan(self.current_scan_id)
                return

            # Load exploit module
            module = self._load_module(module_name)
            if not module:
                return

            total = m_meta["payloads_count"]

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("{task.completed}/{task.total}"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(f"Scanning {module_name}...", total=total)

                results = module.run(client)

                for res in results:
                    payload = res.get("payload", "")
                    response = res.get("response", "")

                    # ── Guard: Kiểm tra lỗi kết nối trước khi đưa vào detector ──
                    if response.startswith("[-]") or response.startswith("[ERROR]"):
                        if module_name == "model_dos" and ("timeout" in response.lower() or "timed out" in response.lower()):
                            pass  # Timeout trong DoS là dấu hiệu cạn kiệt tài nguyên hợp lệ
                        else:
                            console.print(
                                f"  [bold yellow][ERROR][/bold yellow] {res.get('name','Payload')[:50]} → {response[:70]}"
                            )
                            progress.advance(task)
                            continue

                    # ── Tầng 1: PatternDetector (nhanh, offline) ─────────
                    is_vuln, reason, confidence = detector.analyze(response, payload, module_name)

                    # ── Tầng 2: LLM-as-Judge (khi confidence thấp) ───────
                    judge_verdict = None
                    if confidence == "LOW":
                        judge_verdict = judge.evaluate(payload, response, module_name,
                                                       pattern_result=(is_vuln, reason, confidence))
                        if judge_verdict.get("judge_used"):
                            # Cập nhật kết quả theo judge
                            is_vuln = judge_verdict["is_exploited"]
                            reason = f"[LLM-Judge] {judge_verdict['reasoning']}"
                            confidence = f"JUDGE({judge_verdict['confidence']:.0%})"

                    risk_score = self.risk_scorer.calculate_score(module_name, is_vuln, len(response)) if is_vuln else 0.0
                    severity = self.risk_scorer.score_to_severity(risk_score) if is_vuln else "INFO"
                    sev_color = SEVERITY_COLORS.get(severity, "white")

                    owasp = res.get("owasp", m_meta["owasp"])
                    mitre = res.get("mitre", m_meta["mitre"])

                    if is_vuln:
                        console.print(
                            f"  [bold red][VULN][/bold red] [{sev_color}]{severity}[/{sev_color}] "
                            f"[{m_meta['icon']}] {res.get('name','Payload')[:50]} → {reason}"
                        )
                        console.print(
                            f"         Risk: [bold]{risk_score}/10[/bold] | "
                            f"[yellow]{owasp}[/yellow] | Confidence: {confidence}"
                        )
                        save_finding(self.current_scan_id, self.target_url, module_name,
                                     payload, response, severity, risk_score, owasp, mitre)
                    else:
                        console.print(
                            f"  [bold green][SAFE][/bold green] {res.get('name','Payload')[:50]} → {reason}"
                        )

                    progress.advance(task)


            complete_scan(self.current_scan_id)

        except ConnectionError as e:
            console.print(f"[red]Lỗi kết nối: {e}[/red]")
            console.print(f"[dim]Kiểm tra xem Ollama có đang chạy tại {self.target_url} không.[/dim]")
        except Exception as e:
            console.print(f"[red]Lỗi khi chạy module {module_name}: {e}[/red]")
            import traceback
            console.print(f"[dim]{traceback.format_exc()}[/dim]")

    def _load_module(self, name):
        try:
            if name == "prompt_injection":
                from modules.exploits.prompt_injection import PromptInjection
                return PromptInjection()
            elif name == "jailbreak":
                from modules.exploits.jailbreak import JailbreakDAN
                return JailbreakDAN()
            elif name == "prompt_leak":
                from modules.exploits.prompt_leak import PromptLeak
                return PromptLeak()
            elif name == "model_dos":
                from modules.exploits.model_dos import ModelDoS
                return ModelDoS()
            elif name == "sensitive_disclosure":
                from modules.exploits.sensitive_disclosure import SensitiveDisclosure
                return SensitiveDisclosure()
            elif name == "output_handling":
                from modules.exploits.output_handling import OutputHandling
                return OutputHandling()
            elif name == "misinformation":
                from modules.exploits.misinformation import Misinformation
                return Misinformation()
            elif name == "excessive_agency":
                from modules.exploits.excessive_agency import ExcessiveAgency
                return ExcessiveAgency()
            elif name == "rag_security":
                from modules.exploits.rag_security import RAGSecurity
                return RAGSecurity()
            elif name == "multiturn_jailbreak":
                from modules.exploits.multiturn_jailbreak import MultiTurnJailbreak
                return MultiTurnJailbreak()
            elif name == "model_fingerprint":
                from modules.auxiliary.model_fingerprint import ModelFingerprint
                return ModelFingerprint()
        except ImportError as e:
            console.print(f"[red]Không thể load module {name}: {e}[/red]")
        return None

    # ──────────────────────────────────────────
    # Command: show findings
    # ──────────────────────────────────────────
    def cmd_show_findings(self, args):
        limit = 50
        severity = None
        for i, a in enumerate(args):
            if a == "--limit" and i + 1 < len(args):
                try:
                    limit = int(args[i + 1])
                except ValueError:
                    pass
            elif a in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
                severity = a

        findings = get_findings(severity=severity, limit=limit)
        if not findings:
            console.print("[dim]Chưa có findings nào. Chạy scan để bắt đầu.[/dim]")
            return

        table = Table(
            title=f"🐛 Findings ({len(findings)} kết quả)",
            box=box.ROUNDED, border_style="red",
            show_header=True, header_style="bold",
        )
        table.add_column("#", width=4)
        table.add_column("Module", min_width=16)
        table.add_column("Severity", width=10)
        table.add_column("Score", width=6, justify="center")
        table.add_column("OWASP", width=8)
        table.add_column("Payload", min_width=40)
        table.add_column("Thời gian", width=18)

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            sev_color = SEVERITY_COLORS.get(sev, "white")
            ts = (f.get("timestamp") or "")[:16].replace("T", " ")
            table.add_row(
                str(i),
                f.get("module_name", "-"),
                f"[{sev_color}]{sev}[/{sev_color}]",
                f"[bold]{f.get('risk_score', 0):.1f}[/bold]",
                f.get("owasp_code", "-"),
                (f.get("payload") or "")[:60],
                ts,
            )
        console.print(table)

    # ──────────────────────────────────────────
    # Command: stats
    # ──────────────────────────────────────────
    def _show_summary_table(self):
        stats = get_stats()
        sev = stats.get("by_severity", {})
        by_mod = stats.get("by_module", {})

        console.print(Panel(
            f"  Total: [bold cyan]{stats.get('total_findings', 0)}[/bold cyan] findings  |  "
            f"[bold red]CRITICAL: {sev.get('CRITICAL', 0)}[/bold red]  |  "
            f"[bold orange1]HIGH: {sev.get('HIGH', 0)}[/bold orange1]  |  "
            f"[bold yellow]MEDIUM: {sev.get('MEDIUM', 0)}[/bold yellow]  |  "
            f"[bold cyan]LOW: {sev.get('LOW', 0)}[/bold cyan]  |  "
            f"[bold blue]INFO: {sev.get('INFO', 0)}[/bold blue]",
            title="📊 Tóm tắt kết quả", border_style="green",
        ))

    def cmd_stats(self):
        self._show_summary_table()

    # ──────────────────────────────────────────
    # Command: clear
    # ──────────────────────────────────────────
    def cmd_clear(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        console.print(BANNER)

    # ──────────────────────────────────────────
    # Command: report
    # ──────────────────────────────────────────
    def cmd_report(self, args):
        if not args:
            console.print("Dùng: report generate | report json | report clear")
            return
        sub = args[0].lower()
        if sub == "generate":
            report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.html")
            console.print("[blue][*] Đang tạo báo cáo HTML...[/blue]")
            if generate_html_report(report_path):
                console.print(f"[bold green][+] Đã tạo:[/bold green] {report_path}")
            else:
                console.print("[red]Lỗi khi tạo báo cáo.[/red]")
        elif sub == "json":
            data = export_json_report()
            import json
            out_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "report.json")
            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
            console.print(f"[bold green][+] Đã xuất JSON:[/bold green] {out_path}")
        elif sub == "clear":
            if console.input("[yellow]Xác nhận xóa tất cả findings? (y/N):[/yellow] ").lower() == 'y':
                clear_findings()
                console.print("[green][+] Đã xóa tất cả findings và lịch sử scan.[/green]")

    # ──────────────────────────────────────────
    # Command: help
    # ──────────────────────────────────────────
    def cmd_help(self):
        table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
        table.add_column("Lệnh", style="bold yellow", min_width=32)
        table.add_column("Mô tả")

        cmds = [
            ("show modules", "Hiển thị tất cả attack modules"),
            ("show options", "Hiển thị cấu hình hiện tại"),
            ("show findings [SEVERITY]", "Xem danh sách lỗ hổng đã tìm thấy"),
            ("use <module>", "Chọn module để sử dụng"),
            ("info [module]", "Xem thông tin chi tiết module"),
            ("set <key> <value>", "Cập nhật cấu hình (target_url/model/timeout/api_key)"),
            ("run", "Chạy module đang chọn"),
            ("run all", "Chạy tất cả modules lần lượt"),
            ("stats", "Xem thống kê tổng hợp"),
            ("report generate", "Tạo báo cáo HTML"),
            ("report json", "Xuất báo cáo JSON"),
            ("report clear", "Xóa tất cả findings"),
            ("clear", "Xóa màn hình"),
            ("exit / quit", "Thoát chương trình"),
        ]
        for cmd, desc in cmds:
            table.add_row(cmd, desc)

        console.print(Panel(table, title="📖 Hướng dẫn sử dụng", border_style="blue"))

    # ──────────────────────────────────────────
    # Main loop
    # ──────────────────────────────────────────
    def run(self):
        console.print(BANNER)
        init_db()
        console.print(f"[dim]  Database: scanner.db | Target: {self.target_url}[/dim]")
        console.print(f"[dim]  Gõ [bold]help[/bold] để xem hướng dẫn, [bold]show modules[/bold] để xem danh sách modules.\n[/dim]")

        while True:
            try:
                module_label = f" ({self.current_module})" if self.current_module else ""
                cmd_input = console.input(
                    f"[bold blue]ai-scanner{module_label}[/bold blue] [dim]>[/dim] "
                ).strip().split()

                if not cmd_input:
                    continue

                cmd = cmd_input[0].lower()
                args = cmd_input[1:]

                if cmd in ("exit", "quit"):
                    console.print("[bold red]\nĐang thoát... Goodbye! 👋[/bold red]")
                    break
                elif cmd == "help":
                    self.cmd_help()
                elif cmd == "show":
                    if args and args[0] == "modules":
                        self.cmd_show_modules()
                    elif args and args[0] == "options":
                        self.cmd_show_options()
                    elif args and args[0] == "findings":
                        self.cmd_show_findings(args[1:])
                    else:
                        console.print("[dim]Dùng: show modules | show options | show findings[/dim]")
                elif cmd == "use":
                    self.cmd_use(args)
                elif cmd == "info":
                    self.cmd_info(args)
                elif cmd == "set":
                    self.cmd_set(args)
                elif cmd == "run":
                    self.cmd_run(args)
                elif cmd == "stats":
                    self.cmd_stats()
                elif cmd == "report":
                    self.cmd_report(args)
                elif cmd == "clear":
                    self.cmd_clear()
                else:
                    console.print(f"[red]Lệnh không hợp lệ: '{cmd}'[/red]  Gõ [bold yellow]help[/bold yellow] để xem các lệnh.")

            except KeyboardInterrupt:
                console.print("\n[yellow]Dùng 'exit' để thoát.[/yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red]Lỗi hệ thống: {e}[/red]")


if __name__ == "__main__":
    cli = AIScannerCLI()
    cli.run()