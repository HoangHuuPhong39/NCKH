"""
AI Security Scanner - Enhanced CLI (Metasploit-style)
Giao diện dòng lệnh nâng cao cho bộ công cụ kiểm thử an toàn AI.
"""

import argparse
import json
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
from modules.registry import get_modules_metadata

console = Console(legacy_windows=False)

BANNER = """
[bold red]  ██████╗ ██████╗ ██████╗ ██████╗     [/bold red][bold blue]     █████╗ ██╗    [/bold blue]
[bold red]  ██╔══██╗██╔══██╗╚════██╗╚════██╗    [/bold red][bold blue]    ██╔══██╗██║    [/bold blue]
[bold red]  ██║  ██║██║  ██║ █████╔╝ █████╔╝    [/bold red][bold blue]    ███████║██║    [/bold blue]
[bold red]  ██║  ██║██║  ██║ ╚═══██╗ ╚═══██╗    [/bold red][bold blue]    ██╔══██║██║    [/bold blue]
[bold red]  ██████╔╝██████╔╝██████╔╝██████╔╝    [/bold red][bold blue]    ██║  ██║██║    [/bold blue]
[bold red]  ╚═════╝ ╚═════╝ ╚═════╝ ╚═════╝     [/bold red][bold blue]    ╚═╝  ╚═╝╚═╝   [/bold blue]

[bold yellow]       AI Security Scanner — Static AST Taint & Hybrid Red-Teaming Suite[/bold yellow]
[dim]       OWASP LLM Top 10 (2025) · MITRE ATLAS · Research Edition v2.1[/dim]
"""

MODULES_METADATA = get_modules_metadata(dynamic_counts=True)

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
            judge_model_cfg = cfg.get("scanner.judge_model", "")
            if judge_model_cfg and judge_model_cfg != self.target_model:
                judge = LLMJudge.create_with_separate_model(
                    api_url=self.target_url,
                    judge_model=judge_model_cfg,
                    timeout=self.timeout,
                    api_key=self.api_key or "",
                )
            else:
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

            actual_payloads = getattr(module, "payloads", None)
            total = len(actual_payloads) if isinstance(actual_payloads, list) and actual_payloads else m_meta["payloads_count"]

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
        from modules.registry import load_module
        mod = load_module(name)
        if mod is None:
            console.print(f"[red]Không thể load module {name}[/red]")
        return mod

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


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ai-security-scanner",
        description=(
            "AI Security Scanner — Static AST Taint-Tracking SAST, OSS Supply-Chain Audit, "
            "and Interactive OWASP LLM / MITRE ATLAS Red-Teaming CLI. "
            "Run without flags to launch the interactive console."
        ),
    )
    parser.add_argument(
        "--sast",
        metavar="PATH",
        help="Run static AST taint-tracking & multi-format SAST scan on a file or directory.",
    )
    parser.add_argument(
        "--hybrid",
        action="store_true",
        help="Enable optional Ollama LLM semantic auditing alongside AST SAST (used with --sast).",
    )
    parser.add_argument(
        "--no-external-tools",
        action="store_true",
        help="Disable external Bandit/Semgrep subprocess probes during --sast scans.",
    )
    parser.add_argument(
        "--oss",
        metavar="PATH",
        help="Run Open-Source AI Supply-Chain (SCA & model checkpoint) scan on a directory.",
    )
    parser.add_argument(
        "--list-modules",
        action="store_true",
        help="List all registered exploit and auxiliary scanner modules and exit.",
    )
    parser.add_argument(
        "--rbst",
        metavar="PROFILE",
        help="Run RBST-AI Risk-Based Security Testing on a built-in case study (cs1..cs4) or custom YAML/JSON system graph.",
    )
    parser.add_argument(
        "--rbst-strategy",
        default="rbst_ai",
        help="RBST-AI orchestration policy: rbst_ai, B0_random, B1_owasp, B2_static_rbst, B3_default_tool, B4_qualitative_rbt, A1_no_M, A2_no_bayes, A3_greedy.",
    )
    parser.add_argument(
        "--rbst-budget",
        type=float,
        default=40.0,
        help="Testing budget B for --rbst (default: 40.0).",
    )
    parser.add_argument(
        "--rbst-tau",
        type=float,
        default=0.0,
        help="Acceptable residual risk threshold tau for --rbst stopping criterion (0 disables early stop).",
    )
    parser.add_argument(
        "--rbst-seed",
        type=int,
        default=42,
        help="Random seed for reproducible --rbst execution (default: 42).",
    )
    parser.add_argument(
        "--rbst-live",
        action="store_true",
        help="Execute --rbst test cases against live LLM endpoint instead of calibrated benchmark oracle.",
    )
    parser.add_argument(
        "--rbst-model",
        metavar="MODEL",
        default=None,
        help="Target LLM model for --rbst-live (e.g. qwen2.5:latest or ollama/qwen2.5:latest).",
    )
    parser.add_argument(
        "--rbst-output",
        metavar="PATH",
        help="Optional output path to save full RBST-AI JSON compliance report.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="as_json",
        help="Print scan results as formatted JSON (used with --sast, --oss, or --rbst).",
    )
    return parser


def _run_cli_sast(target: str, use_hybrid: bool, include_external: bool, as_json: bool) -> int:
    from modules.auxiliary.scanner.code_scanner import AICodeScanner

    scanner = AICodeScanner()
    result = scanner.scan_directory(
        target,
        include_external_tools=include_external,
        use_hybrid_llm=use_hybrid,
    )
    if as_json:
        print(json.dumps(result, ensure_ascii=False, indent=2))
        return 0 if result.get("success") else 1

    if not result.get("success"):
        console.print(f"[bold red]SAST scan failed:[/bold red] {result.get('error', 'Unknown error')}")
        return 1

    findings = result.get("findings", [])
    summary = result.get("summary", {})
    table = Table(
        title=f"AI SAST Findings ({len(findings)} total) — {target}",
        box=box.ROUNDED,
        show_lines=False,
    )
    table.add_column("Rule", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("OWASP", style="magenta", no_wrap=True)
    table.add_column("Location", style="yellow")
    table.add_column("Title")
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        sev_style = SEVERITY_COLORS.get(sev, "white")
        loc = f"{f.get('file', '<snippet>')}:{f.get('line', 0)}"
        table.add_row(
            str(f.get("rule_id", "N/A")),
            f"[{sev_style}]{sev}[/{sev_style}]",
            str(f.get("owasp", "N/A")),
            loc,
            str(f.get("title", "")),
        )
    console.print(table)
    by_sev = summary.get("by_severity", {})
    console.print(
        f"[dim]Files scanned: {summary.get('files_scanned', '?')} ({summary.get('elapsed_ms', 0)} ms) | "
        f"Critical: {by_sev.get('CRITICAL', 0)} | High: {by_sev.get('HIGH', 0)} | "
        f"Medium: {by_sev.get('MEDIUM', 0)} | Low: {by_sev.get('LOW', 0)}[/dim]"
    )
    return 0


def _run_cli_oss(target: str, as_json: bool) -> int:
    from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner

    scanner = OpenSourceAIScanner()
    res = scanner.scan_model_artifacts(target_dir=target, include_requirements=True)
    findings = list(res.get("findings", []))
    payload = {
        "success": bool(res.get("success", True)),
        "target": target,
        "total_findings": len(findings),
        "error": res.get("error"),
        "findings": findings,
    }
    if as_json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
        return 0 if payload["success"] else 1

    if not payload["success"]:
        console.print(f"[bold red]OSS scan failed:[/bold red] {payload.get('error', 'Unknown error')}")
        return 1

    table = Table(title=f"OSS AI Supply-Chain Audit ({len(findings)} findings) — {target}", box=box.ROUNDED)
    table.add_column("ID", style="bold cyan", no_wrap=True)
    table.add_column("Severity", no_wrap=True)
    table.add_column("OWASP", style="magenta", no_wrap=True)
    table.add_column("Title")
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        sev_style = SEVERITY_COLORS.get(sev, "white")
        table.add_row(
            str(f.get("rule_id") or f.get("cve") or "OSS"),
            f"[{sev_style}]{sev}[/{sev_style}]",
            str(f.get("owasp", "LLM03")),
            str(f.get("title") or f.get("description", ""))[:90],
        )
    console.print(table)
    return 0


def _run_cli_rbst(
    profile: str,
    strategy: str,
    budget_B: float,
    tau: float,
    seed: int,
    live: bool,
    rbst_model: str | None,
    output_path: str | None,
    as_json: bool,
) -> int:
    from core.rbst_adapter import (
        EmpiricalCalibrationExecutor,
        LiveScannerExecutor,
        build_pipeline_for_case_study,
        default_ground_truth_for_case_study,
    )
    from core.rbst_engine import RBSTOrchestrator
    from core.rbst_metrics import RBSTComplianceReporter, evaluate_run

    try:
        graph, pairs, cases = build_pipeline_for_case_study(profile)
    except Exception as exc:
        console.print(f"[bold red]Failed to load RBST-AI profile '{profile}':[/bold red] {exc}")
        return 1

    gt_vulns = None
    actual_sev = None
    if live:
        raw_model = (rbst_model or cfg.get("scanner.target_model", "qwen2.5:latest")).strip()
        provider = None
        if "/" in raw_model and raw_model.split("/", 1)[0].lower() in ("ollama", "openai"):
            provider, model_name = raw_model.split("/", 1)
            provider = provider.lower()
        else:
            model_name = raw_model

        api_url = cfg.get("scanner.target_url", "http://localhost:11434")
        client = SimpleLLMClient(
            api_url=api_url,
            model_name=model_name,
            timeout=cfg.get("scanner.timeout", 90),
            api_key=cfg.get("scanner.api_key", ""),
            provider=provider,
        )
        base_executor = LiveScannerExecutor(llm_client=client, seed=seed)

        if not as_json:
            console.print(
                Panel(
                    f"[bold yellow]⚡ RBST-AI LIVE CLOSED-LOOP EXECUTION (Algorithm 1)[/bold yellow]\n"
                    f"Hồ sơ hệ thống: [cyan]{graph.name}[/cyan] ({len(pairs)} cặp rủi ro) | "
                    f"Chiến lược: [green]{strategy}[/green] | Ngân sách B = [bold]{budget_B}[/bold]\n"
                    f"Endpoint LIVE: [cyan]{api_url}[/cyan] | Mô hình đích: [bold green]{client.resolve_model_name()}[/bold green]",
                    border_style="blue",
                )
            )

            def _verbose_live_executor(tc, pair_state, step_idx):
                console.print(
                    f"  [bold cyan][Bước {step_idx}][/bold cyan] Chọn cặp [yellow]{pair_state.pair_id}[/yellow] "
                    f"(M={pair_state.M:.2f}, K={tc.cost:.2f}) → Đang gửi LIVE tới [green]{client.model_name}[/green]..."
                )
                out = base_executor(tc, pair_state, step_idx)
                verdict_str = (
                    "[bold red]THỦNG (y=1)[/bold red]"
                    if out.success
                    else "[bold green]AN TOÀN (y=0)[/bold green]"
                )
                elapsed_s = out.metadata.get("elapsed_sec", 0.0)
                snippet = repr((out.response or "")[:95])
                console.print(
                    f"           ↳ {verdict_str} ({elapsed_s:.1f}s, oracle={out.oracle_method}) | Phản hồi: {snippet}"
                )
                return out

            executor = _verbose_live_executor
        else:
            executor = base_executor
    else:
        cs_key = str(graph.metadata.get("case_study", profile)).lower()
        true_asr, gt_vulns, actual_sev = default_ground_truth_for_case_study(cs_key, pairs)
        executor = EmpiricalCalibrationExecutor(true_asr_by_pair=true_asr, seed=seed)

    orchestrator = RBSTOrchestrator(
        pairs=pairs,
        test_cases=cases,
        system_name=graph.name,
    )
    run_res = orchestrator.run(
        executor=executor,
        budget_B=budget_B,
        threshold_tau=tau,
        strategy=strategy,
        seed=seed,
    )
    metrics = evaluate_run(
        run_res,
        n_min=2,
        ground_truth_vulns=gt_vulns,
        actual_severity_by_pair=actual_sev,
    )
    reporter = RBSTComplianceReporter()
    report = reporter.generate_report(run_res, metrics=metrics, system_version=graph.version)

    if output_path:
        saved = reporter.export_json(report, output_path)
        if not as_json:
            console.print(f"[green]Saved RBST-AI report to:[/green] {saved}")

    if as_json:
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0

    table = Table(
        title=f"RBST-AI Risk-Based Security Testing — {graph.name} ({strategy})",
        box=box.ROUNDED,
    )
    table.add_column("Cặp (t, c)", style="bold cyan")
    table.add_column("OWASP", style="magenta", no_wrap=True)
    table.add_column("M", justify="right")
    table.add_column("n / s", justify="center")
    table.add_column("θ_tb", justify="right")
    table.add_column("R", justify="right")
    table.add_column("R_res", justify="right", style="bold yellow")

    for st in report["pair_risk_summary"]:
        table.add_row(
            st["pair_id"],
            st["owasp_code"],
            f"{st['M']:.2f}",
            f"{st['n']} / {st['s']}",
            f"{st['theta_tb']:.3f}",
            f"{st['risk_R']:.2f}",
            f"{st['residual_risk_R_res']:.2f}",
        )
    console.print(table)
    console.print(
        f"[bold green]APFD_R:[/bold green] {metrics['APFD_R']:.4f} | "
        f"[bold green]RC:[/bold green] {metrics['RC']:.4f} | "
        f"[bold green]CF:[/bold green] {metrics['CF']} | "
        f"[bold green]Steps:[/bold green] {run_res.total_steps} | "
        f"[bold green]Cost:[/bold green] {run_res.total_cost:.2f}/{budget_B:.2f} | "
        f"[bold green]Stopped:[/bold green] {run_res.stopped_reason}"
    )
    return 0


def main(argv=None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    if args.list_modules:
        cli = AIScannerCLI()
        cli.cmd_show_modules()
        return 0
    if args.sast:
        return _run_cli_sast(
            target=args.sast,
            use_hybrid=args.hybrid,
            include_external=not args.no_external_tools,
            as_json=args.as_json,
        )
    if args.oss:
        return _run_cli_oss(target=args.oss, as_json=args.as_json)
    if args.rbst:
        return _run_cli_rbst(
            profile=args.rbst,
            strategy=args.rbst_strategy,
            budget_B=args.rbst_budget,
            tau=args.rbst_tau,
            seed=args.rbst_seed,
            live=args.rbst_live,
            rbst_model=args.rbst_model,
            output_path=args.rbst_output,
            as_json=args.as_json,
        )

    cli = AIScannerCLI()
    cli.run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
