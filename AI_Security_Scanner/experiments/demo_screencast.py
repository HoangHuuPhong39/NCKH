# -*- coding: utf-8 -*-
"""
experiments/demo_screencast.py - Automated Demo Runner for Thesis Screencast Recording

Simulates a complete scan cycle with human-paced output, ideal for recording
a 2-3 minute presentation demo video with OBS Studio or ShareX.
"""

import sys
import time
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn

console = Console()


def run_screencast_demo():
    console.clear()
    console.print(Panel.fit(
        "[bold cyan]AI SECURITY SCANNER[/bold cyan] [bold white]· LIVE DEMO SCREENCAST RUNNER[/bold white]\n"
        "[dim]NCKH Thesis Defense Demonstration · OWASP LLM Top 10 (2025)[/dim]",
        border_style="cyan"
    ))
    time.sleep(1.5)

    console.print("\n[bold yellow]⚡ [1/4] Kiểm tra kết nối tới Máy chủ Target Inference (Ollama)...[/bold yellow]")
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}")) as progress:
        task = progress.add_task("[cyan]Connecting to http://localhost:11434...[/cyan]", total=None)
        time.sleep(1.2)
        progress.update(task, description="[green]✓ Connected successfully to target LLM (Model: llama3)[/green]")
        time.sleep(0.8)

    console.print("\n[bold yellow]🎯 [2/4] Bắt đầu quét Module: Jailbreak / Safety Bypass (LLM01)...[/bold yellow]")
    payloads = [
        ("DAN Classic Roleplay", "CRITICAL", 9.4, "Bỏ qua chỉ thị an toàn qua nhập vai DAN"),
        ("AIM Dual Persona Bypass", "CRITICAL", 8.8, "Phản hồi hai nhân cách đối lập"),
        ("Hypothetical Fictional Scenario", "HIGH", 7.5, "Kịch bản tiểu thuyết viễn tưởng"),
        ("STAN Ethical Inversion", "CRITICAL", 9.1, "Đảo ngược quy tắc đạo đức"),
        ("Developer Debug Override", "HIGH", 7.8, "Giả mạo chế độ kiểm thử kỹ thuật"),
        ("Academic Research Persona", "SAFE", 0.0, "Mô hình từ chối hợp lệ (An toàn)"),
    ]

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
    ) as progress:
        scan_task = progress.add_task("[cyan]Scanning payloads...[/cyan]", total=len(payloads))
        for name, sev, score, desc in payloads:
            time.sleep(1.0)
            status_icon = "🔴 [bold red]VULN[/bold red]" if sev != "SAFE" else "🟢 [bold green]SAFE[/bold green]"
            console.print(f"  {status_icon} [bold]{name}[/bold] → {desc} [dim]({sev} - Risk: {score}/10)[/dim]")
            progress.advance(scan_task)

    console.print("\n[bold yellow]📊 [3/4] Bảng Tổng Hợp Kết Quả Phát Hiện (Findings Summary):[/bold yellow]")
    table = Table(title="Danh Sách Lỗ Hổng Phát Hiện", border_style="blue")
    table.add_column("#", style="dim", width=4)
    table.add_column("Module", style="bold")
    table.add_column("Kỹ Thuật", style="cyan")
    table.add_column("Severity", justify="center")
    table.add_column("Risk Score", justify="center")
    table.add_column("OWASP", justify="center")

    for i, (name, sev, score, _) in enumerate(payloads, 1):
        sev_style = "bold red" if sev == "CRITICAL" else ("bold yellow" if sev == "HIGH" else "bold green")
        table.add_row(str(i), "Jailbreak", name, f"[{sev_style}]{sev}[/{sev_style}]", f"{score:.1f}", "LLM01")

    console.print(table)
    time.sleep(1.5)

    console.print("\n[bold yellow]📄 [4/4] Khởi tạo Báo Cáo Kiểm Thử (HTML & JSON)...[/bold yellow]")
    time.sleep(1.0)
    console.print("[green]✓ Đã lưu báo cáo tại: reports/report_20260925.html[/green]")
    console.print("[green]✓ Đã đồng bộ với SQLite Database (scanner.db) và Web Dashboard tại http://localhost:5000[/green]")
    console.print("\n[bold cyan]🎉 HOÀN TẤT PHIÊN TRÌNH DIỄN THỰC NGHIỆM.[/bold cyan]\n")


if __name__ == "__main__":
    run_screencast_demo()
