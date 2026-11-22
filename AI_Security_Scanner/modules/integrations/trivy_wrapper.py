# -*- coding: utf-8 -*-
"""
modules/integrations/trivy_wrapper.py - Aqua Security Trivy Container & IaC Scanner Integration

Integrates Aqua Security Trivy (https://github.com/aquasecurity/trivy) for scanning
AI infrastructure:
  1. Container images (OS packages & Python ML/AI libraries CVEs)
  2. Filesystem / Repository dependencies & hardcoded secrets
  3. IaC / Container misconfigurations (Dockerfile, docker-compose.yml, Kubernetes YAML)

If the `trivy` binary is not installed on PATH, automatically falls back to a built-in
static Container/IaC security auditor for `Dockerfile` and `docker-compose.yml` so the
platform still detects high-impact container misconfigurations out-of-the-box.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

_SEVERITY_RISK_MAP: Dict[str, float] = {
    "CRITICAL": 9.4,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 3.0,
    "INFO": 1.0,
    "UNKNOWN": 3.0,
}

_SENSITIVE_AI_PORTS = {
    "11434": "Ollama LLM Server",
    "6333": "Qdrant Vector DB",
    "6334": "Qdrant gRPC",
    "8265": "Ray Dashboard",
    "5000": "MLflow / AI Web UI",
    "8000": "ChromaDB / vLLM / Proxy",
}


class TrivyWrapper:
    """
    Standardized wrapper around Aqua Security Trivy CLI with a built-in static
    Dockerfile/docker-compose fallback auditor when the CLI binary is unavailable.
    """

    def __init__(self, trivy_bin: Optional[str] = None, timeout: int = 120) -> None:
        self._explicit_bin = trivy_bin
        self.timeout = int(timeout)
        self._available: Optional[bool] = None
        self._bin_path: Optional[str] = None

    def is_available(self) -> bool:
        """Check whether the `trivy` binary is available on PATH."""
        if self._available is not None:
            return self._available
        candidate = self._explicit_bin or "trivy"
        found = shutil.which(candidate)
        self._bin_path = found
        self._available = found is not None
        return self._available

    def get_install_instructions(self) -> str:
        return (
            "Aqua Security Trivy chưa được cài đặt trên hệ thống.\n"
            "Hướng dẫn cài đặt:\n"
            "  - Windows (winget): winget install AquaSecurity.Trivy\n"
            "  - Windows (choco):  choco install trivy\n"
            "  - macOS (brew):     brew install trivy\n"
            "  - Docker:           docker run aquasec/trivy:latest ...\n"
            "Lưu ý: Khi chưa có CLI, TrivyWrapper tự động chạy chế độ Built-in Static IaC Fallback."
        )

    def get_version(self) -> Optional[str]:
        if not self.is_available() or not self._bin_path:
            return None
        try:
            res = subprocess.run(
                [self._bin_path, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            first_line = (res.stdout or res.stderr or "").strip().splitlines()
            return first_line[0] if first_line else None
        except Exception as exc:
            logger.debug("Trivy version check failed: %s", exc)
            return None

    # ------------------------------------------------------------------
    # Trivy CLI JSON Parsing
    # ------------------------------------------------------------------

    @staticmethod
    def parse_trivy_json(raw_json: Dict[str, Any], target_label: str = "") -> List[Dict[str, Any]]:
        """Normalize Trivy JSON output (Vulnerabilities, Misconfigurations, Secrets) into findings."""
        findings: List[Dict[str, Any]] = []
        results = raw_json.get("Results") or []
        for result in results:
            res_target = result.get("Target") or target_label

            for vuln in result.get("Vulnerabilities") or []:
                sev = str(vuln.get("Severity") or "MEDIUM").upper()
                vuln_id = vuln.get("VulnerabilityID") or "TRIVY-VULN"
                pkg = vuln.get("PkgName") or "unknown"
                inst_ver = vuln.get("InstalledVersion") or ""
                fixed_ver = vuln.get("FixedVersion") or "latest patched version"
                findings.append({
                    "finding_id": vuln_id,
                    "tool": "trivy",
                    "category": "CONTAINER_VULNERABILITY",
                    "target": res_target,
                    "title": vuln.get("Title") or f"{vuln_id} in {pkg} ({inst_ver})",
                    "description": (vuln.get("Description") or "")[:400],
                    "severity": sev,
                    "risk_score": _SEVERITY_RISK_MAP.get(sev, 5.5),
                    "owasp": "LLM03",
                    "mitre": "AML.T0010",
                    "remediation": f"Nâng cấp gói `{pkg}` từ `{inst_ver}` lên `{fixed_ver}`.",
                    "evidence": f"{pkg}=={inst_ver} -> fix: {fixed_ver}",
                    "mode": "trivy_cli",
                })

            for mis in result.get("Misconfigurations") or []:
                if str(mis.get("Status") or "FAIL").upper() != "FAIL":
                    continue
                sev = str(mis.get("Severity") or "MEDIUM").upper()
                mis_id = mis.get("ID") or "TRIVY-MISCONFIG"
                findings.append({
                    "finding_id": mis_id,
                    "tool": "trivy",
                    "category": "IAC_MISCONFIGURATION",
                    "target": res_target,
                    "title": mis.get("Title") or mis_id,
                    "description": (mis.get("Description") or mis.get("Message") or "")[:400],
                    "severity": sev,
                    "risk_score": _SEVERITY_RISK_MAP.get(sev, 5.5),
                    "owasp": "LLM03",
                    "mitre": "AML.T0010",
                    "remediation": mis.get("Resolution") or "Khắc phục cấu hình container/IaC theo chuẩn bảo mật.",
                    "evidence": mis.get("Message") or res_target,
                    "mode": "trivy_cli",
                })

            for sec in result.get("Secrets") or []:
                sev = str(sec.get("Severity") or "CRITICAL").upper()
                rule_id = sec.get("RuleID") or "TRIVY-SECRET"
                findings.append({
                    "finding_id": rule_id,
                    "tool": "trivy",
                    "category": "SECRET_EXPOSURE",
                    "target": res_target,
                    "title": sec.get("Title") or f"Hardcoded secret detected ({rule_id})",
                    "description": f"Phát hiện bí mật/khóa nhạy cảm trong tệp cấu hình tại dòng {sec.get('StartLine', '?')}.",
                    "severity": sev,
                    "risk_score": _SEVERITY_RISK_MAP.get(sev, 9.0),
                    "owasp": "LLM02",
                    "mitre": "AML.T0024",
                    "remediation": "Thu hồi secret ngay lập tức và chuyển sang biến môi trường / Secrets Manager.",
                    "evidence": f"{res_target}:{sec.get('StartLine', '?')} ({sec.get('Category', 'Secret')})",
                    "mode": "trivy_cli",
                })

        return findings

    # ------------------------------------------------------------------
    # Built-in Static Fallback Auditor (Dockerfile & docker-compose.yml)
    # ------------------------------------------------------------------

    def scan_dockerfile_and_compose_static(self, target_path: str) -> Dict[str, Any]:
        """
        Static fallback auditor for Dockerfile & docker-compose*.yml when `trivy`
        binary is not installed. Checks common high-risk AI container misconfigurations.
        """
        from core.path_security import resolve_safe_path

        try:
            base = resolve_safe_path(target_path, must_exist=True)
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {
                "success": False,
                "mode": "builtin_static_fallback",
                "error": str(exc),
                "findings": [],
            }
        files_checked: List[str] = []
        findings: List[Dict[str, Any]] = []

        if base.is_file():
            candidate_files = [base]
        elif base.is_dir():
            candidate_files = []
            for root, dirs, files in os.walk(base):
                dirs[:] = [d for d in dirs if d not in {".git", ".venv", "venv", "node_modules", "__pycache__"}]
                for fname in files:
                    low = fname.lower()
                    if low == "dockerfile" or low.startswith("dockerfile.") or (
                        "docker-compose" in low and low.endswith((".yml", ".yaml"))
                    ):
                        candidate_files.append(Path(root) / fname)
        else:
            return {
                "success": False,
                "mode": "builtin_static_fallback",
                "error": f"Path not found: {target_path}",
                "findings": [],
            }

        secret_re = re.compile(
            r"(?:API_KEY|SECRET|PASSWORD|TOKEN|PRIVATE_KEY)\s*[=:]\s*[\"']?(?!\$\{|\s*$|<)([A-Za-z0-9_\-\.!@#$%^&*]{8,})",
            re.IGNORECASE,
        )

        for fpath in candidate_files:
            try:
                content = fpath.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(fpath)
            files_checked.append(rel)
            low_name = fpath.name.lower()

            if low_name == "dockerfile" or low_name.startswith("dockerfile."):
                lines = content.splitlines()
                has_user = any(re.match(r"^\s*USER\s+(?!root\b|0\b)\S+", ln, re.IGNORECASE) for ln in lines)
                if not has_user:
                    findings.append({
                        "finding_id": "TRIVY-IAC-001",
                        "tool": "trivy_static",
                        "category": "IAC_MISCONFIGURATION",
                        "target": rel,
                        "title": "Container runs as root user (missing non-root USER directive)",
                        "description": "Dockerfile không khai báo người dùng non-root (USER), tăng nguy cơ leo thang đặc quyền nếu container AI bị chiếm quyền.",
                        "severity": "HIGH",
                        "risk_score": 8.0,
                        "owasp": "LLM03",
                        "mitre": "AML.T0010",
                        "remediation": "Thêm `RUN adduser --disabled-password appuser` và `USER appuser` trước lệnh CMD/ENTRYPOINT.",
                        "evidence": f"{rel}: Missing non-root USER instruction",
                        "mode": "builtin_static_fallback",
                    })

                for ln_no, ln in enumerate(lines, 1):
                    if re.match(r"^\s*FROM\s+\S+:latest\b", ln, re.IGNORECASE):
                        findings.append({
                            "finding_id": "TRIVY-IAC-002",
                            "tool": "trivy_static",
                            "category": "IAC_MISCONFIGURATION",
                            "target": f"{rel}:{ln_no}",
                            "title": "Unpinned container base image tag (:latest)",
                            "description": "Sử dụng thẻ `:latest` làm mất tính tái lập và dễ dính rủi ro chuỗi cung ứng khi image gốc bị thay đổi.",
                            "severity": "MEDIUM",
                            "risk_score": 5.5,
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "remediation": "Ghim phiên bản cụ thể kèm SHA256 digest (ví dụ `python:3.11-slim@sha256:...`).",
                            "evidence": ln.strip(),
                            "mode": "builtin_static_fallback",
                        })
                    if re.match(r"^\s*(?:ENV|ARG)\s+", ln, re.IGNORECASE) and secret_re.search(ln):
                        findings.append({
                            "finding_id": "TRIVY-IAC-004",
                            "tool": "trivy_static",
                            "category": "SECRET_EXPOSURE",
                            "target": f"{rel}:{ln_no}",
                            "title": "Hardcoded secret or API key in Dockerfile ENV/ARG",
                            "description": "Phát hiện khóa bí mật hoặc mật khẩu gán cứng trong Dockerfile layer.",
                            "severity": "CRITICAL",
                            "risk_score": 9.4,
                            "owasp": "LLM02",
                            "mitre": "AML.T0024",
                            "remediation": "Không đưa secret vào Dockerfile; truyền qua runtime environment hoặc Docker Secrets.",
                            "evidence": f"Line {ln_no}: [REDACTED_SECRET_LINE]",
                            "mode": "builtin_static_fallback",
                        })

            if "docker-compose" in low_name:
                lines = content.splitlines()
                for ln_no, ln in enumerate(lines, 1):
                    if re.search(r"privileged\s*:\s*true", ln, re.IGNORECASE) or "/var/run/docker.sock" in ln:
                        findings.append({
                            "finding_id": "TRIVY-IAC-003",
                            "tool": "trivy_static",
                            "category": "IAC_MISCONFIGURATION",
                            "target": f"{rel}:{ln_no}",
                            "title": "Privileged container or Docker socket mount detected",
                            "description": "Container chạy chế độ `privileged: true` hoặc mount `/var/run/docker.sock` cho phép thoát container (container escape).",
                            "severity": "CRITICAL",
                            "risk_score": 9.4,
                            "owasp": "LLM03",
                            "mitre": "AML.T0010",
                            "remediation": "Tắt `privileged: true`, bỏ mount docker.sock và áp dụng `cap_drop: [ALL]`.",
                            "evidence": ln.strip(),
                            "mode": "builtin_static_fallback",
                        })
                    if secret_re.search(ln):
                        findings.append({
                            "finding_id": "TRIVY-IAC-004",
                            "tool": "trivy_static",
                            "category": "SECRET_EXPOSURE",
                            "target": f"{rel}:{ln_no}",
                            "title": "Hardcoded secret in docker-compose environment",
                            "description": "Phát hiện API key/mật khẩu gán cứng trong file docker-compose.",
                            "severity": "HIGH",
                            "risk_score": 8.4,
                            "owasp": "LLM02",
                            "mitre": "AML.T0024",
                            "remediation": "Dùng biến `${SECRET_VAR}` từ tệp `.env` (không commit) hoặc Docker Secrets.",
                            "evidence": f"Line {ln_no}: [REDACTED_SECRET_LINE]",
                            "mode": "builtin_static_fallback",
                        })
                    for port_num, svc_name in _SENSITIVE_AI_PORTS.items():
                        # Flag exposed port mapping not bound to 127.0.0.1 (e.g. "11434:11434" or "0.0.0.0:11434:11434")
                        if re.search(rf"[\"']?(?:0\.0\.0\.0:)?{port_num}:{port_num}[\"']?", ln) and "127.0.0.1" not in ln:
                            findings.append({
                                "finding_id": "TRIVY-IAC-005",
                                "tool": "trivy_static",
                                "category": "IAC_MISCONFIGURATION",
                                "target": f"{rel}:{ln_no}",
                                "title": f"AI service port {port_num} ({svc_name}) bound to all interfaces (0.0.0.0)",
                                "description": f"Cổng dịch vụ AI {port_num} ({svc_name}) được mở ra tất cả giao diện mạng thay vì giới hạn `127.0.0.1`.",
                                "severity": "MEDIUM",
                                "risk_score": 6.2,
                                "owasp": "LLM03",
                                "mitre": "AML.T0010",
                                "remediation": f"Ràng buộc cổng về loopback `127.0.0.1:{port_num}:{port_num}` hoặc đặt sau Reverse Proxy có xác thực.",
                                "evidence": ln.strip(),
                                "mode": "builtin_static_fallback",
                            })

        return {
            "success": True,
            "mode": "builtin_static_fallback",
            "trivy_cli_available": False,
            "files_checked": files_checked,
            "total_findings": len(findings),
            "findings": findings,
        }

    # ------------------------------------------------------------------
    # Public Scan Methods
    # ------------------------------------------------------------------

    def _run_trivy_cmd(self, args: List[str], target_label: str) -> Dict[str, Any]:
        if not self.is_available() or not self._bin_path:
            return {
                "success": False,
                "mode": "trivy_cli",
                "error": self.get_install_instructions(),
                "findings": [],
            }
        try:
            proc = subprocess.run(
                [self._bin_path, *args],
                capture_output=True,
                text=True,
                timeout=self.timeout,
                check=False,
            )
            stdout = (proc.stdout or "").strip()
            if not stdout:
                return {
                    "success": proc.returncode == 0,
                    "mode": "trivy_cli",
                    "trivy_cli_available": True,
                    "total_findings": 0,
                    "findings": [],
                    "stderr": (proc.stderr or "")[:400],
                }
            parsed = json.loads(stdout)
            findings = self.parse_trivy_json(parsed, target_label=target_label)
            return {
                "success": True,
                "mode": "trivy_cli",
                "trivy_cli_available": True,
                "total_findings": len(findings),
                "findings": findings,
            }
        except subprocess.TimeoutExpired:
            return {"success": False, "mode": "trivy_cli", "error": "Trivy scan timed out.", "findings": []}
        except Exception as exc:
            return {"success": False, "mode": "trivy_cli", "error": str(exc), "findings": []}

    def scan_filesystem(self, target_path: str, allow_static_fallback: bool = True) -> Dict[str, Any]:
        """Scan a local AI repository/directory for CVEs, misconfigurations, and secrets."""
        from core.path_security import resolve_safe_path

        try:
            safe_path = str(resolve_safe_path(target_path, must_exist=True))
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {
                "success": False,
                "mode": "trivy_cli" if self.is_available() else "static_fallback",
                "error": str(exc),
                "findings": [],
            }

        if self.is_available():
            return self._run_trivy_cmd(
                ["fs", "--format", "json", "--scanners", "vuln,misconfig,secret", "--quiet", "--", safe_path],
                target_label=safe_path,
            )
        if allow_static_fallback:
            return self.scan_dockerfile_and_compose_static(safe_path)
        return {
            "success": False,
            "mode": "trivy_cli",
            "trivy_cli_available": False,
            "error": self.get_install_instructions(),
            "findings": [],
        }

    def scan_config(self, target_path: str, allow_static_fallback: bool = True) -> Dict[str, Any]:
        """Scan IaC files (Dockerfile, docker-compose, K8s) for misconfigurations."""
        from core.path_security import resolve_safe_path

        try:
            safe_path = str(resolve_safe_path(target_path, must_exist=True))
        except (ValueError, PermissionError, FileNotFoundError) as exc:
            return {
                "success": False,
                "mode": "trivy_cli" if self.is_available() else "static_fallback",
                "error": str(exc),
                "findings": [],
            }

        if self.is_available():
            return self._run_trivy_cmd(
                ["config", "--format", "json", "--quiet", "--", safe_path],
                target_label=safe_path,
            )
        if allow_static_fallback:
            return self.scan_dockerfile_and_compose_static(safe_path)
        return {
            "success": False,
            "mode": "trivy_cli",
            "trivy_cli_available": False,
            "error": self.get_install_instructions(),
            "findings": [],
        }

    def scan_image(self, image_name: str) -> Dict[str, Any]:
        """Scan a container image (e.g. `ollama/ollama:latest`) using Trivy CLI."""
        from core.path_security import validate_container_image_ref

        try:
            clean_image = validate_container_image_ref(image_name)
        except ValueError as exc:
            return {
                "success": False,
                "mode": "trivy_cli",
                "error": str(exc),
                "findings": [],
            }

        return self._run_trivy_cmd(
            ["image", "--format", "json", "--quiet", "--", clean_image],
            target_label=clean_image,
        )
