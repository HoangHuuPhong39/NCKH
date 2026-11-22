# -*- coding: utf-8 -*-
"""
tests/unit/test_oss_scanner_advanced.py

Kiểm thử toàn diện 4 nâng cấp của OpenSourceAIScanner (Tab 2 - Hệ thống Mở & Chuỗi cung ứng):
  1. HTTP Fingerprint chặt chẽ (chặn báo giả MLflow trên Port 5000 Flask AI Security Scanner).
  2. Quét toàn bộ model Ollama (bỏ giới hạn [:3]).
  3. ModelScan chuyên sâu: pickletools.genops() + PyTorch ZIP (.pt nén DEFLATE), Modelfile, YAML Anchor.
  4. SCA mở rộng (22 gói CVE, hỗ trợ requirements.txt / pyproject.toml / package.json, sửa đếm packages_checked).
"""

import json
import pickle
import zipfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from modules.auxiliary.scanner.oss_scanner import OpenSourceAIScanner

WHITEBOX_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "whitebox_sast"


class _MaliciousPicklePayload:
    """Chỉ dùng để sinh chuỗi byte Pickle protocol 4 có opcode STACK_GLOBAL (KHÔNG chạy lệnh thật)."""

    def __reduce__(self):
        import os
        return (os.system, ("echo harmless_test",))


class TestOSSScannerUpgrades:
    def setup_method(self):
        self.scanner = OpenSourceAIScanner()

    def test_fingerprint_blocks_flask_port_5000_false_positive(self):
        fake_flask_resp = SimpleNamespace(
            status_code=200,
            text="<html><title>AI Security Scanner - Dashboard</title></html>",
            headers={"Content-Type": "text/html"},
            json=lambda: (_ for _ in ()).throw(ValueError("not json")),
        )
        matched, _ = self.scanner._verify_platform_fingerprint("mlflow", "/version", fake_flask_resp)
        assert matched is False, "Không được nhận nhầm Flask AI Security Scanner (Port 5000) thành MLflow"

        real_mlflow_resp = SimpleNamespace(
            status_code=200,
            text='{"experiments": []}',
            headers={"Content-Type": "application/json"},
            json=lambda: {"experiments": []},
        )
        matched_real, _ = self.scanner._verify_platform_fingerprint("mlflow", "/api/2.0/mlflow/experiments/search", real_mlflow_resp)
        assert matched_real is True

    def test_pickle_protocol4_and_pytorch_zip_checkpoint_scan(self, tmp_path):
        # 1. File .pkl dùng Pickle protocol 4 (STACK_GLOBAL thay vì GLOBAL)
        mal_bytes = pickle.dumps(_MaliciousPicklePayload(), protocol=4)
        pkl_path = tmp_path / "evil_proto4.pkl"
        pkl_path.write_bytes(mal_bytes)

        # 2. File .pt định dạng chuẩn PyTorch nén ZIP DEFLATE chứa archive/data.pkl độc hại
        pt_path = tmp_path / "malicious_weights.pt"
        with zipfile.ZipFile(pt_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("archive/data.pkl", mal_bytes)
            zf.writestr("archive/version", "3\n")

        # 3. File .pkl sạch (chỉ chứa dict thường) -> không được báo giả
        safe_pkl = tmp_path / "clean_weights.pkl"
        safe_pkl.write_bytes(pickle.dumps({"layer1": [0.1, 0.2, 0.3]}, protocol=4))

        res = self.scanner.scan_model_artifacts(str(tmp_path))
        assert res["success"] is True
        rce_files = {f["file"] for f in res["findings"] if f["finding_id"] == "OSS-MODELSCAN-PICKLE-RCE"}
        assert "evil_proto4.pkl" in rce_files, "Phải bắt được Pickle protocol 4 (STACK_GLOBAL)"
        assert "malicious_weights.pt" in rce_files, "Phải giải nén ZIP và bắt được PyTorch .pt nén DEFLATE"
        assert "clean_weights.pkl" not in rce_files, "Không được báo giả trên file Pickle sạch"

    def test_sca_requirements_pyproject_and_package_json(self):
        # 1. requirements.txt với các CVE mới bổ sung
        req = "jinja2==3.1.2\nlitellm==1.20.0\nchromadb==0.4.15\nkeras==2.12.0\npillow==10.0.0\nonnx==1.14.0\n"
        r1 = self.scanner.scan_dependencies(req, source_name="requirements.txt")
        assert r1["packages_scanned"] == 6
        cves1 = {f["finding_id"] for f in r1["findings"]}
        assert {"CVE-2024-34064", "CVE-2024-2952 / CVE-2024-4888", "CVE-2024-28189", "CVE-2024-3660", "CVE-2023-50447", "CVE-2024-27318"} <= cves1

        # 2. pyproject.toml (PEP 621)
        pyproject = '[project]\nname = "demo"\ndependencies = [\n  "langchain==0.0.300",\n  "aiohttp==3.8.5",\n]\n'
        r2 = self.scanner.scan_dependencies(pyproject, source_name="pyproject.toml")
        assert r2["packages_scanned"] == 2
        assert any("CVE-2024-23334" in f["finding_id"] for f in r2["findings"])

        # 3. package.json
        pkg_json = json.dumps({"dependencies": {"langchain": "^0.0.200", "requests": "2.31.0"}})
        r3 = self.scanner.scan_dependencies(pkg_json, source_name="package.json")
        assert r3["packages_scanned"] == 2
        assert len(r3["findings"]) >= 1

    @pytest.mark.skipif(not WHITEBOX_DIR.exists(), reason="Thư mục mẫu kiểm thử hộp trắng không tồn tại")
    def test_model_artifacts_on_whitebox_folder(self):
        res = self.scanner.scan_model_artifacts(str(WHITEBOX_DIR), include_requirements=True)
        assert res["success"] is True
        assert res["packages_scanned"] > 0, "Phải đếm chính xác packages_scanned khi quét requirements.txt"
        fids = {f["finding_id"] for f in res["findings"]}
        # Modelfile đầy đủ (num_ctx/num_predict, secrets, backdoor)
        assert "OSS-MF-AI-SAST-007" in fids
        assert "OSS-MF-AI-SAST-002" in fids
        assert "OSS-MF-AI-SAST-010" in fids
        # agent_config.yaml (YAML Anchor)
        assert "OSS-YAML-AI-SAST-005" in fids
        assert "OSS-YAML-AI-SAST-009" in fids
        assert "OSS-YAML-AI-SAST-004" in fids
        # HuggingFace config.json auto_map
        assert "OSS-HF-AUTOMAP-001" in fids
