# -*- coding: utf-8 -*-
"""
tests/integration/test_web_api.py - Integration tests for Flask Web REST API
"""

import json
import pytest
from core.db import save_finding, start_scan, complete_scan


def test_api_modules_returns_full_metadata(client):
    res = client.get("/api/modules")
    assert res.status_code == 200
    data = res.get_json()
    assert "modules" in data
    modules = data["modules"]
    assert "prompt_injection" in modules
    assert "jailbreak" in modules
    assert "rag_security" in modules
    assert "excessive_agency" in modules
    assert "output_handling" in modules
    assert "misinformation" in modules
    assert len(modules) >= 9


def test_api_health_endpoint(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.get_json()
    assert data["status"] in ("healthy", "degraded")
    assert "database" in data
    assert "scanner_running" in data


def test_api_metrics_endpoint(client):
    res = client.get("/api/metrics")
    assert res.status_code == 200
    data = res.get_json()
    assert "total_scans" in data
    assert "total_findings" in data


def test_security_headers_present(client):
    res = client.get("/api/modules")
    assert res.headers.get("X-Content-Type-Options") == "nosniff"
    assert res.headers.get("X-Frame-Options") == "SAMEORIGIN"
    assert "1; mode=block" in res.headers.get("X-XSS-Protection", "")


def test_api_auth_login_and_token(client):
    # Invalid login
    res = client.post("/api/auth/login", json={"username": "wrong", "password": "bad"})
    assert res.status_code == 401

    # Valid login with runtime-configured admin API key (never hardcoded placeholder)
    from core.config import cfg
    active_admin_key = cfg.get("web.admin_api_key")
    assert active_admin_key and active_admin_key != "ai-scanner-admin-secret-token"
    res = client.post("/api/auth/login", json={"api_key": active_admin_key})
    assert res.status_code == 200
    data = res.get_json()
    assert data.get("success") is True
    assert "token" in data
    token = data["token"]
    assert len(token.split(".")) == 3


def test_api_validation_invalid_url_scheme(client):
    res = client.post("/api/scan/run", json={
        "target_url": "ftp://malicious-server.com",
        "target_model": "llama3",
        "module": "jailbreak"
    })
    assert res.status_code == 400
    data = res.get_json()
    assert "Validation Error" in data.get("error", "")


def test_api_validation_unknown_module(client):
    res = client.post("/api/scan/run", json={
        "target_url": "http://localhost:11434",
        "target_model": "llama3",
        "module": "non_existent_exploit"
    })
    assert res.status_code == 400


def test_api_findings_and_scans_workflow(client):
    # 1. Create a scan and finding in DB
    scan_id = start_scan("http://localhost:11434", "llama3")
    save_finding(
        scan_id=scan_id,
        target_url="http://localhost:11434",
        module_name="jailbreak",
        payload="DAN test",
        response="DAN response",
        severity="CRITICAL",
        risk_score=9.2,
        owasp="LLM01",
        mitre="AML.T0054",
    )
    complete_scan(scan_id)

    # 2. Query /api/findings
    res = client.get("/api/findings")
    assert res.status_code == 200
    data = res.get_json()
    assert data["count"] >= 1
    assert data["findings"][0]["severity"] == "CRITICAL"
    assert "dates" in data

    # 3. Query /api/scans
    res_scans = client.get("/api/scans")
    assert res_scans.status_code == 200
    scans_data = res_scans.get_json()
    assert scans_data["count"] >= 1
    assert "dates" in scans_data


def test_swagger_and_openapi_endpoints(client):
    res_docs = client.get("/docs")
    assert res_docs.status_code == 200
    docs_html = res_docs.get_data(as_text=True)
    assert "swagger-ui-bundle.js" in docs_html
    assert "swagger_init.js" in docs_html

    res_swagger = client.get("/swagger")
    assert res_swagger.status_code == 200

    res_spec = client.get("/api/openapi.json")
    assert res_spec.status_code == 200
    spec = res_spec.get_json()
    assert spec["openapi"].startswith("3.")
    assert "paths" in spec
    assert "/api/scan/run" in spec["paths"]


def test_prometheus_metrics_endpoint(client):
    res = client.get("/metrics")
    assert res.status_code == 200
    assert "text/plain" in res.headers.get("Content-Type", "")
    content = res.get_data(as_text=True)
    assert "ai_scanner_up 1" in content
    assert "ai_scanner_uptime_seconds" in content
    assert "ai_scanner_findings_total" in content


def test_api_module_payloads_endpoint(client):
    res = client.get("/api/modules/prompt_injection/payloads")
    assert res.status_code == 200
    data = res.get_json()
    assert data["module"] == "prompt_injection"
    assert len(data["payloads"]) >= 6

    res_multi = client.get("/api/modules/multiturn_jailbreak/payloads")
    assert res_multi.status_code == 200
    data_multi = res_multi.get_json()
    assert len(data_multi["payloads"]) >= 3
    assert "turns" in data_multi["payloads"][0]

    res_404 = client.get("/api/modules/non_existent_module/payloads")
    assert res_404.status_code == 404


def test_api_report_generate_and_json_with_filters(client):
    # Test POST /api/report/generate with filters
    res_gen = client.post("/api/report/generate", json={"severity": "CRITICAL", "module": "jailbreak"})
    assert res_gen.status_code == 200
    assert res_gen.get_json()["success"] is True

    # Test GET /api/report/json with query filters
    res_json = client.get("/api/report/json?severity=CRITICAL&module=jailbreak")
    assert res_json.status_code == 200
    data = res_json.get_json()
    assert "findings" in data
    assert data["filter"]["severity"] == "CRITICAL"
    assert data["filter"]["module"] == "jailbreak"


def test_api_logs_endpoint(client):
    res = client.get("/api/logs?limit=10")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "logs" in data
    assert isinstance(data["logs"], list)


def test_api_incidents_endpoint(client):
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.get_json()
    assert data["success"] is True
    assert "incidents" in data
    assert "count" in data


def test_api_connection_test_model_validation(client):
    """Kiểm tra /api/connection/test xác thực model tồn tại trên Ollama và từ chối model không cài đặt."""
    from unittest.mock import patch, MagicMock

    # Giả lập Ollama trả về danh sách model: llama3:latest, qwen2.5:latest
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "models": [{"name": "llama3:latest"}, {"name": "qwen2.5:latest"}]
    }

    with patch("requests.Session.get", return_value=mock_resp):
        # 1. Model hợp lệ (cần auto-map)
        res1 = client.post("/api/connection/test", json={"url": "http://localhost:11434", "model": "llama3"})
        assert res1.status_code == 200
        d1 = res1.get_json()
        assert d1["success"] is True
        assert d1["resolved_model"] == "llama3:latest"

        # 2. Model không tồn tại trong danh sách
        res2 = client.post("/api/connection/test", json={"url": "http://localhost:11434", "model": "unknown_ai_model"})
        assert res2.status_code == 200
        d2 = res2.get_json()
        assert d2["success"] is False
        assert "chưa được cài đặt" in d2["message"]



def test_api_code_and_oss_scanner_endpoints(client):
    """Kiểm tra các API endpoint cho Quét Mã Nguồn (SAST) và Hệ Thống AI Mã Nguồn Mở."""
    # 1. Sample SAST code
    res_sample = client.get("/api/code-scan/sample")
    assert res_sample.status_code == 200
    d_sample = res_sample.get_json()
    assert d_sample["success"] is True
    assert "AI-SAST-001" in [r["rule_id"] for r in d_sample["rules"]]
    assert len(d_sample["sample_code"]) > 100

    # 2. Run SAST Code Scan on sample code and sample directory
    res_sast = client.post("/api/code-scan/run", json={
        "code": d_sample["sample_code"],
        "target_path": d_sample["sample_dir"],
        "use_bandit": False,
        "save_to_db": True,
    })
    assert res_sast.status_code == 200
    d_sast = res_sast.get_json()
    assert d_sast["success"] is True
    assert d_sast["summary"]["total_findings"] >= 8
    assert d_sast["summary"]["by_severity"]["CRITICAL"] >= 2

    # 3. Sample OSS config
    res_oss_sample = client.get("/api/oss-scan/sample")
    assert res_oss_sample.status_code == 200
    d_oss_sample = res_oss_sample.get_json()
    assert d_oss_sample["success"] is True
    assert len(d_oss_sample["platforms"]) >= 8

    # 4. Run OSS AI Scan (ModelScan + Dependency CVE Scan on sample directory)
    res_oss = client.post("/api/oss-scan/run", json={
        "mode": "full",
        "target_url": "http://127.0.0.1:59999",
        "project_dir": d_oss_sample["sample_dir"],
        "requirements_text": d_oss_sample["sample_requirements"],
        "save_to_db": True,
    })
    assert res_oss.status_code == 200
    d_oss = res_oss.get_json()
    assert d_oss["success"] is True
    assert d_oss["summary"]["total_findings"] >= 5
    assert d_oss["summary"]["packages_checked"] >= 4
    assert d_oss["summary"]["artifacts_checked"] >= 2
