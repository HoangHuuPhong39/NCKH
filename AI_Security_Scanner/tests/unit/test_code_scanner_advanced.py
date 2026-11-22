# -*- coding: utf-8 -*-
"""
tests/unit/test_code_scanner_advanced.py

Kiểm thử toàn diện 5 tầng phân tích Python AST, Cross-File Taint Analysis,
các bộ phân tích đa định dạng (YAML, Modelfile, JS/TS) và kiểm soát False Positive.
"""

from pathlib import Path
import pytest

from modules.auxiliary.scanner.code_scanner import AICodeScanner

WHITEBOX_DIR = Path(__file__).resolve().parent.parent / "fixtures" / "whitebox_sast"

REQUIRED_FINDING_KEYS = {
    "rule_id",
    "title",
    "severity",
    "risk_score",
    "owasp",
    "mitre",
    "cwe",
    "file",
    "line",
    "code_line",
    "context_snippet",
    "description",
    "remediation",
    "fix_example",
    "engine",
}


def _assert_valid_schema(findings):
    for f in findings:
        missing = REQUIRED_FINDING_KEYS - set(f.keys())
        assert not missing, f"Finding thiếu trường schema: {missing}"


@pytest.mark.skipif(not WHITEBOX_DIR.exists(), reason="Thư mục mẫu kiểm thử hộp trắng không tồn tại")
class TestWhiteboxSampleSuite:
    def setup_method(self):
        self.scanner = AICodeScanner()

    def test_amateur_chatbot_baseline_vulns(self):
        p = WHITEBOX_DIR / "amateur_chatbot.py"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        for expected in ("AI-SAST-001", "AI-SAST-002", "AI-SAST-003", "AI-SAST-004", "AI-SAST-006", "AI-SAST-007", "AI-SAST-009", "AI-SAST-010"):
            assert expected in rules, f"Thiếu rule {expected} trên amateur_chatbot.py"

    def test_enterprise_ai_copilot_evasion_and_zero_decoy_fp(self):
        p = WHITEBOX_DIR / "enterprise_ai_copilot.py"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert len(findings) == 8, f"Kỳ vọng đúng 8 lỗ hổng AST, nhận được {len(findings)}: {findings}"
        for expected in ("AI-SAST-001", "AI-SAST-002", "AI-SAST-003", "AI-SAST-004", "AI-SAST-005", "AI-SAST-006", "AI-SAST-007", "AI-SAST-008"):
            assert expected in rules, f"Thiếu rule {expected} trên enterprise_ai_copilot.py"
        # Bắt buộc 0 False Positive trên 4 hàm decoy an toàn (dòng 66–104)
        for f in findings:
            assert not (66 <= f["line"] <= 104), f"Báo động giả trên hàm decoy tại dòng {f['line']}: {f}"

    def test_advanced_agent_metaprog(self):
        p = WHITEBOX_DIR / "advanced_agent_metaprog.py"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert "AI-SAST-006" in rules, "Phải bắt được Text-to-SQL Injection trong Decorator"
        assert "AI-SAST-004" in rules, "Phải bắt được RCE bằng compile() + types.FunctionType"
        assert "AI-SAST-008" in rules, "Phải bắt được Vector DB Filter Injection (**user_filters)"

    def test_cross_file_taint_directory(self):
        cf_dir = WHITEBOX_DIR / "cross_file_test"
        res = self.scanner.scan_directory(str(cf_dir), include_external_tools=False)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert "AI-SAST-001" in rules, "Phải bắt được Cross-File Prompt Injection"
        assert "AI-SAST-006" in rules, "Phải bắt được SQLi từ đầu ra LLM trong llm_executor.py"
        cf_traces = [f for f in findings if f["engine"] == "Cross-File Taint Flow Analyzer"]
        assert cf_traces, "Phải có finding từ Cross-File Taint Flow Analyzer"
        assert any(
            "routes.py" in f["description"] and "utils.py" in f["description"] and "llm_executor.py" in f["description"]
            for f in cf_traces
        ), "Phải có đầy đủ chuỗi truy vết routes.py -> utils.py -> llm_executor.py"

    def test_false_positive_trap_zero_findings(self):
        p = WHITEBOX_DIR / "false_positive_trap.py"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        assert res["findings"] == [], f"BẮT BUỘC 0 False Positive, nhưng phát hiện: {res['findings']}"

    def test_agent_config_yaml_anchors(self):
        p = WHITEBOX_DIR / "agent_config.yaml"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert "AI-SAST-005" in rules, "Phải bắt được trust_remote_code: true sau khi bung YAML anchor"
        assert "AI-SAST-009" in rules, "Phải bắt được verify_ssl: false"
        assert "AI-SAST-007" in rules, "Phải bắt được max_tokens: -1"
        assert "AI-SAST-004" in rules, "Phải bắt được sandbox_mode: off và allowed_tools nguy hiểm"
        assert "AI-SAST-002" in rules, "Phải bắt được credential_ref sk-live-..."
        assert "AI-SAST-001" in rules, "Phải bắt được system_prompt_override: true"

    def test_modelfile_directives_and_system_block(self):
        p = WHITEBOX_DIR / "Modelfile"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert "AI-SAST-007" in rules, "Phải bắt được num_ctx 131072 / num_predict -1"
        assert "AI-SAST-002" in rules, "Phải bắt được postgres:// URI và whsec_ trong SYSTEM block"
        assert "AI-SAST-010" in rules, "Phải bắt được lệnh backdoor DEBUG_OVERRIDE_99 trong SYSTEM block"

    def test_ai_gateway_ts(self):
        p = WHITEBOX_DIR / "ai_gateway.ts"
        res = self.scanner.scan_code_snippet(p.read_text(encoding="utf-8"), filename=p.name)
        findings = res["findings"]
        _assert_valid_schema(findings)
        rules = {f["rule_id"] for f in findings}
        assert "AI-SAST-002" in rules, "Phải bắt được keyChunks.join('-') -> sk-ant-..."
        assert "AI-SAST-001" in rules, "Phải bắt được Tagged Template Injection buildPrompt`...${userInput}`"
        assert "AI-SAST-004" in rules, "Phải bắt được new Function(...) RCE"


class TestGeneralizationAndEdgeCases:
    """Kiểm thử tổng quát hóa (không hardcode tên biến/hàm), sanitizers, 3 kiểu dict merge & circular imports."""

    def setup_method(self):
        self.scanner = AICodeScanner()

    def test_vector_db_filter_pipe_and_update(self):
        code = '''
def search_v1(vdb, query: str, extra_filter: dict):
    f1 = {"department": "hr"} | extra_filter
    return vdb.similarity_search(query, filter=f1)

def search_v2(vdb, query: str, extra_filter: dict):
    f2 = {"department": "hr"}
    f2.update(extra_filter)
    return vdb.search(query, where=f2)
'''
        res = self.scanner.scan_code_snippet(code, filename="vdb_ops.py")
        sast8 = [f for f in res["findings"] if f["rule_id"] == "AI-SAST-008"]
        assert len(sast8) == 2

    def test_base64_and_hex_obfuscated_secret(self):
        # "sk-proj-1234567890abcdef" in base64 and hex
        code = '''
import base64
K1 = base64.b64decode("c2stcHJvai0xMjM0NTY3ODkwYWJjZGVm").decode()
K2 = bytes.fromhex("736b2d70726f6a2d31323334353637383930616263646566").decode()
'''
        res = self.scanner.scan_code_snippet(code, filename="secrets_obf.py")
        sast2 = [f for f in res["findings"] if f["rule_id"] == "AI-SAST-002"]
        assert len(sast2) == 2

    def test_sanitizer_prevents_false_positive(self):
        code = '''
import re
import urllib.request

def fetch_safe(user_id: str):
    uid = int(user_id)
    if not re.fullmatch(r"[0-9]+", str(uid)):
        raise ValueError("bad")
    return urllib.request.urlopen(f"https://api.internal/items/{uid}", timeout=5)
'''
        res = self.scanner.scan_code_snippet(code, filename="safe_fetch.py")
        assert res["findings"] == []

    def test_circular_import_and_alias_relative_import(self, tmp_path):
        (tmp_path / "a.py").write_text(
            "from .b import step_b as sb\ndef entry(user_query: str):\n    return sb(user_query)\n",
            encoding="utf-8",
        )
        (tmp_path / "b.py").write_text(
            "from .c import sink_c\nimport a as mod_a\ndef step_b(raw_input: str):\n    p = f'System task: {raw_input}'\n    return sink_c(p)\n",
            encoding="utf-8",
        )
        (tmp_path / "c.py").write_text(
            "def sink_c(prompt_text: str):\n    return client.chat.completions.create(model='m', messages=[{'role': 'user', 'content': prompt_text}])\n",
            encoding="utf-8",
        )
        res = self.scanner.scan_directory(str(tmp_path), include_external_tools=False)
        cf = [f for f in res["findings"] if f["engine"] == "Cross-File Taint Flow Analyzer"]
        assert cf, "Phải theo dõi được chuỗi gọi sâu 3 file với relative import, alias và không treo khi có circular import"

    def test_sink_first_prompt_injection_generic_param(self):
        code = '''
from dataclasses import dataclass, field
from typing import List

@dataclass
class Buf:
    items: List[str] = field(default_factory=list)
    def add(self, v):
        self.items.append(v)
    def dump(self):
        return "\\n".join(self.items)

def run_job(llm_client, x):
    b = Buf()
    b.add("System instruction")
    b.add(x)
    out = b.dump()
    return llm_client.chat.completions.create(model="m", messages=[{"role": "user", "content": out}])
'''
        res = self.scanner.scan_code_snippet(code, filename="sink_first.py")
        rules = {f["rule_id"] for f in res["findings"]}
        assert "AI-SAST-001" in rules

    def test_hybrid_candidate_extraction_grounding_merge_and_fallback(self, monkeypatch):
        from modules.auxiliary.scanner.llm_sast_auditor import LLMSASTAuditor, merge_ast_and_llm_findings

        code = (WHITEBOX_DIR / "enterprise_ai_copilot.py").read_text(encoding="utf-8")
        import ast as _ast
        cands = self.scanner._extract_llm_candidates(code, _ast.parse(code))
        assert len(cands) == 1, "File <= 180 dòng phải gộp thành đúng 1 chunk gửi sang Ollama"
        assert len(cands[0]["numbered_code"].splitlines()) <= 180
        assert cands[0]["numbered_code"].startswith("L1:")

        # Kiểm tra Parse JSON linh hoạt cho model 8B (markdown fence, key vulnerabilities/issues, single object)
        parsed_md, ok_md = LLMSASTAuditor._parse_llm_json(
            'Here is the audit result:\n```json\n{"vulnerabilities": [{"rule": "001", "lineno": "L10", "confidence": "high"}]}\n```\nDone.'
        )
        assert ok_md is True and len(parsed_md) == 1
        parsed_single, ok_single = LLMSASTAuditor._parse_llm_json(
            '{"id": "AI-SAST-004", "line_number": "L29", "reason": "os.popen"}'
        )
        assert ok_single is True and len(parsed_single) == 1

        # Kiểm tra bộ lọc Grounding chống ảo giác + tự dịch dòng ±2 + ngưỡng confidence 0.65
        auditor = LLMSASTAuditor(ollama_url="http://127.0.0.1:1", model="llama3:latest", timeout=1)
        trap_lines = [
            "# comment with eval(x)",
            "import yaml",
            "x = yaml.safe_load(raw)",
            "subprocess.run(['ping', h], shell=False)",
            "# comment right above popen",
            "os.popen(cmd).read()",
        ]
        assert auditor._ground_finding({"rule_id": "AI-SAST-999", "line": 3, "confidence": 0.95}, trap_lines, 1, 6) is None
        assert auditor._ground_finding({"rule_id": "AI-SAST-004", "line": 4, "confidence": 0.50}, trap_lines, 1, 6) is None
        assert auditor._ground_finding({"rule_id": "AI-SAST-004", "line": 4, "confidence": 0.95}, trap_lines, 1, 6) is None
        # Dòng 5 là comment ngay sát dòng 6 (os.popen) -> tự dịch sang dòng 6 và chuẩn hóa rule '004' + default confidence 0.8
        snapped = auditor._ground_finding({"rule": "004", "line_number": "L5"}, trap_lines, 1, 6)
        assert snapped is not None and snapped["rule_id"] == "AI-SAST-004" and snapped["line"] == 6 and snapped["confidence"] == 0.8

        # Kiểm tra Merge & Deduplication (<= 5 dòng -> hybrid_verified; chỉ LLM -> llm_semantic)
        rules_by_id = {r["rule_id"]: r for r in self.scanner.rules}
        sample_lines = ["a = 1"] * 20
        ast_f = [{"rule_id": "AI-SAST-001", "file": "a.py", "line": 10, "description": "ast", "detection_source": "ast_static"}]
        llm_f = [
            {"rule_id": "AI-SAST-001", "line": 13, "confidence": 0.92, "reason": "confirmed", "evidence": "a = 1"},
            {"rule_id": "AI-SAST-008", "line": 18, "confidence": 0.88, "reason": "vector filter", "evidence": "a = 1"},
        ]
        merged = merge_ast_and_llm_findings(ast_f, llm_f, "a.py", sample_lines, rules_by_id, self.scanner._format_context_snippet)
        assert len(merged) == 2
        by_rule = {f["rule_id"]: f for f in merged}
        assert by_rule["AI-SAST-001"]["detection_source"] == "hybrid_verified"
        assert by_rule["AI-SAST-008"]["detection_source"] == "llm_semantic"

        # Kiểm tra Fallback an toàn khi Ollama không kết nối được (không crash)
        res_fb = self.scanner.scan_code_snippet(
            "import pickle\npickle.loads(data)\n",
            filename="fb.py",
            use_hybrid_llm=True,
            ollama_url="http://127.0.0.1:1",
        )
        assert res_fb["success"] is True
        assert res_fb["summary"]["hybrid_llm_status"] == "fallback_ast_only"
        assert any(f["rule_id"] == "AI-SAST-003" and f["detection_source"] == "ast_static" for f in res_fb["findings"])

    def test_skip_config_selective_batching_and_sha256_cache(self, monkeypatch):
        from modules.auxiliary.scanner.llm_sast_auditor import (
            LLMSASTAuditor,
            clear_llm_audit_cache,
            is_config_file_for_llm_skip,
            is_llm_eligible_file,
        )

        clear_llm_audit_cache()

        # 1. Skip config files already covered by dedicated parsers
        for cfg_name in ("Modelfile", "agent_config.yaml", "config.json", ".env", "requirements.txt", "ambient.d.ts"):
            assert is_config_file_for_llm_skip(cfg_name) is True
        assert is_config_file_for_llm_skip("enterprise_ai_copilot.py") is False

        # 2. Selective mode skips AST-covered files without deep semantic hints, keeps 0-AST or semantic-hint files
        ok_zero, _ = is_llm_eligible_file("a.py", "client.chat.completions.create(messages=[])", ast_findings_count=0, hybrid_mode="selective")
        ok_covered, _ = is_llm_eligible_file("b.py", "pickle.loads(data)", ast_findings_count=3, hybrid_mode="selective")
        ok_deep, _ = is_llm_eligible_file("c.py", "f = lambda x: os.popen(x).read()", ast_findings_count=2, hybrid_mode="selective")
        ok_full, _ = is_llm_eligible_file("b.py", "pickle.loads(data)", ast_findings_count=3, hybrid_mode="full")
        assert ok_zero is True and ok_covered is False and ok_deep is True and ok_full is True

        # 3. Multi-File Batching + SHA-256 Cache
        calls = []

        def fake_stream(self_aud, messages):
            calls.append(messages[-1]["content"])
            return '{"findings":[{"file":"f1.py","rule_id":"AI-SAST-004","line":2,"confidence":0.95,"reason":"os.popen"}]}'

        monkeypatch.setattr(LLMSASTAuditor, "_call_ollama_stream", fake_stream)
        aud = LLMSASTAuditor(model="qwen2.5:latest", use_cache=True)
        bundle = [
            ("f1.py", "import os\nrunner = lambda c: os.popen(c).read()\n", None),
            ("f2.py", "def ask(client, q):\n    return client.chat.completions.create(model='m', messages=[{'role':'system','content':'hi'},{'role':'user','content':q}])\n", None),
        ]
        res1, meta1 = aud.audit_file_batch(bundle, max_batch_lines=180, max_files_per_batch=3)
        assert len(calls) == 1, "2 file nhỏ phải được gom vào đúng 1 batch request"
        assert meta1["chunks_sent"] == 1 and meta1["cache_hits"] == 0
        assert len(res1["f1.py"]) == 1 and res1["f1.py"][0]["rule_id"] == "AI-SAST-004"

        # Quét lặp lại -> 100% cache hit, không gọi Ollama lần 2
        res2, meta2 = aud.audit_file_batch(bundle, max_batch_lines=180, max_files_per_batch=3)
        assert len(calls) == 1, "Lượt quét thứ 2 phải dùng SHA-256 cache, không gọi Ollama"
        assert meta2["chunks_sent"] == 0 and meta2["cache_hits"] == 2
        assert len(res2["f1.py"]) == 1
        clear_llm_audit_cache()
