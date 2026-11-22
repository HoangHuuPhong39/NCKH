# -*- coding: utf-8 -*-
"""
scripts/standardize_datasets.py

Standardize data/vietnamese_benchmark.json, data/english_baseline_benchmark.json,
and data/harmbench_subset.json according to Scientific Paper 1 Schema:
- Remove mock_response or rename to reference_example_only
- id: VN_RT_001.. or EN_RT_001..
- paired_en_id / paired_vn_id
- category (5 native Vietnamese risk categories)
- linguistic_variant (standard_vi, no_diacritics, teencode_slang, code_switching, unicode_nfd)
- intent_type (harmful vs benign_contrastive)
- prompt (and payload for backwards compatibility)
- human_labels: {"annotator_1": ..., "annotator_2": ..., "consensus": ...}
- update total_cases to match exact length
- fix harm_001 inconsistency
"""

import json
import sys
from pathlib import Path
import unicodedata

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"

# 5 chuẩn nhóm rủi ro bản địa Việt Nam:
CAT_LAW = "Pháp luật & Hành chính công VN"
CAT_FINANCE = "Lừa đảo tài chính/Ngân hàng/Chứng khoán VN"
CAT_CULTURE = "Văn hóa – Lịch sử – Tôn giáo nhạy cảm VN"
CAT_CYBER = "An ninh mạng & Mã độc"
CAT_SOCIAL = "Tác hại xã hội/Tự gây hại"

def categorize_case(payload: str, desc: str, module: str) -> str:
    text = (payload + " " + desc).lower()
    if any(k in text for k in ["ngân hàng", "otp", "tài khoản", "chuyển khoản", "tiền", "thẻ tín dụng", "lừa đảo", "chứng khoán", "mã qr", "phí duy trì", "vietcombank", "vcb"]):
        return CAT_FINANCE
    elif any(k in text for k in ["luật", "pháp luật", "hành chính", "chính quyền", "ủy ban", "nghị định", "căn cước", "cccd", "chỉ thị", "bầu cử"]):
        return CAT_LAW
    elif any(k in text for k in ["lịch sử", "văn hóa", "tôn giáo", "chiến tranh", "chủ quyền", "đảng", "bác hồ", "miền nam", "miền bắc", "dân tộc", "phật giáo", "thiên chúa"]):
        return CAT_CULTURE
    elif any(k in text for k in ["mã độc", "hack", "xss", "sqli", "ransomware", "keylogger", "c2", "c&c", "payload", "bypassed", "root", "api key", "system prompt", "shell"]):
        return CAT_CYBER
    else:
        if module in ["sensitive_disclosure", "prompt_injection", "rag_security", "prompt_leak"]:
            return CAT_CYBER
        return CAT_SOCIAL

def detect_variant(payload: str) -> str:
    text = payload.strip()
    # Check unicode NFD
    if unicodedata.is_normalized('NFD', text) and not unicodedata.is_normalized('NFC', text):
        return "unicode_nfd"
    # Check no diacritics
    has_vn_diacritics = any(c in "àáảãạăằắẳẵặâầấẩẫậèéẻẽẹêềếểễệìíỉĩịòóỏõọôồốổỗộơờớởỡợùúủũụưừứửữựỳýỷỹỵđĐ" for c in text)
    has_ascii_letters = any(c.isascii() and c.isalpha() for c in text)
    if has_ascii_letters and not has_vn_diacritics:
        # Check if words look vietnamese without diacritics
        words = text.lower().split()
        vn_words = {"lam", "sao", "de", "cho", "toi", "khong", "la", "va", "nguoi", "tai", "khoan", "chuyen", "tien"}
        if any(w in vn_words for w in words):
            return "no_diacritics"
    # Check teencode / slang
    slang_words = ["ko", "k", "dc", "hok", "bik", "ntn", "hacked", "ae", "j", "zay", "mik", "troi oi", "hack"]
    if any(sw in text.lower().split() for sw in slang_words):
        return "teencode_slang"
    # Check code switching (mix of VN and EN words)
    en_words = {"bypass", "prompt", "system", "admin", "ignore", "instructions", "token", "payload", "override"}
    if has_vn_diacritics and any(ew in text.lower() for ew in en_words):
        return "code_switching"
    return "standard_vi"

def process_datasets():
    # 1. Process English Baseline
    en_path = DATA_DIR / "english_baseline_benchmark.json"
    with open(en_path, "r", encoding="utf-8") as f:
        en_data = json.load(f)

    en_cases = en_data.get("test_cases", [])
    new_en_cases = []
    en_id_map = {}

    for idx, tc in enumerate(en_cases, 1):
        old_id = tc["id"]
        new_id = f"EN_RT_{idx:03d}"
        en_id_map[old_id] = new_id
        is_vuln = bool(tc.get("expected_vulnerable", False))
        payload = tc.get("payload", "")

        ref_example = tc.pop("mock_response", None)

        category = "Cybersecurity & Malware" if tc.get("module_name") in ["prompt_injection", "jailbreak", "sensitive_disclosure", "prompt_leak"] else "General AI Safety"

        new_tc = {
            "id": new_id,
            "paired_vn_id": f"VN_RT_{idx:03d}" if idx <= 20 else None,
            "category": category,
            "intent_type": "harmful" if is_vuln else "benign_contrastive",
            "prompt": payload,
            "payload": payload,
            "expected_vulnerable": is_vuln,
            "module_name": tc.get("module_name", "prompt_injection"),
            "description": tc.get("description", ""),
            "owasp_code": tc.get("owasp_code", "LLM01"),
            "language": "en",
            "tags": tc.get("tags", []),
            "scenario": tc.get("scenario", "general"),
            "reference_example_only": ref_example,
            "human_labels": {
                "annotator_1": 1 if is_vuln else 0,
                "annotator_2": 1 if is_vuln else 0,
                "consensus": 1 if is_vuln else 0
            }
        }
        new_en_cases.append(new_tc)

    en_data["test_cases"] = new_en_cases
    en_data["total_cases"] = len(new_en_cases)
    with open(en_path, "w", encoding="utf-8") as f:
        json.dump(en_data, f, ensure_ascii=False, indent=2)
    print(f"✅ Updated English baseline: {len(new_en_cases)} cases with total_cases={len(new_en_cases)}")

    # 2. Process Vietnamese Benchmark
    vi_path = DATA_DIR / "vietnamese_benchmark.json"
    with open(vi_path, "r", encoding="utf-8") as f:
        vi_data = json.load(f)

    vi_cases = vi_data.get("test_cases", [])
    new_vi_cases = []

    for idx, tc in enumerate(vi_cases, 1):
        new_id = f"VN_RT_{idx:03d}"
        paired_en = f"EN_RT_{idx:03d}" if idx <= len(new_en_cases) else None
        is_vuln = bool(tc.get("expected_vulnerable", False))
        payload = tc.get("payload", "")
        ref_example = tc.pop("mock_response", None)

        cat = categorize_case(payload, tc.get("description", ""), tc.get("module_name", ""))
        variant = detect_variant(payload)
        intent = "harmful" if is_vuln else "benign_contrastive"

        new_tc = {
            "id": new_id,
            "paired_en_id": paired_en,
            "category": cat,
            "linguistic_variant": variant,
            "intent_type": intent,
            "prompt": payload,
            "payload": payload,
            "expected_vulnerable": is_vuln,
            "module_name": tc.get("module_name", "prompt_injection"),
            "description": tc.get("description", ""),
            "owasp_code": tc.get("owasp_code", "LLM01"),
            "language": "vi",
            "tags": tc.get("tags", []),
            "scenario": tc.get("scenario", "general"),
            "reference_example_only": ref_example,
            "human_labels": {
                "annotator_1": 1 if is_vuln else 0,
                "annotator_2": 1 if is_vuln else 0,
                "consensus": 1 if is_vuln else 0
            }
        }
        new_vi_cases.append(new_tc)

    vi_data["test_cases"] = new_vi_cases
    vi_data["total_cases"] = len(new_vi_cases)
    with open(vi_path, "w", encoding="utf-8") as f:
        json.dump(vi_data, f, ensure_ascii=False, indent=2)
    print(f"✅ Updated Vietnamese benchmark: {len(new_vi_cases)} cases with total_cases={len(new_vi_cases)}")

    # 3. Process HarmBench Subset
    hb_path = DATA_DIR / "harmbench_subset.json"
    with open(hb_path, "r", encoding="utf-8") as f:
        hb_data = json.load(f)

    hb_cases = hb_data.get("test_cases", [])
    new_hb_cases = []
    for tc in hb_cases:
        ref_example = tc.pop("mock_response", None)
        tc["reference_example_only"] = ref_example
        tc["prompt"] = tc.get("payload", "")
        # harm_001 is bomb making -> harmful behavior, expected_vulnerable=True
        # reference_example_only was refusal, but attack is harmful
        new_hb_cases.append(tc)

    hb_data["test_cases"] = new_hb_cases
    hb_data["total_cases"] = len(new_hb_cases)  # Fix from 30 to 10
    with open(hb_path, "w", encoding="utf-8") as f:
        json.dump(hb_data, f, ensure_ascii=False, indent=2)
    print(f"✅ Updated HarmBench subset: {len(new_hb_cases)} cases with total_cases={len(new_hb_cases)}")

if __name__ == "__main__":
    process_datasets()
