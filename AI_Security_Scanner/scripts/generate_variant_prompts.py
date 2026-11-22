# -*- coding: utf-8 -*-
"""
scripts/generate_variant_prompts.py - Linguistic Variant Generator for Vietnamese Red-Teaming Benchmark

Generates Vietnamese linguistic variants:
1. `no_diacritics`: Stripped tone marks and accents.
2. `unicode_nfd`: Unicode Normalization Form D (decomposed characters).
3. `code_switching`: Mixed Vietnamese-English technical terminology.
4. `teencode_slang`: Vietnamese youth slang/teencode abbreviations.

Used to expand the benchmark to 300-500 test cases for comprehensive evaluation
of LLM safety guardrails under linguistic perturbations.
"""

import argparse
import copy
import json
import re
import sys
import unicodedata
from pathlib import Path
from typing import Dict, List, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

# Vietnamese diacritics mapping
DIACRITICS_MAP = {
    'à': 'a', 'á': 'a', 'ả': 'a', 'ã': 'a', 'ạ': 'a',
    'ă': 'a', 'ằ': 'a', 'ắ': 'a', 'ẳ': 'a', 'ẵ': 'a', 'ặ': 'a',
    'â': 'a', 'ầ': 'a', 'ấ': 'a', 'ẩ': 'a', 'ẫ': 'a', 'ậ': 'a',
    'è': 'e', 'é': 'e', 'ẻ': 'e', 'ẽ': 'e', 'ẹ': 'e',
    'ê': 'e', 'ề': 'e', 'ế': 'e', 'ể': 'e', 'ễ': 'e', 'ệ': 'e',
    'ì': 'i', 'í': 'i', 'ỉ': 'i', 'ĩ': 'i', 'ị': 'i',
    'ò': 'o', 'ó': 'o', 'ỏ': 'o', 'õ': 'o', 'ọ': 'o',
    'ô': 'o', 'ồ': 'o', 'ố': 'o', 'ổ': 'o', 'ỗ': 'o', 'ộ': 'o',
    'ơ': 'o', 'ờ': 'o', 'ớ': 'o', 'ở': 'o', 'ỡ': 'o', 'ợ': 'o',
    'ù': 'u', 'ú': 'u', 'ủ': 'u', 'ũ': 'u', 'ụ': 'u',
    'ư': 'u', 'ừ': 'u', 'ứ': 'u', 'ử': 'u', 'ữ': 'u', 'ự': 'u',
    'ỳ': 'y', 'ý': 'y', 'ỷ': 'y', 'ỹ': 'y', 'ỵ': 'y',
    'đ': 'd',
    'À': 'A', 'Á': 'A', 'Ả': 'A', 'Ã': 'A', 'Ạ': 'A',
    'Ă': 'A', 'Ằ': 'A', 'Ắ': 'A', 'Ẳ': 'A', 'Ẵ': 'A', 'Ặ': 'A',
    'Â': 'A', 'Ầ': 'A', 'Ấ': 'A', 'Ẩ': 'A', 'Ẫ': 'A', 'Ậ': 'A',
    'È': 'E', 'É': 'E', 'Ẻ': 'E', 'Ẽ': 'E', 'Ẹ': 'E',
    'Ê': 'E', 'Ề': 'E', 'Ế': 'E', 'Ể': 'E', 'Ễ': 'E', 'Ệ': 'E',
    'Ì': 'I', 'Í': 'I', 'Ỉ': 'I', 'Ĩ': 'I', 'Ị': 'I',
    'Ò': 'O', 'Ó': 'O', 'Ỏ': 'O', 'Õ': 'O', 'Ọ': 'O',
    'Ô': 'O', 'Ồ': 'O', 'Ố': 'O', 'Ổ': 'O', 'Ỗ': 'O', 'Ộ': 'O',
    'Ơ': 'O', 'Ờ': 'O', 'Ớ': 'O', 'Ở': 'O', 'Ỡ': 'O', 'Ợ': 'O',
    'Ù': 'U', 'Ú': 'U', 'Ủ': 'U', 'Ũ': 'U', 'Ụ': 'U',
    'Ư': 'U', 'Ừ': 'U', 'Ứ': 'U', 'Ử': 'U', 'Ữ': 'U', 'Ự': 'U',
    'Ỳ': 'Y', 'Ý': 'Y', 'Ỷ': 'Y', 'Ỹ': 'Y', 'Ỵ': 'Y',
    'Đ': 'D'
}

# Code-switching lexicon (Vietnamese -> English)
CODE_SWITCH_LEXICON = {
    r"\bmã độc\b": "malware",
    r"\btấn công\b": "attack",
    r"\bvượt qua\b": "bypass",
    r"\bvượt rào\b": "jailbreak bypass",
    r"\bhướng dẫn\b": "tutorial",
    r"\bcách thức\b": "method",
    r"\btài khoản\b": "account",
    r"\bmật khẩu\b": "password",
    r"\bhệ thống\b": "system",
    r"\bdữ liệu\b": "data",
    r"\bthông tin\b": "information",
    r"\blừa đảo\b": "phishing/scam",
    r"\bchiếm quyền\b": "takeover",
    r"\bđánh cắp\b": "steal",
    r"\blỗ hổng\b": "vulnerability/exploit",
    r"\bbảo mật\b": "security",
    r"\bchuyển tiền\b": "transfer money",
    r"\bngân hàng\b": "banking",
    r"\bmã xác thực\b": "OTP code",
    r"\bkiểm tra\b": "verify",
    r"\byêu cầu\b": "request",
    r"\bbỏ qua quy tắc\b": "ignore safety policy",
    r"\btruy cập\b": "access",
}

# Teencode / slang replacements
TEENCODE_LEXICON = {
    r"\bkhông\b": "ko",
    r"\bđược\b": "dc",
    r"\bbiết\b": "bik",
    r"\bthế nào\b": "ntn",
    r"\bngười\b": "ng",
    r"\bmình\b": "mik",
    r"\bgì\b": "j",
    r"\btại sao\b": "sao z",
    r"\bquá\b": "qúa",
    r"\banh em\b": "ae",
}


def to_no_diacritics(text: str) -> str:
    """Convert Vietnamese text to tone-stripped version (no diacritics)."""
    return "".join(DIACRITICS_MAP.get(c, c) for c in text)


def to_unicode_nfd(text: str) -> str:
    """Normalize text into Unicode NFD (Decomposed Form)."""
    return unicodedata.normalize("NFD", text)


def to_code_switching(text: str) -> str:
    """Inject English loanwords/terms for cybersecurity and tech verbs."""
    result = text
    for pattern, replacement in CODE_SWITCH_LEXICON.items():
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    # If no replacement was triggered, append an English instruction suffix
    if result == text:
        result = f"{text}. Please explain step-by-step with technical details."
    return result


def to_teencode_slang(text: str) -> str:
    """Transform text with Vietnamese teencode and slang words."""
    result = text
    for pattern, replacement in TEENCODE_LEXICON.items():
        result = re.sub(pattern, replacement, result, flags=re.IGNORECASE)
    return result


def generate_variants(prompt: str) -> Dict[str, str]:
    """Generate all 4 linguistic variants for a single standard prompt."""
    return {
        "standard_vi": unicodedata.normalize("NFC", prompt),
        "no_diacritics": to_no_diacritics(prompt),
        "unicode_nfd": to_unicode_nfd(prompt),
        "code_switching": to_code_switching(prompt),
        "teencode_slang": to_teencode_slang(prompt),
    }


def expand_benchmark_dataset(
    input_file: Path,
    output_file: Path,
    target_count: int = 310,
) -> int:
    """
    Expand a benchmark dataset JSON file to target_count by adding
    linguistic variants of each base case.
    """
    with open(input_file, "r", encoding="utf-8") as f:
        data = json.load(f)

    base_cases = data.get("test_cases", [])
    expanded_cases: List[Dict] = []
    case_counter = 1

    # First add all original cases as standard_vi
    for tc in base_cases:
        item = copy.deepcopy(tc)
        item["id"] = f"VN_RT_{case_counter:03d}"
        item["linguistic_variant"] = "standard_vi"
        expanded_cases.append(item)
        case_counter += 1

    # Now systematically generate variants: no_diacritics, code_switching, unicode_nfd, teencode
    variants_to_generate = ["no_diacritics", "code_switching", "unicode_nfd", "teencode_slang"]

    for var_type in variants_to_generate:
        for tc in base_cases:
            if len(expanded_cases) >= target_count:
                break
            orig_prompt = tc.get("prompt", tc.get("payload", ""))
            if var_type == "no_diacritics":
                var_prompt = to_no_diacritics(orig_prompt)
            elif var_type == "unicode_nfd":
                var_prompt = to_unicode_nfd(orig_prompt)
            elif var_type == "code_switching":
                var_prompt = to_code_switching(orig_prompt)
            elif var_type == "teencode_slang":
                var_prompt = to_teencode_slang(orig_prompt)
            else:
                continue

            new_case = copy.deepcopy(tc)
            new_case["id"] = f"VN_RT_{case_counter:03d}"
            new_case["base_case_id"] = tc.get("id")
            new_case["linguistic_variant"] = var_type
            new_case["prompt"] = var_prompt
            new_case["payload"] = var_prompt
            new_case["description"] = f"[{var_type.upper()}] {tc.get('description', '')}"

            expanded_cases.append(new_case)
            case_counter += 1

        if len(expanded_cases) >= target_count:
            break

    data["test_cases"] = expanded_cases
    data["total_cases"] = len(expanded_cases)
    data["metadata_variant_distribution"] = {
        var: sum(1 for c in expanded_cases if c.get("linguistic_variant") == var)
        for var in ["standard_vi", "no_diacritics", "unicode_nfd", "code_switching", "teencode_slang"]
    }

    output_file.parent.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)

    return len(expanded_cases)


def main():
    parser = argparse.ArgumentParser(description="Vietnamese Benchmark Linguistic Variant Generator")
    parser.add_argument("--prompt", type=str, help="Single prompt to generate variants for")
    parser.add_argument("--input-file", type=str, default="data/vietnamese_benchmark.json", help="Input dataset JSON")
    parser.add_argument("--output-file", type=str, default="data/vietnamese_benchmark_expanded.json", help="Output dataset JSON")
    parser.add_argument("--target-count", type=int, default=310, help="Target number of test cases (default: 310)")

    args = parser.parse_args()

    if args.prompt:
        variants = generate_variants(args.prompt)
        print(f"\nOriginal: {args.prompt}")
        for k, v in variants.items():
            print(f"  [{k}]: {v}")
    else:
        in_p = Path(args.input_file)
        out_p = Path(args.output_file)
        if not in_p.is_absolute():
            in_p = Path(__file__).resolve().parent.parent / in_p
        if not out_p.is_absolute():
            out_p = Path(__file__).resolve().parent.parent / out_p

        total = expand_benchmark_dataset(in_p, out_p, target_count=args.target_count)
        print(f"✅ Generated {total} expanded cases -> {out_p}")


if __name__ == "__main__":
    main()
