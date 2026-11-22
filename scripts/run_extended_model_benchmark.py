# -*- coding: utf-8 -*-
"""
scripts/run_extended_model_benchmark.py - Pipeline thực nghiệm mở rộng trên 5 mô hình LLM.

Chức năng:
1. Tải 180 prompt benchmark (150 tiếng Việt qua 5 biến thể + 30 tiếng Anh chuẩn).
2. Chạy lặp 3 lần với mỗi mô hình theo danh sách trong experiments/configs/models_eval_config.yaml.
3. Cố định temperature và seed cho từng lần chạy để đảm bảo tính tất định và khả năng tái lập.
4. Ghi response kèm metadata đầy đủ ra định dạng JSONL (hỗ trợ checkpointing resume khi bị ngắt).
5. Đo latency chính xác bằng time.perf_counter().
"""

import argparse
from datetime import datetime, timezone
import json
import logging
import os
from pathlib import Path
import sys
import time
from typing import Any, Dict, List, Set, Tuple

import requests
import yaml

# Đảm bảo import được các module trong hệ thống
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SCANNER_PATH = PROJECT_ROOT / "AI_Security_Scanner"
if str(SCANNER_PATH) not in sys.path:
    sys.path.insert(0, str(SCANNER_PATH))

# Thiết lập logging tiếng Việt
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("ExtendedBenchmarkRunner")


def load_yaml_config(config_path: Path) -> Dict[str, Any]:
    """Tải file cấu hình YAML."""
    if not config_path.exists():
        raise FileNotFoundError(f"Không tìm thấy file cấu hình: {config_path}")
    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def load_all_benchmark_prompts(project_root: Path) -> List[Dict[str, Any]]:
    """
    Tải toàn bộ 180 prompt benchmark:
    - 150 prompt tiếng Việt từ data/vietnamese_benchmark.json (5 biến thể x 30 seed).
    - 30 prompt tiếng Anh chuẩn từ data/english_baseline_benchmark.json.
    """
    vn_path = project_root / "AI_Security_Scanner" / "data" / "vietnamese_benchmark.json"
    en_path = project_root / "AI_Security_Scanner" / "data" / "english_baseline_benchmark.json"

    prompts: List[Dict[str, Any]] = []

    # 1. Tải tập tiếng Việt (150 test cases)
    if vn_path.exists():
        with open(vn_path, "r", encoding="utf-8") as f:
            vn_data = json.load(f)
            cases = vn_data.get("test_cases", [])
            for c in cases:
                item = {
                    "prompt_id": c.get("id"),
                    "paired_en_id": c.get("paired_en_id"),
                    "category": c.get("category", "Unknown"),
                    "linguistic_variant": c.get("linguistic_variant", "standard_vi"),
                    "intent_type": c.get("intent_type", "Harmful"),
                    "prompt": c.get("prompt", ""),
                    "language": "vi",
                    "description": c.get("description", ""),
                }
                prompts.append(item)
    else:
        logger.error(f"Không tìm thấy tập tiếng Việt tại: {vn_path}")

    # 2. Tải tập tiếng Anh chuẩn (30 test cases)
    if en_path.exists():
        with open(en_path, "r", encoding="utf-8") as f:
            en_data = json.load(f)
            cases = en_data.get("test_cases", [])
            for c in cases:
                item = {
                    "prompt_id": c.get("id"),
                    "paired_en_id": c.get("id"),  # Bản thân nó là paired_en_id
                    "category": c.get("category", "Unknown"),
                    "linguistic_variant": "english",
                    "intent_type": c.get("intent_type", "Harmful"),
                    "prompt": c.get("prompt", ""),
                    "language": "en",
                    "description": c.get("description", ""),
                }
                prompts.append(item)
    else:
        logger.error(f"Không tìm thấy tập tiếng Anh tại: {en_path}")

    logger.info(f"Đã tải tổng cộng {len(prompts)} prompts benchmark (Mục tiêu: 180 prompts).")
    return prompts


def load_completed_keys(jsonl_path: Path) -> Set[Tuple[str, str, int]]:
    """
    Quét file JSONL để xác định các lượt chạy đã hoàn thành (model_id, prompt_id, run_index).
    Phục vụ tính năng Resume checkpointing khi bị ngắt.
    """
    completed: Set[Tuple[str, str, int]] = set()
    if not jsonl_path.exists():
        return completed

    with open(jsonl_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
                m_id = rec.get("model_id")
                p_id = rec.get("prompt_id")
                r_idx = rec.get("run_index")
                if m_id is not None and p_id is not None and r_idx is not None:
                    completed.add((str(m_id), str(p_id), int(r_idx)))
            except Exception as e:
                logger.warning(f"Bỏ qua dòng lỗi tại {jsonl_path}:{line_num} - {e}")

    logger.info(f"Đã phát hiện {len(completed)} lượt chạy đã ghi nhận trong checkpoint {jsonl_path.name}")
    return completed


def call_llm_model(
    model_cfg: Dict[str, Any],
    prompt_text: str,
    seed: int,
    temperature: float,
    max_tokens: int,
    timeout: int = 90,
    mock: bool = False,
) -> Dict[str, Any]:
    """
    Gửi prompt đến mô hình LLM qua Ollama API hoặc OpenAI-compatible endpoint.
    Đo đạc thời gian đáp ứng (latency) chính xác bằng time.perf_counter().
    """
    if mock:
        # Chế độ giả lập phục vụ kiểm thử pipeline tự động (dry-run)
        time.sleep(0.01)
        simulated_refusal = "Tôi không thể thực hiện yêu cầu này vì lý do an toàn."
        return {
            "response_text": simulated_refusal,
            "latency_ms": 12.5,
            "tokens_generated": 16,
            "status": "success",
            "provider_response": {"mock": True},
        }

    provider = model_cfg.get("provider", "ollama").lower()
    api_url = model_cfg.get("api_url", "http://localhost:11434").rstrip("/")
    model_name = model_cfg.get("model_name", "llama3.1:8b")
    api_key = model_cfg.get("api_key", "")

    start_time = time.perf_counter()

    try:
        if provider == "ollama":
            url = f"{api_url}/api/generate"
            payload = {
                "model": model_name,
                "prompt": prompt_text,
                "stream": False,
                "options": {
                    "temperature": temperature,
                    "seed": seed,
                    "num_predict": max_tokens,
                },
            }
            resp = requests.post(url, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            return {
                "response_text": data.get("response", ""),
                "latency_ms": round(latency_ms, 2),
                "tokens_generated": data.get("eval_count", 0),
                "status": "success",
                "provider_response": {
                    "total_duration": data.get("total_duration"),
                    "eval_duration": data.get("eval_duration"),
                },
            }

        elif provider in ("openai", "vllm", "openai_compatible"):
            url = f"{api_url}/v1/chat/completions"
            headers = {"Content-Type": "application/json"}
            if api_key:
                headers["Authorization"] = f"Bearer {api_key}"

            payload = {
                "model": model_name,
                "messages": [{"role": "user", "content": prompt_text}],
                "temperature": temperature,
                "seed": seed,
                "max_tokens": max_tokens,
            }
            resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
            resp.raise_for_status()
            data = resp.json()
            latency_ms = (time.perf_counter() - start_time) * 1000.0

            choice = data.get("choices", [{}])[0]
            msg = choice.get("message", {}).get("content", "")
            usage = data.get("usage", {})

            return {
                "response_text": msg,
                "latency_ms": round(latency_ms, 2),
                "tokens_generated": usage.get("completion_tokens", 0),
                "status": "success",
                "provider_response": usage,
            }

        else:
            raise ValueError(f"Provider không được hỗ trợ: {provider}")

    except Exception as e:
        latency_ms = (time.perf_counter() - start_time) * 1000.0
        logger.error(f"Lỗi khi gọi model {model_name}: {e}")
        return {
            "response_text": "",
            "latency_ms": round(latency_ms, 2),
            "tokens_generated": 0,
            "status": f"error: {str(e)}",
            "provider_response": {},
        }


def run_benchmark(
    config_file: str = "experiments/configs/models_eval_config.yaml",
    target_model_id: str = None,
    mock: bool = False,
    limit_prompts: int = None,
) -> None:
    """Điều phối toàn bộ quá trình thực thi benchmark trên 5 mô hình."""
    cfg_path = PROJECT_ROOT / config_file
    cfg = load_yaml_config(cfg_path)

    exp_cfg = cfg.get("experiment", {})
    output_dir = PROJECT_ROOT / exp_cfg.get("output_dir", "experiments/results/extended_evaluations")
    output_dir.mkdir(parents=True, exist_ok=True)

    jsonl_path = PROJECT_ROOT / exp_cfg.get("jsonl_file", "experiments/results/extended_evaluations/raw_responses.jsonl")

    # Siêu tham số
    num_repeats = int(exp_cfg.get("num_repeats", 3))
    seeds = exp_cfg.get("seeds", [42, 100, 2026])
    temperature = float(exp_cfg.get("temperature", 0.0))
    max_tokens = int(exp_cfg.get("max_tokens", 512))
    timeout = int(exp_cfg.get("timeout_seconds", 90))

    # Tải prompts
    prompts = load_all_benchmark_prompts(PROJECT_ROOT)
    if limit_prompts and limit_prompts > 0:
        prompts = prompts[:limit_prompts]
        logger.info(f"Đang giới hạn chạy thử {limit_prompts} prompts đầu tiên.")

    # Tải danh sách model
    models = cfg.get("models", [])
    if target_model_id:
        models = [m for m in models if m.get("id") == target_model_id]
        if not models:
            logger.error(f"Không tìm thấy model với id: {target_model_id}")
            return

    # Checkpoint phục hồi
    completed_keys = load_completed_keys(jsonl_path)

    total_tasks = len(models) * len(prompts) * num_repeats
    logger.info(f"Khởi động pipeline: {len(models)} models x {len(prompts)} prompts x {num_repeats} repeats = {total_tasks} lượt chạy.")

    executed_count = 0
    skipped_count = 0

    # Mở file JSONL ở chế độ append (a)
    with open(jsonl_path, "a", encoding="utf-8") as out_file:
        for m_idx, model in enumerate(models, start=1):
            m_id = model.get("id")
            m_name = model.get("display_name", m_id)
            logger.info(f"[{m_idx}/{len(models)}] Đang xử lý mô hình: {m_name} ({m_id})")

            for p_idx, prompt_item in enumerate(prompts, start=1):
                p_id = prompt_item["prompt_id"]

                for run_idx in range(num_repeats):
                    seed = seeds[run_idx] if run_idx < len(seeds) else 42 + run_idx

                    # Kiểm tra Resume
                    if (m_id, p_id, run_idx) in completed_keys:
                        skipped_count += 1
                        continue

                    # Gọi LLM thực thi
                    call_res = call_llm_model(
                        model_cfg=model,
                        prompt_text=prompt_item["prompt"],
                        seed=seed,
                        temperature=temperature,
                        max_tokens=max_tokens,
                        timeout=timeout,
                        mock=mock,
                    )

                    # Đóng gói bản ghi JSONL đầy đủ metadata
                    record = {
                        "model_id": m_id,
                        "model_name": m_name,
                        "prompt_id": p_id,
                        "paired_en_id": prompt_item["paired_en_id"],
                        "category": prompt_item["category"],
                        "linguistic_variant": prompt_item["linguistic_variant"],
                        "intent_type": prompt_item["intent_type"],
                        "run_index": run_idx,
                        "seed": seed,
                        "temperature": temperature,
                        "prompt_text": prompt_item["prompt"],
                        "response_text": call_res["response_text"],
                        "latency_ms": call_res["latency_ms"],
                        "tokens_generated": call_res["tokens_generated"],
                        "status": call_res["status"],
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }

                    # Ghi ra JSONL và flush ngay lập tức
                    out_file.write(json.dumps(record, ensure_ascii=False) + "\n")
                    out_file.flush()

                    completed_keys.add((m_id, p_id, run_idx))
                    executed_count += 1

                    if executed_count % 25 == 0:
                        logger.info(f"Tiến độ: Đã chạy {executed_count}/{total_tasks} lượt (Bỏ qua đã có: {skipped_count}).")

    logger.info(f"Hoàn thành phiên làm việc! Đã thực thi mới: {executed_count}, Đã bỏ qua từ trước: {skipped_count}.")
    logger.info(f"Dữ liệu được lưu an toàn tại: {jsonl_path}")


def main():
    parser = argparse.ArgumentParser(description="Pipeline chạy mở rộng 180 prompt x 5 LLMs x 3 repeats.")
    parser.add_argument("--config", type=str, default="experiments/configs/models_eval_config.yaml", help="Đường dẫn file YAML cấu hình.")
    parser.add_argument("--model-id", type=str, default=None, help="Chỉ định ID mô hình muốn chạy (vd: llama-3.1-8b). Mặc định chạy tất cả.")
    parser.add_argument("--mock", action="store_true", help="Chạy ở chế độ giả lập dry-run (dùng để kiểm thử pipeline không cần GPU).")
    parser.add_argument("--limit", type=int, default=None, help="Giới hạn số prompt chạy thử nghiệm.")
    args = parser.parse_args()

    run_benchmark(
        config_file=args.config,
        target_model_id=args.model_id,
        mock=args.mock,
        limit_prompts=args.limit,
    )


if __name__ == "__main__":
    main()
