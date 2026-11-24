# -*- coding: utf-8 -*-
"""
experiments/run_sota_s2_gcg_transfer.py
100% Real-Response Execution of S2 (GCG Standalone / Transfer Attack, Zou et al. [27])

Takes real white-box gradient-optimized adversarial suffixes produced by
`experiments/colab_s2_gcg_real.ipynb` (saved to
`experiments/results/rbst_real/s2_gcg_suffixes_real.json`), appends each real suffix
to the applicable CS1, CS2, and CS3 threat prompts, executes them LIVE against the
target Ollama model (`qwen2.5:latest`), evaluates them with the exact real Oracles
(canary / AgentSandbox / PatternDetector), and caches per-case checkpoints to:
  - real_responses_s2_gcg_cs1_qwen2.5_latest.json
  - real_responses_s2_gcg_cs2_qwen2.5_latest.json
  - real_responses_s2_gcg_cs3_qwen2.5_latest.json

After this script finishes, run:
    python experiments/run_rbst_real_experiments.py
to automatically populate row S2 in Tables E3 and E4 (CSV, JSON, and Markdown).
"""

from __future__ import annotations

import argparse
from datetime import datetime
import json
from pathlib import Path
import sys
from typing import Any, Dict, List, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.rbst_adapter import build_test_cases_for_pairs, load_case_study_graph
from core.rbst_engine import TestCaseSpec
from core.rbst_graph import RBSTThreatModeler
from experiments.run_rbst_real_experiments import RESULTS_DIR
from experiments.run_sota_s1_s3_real import (
    _load_json,
    _save_json,
    execute_against_target_system,
)
from modules.detectors.pattern_match import PatternDetector


DEFAULT_SUFFIX_FILE = RESULTS_DIR / "s2_gcg_suffixes_real.json"


def run_s2_gcg_transfer(
    suffix_file: Path,
    target_model: str = "qwen2.5:latest",
    cases_per_pair: int = 2,
    force_refresh: bool = False,
) -> Dict[str, Path]:
    if not suffix_file.exists():
        raise FileNotFoundError(
            f"Không tìm thấy file hậu tố GCG thật: {suffix_file}\n"
            "Vui lòng chạy notebook experiments/colab_s2_gcg_real.ipynb trên Google Colab (T4 GPU), "
            "tải s2_gcg_suffixes_real.json về và đặt vào đường dẫn trên."
        )

    bundle = json.loads(suffix_file.read_text(encoding="utf-8"))
    suffix_map: Dict[str, Dict[str, Any]] = bundle.get("suffixes_by_threat", {})
    if not suffix_map:
        raise ValueError(f"File {suffix_file} không chứa 'suffixes_by_threat' hợp lệ.")

    surrogate_model = bundle.get("surrogate_model", "unknown_surrogate")
    gpu_name = bundle.get("gpu", "unknown_gpu")
    detector = PatternDetector()
    out_paths: Dict[str, Path] = {}

    for cs in ("cs1", "cs2", "cs3"):
        graph = load_case_study_graph(cs)
        pairs = RBSTThreatModeler().enumerate_applicable_pairs(graph)
        base_cases = build_test_cases_for_pairs(pairs, cases_per_pair=cases_per_pair)

        res_path = RESULTS_DIR / f"real_responses_s2_gcg_{cs}_{target_model.replace(':', '_')}.json"
        out_paths[cs] = res_path
        existing = {} if force_refresh else _load_json(res_path, {})
        records: Dict[str, Dict[str, Any]] = existing.get("records", {})

        # Only build cases for threats that actually have a real GCG suffix in suffix_map
        gcg_cases: List[Tuple[TestCaseSpec, Dict[str, Any]]] = []
        for idx, tc in enumerate(base_cases, 1):
            if tc.threat_id not in suffix_map:
                continue
            s_info = suffix_map[tc.threat_id]
            suffix_str = str(s_info["best_suffix"]).strip()
            gcg_cid = f"S2_GCG__{cs}__{tc.threat_id}__{tc.component_id}__v{idx}"
            # Combine base attack prompt with the real gradient-optimized GCG suffix
            combined_payload = f"{tc.payload} {suffix_str}"
            gcg_tc = TestCaseSpec(
                case_id=gcg_cid,
                threat_id=tc.threat_id,
                component_id=tc.component_id,
                payload=combined_payload,
                cost=tc.cost,
                attack_family="s2_gcg_transfer",
                module_name=tc.module_name,
                vulnerability_id=f"VULN:{tc.pair_id}",
            )
            gcg_cases.append((gcg_tc, s_info))

        remaining = sum(1 for (gtc, _) in gcg_cases if gtc.case_id not in records)
        print(
            f"[S2 GCG — {cs.upper()}] Surrogate={surrogate_model} ({gpu_name}) -> Target={target_model}: "
            f"{len(gcg_cases) - remaining}/{len(gcg_cases)} cached, executing {remaining}..."
        )

        done_now = 0
        for gtc, s_info in gcg_cases:
            if gtc.case_id in records:
                continue
            ex = execute_against_target_system(cs, target_model, gtc, detector)
            # Amortized GCG white-box optimization cost + real target transfer query cost
            opt_sec = float(s_info.get("elapsed_sec", 20.0))
            gcg_cost = round(ex["cost_K"] + min(3.5, 0.75 + opt_sec / 30.0), 3)

            records[gtc.case_id] = {
                "case_id": gtc.case_id,
                "pair_id": gtc.pair_id,
                "threat_id": gtc.threat_id,
                "component_id": gtc.component_id,
                "attack_family": "s2_gcg_transfer",
                "surrogate_model": surrogate_model,
                "gpu": gpu_name,
                "target_model": target_model,
                "gcg_suffix": s_info["best_suffix"],
                "gcg_best_loss": s_info.get("best_loss"),
                "gcg_opt_elapsed_sec": opt_sec,
                **ex,
                "cost_K": gcg_cost,
                "timestamp": datetime.now().isoformat(),
            }
            done_now += 1
            _save_json(
                res_path,
                {
                    "method": "S2_GCG_Standalone_Transfer",
                    "case_study": cs.upper(),
                    "surrogate_model": surrogate_model,
                    "gpu": gpu_name,
                    "target_model": target_model,
                    "total_cases": len(records),
                    "total_vulnerable": sum(1 for r in records.values() if r["is_vulnerable"]),
                    "records": records,
                },
            )
            if done_now % 10 == 0 or done_now == remaining:
                hits = sum(1 for r in records.values() if r["is_vulnerable"])
                print(
                    f"  [S2 {cs.upper()}] {len(records)}/{len(gcg_cases)} done | "
                    f"real hits={hits} | last={ex['latency_ms']:.0f}ms"
                )

    print("\n=== S2 (GCG) REAL TRANSFER EXECUTION COMPLETE ===")
    print("Tiếp theo chạy: python experiments/run_rbst_real_experiments.py")
    return out_paths


def main() -> int:
    parser = argparse.ArgumentParser(description="Execute real S2 (GCG) transfer probes on local Ollama (CS1-CS3)")
    parser.add_argument(
        "--suffix-file",
        default=str(DEFAULT_SUFFIX_FILE),
        help=f"Path to s2_gcg_suffixes_real.json downloaded from Colab (default: {DEFAULT_SUFFIX_FILE})",
    )
    parser.add_argument("--target-model", default="qwen2.5:latest")
    parser.add_argument("--cases-per-pair", type=int, default=2)
    parser.add_argument("--force-refresh", action="store_true")
    args = parser.parse_args()

    run_s2_gcg_transfer(
        suffix_file=Path(args.suffix_file),
        target_model=args.target_model,
        cases_per_pair=args.cases_per_pair,
        force_refresh=args.force_refresh,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
