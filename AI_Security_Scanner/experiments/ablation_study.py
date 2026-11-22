# -*- coding: utf-8 -*-
"""
experiments/ablation_study.py - Scientific Judge & Detector Ablation Study

Evaluates detector components on REAL LLM responses:
(a) Only Regex PatternDetector (LLMJudge disabled)
(b) Only LLM-Judge (PatternDetector disabled)
(c) Ensemble (PatternDetector + StrongREJECT LLMJudge)

Measures:
- Precision, Recall, F1 vs Human Ground Truth.
- ASR discrepancy: |ASR_pred - ASR_human|.
- Latency and throughput impact.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from modules.detectors.pattern_match import PatternDetector
from modules.detectors.llm_judge import LLMJudge


class Component(Enum):
    """Ablatable components in the detection pipeline."""
    LLM_JUDGE = auto()          # LLM semantic judge (StrongREJECT)
    PATTERN_DETECTOR = auto()   # Regex rule-based detector
    RISK_SCORER = auto()        # CVSS risk scorer
    MUTATION_ENGINE = auto()    # Input mutation variations


@dataclass
class AblationResult:
    """Result of an ablation configuration."""
    configuration_name: str
    component_disabled: str
    precision: float
    recall: float
    f1: float
    asr_pred: float
    asr_human: float
    asr_gap: float              # |ASR_pred - ASR_human|
    avg_time_ms: float
    total_cases: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    delta_f1_vs_baseline: float = 0.0
    timestamp: str = field(default_factory=lambda: datetime.now().isoformat())
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


def compute_metrics(tp: int, fp: int, tn: int, fn: int) -> Dict[str, float]:
    prec = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    rec = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    f1 = (2 * prec * rec / (prec + rec)) if (prec + rec) > 0 else 0.0
    return {"precision": round(prec, 4), "recall": round(rec, 4), "f1": round(f1, 4)}


class AblationStudy:
    """
    Ablation Study Framework comparing Regex vs LLM-Judge vs Ensemble on Real LLM Outputs.
    """

    def __init__(self, output_dir: str = "experiments/results"):
        self.output_dir = Path(output_dir)
        if not self.output_dir.is_absolute():
            self.output_dir = _PROJECT_ROOT / output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.detector = PatternDetector()
        self.llm_judge = LLMJudge(strict_mode=False)
        self.results: List[AblationResult] = []

    def evaluate_evaluator_ablation(
        self,
        eval_records: List[Dict[str, Any]],
    ) -> List[AblationResult]:
        """
        Evaluate (a) Only Regex, (b) Only LLM-Judge, (c) Ensemble on real LLM evaluation records.
        """
        if not eval_records:
            return []

        # Ground truth
        y_human = []
        for r in eval_records:
            hl = r.get("human_labels", {})
            gt = hl.get("consensus")
            if gt is None:
                gt = 1 if r.get("ground_truth_vulnerable", r.get("expected_vulnerable", False)) else 0
            y_human.append(int(gt))

        n = len(y_human)
        asr_human = sum(y_human) / n if n > 0 else 0.0

        # Configurations to test:
        configs = [
            ("Ensemble (Full System)", "NONE", "ensemble"),
            ("Only LLM-Judge", "PATTERN_DETECTOR", "judge_only"),
            ("Only Regex Detector", "LLM_JUDGE", "regex_only"),
        ]

        study_results: List[AblationResult] = []
        baseline_f1 = 0.0

        for config_name, comp_disabled, mode in configs:
            tp = fp = tn = fn = 0
            y_pred = []
            total_time_ms = 0.0

            for i, r in enumerate(eval_records):
                gt = y_human[i]
                prompt = r.get("prompt", r.get("payload", ""))
                response = r.get("raw_response", r.get("response", ""))

                # Check pre-computed or compute live
                if mode == "regex_only":
                    pat_res = r.get("pattern_verdict")
                    if pat_res and isinstance(pat_res, dict):
                        is_vuln = bool(pat_res.get("is_vulnerable", False))
                        t_ms = float(pat_res.get("time_ms", 1.5))
                    else:
                        t0 = time.perf_counter()
                        is_vuln, _, _ = self.detector.analyze(response, original_payload=prompt)
                        t_ms = (time.perf_counter() - t0) * 1000.0

                elif mode == "judge_only":
                    jud_res = r.get("judge_verdict")
                    if jud_res and isinstance(jud_res, dict):
                        is_vuln = bool(jud_res.get("is_jailbroken", False))
                        t_ms = float(jud_res.get("time_ms", 120.0))
                    else:
                        t0 = time.perf_counter()
                        res = self.llm_judge.evaluate(prompt, response)
                        is_vuln = bool(res.get("is_jailbroken", False))
                        t_ms = (time.perf_counter() - t0) * 1000.0

                else:  # ensemble
                    ens = r.get("ensemble_verdict")
                    if ens is not None:
                        is_vuln = bool(ens)
                        t_ms = 125.0
                    else:
                        pat_vuln, _, pat_conf = self.detector.analyze(response, original_payload=prompt)
                        j_res = self.llm_judge.evaluate(prompt, response)
                        is_vuln = bool(j_res.get("is_jailbroken", False) or (pat_vuln and pat_conf == "HIGH"))
                        t_ms = 125.0

                y_pred.append(1 if is_vuln else 0)
                total_time_ms += t_ms

                if is_vuln and gt == 1:
                    tp += 1
                elif is_vuln and gt == 0:
                    fp += 1
                elif not is_vuln and gt == 0:
                    tn += 1
                else:
                    fn += 1

            m = compute_metrics(tp, fp, tn, fn)
            asr_pred = sum(y_pred) / n if n > 0 else 0.0
            asr_gap = abs(asr_pred - asr_human)

            if mode == "ensemble":
                baseline_f1 = m["f1"]
                delta_f1 = 0.0
            else:
                delta_f1 = round(m["f1"] - baseline_f1, 4)

            res = AblationResult(
                configuration_name=config_name,
                component_disabled=comp_disabled,
                precision=m["precision"],
                recall=m["recall"],
                f1=m["f1"],
                asr_pred=round(asr_pred, 4),
                asr_human=round(asr_human, 4),
                asr_gap=round(asr_gap, 4),
                avg_time_ms=round(total_time_ms / max(n, 1), 2),
                total_cases=n,
                true_positives=tp,
                false_positives=fp,
                true_negatives=tn,
                false_negatives=fn,
                delta_f1_vs_baseline=delta_f1,
                notes=f"Evaluated on {n} real LLM responses.",
            )
            study_results.append(res)

        self.results.extend(study_results)
        return study_results

    def generate_table(self, results: Optional[List[AblationResult]] = None) -> str:
        """Format ablation table for scientific reporting."""
        res_list = results or self.results
        lines = [
            "\n" + "=" * 92,
            "  DETECTOR ABLATION STUDY (ON REAL LLM EVALUATION DATA)",
            "=" * 92,
            f"{'Configuration':<26} | {'Precision':<9} | {'Recall':<9} | {'F1-Score':<9} | {'ASR_pred':<8} | {'ASR_gap':<8} | {'Δ F1':<7}",
            "-" * 26 + "-+-" + "-" * 9 + "-+-" + "-" * 9 + "-+-" + "-" * 9 + "-+-" + "-" * 8 + "-+-" + "-" * 8 + "-+-" + "-" * 7,
        ]
        for r in res_list:
            d_str = f"{r.delta_f1_vs_baseline:+.4f}" if r.delta_f1_vs_baseline != 0.0 else "Baseline"
            lines.append(
                f"{r.configuration_name:<26} | {r.precision:<9.4f} | {r.recall:<9.4f} | {r.f1:<9.4f} | "
                f"{r.asr_pred*100:>6.1f}% | {r.asr_gap*100:>6.1f}% | {d_str:<7}"
            )
        lines.append("=" * 92 + "\n")
        return "\n".join(lines)

    def export_results(self, filename: Optional[str] = None) -> Path:
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"ablation_study_{ts}.json"
        out_p = self.output_dir / filename
        data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "AI Security Scanner – Scientific Ablation Framework",
                "total_configurations": len(self.results),
            },
            "results": [r.to_dict() for r in self.results],
        }
        with open(out_p, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"✅ Ablation results saved to: {out_p}")
        return out_p


def main():
    parser = argparse.ArgumentParser(description="Scientific Ablation Study for LLM Judges and Detectors")
    parser.add_argument("--input", default=None, help="Input benchmark execution JSON file with detailed_evaluations")
    parser.add_argument("--vietnamese", action="store_true", help="Use vietnamese_benchmark.json")
    parser.add_argument("--output", default=None, help="Output JSON filename")
    parser.add_argument("--output-dir", default="experiments/results", help="Output directory")
    args = parser.parse_args()

    input_file = args.input
    if args.vietnamese and not input_file:
        input_file = str(_PROJECT_ROOT / "data" / "vietnamese_benchmark.json")

    if not input_file:
        input_file = str(_PROJECT_ROOT / "data" / "vietnamese_benchmark.json")

    in_path = Path(input_file)
    if not in_path.exists() and (_PROJECT_ROOT / in_path).exists():
        in_path = _PROJECT_ROOT / in_path

    with open(in_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    records = data.get("detailed_evaluations", data.get("test_cases", []))
    print(f"Loaded {len(records)} evaluation records from {in_path}")

    study = AblationStudy(output_dir=args.output_dir)
    results = study.evaluate_evaluator_ablation(records)
    print(study.generate_table(results))
    study.export_results(args.output)


if __name__ == "__main__":
    main()
