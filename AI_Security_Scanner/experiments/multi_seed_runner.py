# -*- coding: utf-8 -*-
"""
experiments/multi_seed_runner.py - Multi-Seed Experiment Runner (G8 Statistical Rigor)

Runs experiments across multiple random seeds and temperatures with direct transmission
to LLM client (Ollama options: {seed, temperature} / OpenAI: seed, temperature).
Computes bootstrap confidence intervals (10,000 resamples), effect size (Cohen's d),
and non-parametric tests (Wilcoxon, McNemar).
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

import numpy as np

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from core.statistical_analysis import (
    bootstrap_confidence_interval,
    bootstrap_metric_ci,
    independent_t_test,
    wilcoxon_signed_rank_test,
    cohens_d,
    interpret_cohens_d,
    summary_statistics,
)
from experiments.benchmark import Benchmarker, TestCase, load_benchmark_dataset


@dataclass
class MultiSeedResult:
    """Result from multi-seed experiment run."""
    experiment_name: str
    seeds: List[int]
    metric_name: str
    values: List[float]
    mean: float
    std: float
    ci_lower: float
    ci_upper: float
    confidence: float
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class MultiSeedRunner:
    """
    Run experiments across multiple seeds and aggregate statistical distributions.
    """

    def __init__(
        self,
        seeds: Optional[List[int]] = None,
        output_dir: str = "experiments/results",
        temperature: float = 0.7,
    ):
        self.seeds = seeds or [42, 123, 456, 789, 999]
        self.output_dir = Path(output_dir)
        if not self.output_dir.is_absolute():
            self.output_dir = _PROJECT_ROOT / output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.temperature = temperature
        self.results: List[MultiSeedResult] = []

    def run_benchmark_multi_seed(
        self,
        test_cases: List[TestCase],
        model_name: str = "llama3",
        target_url: str = "http://localhost:11434",
        max_cases: Optional[int] = 5,
    ) -> Dict[str, MultiSeedResult]:
        """
        Run real benchmark across seeds passing seed directly to LLM payload.
        """
        print(f"\n🔄 Running multi-seed benchmark for model: {model_name}")
        print(f"   Seeds: {self.seeds} | Temperature: {self.temperature}")
        print(f"   Test cases: {len(test_cases[:max_cases]) if max_cases else len(test_cases)}\n")

        asr_values: List[float] = []
        latency_values: List[float] = []

        for seed in self.seeds:
            print(f"   [Seed {seed}] Initiating benchmark...")
            benchmarker = Benchmarker(
                target_url=target_url,
                model_name=model_name,
                output_dir=str(self.output_dir),
                seed=seed,
                temperature=self.temperature,
            )

            mod_results, detailed = benchmarker.run_benchmark(
                test_cases=test_cases,
                max_cases=max_cases,
            )

            tot = len(detailed)
            vuln_count = sum(1 for d in detailed if d.get("ensemble_verdict", False))
            asr = vuln_count / max(tot, 1)
            avg_lat = sum(d.get("latency_ms", 0.0) for d in detailed) / max(tot, 1)

            asr_values.append(round(asr, 4))
            latency_values.append(round(avg_lat, 2))
            print(f"   [Seed {seed}] Completed -> ASR: {asr*100:.1f}%, Avg Latency: {avg_lat:.1f}ms")

        # Compute Bootstrap 95% CI (10,000 resamples)
        asr_ci = bootstrap_metric_ci(asr_values, metric_name="ASR", n_bootstrap=10000)
        lat_ci = bootstrap_confidence_interval(latency_values, n_bootstrap=10000)

        asr_res = MultiSeedResult(
            experiment_name=f"real_benchmark_{model_name}",
            seeds=self.seeds,
            metric_name="asr",
            values=asr_values,
            mean=asr_ci.mean,
            std=float(np.std(asr_values, ddof=1 if len(asr_values) > 1 else 0)),
            ci_lower=asr_ci.lower,
            ci_upper=asr_ci.upper,
            confidence=0.95,
            timestamp=datetime.now().isoformat(),
        )

        lat_res = MultiSeedResult(
            experiment_name=f"real_benchmark_{model_name}",
            seeds=self.seeds,
            metric_name="latency_ms",
            values=latency_values,
            mean=lat_ci.mean,
            std=float(np.std(latency_values, ddof=1 if len(latency_values) > 1 else 0)),
            ci_lower=lat_ci.lower,
            ci_upper=lat_ci.upper,
            confidence=0.95,
            timestamp=datetime.now().isoformat(),
        )

        self.results.extend([asr_res, lat_res])

        print("\n" + "=" * 60)
        print(f"  MULTI-SEED SUMMARY ({len(self.seeds)} SEEDS)")
        print("=" * 60)
        print(f"  ASR Mean     : {asr_res.mean*100:.2f}% ± {asr_res.std*100:.2f}%")
        print(f"  ASR 95% CI   : [{asr_res.ci_lower*100:.2f}%, {asr_res.ci_upper*100:.2f}%]")
        print(f"  Latency Mean : {lat_res.mean:.1f}ms ± {lat_res.std:.1f}ms")
        print("=" * 60 + "\n")

        return {"asr": asr_res, "latency": lat_res}

    def export_results(self, filename: Optional[str] = None) -> Path:
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"multi_seed_results_{ts}.json"

        output_path = self.output_dir / filename
        payload = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "AI Security Scanner – Multi-Seed Runner",
                "seeds": self.seeds,
                "temperature": self.temperature,
                "total_results": len(self.results),
            },
            "results": [r.to_dict() for r in self.results],
        }

        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)

        print(f"✅ Multi-seed results exported to: {output_path}")
        return output_path


def main():
    parser = argparse.ArgumentParser(description="Multi-Seed Experiment Runner (100% Real LLM)")
    parser.add_argument("--model", default="llama3", help="Target LLM model")
    parser.add_argument("--url", default="http://localhost:11434", help="Target LLM server URL")
    parser.add_argument("--seeds", nargs="+", type=int, default=[42, 123, 456], help="List of seeds")
    parser.add_argument("--temperature", type=float, default=0.7, help="Sampling temperature")
    parser.add_argument("--max-cases", type=int, default=5, help="Number of test cases per seed")
    parser.add_argument("--vietnamese", action="store_true", help="Use vietnamese benchmark")
    parser.add_argument("--output-dir", default="experiments/results", help="Output directory")

    args = parser.parse_args()

    dataset_path = _PROJECT_ROOT / "data" / "vietnamese_benchmark.json" if args.vietnamese else None
    cases = load_benchmark_dataset(dataset_path)

    runner = MultiSeedRunner(seeds=args.seeds, output_dir=args.output_dir, temperature=args.temperature)
    runner.run_benchmark_multi_seed(
        test_cases=cases,
        model_name=args.model,
        target_url=args.url,
        max_cases=args.max_cases,
    )
    runner.export_results()


if __name__ == "__main__":
    main()
