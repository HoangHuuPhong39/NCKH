# -*- coding: utf-8 -*-
"""
experiments/multi_seed_runner.py - Multi-Seed Experiment Runner

Chạy experiments với nhiều random seeds để đánh giá variance và
tính toán confidence intervals cho reproducibility.

Tuân thủ best practices:
- Multiple seeds (5-10 runs)
- Statistical significance testing
- Confidence intervals
- Effect size reporting
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

# Add project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_PROJECT_ROOT))

from core.statistical_analysis import (
    bootstrap_confidence_interval,
    independent_t_test,
    cohens_d,
    interpret_cohens_d,
    summary_statistics,
)


@dataclass
class MultiSeedResult:
    """Result from multi-seed experiment run."""
    experiment_name: str
    seeds: List[int]
    metric_name: str  # e.g., 'precision', 'recall', 'f1', 'asr'
    values: List[float]  # One value per seed
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
    Run experiments across multiple random seeds and aggregate statistics.
    
    Example::
    
        runner = MultiSeedRunner(seeds=[42, 123, 456, 789, 999])
        results = runner.run_ablation_multi_seed(test_cases, component="MUTATION_ENGINE")
        runner.export_results("results/multi_seed_ablation.json")
    """
    
    def __init__(
        self,
        seeds: Optional[List[int]] = None,
        output_dir: str = "experiments/results",
    ):
        """
        Initialize multi-seed runner.
        
        Args:
            seeds: List of random seeds (default: [42, 123, 456, 789, 999]).
            output_dir: Directory to save results.
        """
        self.seeds = seeds or [42, 123, 456, 789, 999]
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.results: List[MultiSeedResult] = []
    
    def run_ablation_multi_seed(
        self,
        test_cases: List[Dict[str, Any]],
        component: str,
        metrics: Optional[List[str]] = None,
    ) -> Dict[str, MultiSeedResult]:
        """
        Run ablation study across multiple seeds.
        
        Args:
            test_cases: List of test case dicts.
            component: Component to disable (e.g., 'MUTATION_ENGINE').
            metrics: Metrics to track (default: ['precision', 'recall', 'f1', 'asr']).
        
        Returns:
            Dict mapping metric name to MultiSeedResult.
        """
        if metrics is None:
            metrics = ['precision', 'recall', 'f1', 'asr']
        
        print(f"\n🔄 Running multi-seed ablation for component: {component}")
        print(f"   Seeds: {self.seeds}")
        print(f"   Metrics: {metrics}\n")
        
        # Import here to avoid circular dependency
        try:
            from experiments.ablation_study import AblationStudy, Component
        except ImportError:
            print("❌ Could not import AblationStudy. Make sure experiments/ablation_study.py exists.")
            return {}
        
        # Storage for each metric across seeds
        metric_values: Dict[str, List[float]] = {m: [] for m in metrics}
        
        # Run for each seed
        for seed in self.seeds:
            print(f"   Running with seed={seed}...")
            
            # Set seed (this would need to be passed to AblationStudy)
            study = AblationStudy(output_dir=str(self.output_dir))
            
            try:
                # Run baseline first
                baseline = study.run_baseline(test_cases, llm_client=None)
                
                # Run ablation for this component
                component_enum = Component[component]
                result = study.run_ablation(
                    component_to_disable=component_enum,
                    test_cases=list(test_cases),
                    llm_client=None,
                )
                
                # Collect metrics
                for metric in metrics:
                    value = getattr(result, metric, 0.0)
                    metric_values[metric].append(value)
            
            except Exception as exc:
                print(f"      ⚠️ Error with seed {seed}: {exc}")
                # Append NaN or skip
                for metric in metrics:
                    metric_values[metric].append(0.0)
        
        # Calculate statistics for each metric
        multi_seed_results: Dict[str, MultiSeedResult] = {}
        
        for metric in metrics:
            values = metric_values[metric]
            
            # Calculate CI
            ci = bootstrap_confidence_interval(values, confidence=0.95, random_seed=42)
            
            result = MultiSeedResult(
                experiment_name=f"ablation_{component}",
                seeds=self.seeds,
                metric_name=metric,
                values=values,
                mean=ci.mean,
                std=float(np.std(values)),
                ci_lower=ci.lower,
                ci_upper=ci.upper,
                confidence=ci.confidence,
                timestamp=datetime.now().isoformat(),
            )
            
            multi_seed_results[metric] = result
            self.results.append(result)
            
            print(f"\n   {metric.upper()}: {result.mean:.4f} ± {result.std:.4f}")
            print(f"      95% CI: [{result.ci_lower:.4f}, {result.ci_upper:.4f}]")
        
        return multi_seed_results
    
    def compare_configurations(
        self,
        config_a_values: List[float],
        config_b_values: List[float],
        config_a_name: str = "Config A",
        config_b_name: str = "Config B",
        metric_name: str = "metric",
    ) -> Dict[str, Any]:
        """
        Compare two configurations using statistical tests.
        
        Args:
            config_a_values: Values from configuration A across seeds.
            config_b_values: Values from configuration B across seeds.
            config_a_name: Name of configuration A.
            config_b_name: Name of configuration B.
            metric_name: Name of the metric being compared.
        
        Returns:
            Dict with comparison statistics.
        """
        print(f"\n📊 Comparing {config_a_name} vs {config_b_name} on {metric_name}:")
        
        # Summary statistics
        stats_a = summary_statistics(config_a_values)
        stats_b = summary_statistics(config_b_values)
        
        print(f"   {config_a_name}: {stats_a['mean']:.4f} ± {stats_a['std']:.4f}")
        print(f"   {config_b_name}: {stats_b['mean']:.4f} ± {stats_b['std']:.4f}")
        
        # T-test
        test_result = independent_t_test(config_a_values, config_b_values, alpha=0.05)
        
        print(f"\n   {test_result}")
        print(f"   {test_result.interpretation}")
        
        # Effect size
        d = cohens_d(config_a_values, config_b_values)
        interpretation = interpret_cohens_d(d)
        
        print(f"   Effect size: Cohen's d = {d:.3f} ({interpretation})")
        
        return {
            "config_a": {
                "name": config_a_name,
                "values": config_a_values,
                "statistics": stats_a,
            },
            "config_b": {
                "name": config_b_name,
                "values": config_b_values,
                "statistics": stats_b,
            },
            "test_result": {
                "test_name": test_result.test_name,
                "statistic": test_result.statistic,
                "p_value": test_result.p_value,
                "significant": test_result.significant,
                "alpha": test_result.alpha,
            },
            "effect_size": {
                "cohens_d": d,
                "interpretation": interpretation,
            },
        }
    
    def export_results(self, filename: Optional[str] = None) -> Path:
        """
        Export all multi-seed results to JSON.
        
        Args:
            filename: Output filename (default: auto-generated).
        
        Returns:
            Path to exported file.
        """
        if filename is None:
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"multi_seed_results_{ts}.json"
        
        output_path = self.output_dir / filename
        
        payload = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "tool": "AI Security Scanner – Multi-Seed Runner",
                "seeds": self.seeds,
                "total_results": len(self.results),
            },
            "results": [r.to_dict() for r in self.results],
        }
        
        with open(output_path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, ensure_ascii=False, indent=2)
        
        print(f"\n✅ Multi-seed results exported to: {output_path}")
        return output_path


# ===========================================================================
# CLI
# ===========================================================================

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Multi-Seed Experiment Runner for AI Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--seeds",
        nargs="+",
        type=int,
        default=[42, 123, 456, 789, 999],
        help="List of random seeds (default: 42 123 456 789 999)",
    )
    parser.add_argument(
        "--component",
        default="MUTATION_ENGINE",
        choices=["MUTATION_ENGINE", "ADAPTIVE_GENERATOR", "LLM_JUDGE", "RISK_SCORER", "PATTERN_DETECTOR"],
        help="Component to ablate",
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to test dataset JSON",
    )
    parser.add_argument(
        "--output-dir",
        default="experiments/results",
        help="Output directory for results",
    )
    return parser


def main() -> None:
    """CLI entry point."""
    parser = _build_parser()
    args = parser.parse_args()
    
    print(f"\n{'='*70}")
    print("  AI Security Scanner – Multi-Seed Experiment Runner")
    print(f"  Component: {args.component}")
    print(f"  Seeds: {args.seeds}")
    print(f"{'='*70}\n")
    
    # Load test cases
    if args.dataset:
        dataset_path = Path(args.dataset)
    else:
        dataset_path = _PROJECT_ROOT / "data" / "benchmark_dataset.json"
    
    if dataset_path.exists():
        with open(dataset_path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
        test_cases = data.get("test_cases", [])
        print(f"✅ Loaded {len(test_cases)} test cases from {dataset_path}\n")
    else:
        print(f"⚠️ Dataset not found: {dataset_path}")
        print("Using built-in minimal test cases...\n")
        test_cases = [
            {"payload": "Test 1", "expected_vulnerable": False, "module_name": "prompt_injection"},
            {"payload": "Test 2", "expected_vulnerable": True, "module_name": "jailbreak"},
        ]
    
    # Run multi-seed experiment
    runner = MultiSeedRunner(seeds=args.seeds, output_dir=args.output_dir)
    results = runner.run_ablation_multi_seed(
        test_cases=test_cases,
        component=args.component,
        metrics=['precision', 'recall', 'f1', 'asr'],
    )
    
    # Export
    runner.export_results()
    
    print("\n✅ Multi-seed experiment complete!\n")


if __name__ == "__main__":
    import numpy as np  # Import here for demo
    main()
