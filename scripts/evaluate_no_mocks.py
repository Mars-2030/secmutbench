#!/usr/bin/env python3
"""
No-Mock Evaluation for SecMutBench

Runs evaluation WITHOUT mock injection to compare:
1. How tests perform with real execution vs. mock objects
2. Whether tests rely on mock state vs. actual behavior

WARNING: Without mocks, tests may execute real operations including:
- File I/O
- Network requests
- Database connections (if configured)
- System commands (blocked by SafeOS wrapper, but be cautious)

Use this only on safe samples or in isolated environments.

Usage:
    python scripts/evaluate_no_mocks.py --max-samples 10
    python scripts/evaluate_no_mocks.py --cwe CWE-89 --output results/no_mocks/
    python scripts/evaluate_no_mocks.py --dataset data/dataset.json --compare-mocks
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.evaluate import (
    load_benchmark,
    evaluate_generated_tests,
    calculate_metrics,
    aggregate_by_cwe,
    calculate_kill_breakdown,
)
from evaluation.test_runner import TestRunner
from evaluation.mutation_engine import MutationEngine


def evaluate_with_mocks(
    benchmark: List[Dict],
    max_samples: int = None,
) -> Dict[str, Any]:
    """Run evaluation WITH mock injection (standard mode)."""
    runner = TestRunner(use_mocks=True)
    engine = MutationEngine()

    results = []
    for i, sample in enumerate(benchmark[:max_samples] if max_samples else benchmark):
        tests = sample.get("security_tests", "")
        if not tests:
            continue

        if (i + 1) % 10 == 0:
            print(f"  [Mocks] Progress: {i + 1}/{len(benchmark)}")

        result = evaluate_generated_tests(sample, tests, engine, runner)
        results.append(result)

    return {
        "mode": "with_mocks",
        "samples": len(results),
        "metrics": calculate_metrics(results),
        "by_cwe": aggregate_by_cwe(results),
        "kill_breakdown": calculate_kill_breakdown(results),
        "details": results,
    }


def evaluate_without_mocks(
    benchmark: List[Dict],
    max_samples: int = None,
) -> Dict[str, Any]:
    """Run evaluation WITHOUT mock injection."""
    runner = TestRunner(use_mocks=False)
    engine = MutationEngine()

    results = []
    for i, sample in enumerate(benchmark[:max_samples] if max_samples else benchmark):
        tests = sample.get("security_tests", "")
        if not tests:
            continue

        if (i + 1) % 10 == 0:
            print(f"  [No Mocks] Progress: {i + 1}/{len(benchmark)}")

        result = evaluate_generated_tests(sample, tests, engine, runner)
        results.append(result)

    return {
        "mode": "without_mocks",
        "samples": len(results),
        "metrics": calculate_metrics(results),
        "by_cwe": aggregate_by_cwe(results),
        "kill_breakdown": calculate_kill_breakdown(results),
        "details": results,
    }


def compare_results(with_mocks: Dict, without_mocks: Dict) -> Dict[str, Any]:
    """Compare results from mock vs no-mock evaluation."""
    comparison = {
        "samples_compared": min(with_mocks["samples"], without_mocks["samples"]),
        "with_mocks": {
            "mutation_score": with_mocks["metrics"].get("avg_mutation_score", 0),
            "vuln_detection": with_mocks["metrics"].get("avg_vuln_detection", 0),
        },
        "without_mocks": {
            "mutation_score": without_mocks["metrics"].get("avg_mutation_score", 0),
            "vuln_detection": without_mocks["metrics"].get("avg_vuln_detection", 0),
        },
        "delta": {
            "mutation_score": (
                with_mocks["metrics"].get("avg_mutation_score", 0) -
                without_mocks["metrics"].get("avg_mutation_score", 0)
            ),
            "vuln_detection": (
                with_mocks["metrics"].get("avg_vuln_detection", 0) -
                without_mocks["metrics"].get("avg_vuln_detection", 0)
            ),
        },
    }

    # Per-CWE comparison
    cwe_comparison = {}
    for cwe in with_mocks.get("by_cwe", {}):
        if cwe in without_mocks.get("by_cwe", {}):
            cwe_comparison[cwe] = {
                "with_mocks_ms": with_mocks["by_cwe"][cwe].get("avg_mutation_score", 0),
                "without_mocks_ms": without_mocks["by_cwe"][cwe].get("avg_mutation_score", 0),
                "delta_ms": (
                    with_mocks["by_cwe"][cwe].get("avg_mutation_score", 0) -
                    without_mocks["by_cwe"][cwe].get("avg_mutation_score", 0)
                ),
            }
    comparison["by_cwe"] = cwe_comparison

    return comparison


def print_report(
    with_mocks: Dict = None,
    without_mocks: Dict = None,
    comparison: Dict = None,
):
    """Print formatted comparison report."""
    print("=" * 70)
    print("MOCK VS NO-MOCK EVALUATION COMPARISON")
    print("=" * 70)

    if with_mocks:
        print(f"\n[WITH MOCKS]")
        print(f"  Samples: {with_mocks['samples']}")
        print(f"  Mutation Score: {with_mocks['metrics'].get('avg_mutation_score', 0):.1%}")
        print(f"  Vuln Detection: {with_mocks['metrics'].get('avg_vuln_detection', 0):.1%}")

    if without_mocks:
        print(f"\n[WITHOUT MOCKS]")
        print(f"  Samples: {without_mocks['samples']}")
        print(f"  Mutation Score: {without_mocks['metrics'].get('avg_mutation_score', 0):.1%}")
        print(f"  Vuln Detection: {without_mocks['metrics'].get('avg_vuln_detection', 0):.1%}")

    if comparison:
        print(f"\n[COMPARISON]")
        print(f"  Δ Mutation Score: {comparison['delta']['mutation_score']:+.1%}")
        print(f"  Δ Vuln Detection: {comparison['delta']['vuln_detection']:+.1%}")

        if comparison.get("by_cwe"):
            print(f"\n  Per-CWE Δ Mutation Score:")
            for cwe, stats in sorted(comparison["by_cwe"].items()):
                delta = stats["delta_ms"]
                print(f"    {cwe}: {delta:+.1%}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Run evaluation with and without mock injection"
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to dataset file"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum samples to evaluate"
    )
    parser.add_argument(
        "--cwe",
        default=None,
        help="Filter by CWE"
    )
    parser.add_argument(
        "--difficulty",
        choices=["easy", "medium", "hard"],
        default=None,
        help="Filter by difficulty"
    )
    parser.add_argument(
        "--compare-mocks",
        action="store_true",
        help="Run both with and without mocks and compare"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output directory for results"
    )

    args = parser.parse_args()

    # Load benchmark
    print("Loading benchmark...")
    benchmark = load_benchmark(
        path=args.dataset,
        cwe=args.cwe,
        difficulty=args.difficulty,
    )
    print(f"Loaded {len(benchmark)} samples")

    if args.max_samples:
        print(f"Limiting to {args.max_samples} samples")

    results = {}

    if args.compare_mocks:
        # Run both modes and compare
        print("\n--- Evaluating WITH mocks ---")
        results["with_mocks"] = evaluate_with_mocks(benchmark, args.max_samples)

        print("\n--- Evaluating WITHOUT mocks ---")
        results["without_mocks"] = evaluate_without_mocks(benchmark, args.max_samples)

        results["comparison"] = compare_results(
            results["with_mocks"],
            results["without_mocks"]
        )

        print_report(
            with_mocks=results["with_mocks"],
            without_mocks=results["without_mocks"],
            comparison=results["comparison"],
        )
    else:
        # Run only without mocks
        print("\n--- Evaluating WITHOUT mocks ---")
        results["without_mocks"] = evaluate_without_mocks(benchmark, args.max_samples)

        print_report(without_mocks=results["without_mocks"])

    # Save results
    if args.output:
        os.makedirs(args.output, exist_ok=True)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_path = os.path.join(args.output, f"no_mocks_results_{timestamp}.json")

        # Remove details for smaller file (can be very large)
        save_results = {k: v for k, v in results.items() if k != "details"}
        if "with_mocks" in save_results:
            save_results["with_mocks"] = {
                k: v for k, v in save_results["with_mocks"].items() if k != "details"
            }
        if "without_mocks" in save_results:
            save_results["without_mocks"] = {
                k: v for k, v in save_results["without_mocks"].items() if k != "details"
            }

        with open(output_path, "w") as f:
            json.dump(save_results, f, indent=2)
        print(f"\nResults saved to: {output_path}")


if __name__ == "__main__":
    main()
