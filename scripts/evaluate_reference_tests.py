#!/usr/bin/env python3
"""
Evaluate Reference Tests for SecMutBench

Evaluates the human-written reference security tests in the benchmark to
establish an upper bound for test quality metrics.

Reference tests serve as a baseline for:
1. Maximum achievable mutation score with expert-written tests
2. Security mutation score (SMS) upper bound
3. Kill breakdown distribution for well-written tests

Usage:
    python scripts/evaluate_reference_tests.py
    python scripts/evaluate_reference_tests.py --max-samples 50
    python scripts/evaluate_reference_tests.py --cwe CWE-89 --output results/reference_baseline.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.evaluate import (
    load_benchmark,
    evaluate_generated_tests,
    calculate_metrics,
    aggregate_by_cwe,
    aggregate_by_difficulty,
    aggregate_by_operator,
    calculate_kill_breakdown,
    calculate_security_precision,
    format_metrics_report,
)
from evaluation.test_runner import TestRunner
from evaluation.mutation_engine import MutationEngine


def evaluate_reference_tests(
    benchmark: List[Dict],
    max_samples: int = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Evaluate reference security tests in the benchmark.

    Args:
        benchmark: List of benchmark samples with reference tests
        max_samples: Maximum samples to evaluate
        verbose: Print detailed progress

    Returns:
        Dict with evaluation results
    """
    engine = MutationEngine()
    runner = TestRunner()

    results = []
    samples_with_tests = 0
    samples_without_tests = 0

    samples = benchmark[:max_samples] if max_samples else benchmark

    for i, sample in enumerate(samples):
        reference_tests = sample.get("security_tests", "")

        if not reference_tests or reference_tests.strip() == "":
            samples_without_tests += 1
            continue

        samples_with_tests += 1

        if verbose and (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(samples)} (with tests: {samples_with_tests})")

        try:
            result = evaluate_generated_tests(
                sample,
                reference_tests,
                engine,
                runner,
            )
            results.append(result)

            if verbose:
                ms = result["metrics"].get("mutation_score", 0)
                if ms is not None:
                    print(f"    {sample['id']}: MS={ms:.1%}")
        except Exception as e:
            if verbose:
                print(f"    {sample.get('id')}: Error - {str(e)[:50]}")

    # Compute aggregated metrics
    summary = calculate_metrics(results)
    summary["model"] = "reference_tests"
    summary["samples_with_tests"] = samples_with_tests
    summary["samples_without_tests"] = samples_without_tests

    by_cwe = aggregate_by_cwe(results)
    by_difficulty = aggregate_by_difficulty(results)
    by_operator = aggregate_by_operator(results)
    kill_breakdown = calculate_kill_breakdown(results)
    security_precision = calculate_security_precision(results)

    # Add kill breakdown to summary
    summary["kill_breakdown"] = kill_breakdown
    summary["security_mutation_score"] = kill_breakdown.get("security_mutation_score")
    summary["incidental_score"] = kill_breakdown.get("incidental_score")
    summary["crash_score"] = kill_breakdown.get("crash_score")
    summary["security_precision"] = security_precision.get("security_precision")

    return {
        "summary": summary,
        "by_cwe": by_cwe,
        "by_difficulty": by_difficulty,
        "by_operator": by_operator,
        "kill_breakdown": kill_breakdown,
        "security_precision": security_precision,
        "details": results,
    }


def print_report(result: Dict[str, Any]):
    """Print formatted evaluation report."""
    summary = result["summary"]
    kill_breakdown = result.get("kill_breakdown", {})

    print("=" * 70)
    print("REFERENCE TEST EVALUATION (Upper Bound)")
    print("=" * 70)

    print(f"\nSamples:")
    print(f"  With Reference Tests:    {summary.get('samples_with_tests', 0)}")
    print(f"  Without Reference Tests: {summary.get('samples_without_tests', 0)}")
    print(f"  Total Evaluated:         {summary.get('samples', 0)}")

    print(f"\nMutation Testing Metrics:")
    print(f"  Avg Mutation Score (MS):     {summary.get('avg_mutation_score', 0):.1%}")
    print(f"  Security MS (Semantic):      {kill_breakdown.get('security_mutation_score', 0):.1%}")
    print(f"  Incidental MS:               {kill_breakdown.get('incidental_score', 0):.1%}")
    print(f"  Crash MS:                    {kill_breakdown.get('crash_score', 0):.1%}")

    print(f"\nSecurity Precision:")
    sp = result.get("security_precision", {})
    print(f"  Security Precision:          {sp.get('security_precision', 0):.1%}")
    print(f"  (Semantic kills / Total assertion kills)")

    print(f"\nVulnerability Detection:")
    print(f"  Avg Vuln Detection Rate:     {summary.get('avg_vuln_detection', 0):.1%}")
    print(f"  Samples with Perfect Detect: {summary.get('vuln_detection_count', 0)}")

    # Kill breakdown details
    print(f"\nKill Breakdown (absolute counts):")
    print(f"  Semantic Kills:     {kill_breakdown.get('semantic_kills', 0)}")
    print(f"  Functional Kills:   {kill_breakdown.get('functional_kills', 0)}")
    print(f"  Incidental Kills:   {kill_breakdown.get('incidental_kills', 0)}")
    print(f"  Crash Kills:        {kill_breakdown.get('crash_kills', 0)}")
    print(f"  Other Kills:        {kill_breakdown.get('other_kills', 0)}")
    print(f"  Total Killed:       {kill_breakdown.get('total_killed', 0)}")
    print(f"  Total Mutants:      {kill_breakdown.get('total_mutants', 0)}")

    # Per-CWE breakdown
    if result.get("by_cwe"):
        print(f"\nPer-CWE Mutation Score:")
        print(f"  {'CWE':<15} {'Samples':>8} {'MS':>8} {'Vuln Det':>10}")
        print("-" * 45)

        for cwe, stats in sorted(result["by_cwe"].items()):
            print(f"  {cwe:<15} {stats.get('samples', 0):>8} "
                  f"{stats.get('avg_mutation_score', 0):>7.1%} "
                  f"{stats.get('avg_vuln_detection', 0):>9.1%}")

    # Per-difficulty breakdown
    if result.get("by_difficulty"):
        print(f"\nPer-Difficulty Mutation Score:")
        print(f"  {'Difficulty':<12} {'Samples':>8} {'MS':>8}")
        print("-" * 32)

        for diff, stats in sorted(result["by_difficulty"].items()):
            print(f"  {diff:<12} {stats.get('samples', 0):>8} "
                  f"{stats.get('avg_mutation_score', 0):>7.1%}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate reference security tests in SecMutBench"
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
        "--output",
        default=None,
        help="Output JSON file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress"
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

    # Count samples with reference tests
    with_tests = sum(1 for s in benchmark if s.get("security_tests", "").strip())
    print(f"Samples with reference tests: {with_tests}")

    if with_tests == 0:
        print("Error: No samples have reference tests.")
        sys.exit(1)

    # Evaluate
    print("\nEvaluating reference tests...")
    result = evaluate_reference_tests(
        benchmark,
        max_samples=args.max_samples,
        verbose=args.verbose,
    )

    # Print report
    print_report(result)

    # Save results
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)

        # Create a version without full details for smaller file
        save_result = {k: v for k, v in result.items() if k != "details"}

        with open(args.output, "w") as f:
            json.dump(save_result, f, indent=2)
        print(f"\nResults saved to: {args.output}")

        # Also save full details separately if needed
        details_path = args.output.replace(".json", "_details.json")
        with open(details_path, "w") as f:
            json.dump({"details": result.get("details", [])}, f, indent=2)
        print(f"Details saved to: {details_path}")


if __name__ == "__main__":
    main()
