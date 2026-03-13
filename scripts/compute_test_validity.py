#!/usr/bin/env python3
"""
Compute Test Validity Metrics for SecMutBench

Aggregates test validity statistics from evaluation results to determine:
1. Valid test rate: Tests that compile and run successfully
2. Invalid test breakdown: Syntax errors, import errors, runtime errors

Usage:
    python scripts/compute_test_validity.py --results results/baseline_results.json
    python scripts/compute_test_validity.py --results-dir results/
    python scripts/compute_test_validity.py --results results/*.json --output results/test_validity.json
"""

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
import glob

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def extract_error_type(error_msg: str) -> str:
    """
    Extract error type from error message.

    Args:
        error_msg: Full error message

    Returns:
        Error type category
    """
    if not error_msg:
        return "unknown"

    error_lower = error_msg.lower()

    # Syntax errors
    if "syntaxerror" in error_lower or "invalid syntax" in error_lower:
        return "syntax"

    # Import errors
    if "importerror" in error_lower or "modulenotfounderror" in error_lower:
        return "import"

    # Name errors (undefined variables)
    if "nameerror" in error_lower:
        return "name"

    # Type errors
    if "typeerror" in error_lower:
        return "type"

    # Attribute errors
    if "attributeerror" in error_lower:
        return "attribute"

    # Indentation errors
    if "indentationerror" in error_lower:
        return "indentation"

    # Timeout
    if "timeout" in error_lower:
        return "timeout"

    # Runtime errors
    if "runtimeerror" in error_lower:
        return "runtime"

    # If error contains any exception type indicator
    if "error" in error_lower or "exception" in error_lower:
        return "other_runtime"

    return "unknown"


def analyze_results_file(filepath: str) -> Dict[str, Any]:
    """
    Analyze a single results file for test validity.

    Args:
        filepath: Path to results JSON file

    Returns:
        Dict with validity statistics
    """
    with open(filepath, "r") as f:
        data = json.load(f)

    # Handle different result formats
    if "results" in data:
        # Format from run_llm_baselines.py: {"results": [{"detailed_results": [...]}]}
        all_details = []
        for result in data["results"]:
            # Check both "detailed_results" (new) and "details" (legacy)
            details = result.get("detailed_results", []) or result.get("details", [])
            all_details.extend(details)
    elif "detailed_results" in data:
        # Format: {"detailed_results": [...]}
        all_details = data["detailed_results"]
    elif "details" in data:
        # Format: {"details": [...]}
        all_details = data["details"]
    else:
        # Assume it's a list of sample results
        all_details = data if isinstance(data, list) else []

    # Count validity
    total = 0
    valid = 0
    invalid_by_type = defaultdict(int)

    for sample_result in all_details:
        total += 1
        metrics = sample_result.get("metrics", {})
        errors = sample_result.get("errors", [])

        if metrics.get("valid_tests", True):
            valid += 1
        else:
            # Categorize the error
            error_str = " ".join(errors) if errors else ""
            error_type = extract_error_type(error_str)
            invalid_by_type[error_type] += 1

    return {
        "file": os.path.basename(filepath),
        "total": total,
        "valid": valid,
        "invalid": total - valid,
        "valid_ratio": valid / total if total > 0 else 0,
        "invalid_by_type": dict(invalid_by_type),
    }


def analyze_multiple_files(filepaths: List[str]) -> Dict[str, Any]:
    """
    Analyze multiple results files and aggregate.

    Args:
        filepaths: List of paths to results JSON files

    Returns:
        Dict with aggregated validity statistics
    """
    per_file = []
    total = 0
    valid = 0
    invalid_by_type = defaultdict(int)

    for filepath in filepaths:
        try:
            file_result = analyze_results_file(filepath)
            per_file.append(file_result)

            total += file_result["total"]
            valid += file_result["valid"]
            for error_type, count in file_result["invalid_by_type"].items():
                invalid_by_type[error_type] += count
        except Exception as e:
            print(f"Warning: Failed to process {filepath}: {e}")

    return {
        "aggregate": {
            "total_samples": total,
            "valid_tests": valid,
            "invalid_tests": total - valid,
            "valid_ratio": valid / total if total > 0 else 0,
            "invalid_ratio": (total - valid) / total if total > 0 else 0,
        },
        "invalid_by_type": dict(invalid_by_type),
        "per_file": per_file,
    }


def print_report(result: Dict[str, Any]):
    """Print a formatted report of test validity analysis."""
    agg = result["aggregate"]

    print("=" * 70)
    print("TEST VALIDITY ANALYSIS")
    print("=" * 70)

    print(f"\nOverall Statistics:")
    print(f"  Total Samples:    {agg['total_samples']}")
    print(f"  Valid Tests:      {agg['valid_tests']} ({agg['valid_ratio']:.1%})")
    print(f"  Invalid Tests:    {agg['invalid_tests']} ({agg['invalid_ratio']:.1%})")

    if result.get("invalid_by_type"):
        print(f"\nInvalid Test Breakdown:")
        for error_type, count in sorted(result["invalid_by_type"].items(), key=lambda x: -x[1]):
            pct = count / agg["invalid_tests"] if agg["invalid_tests"] > 0 else 0
            print(f"  {error_type:<20} {count:>6} ({pct:>5.1%} of invalid)")

    if result.get("per_file") and len(result["per_file"]) > 1:
        print(f"\nPer-File Breakdown:")
        print(f"  {'File':<40} {'Total':>8} {'Valid':>8} {'Ratio':>8}")
        print("-" * 70)
        for fr in result["per_file"]:
            print(f"  {fr['file']:<40} {fr['total']:>8} {fr['valid']:>8} {fr['valid_ratio']:>7.1%}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Compute test validity metrics from evaluation results"
    )
    parser.add_argument(
        "--results",
        nargs="+",
        help="Path(s) to results JSON file(s), supports glob patterns"
    )
    parser.add_argument(
        "--results-dir",
        help="Directory containing results JSON files"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file for aggregated results"
    )

    args = parser.parse_args()

    # Collect all result files
    filepaths = []

    if args.results:
        for pattern in args.results:
            filepaths.extend(glob.glob(pattern))

    if args.results_dir:
        filepaths.extend(glob.glob(os.path.join(args.results_dir, "*.json")))

    if not filepaths:
        print("Error: No result files specified.")
        print("Use --results or --results-dir to specify input files.")
        sys.exit(1)

    # Remove duplicates
    filepaths = list(set(filepaths))
    print(f"Analyzing {len(filepaths)} result file(s)...")

    # Analyze
    result = analyze_multiple_files(filepaths)

    # Print report
    print_report(result)

    # Save results
    if args.output:
        os.makedirs(os.path.dirname(args.output) or ".", exist_ok=True)
        with open(args.output, "w") as f:
            json.dump(result, f, indent=2)
        print(f"\nResults saved to: {args.output}")


if __name__ == "__main__":
    main()
