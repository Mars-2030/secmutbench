#!/usr/bin/env python3
"""
Compute Mutant Validity Metrics for SecMutBench

Analyzes all pre-generated mutants in the dataset to determine:
1. Compilable ratio: How many mutants pass compile() without SyntaxError
2. Executable ratio: How many mutants can be imported without immediate crash

This script outputs metrics for the paper's §3.2 (Executable Mutant Ratio).

Usage:
    python scripts/compute_mutant_validity.py
    python scripts/compute_mutant_validity.py --dataset data/dataset.json
    python scripts/compute_mutant_validity.py --test-execution  # Also test execution
    python scripts/compute_mutant_validity.py --output results/mutant_validity.json
"""

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any, Tuple
from collections import defaultdict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.evaluate import load_benchmark
from evaluation.test_runner import TestRunner


def check_compilable(code: str) -> Tuple[bool, str]:
    """
    Check if code compiles without SyntaxError.

    Args:
        code: Python source code

    Returns:
        Tuple of (compilable: bool, error: str or None)
    """
    try:
        compile(code, "<string>", "exec")
        return True, None
    except SyntaxError as e:
        return False, f"SyntaxError: {e}"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def check_executable(code: str, runner: TestRunner) -> Tuple[bool, str]:
    """
    Check if code can be imported without immediate crash.

    Uses the test runner with a minimal test that just imports the module.

    Args:
        code: Python source code
        runner: TestRunner instance

    Returns:
        Tuple of (executable: bool, error: str or None)
    """
    # Minimal test that just verifies import succeeds
    minimal_test = """
def test_import():
    # If we get here, the module imported successfully
    assert True
"""
    try:
        result = runner.run_tests(minimal_test, code)
        if result.all_passed:
            return True, None
        else:
            # Get the error from failed test
            for test in result.tests:
                if not test.passed and test.error:
                    return False, test.error
            return False, "Unknown execution error"
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def analyze_mutants(
    benchmark: List[Dict],
    test_execution: bool = False,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Analyze all mutants in the benchmark for validity.

    Args:
        benchmark: List of benchmark samples with mutants
        test_execution: Whether to also test execution (slower)
        verbose: Print progress and details

    Returns:
        Dict with validity metrics
    """
    runner = TestRunner(timeout=3.0) if test_execution else None

    # Counters
    total_mutants = 0
    compilable_count = 0
    executable_count = 0

    # Per-operator breakdown
    by_operator = defaultdict(lambda: {
        "total": 0, "compilable": 0, "executable": 0, "errors": []
    })

    # Per-CWE breakdown
    by_cwe = defaultdict(lambda: {
        "total": 0, "compilable": 0, "executable": 0
    })

    # Error categories
    compile_errors = defaultdict(int)
    execution_errors = defaultdict(int)

    # Process each sample
    for i, sample in enumerate(benchmark):
        if (i + 1) % 10 == 0 or verbose:
            print(f"Processing sample {i + 1}/{len(benchmark)}...", flush=True)

        cwe = sample.get("cwe", "unknown")
        mutants = sample.get("mutants", [])

        for mutant in mutants:
            total_mutants += 1
            operator = mutant.get("operator", "unknown")
            mutated_code = mutant.get("mutated_code", "")

            # Progress indicator for execution testing (slow)
            if test_execution and (total_mutants % 50 == 0):
                print(f"  Tested {total_mutants} mutants...", flush=True)

            by_operator[operator]["total"] += 1
            by_cwe[cwe]["total"] += 1

            # Check compilability
            is_compilable, compile_error = check_compilable(mutated_code)

            if is_compilable:
                compilable_count += 1
                by_operator[operator]["compilable"] += 1
                by_cwe[cwe]["compilable"] += 1

                # Check executability (only if requested and compilable)
                if test_execution:
                    is_executable, exec_error = check_executable(mutated_code, runner)
                    if is_executable:
                        executable_count += 1
                        by_operator[operator]["executable"] += 1
                        by_cwe[cwe]["executable"] += 1
                    else:
                        # Categorize execution error
                        error_type = exec_error.split(":")[0] if exec_error else "Unknown"
                        execution_errors[error_type] += 1
                        if verbose:
                            by_operator[operator]["errors"].append({
                                "mutant_id": mutant.get("id"),
                                "error": exec_error[:200],
                            })
            else:
                # Categorize compile error
                error_type = compile_error.split(":")[0] if compile_error else "Unknown"
                compile_errors[error_type] += 1
                if verbose:
                    by_operator[operator]["errors"].append({
                        "mutant_id": mutant.get("id"),
                        "error": compile_error[:200],
                    })

    # Compute ratios
    compilable_ratio = compilable_count / total_mutants if total_mutants > 0 else 0
    executable_ratio = executable_count / total_mutants if total_mutants > 0 else 0

    # Build result
    result = {
        "summary": {
            "total_mutants": total_mutants,
            "compilable_count": compilable_count,
            "compilable_ratio": compilable_ratio,
            "execution_tested": test_execution,
        },
        "compile_errors": dict(compile_errors),
        "by_operator": {},
        "by_cwe": {},
    }

    if test_execution:
        result["summary"]["executable_count"] = executable_count
        result["summary"]["executable_ratio"] = executable_ratio
        result["execution_errors"] = dict(execution_errors)

    # Convert operator stats
    for op, stats in by_operator.items():
        result["by_operator"][op] = {
            "total": stats["total"],
            "compilable": stats["compilable"],
            "compilable_ratio": stats["compilable"] / stats["total"] if stats["total"] > 0 else 0,
        }
        if test_execution:
            result["by_operator"][op]["executable"] = stats["executable"]
            result["by_operator"][op]["executable_ratio"] = (
                stats["executable"] / stats["total"] if stats["total"] > 0 else 0
            )
        if verbose and stats["errors"]:
            result["by_operator"][op]["sample_errors"] = stats["errors"][:5]

    # Convert CWE stats
    for cwe, stats in by_cwe.items():
        result["by_cwe"][cwe] = {
            "total": stats["total"],
            "compilable": stats["compilable"],
            "compilable_ratio": stats["compilable"] / stats["total"] if stats["total"] > 0 else 0,
        }
        if test_execution:
            result["by_cwe"][cwe]["executable"] = stats["executable"]
            result["by_cwe"][cwe]["executable_ratio"] = (
                stats["executable"] / stats["total"] if stats["total"] > 0 else 0
            )

    return result


def print_report(result: Dict[str, Any]):
    """Print a formatted report of the validity analysis."""
    summary = result["summary"]

    print("=" * 70)
    print("MUTANT VALIDITY ANALYSIS")
    print("=" * 70)
    print(f"\nTotal Mutants: {summary['total_mutants']}")
    print(f"\nCompilability:")
    print(f"  Compilable:  {summary['compilable_count']} / {summary['total_mutants']} ({summary['compilable_ratio']:.1%})")

    if summary.get("execution_tested"):
        print(f"\nExecutability:")
        print(f"  Executable:  {summary['executable_count']} / {summary['total_mutants']} ({summary['executable_ratio']:.1%})")

    # Compile errors
    if result.get("compile_errors"):
        print(f"\nCompile Error Breakdown:")
        for error_type, count in sorted(result["compile_errors"].items(), key=lambda x: -x[1]):
            print(f"  {error_type}: {count}")

    # Execution errors
    if result.get("execution_errors"):
        print(f"\nExecution Error Breakdown:")
        for error_type, count in sorted(result["execution_errors"].items(), key=lambda x: -x[1]):
            print(f"  {error_type}: {count}")

    # By operator
    print(f"\nBy Operator:")
    print(f"  {'Operator':<20} {'Total':>8} {'Compilable':>12} {'Ratio':>8}", end="")
    if summary.get("execution_tested"):
        print(f" {'Executable':>12} {'Ratio':>8}", end="")
    print()
    print("-" * 70)

    for op, stats in sorted(result["by_operator"].items()):
        print(f"  {op:<20} {stats['total']:>8} {stats['compilable']:>12} {stats['compilable_ratio']:>7.1%}", end="")
        if summary.get("execution_tested"):
            print(f" {stats.get('executable', 0):>12} {stats.get('executable_ratio', 0):>7.1%}", end="")
        print()

    # By CWE (top 10)
    print(f"\nBy CWE (Top 10):")
    print(f"  {'CWE':<15} {'Total':>8} {'Compilable':>12} {'Ratio':>8}", end="")
    if summary.get("execution_tested"):
        print(f" {'Executable':>12} {'Ratio':>8}", end="")
    print()
    print("-" * 70)

    cwe_items = sorted(result["by_cwe"].items(), key=lambda x: -x[1]["total"])[:10]
    for cwe, stats in cwe_items:
        print(f"  {cwe:<15} {stats['total']:>8} {stats['compilable']:>12} {stats['compilable_ratio']:>7.1%}", end="")
        if summary.get("execution_tested"):
            print(f" {stats.get('executable', 0):>12} {stats.get('executable_ratio', 0):>7.1%}", end="")
        print()

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Compute mutant validity metrics for SecMutBench"
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to dataset file (default: data/dataset.json)"
    )
    parser.add_argument(
        "--test-execution",
        action="store_true",
        help="Also test if mutants are executable (slower)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file for results"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed progress and sample errors"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of samples to analyze (default: all)"
    )

    args = parser.parse_args()

    # Load benchmark
    print("Loading benchmark...")
    benchmark = load_benchmark(path=args.dataset)

    # Limit samples if requested
    if args.max_samples:
        benchmark = benchmark[:args.max_samples]

    print(f"Loaded {len(benchmark)} samples")

    # Count mutants
    total_mutants = sum(len(s.get("mutants", [])) for s in benchmark)
    print(f"Total mutants to analyze: {total_mutants}")

    if args.test_execution:
        print("\nNote: Execution testing enabled (this will be slower)")

    # Analyze
    print("\nAnalyzing mutant validity...")
    result = analyze_mutants(
        benchmark,
        test_execution=args.test_execution,
        verbose=args.verbose,
    )

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
