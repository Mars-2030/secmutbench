#!/usr/bin/env python3
"""
Manual Kill Audit Script for SecMutBench

Samples N kills per category from existing evaluation results and outputs them
in a format suitable for manual review.

This script is used for validating the accuracy of the kill classification
system by enabling human review of representative samples.

Usage:
    python scripts/sample_kills_for_audit.py results/evaluation.json
    python scripts/sample_kills_for_audit.py results/evaluation.json --samples-per-category 30
    python scripts/sample_kills_for_audit.py results/evaluation.json --output audit_samples.csv --format csv
    python scripts/sample_kills_for_audit.py results/evaluation.json --output audit_samples.md --format markdown
"""

import argparse
import csv
import difflib
import json
import os
import random
import sys
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime
from collections import defaultdict

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))


def load_evaluation_results(path: str) -> Dict[str, Any]:
    """
    Load evaluation results from JSON file.

    Args:
        path: Path to evaluation results JSON file

    Returns:
        Dict with evaluation results
    """
    with open(path, "r") as f:
        return json.load(f)


def load_benchmark_samples(benchmark_path: str = None) -> Dict[str, Dict]:
    """
    Load benchmark samples for joining with evaluation results.

    Args:
        benchmark_path: Path to benchmark JSON (default: data/dataset.json)

    Returns:
        Dict mapping sample_id to sample data
    """
    if benchmark_path is None:
        benchmark_path = PROJECT_ROOT / "data" / "dataset.json"

    try:
        with open(benchmark_path, "r") as f:
            data = json.load(f)

        # Handle both list format and dict with "samples" key
        samples = data if isinstance(data, list) else data.get("samples", [])
        return {s["id"]: s for s in samples}
    except Exception as e:
        print(f"Warning: Could not load benchmark: {e}")
        return {}


def extract_kills_from_results(
    results: Dict[str, Any],
    benchmark_samples: Dict[str, Dict] = None,
) -> List[Dict[str, Any]]:
    """
    Extract all kill records from evaluation results.

    Args:
        results: Evaluation results dict
        benchmark_samples: Optional dict mapping sample_id to benchmark sample
                          (for secure_code lookup when not in results)

    Returns:
        List of kill records with metadata
    """
    kills = []
    benchmark_samples = benchmark_samples or {}

    # Handle different result structures
    # Format from run_llm_baselines.py: {"results": [{"detailed_results": [...]}]}
    details = results.get("details", [])
    if not details and "results" in results:
        # Extract detailed_results from each model result entry
        for model_result in results["results"]:
            model_details = model_result.get("detailed_results", []) or model_result.get("details", [])
            details.extend(model_details)
    if not details:
        details = results.get("detailed_results", [])

    for sample_result in details:
        sample_id = sample_result.get("sample_id") or sample_result.get("id", "unknown")
        cwe = sample_result.get("cwe", "unknown")

        # Get secure_code and test_code - check results first, then benchmark
        secure_code = sample_result.get("secure_code", "")
        test_code = sample_result.get("test_code") or sample_result.get("generated_tests", "")

        # Join against benchmark if needed
        if (not secure_code or not test_code) and sample_id in benchmark_samples:
            benchmark_sample = benchmark_samples[sample_id]
            if not secure_code:
                secure_code = benchmark_sample.get("secure_code", "")
            if not test_code:
                # Try security_tests from benchmark as fallback
                test_code = benchmark_sample.get("security_tests", "")

        # Get mutant results - handle both field names
        mutant_results = sample_result.get("mutant_details", [])
        if not mutant_results:
            mutant_results = sample_result.get("mutant_results", [])  # Legacy fallback

        for mutant_result in mutant_results:
            if not mutant_result.get("killed", False):
                continue

            # Extract error from kill_reason or nested test_results
            error = mutant_result.get("kill_reason", "")
            if not error and mutant_result.get("test_results"):
                for test in mutant_result["test_results"]:
                    if test.get("error"):
                        error = test["error"]
                        break

            kill_record = {
                "sample_id": sample_id,
                "cwe": cwe,
                "operator": mutant_result.get("operator", "unknown"),
                "mutant_id": mutant_result.get("id", mutant_result.get("mutant_id", "unknown")),
                "secure_code": secure_code,
                "mutant_code": mutant_result.get("mutated_code", mutant_result.get("mutant_code", "")),
                "test_code": test_code,
                "error": error,
                "error_type": mutant_result.get("error_type", ""),
                "classification": mutant_result.get("kill_type", mutant_result.get("classification", "unknown")),
                "classification_layer": mutant_result.get("classification_layer", "unknown"),
                "mock_access": mutant_result.get("mock_security_access", {}),
            }
            kills.append(kill_record)

    return kills


def group_kills_by_category(kills: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """
    Group kills by classification category.

    Args:
        kills: List of kill records

    Returns:
        Dict mapping category to list of kills
    """
    grouped = defaultdict(list)

    for kill in kills:
        category = kill.get("classification", "unknown")
        grouped[category].append(kill)

    return dict(grouped)


def stratified_sample(
    grouped_kills: Dict[str, List[Dict[str, Any]]],
    samples_per_category: int = 30,
    seed: int = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Sample N kills from each category.

    Args:
        grouped_kills: Dict mapping category to kills
        samples_per_category: Number of samples per category
        seed: Random seed for reproducibility

    Returns:
        Dict with sampled kills per category
    """
    if seed is not None:
        random.seed(seed)

    sampled = {}

    for category, kills in grouped_kills.items():
        n = min(samples_per_category, len(kills))
        sampled[category] = random.sample(kills, n)

    return sampled


def generate_diff(secure_code: str, mutant_code: str, context: int = 3) -> str:
    """
    Generate a unified diff between secure and mutant code.

    Args:
        secure_code: Original secure code
        mutant_code: Mutated code
        context: Number of context lines

    Returns:
        Unified diff string
    """
    secure_lines = secure_code.splitlines(keepends=True)
    mutant_lines = mutant_code.splitlines(keepends=True)

    diff = difflib.unified_diff(
        secure_lines,
        mutant_lines,
        fromfile="secure",
        tofile="mutant",
        lineterm="",
        n=context,
    )

    return "".join(diff)


def explain_classification(kill: Dict[str, Any]) -> str:
    """
    Generate explanation for why this kill was classified as it is.

    Args:
        kill: Kill record

    Returns:
        Explanation string
    """
    classification = kill.get("classification", "unknown")
    layer = kill.get("classification_layer", "unknown")
    error = kill.get("error", "")
    error_type = kill.get("error_type", "")
    mock_access = kill.get("mock_access", {})

    explanations = []

    if classification == "crash":
        explanations.append(f"Crash kill: {error_type} indicates code structure issue, not security assertion")
        if error_type:
            explanations.append(f"Error type: {error_type}")

    elif classification == "semantic":
        if layer == "mock_observability":
            explanations.append("Semantic kill via mock-state observability (Layer 1.5)")
            if mock_access:
                for mock_name, attrs in mock_access.items():
                    explanations.append(f"  - Accessed {mock_name}.{', '.join(attrs)}")
        else:
            explanations.append("Semantic kill via keyword matching (Layer 1)")
            # Extract matching keywords from error
            security_keywords = [
                "injection", "sql", "command", "path", "traversal", "xss",
                "script", "escape", "sanitize", "validate", "parameterized",
                "prepared", "quote", "encode", "decode", "hash", "crypto",
                "password", "secret", "token", "auth", "permission", "access",
            ]
            found = [kw for kw in security_keywords if kw.lower() in error.lower()]
            if found:
                explanations.append(f"  - Keywords found: {', '.join(found)}")

    elif classification in ("incidental", "assertion_incidental"):
        explanations.append("Incidental kill: AssertionError without security-related terms")
        explanations.append("Test failed but may not demonstrate security awareness")

    elif classification == "other":
        explanations.append(f"Other kill: {error_type or 'unknown error type'}")

    else:
        explanations.append(f"Classification: {classification}")

    return "\n".join(explanations)


def truncate_code(code: str, max_lines: int = 30, max_chars: int = 1500) -> str:
    """
    Truncate code for display while keeping it readable.

    Args:
        code: Code string
        max_lines: Maximum number of lines
        max_chars: Maximum characters

    Returns:
        Truncated code
    """
    lines = code.split("\n")

    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines.append(f"... ({len(code.split(chr(10))) - max_lines} more lines)")

    result = "\n".join(lines)

    if len(result) > max_chars:
        result = result[:max_chars] + "\n... (truncated)"

    return result


def write_csv(
    sampled: Dict[str, List[Dict[str, Any]]],
    output_path: str,
):
    """
    Write sampled kills to CSV file.

    Args:
        sampled: Dict of category -> sampled kills
        output_path: Output file path
    """
    fieldnames = [
        "category",
        "sample_id",
        "cwe",
        "operator",
        "mutant_id",
        "error_type",
        "error_message",
        "classification_explanation",
        "mock_access",
        "diff",
        "test_code",
        "human_classification",
        "human_notes",
    ]

    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()

        for category, kills in sampled.items():
            for kill in kills:
                diff = generate_diff(
                    kill.get("secure_code", ""),
                    kill.get("mutant_code", ""),
                )

                row = {
                    "category": category,
                    "sample_id": kill.get("sample_id", ""),
                    "cwe": kill.get("cwe", ""),
                    "operator": kill.get("operator", ""),
                    "mutant_id": kill.get("mutant_id", ""),
                    "error_type": kill.get("error_type", ""),
                    "error_message": truncate_code(kill.get("error", ""), max_lines=5, max_chars=500),
                    "classification_explanation": explain_classification(kill),
                    "mock_access": json.dumps(kill.get("mock_access", {})),
                    "diff": truncate_code(diff, max_lines=20, max_chars=1000),
                    "test_code": truncate_code(kill.get("test_code", ""), max_lines=30, max_chars=2000),
                    "human_classification": "",  # To be filled by reviewer
                    "human_notes": "",  # To be filled by reviewer
                }
                writer.writerow(row)

    print(f"CSV written to: {output_path}")


def write_markdown(
    sampled: Dict[str, List[Dict[str, Any]]],
    output_path: str,
):
    """
    Write sampled kills to Markdown file.

    Args:
        sampled: Dict of category -> sampled kills
        output_path: Output file path
    """
    lines = []
    lines.append("# Manual Kill Audit Report")
    lines.append("")
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")

    # Summary
    lines.append("## Summary")
    lines.append("")
    lines.append("| Category | Sampled | Description |")
    lines.append("|----------|---------|-------------|")

    category_descriptions = {
        "semantic": "Security-aware assertion failures",
        "incidental": "Assertion failures without security keywords",
        "crash": "Import/Type/Syntax errors",
        "other": "Other failure types",
    }

    for category, kills in sampled.items():
        desc = category_descriptions.get(category, "")
        lines.append(f"| {category} | {len(kills)} | {desc} |")

    lines.append("")
    lines.append("---")
    lines.append("")

    # Detailed samples per category
    for category, kills in sampled.items():
        lines.append(f"## {category.capitalize()} Kills ({len(kills)} samples)")
        lines.append("")

        for i, kill in enumerate(kills, 1):
            lines.append(f"### Sample {i}: {kill.get('sample_id', 'unknown')}")
            lines.append("")

            # Metadata table
            lines.append("| Field | Value |")
            lines.append("|-------|-------|")
            lines.append(f"| CWE | {kill.get('cwe', 'unknown')} |")
            lines.append(f"| Operator | {kill.get('operator', 'unknown')} |")
            lines.append(f"| Mutant ID | {kill.get('mutant_id', 'unknown')} |")
            lines.append(f"| Error Type | {kill.get('error_type', 'unknown')} |")
            lines.append(f"| Classification | {category} |")
            lines.append(f"| Classification Layer | {kill.get('classification_layer', 'unknown')} |")
            lines.append("")

            # Mock access
            mock_access = kill.get("mock_access", {})
            if mock_access:
                lines.append("**Mock Security Access:**")
                for mock_name, attrs in mock_access.items():
                    lines.append(f"- `{mock_name}`: {', '.join(attrs)}")
                lines.append("")

            # Error message
            lines.append("**Error Message:**")
            lines.append("```")
            lines.append(truncate_code(kill.get("error", "No error message"), max_lines=5, max_chars=500))
            lines.append("```")
            lines.append("")

            # Classification explanation
            lines.append("**Classification Explanation:**")
            lines.append("```")
            lines.append(explain_classification(kill))
            lines.append("```")
            lines.append("")

            # Diff
            diff = generate_diff(
                kill.get("secure_code", ""),
                kill.get("mutant_code", ""),
            )
            lines.append("**Mutation Diff (secure → vulnerable):**")
            lines.append("```diff")
            lines.append(truncate_code(diff, max_lines=20, max_chars=1000))
            lines.append("```")
            lines.append("")

            # Test code
            lines.append("**Test Code:**")
            lines.append("```python")
            lines.append(truncate_code(kill.get("test_code", "No test code"), max_lines=30, max_chars=2000))
            lines.append("```")
            lines.append("")

            # Human review section
            lines.append("**Human Review:**")
            lines.append("")
            lines.append("- [ ] Classification correct")
            lines.append("- [ ] Classification incorrect → Correct category: _____")
            lines.append("- Notes: ")
            lines.append("")
            lines.append("---")
            lines.append("")

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    print(f"Markdown written to: {output_path}")


def print_summary(sampled: Dict[str, List[Dict[str, Any]]]):
    """Print summary of sampled kills."""
    print("\n" + "=" * 60)
    print("KILL AUDIT SAMPLE SUMMARY")
    print("=" * 60)

    total = sum(len(kills) for kills in sampled.values())
    print(f"\nTotal sampled: {total}")
    print("\nPer-category breakdown:")

    for category, kills in sorted(sampled.items()):
        print(f"  {category:15} {len(kills):5} samples")

        # Show operator distribution
        operators = defaultdict(int)
        cwes = defaultdict(int)
        for kill in kills:
            operators[kill.get("operator", "unknown")] += 1
            cwes[kill.get("cwe", "unknown")] += 1

        print(f"    Operators: {dict(operators)}")
        print(f"    CWEs: {dict(cwes)}")

    print("=" * 60)


def main():
    parser = argparse.ArgumentParser(
        description="Sample kills for manual audit from evaluation results"
    )
    parser.add_argument(
        "results_file",
        help="Path to evaluation results JSON file"
    )
    parser.add_argument(
        "--samples-per-category",
        type=int,
        default=30,
        help="Number of samples per category (default: 30)"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output file path (default: audit_samples_TIMESTAMP.md)"
    )
    parser.add_argument(
        "--format",
        choices=["csv", "markdown", "both"],
        default="markdown",
        help="Output format (default: markdown)"
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for reproducibility (default: 42)"
    )
    parser.add_argument(
        "--categories",
        nargs="+",
        default=None,
        help="Categories to sample (default: all)"
    )
    parser.add_argument(
        "--benchmark",
        default=None,
        help="Path to benchmark JSON for joining secure_code/test_code (default: data/dataset.json)"
    )

    args = parser.parse_args()

    # Load benchmark for joining
    print("Loading benchmark samples for metadata...")
    benchmark_samples = load_benchmark_samples(args.benchmark)
    print(f"  Loaded {len(benchmark_samples)} benchmark samples")

    # Load results
    print(f"Loading results from: {args.results_file}")
    results = load_evaluation_results(args.results_file)

    # Extract kills with benchmark join
    kills = extract_kills_from_results(results, benchmark_samples)
    print(f"Found {len(kills)} total kills")

    if not kills:
        print("No kills found in results. Check the results file structure.")
        sys.exit(1)

    # Group by category
    grouped = group_kills_by_category(kills)
    print(f"\nCategories found: {list(grouped.keys())}")
    for cat, cat_kills in grouped.items():
        print(f"  {cat}: {len(cat_kills)} kills")

    # Filter categories if specified
    if args.categories:
        grouped = {k: v for k, v in grouped.items() if k in args.categories}

    # Sample
    sampled = stratified_sample(
        grouped,
        samples_per_category=args.samples_per_category,
        seed=args.seed,
    )

    # Print summary
    print_summary(sampled)

    # Generate output path
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if args.output:
        base_path = args.output
    else:
        base_path = f"audit_samples_{timestamp}"

    # Write outputs
    if args.format in ["csv", "both"]:
        csv_path = base_path if base_path.endswith(".csv") else f"{base_path}.csv"
        write_csv(sampled, csv_path)

    if args.format in ["markdown", "both"]:
        md_path = base_path if base_path.endswith(".md") else f"{base_path}.md"
        write_markdown(sampled, md_path)

    print("\nDone! Review the samples and fill in the human_classification columns.")


if __name__ == "__main__":
    main()
