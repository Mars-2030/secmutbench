#!/usr/bin/env python3
"""
Semgrep Baseline for SecMutBench

Runs Semgrep static analysis on benchmark samples to establish a baseline
for vulnerability detection without test generation.

Computes:
1. Detection rate per CWE: What percentage of insecure samples Semgrep flags
2. Rule coverage: Which Semgrep rules fire for which CWEs
3. Comparison with mutation testing results

Usage:
    python scripts/run_semgrep_baseline.py
    python scripts/run_semgrep_baseline.py --ruleset p/security-audit
    python scripts/run_semgrep_baseline.py --max-samples 50 --output results/semgrep_baseline.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Dict, List, Any
from collections import defaultdict
from datetime import datetime

# Add project root to path
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.evaluate import load_benchmark


# CWE to Semgrep rule ID mapping (approximate - rules may vary by ruleset)
CWE_TO_SEMGREP_CATEGORIES = {
    "CWE-78": ["command-injection", "os-command-injection", "subprocess"],
    "CWE-89": ["sql-injection", "sqli"],
    "CWE-94": ["code-injection", "eval", "exec"],
    "CWE-22": ["path-traversal"],
    "CWE-79": ["xss", "cross-site-scripting"],
    "CWE-327": ["weak-crypto", "md5", "sha1", "insecure-hash"],
    "CWE-328": ["weak-hash"],
    "CWE-338": ["weak-random", "random"],
    "CWE-502": ["deserialization", "pickle", "yaml"],
    "CWE-611": ["xxe", "xml"],
    "CWE-798": ["hardcoded", "credential", "password", "secret"],
    "CWE-918": ["ssrf"],
}


def run_semgrep(code: str, ruleset: str = "p/security-audit") -> Dict[str, Any]:
    """
    Run Semgrep on code and return findings.

    Args:
        code: Python source code
        ruleset: Semgrep ruleset to use

    Returns:
        Dict with findings and metadata
    """
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".py", delete=False
    ) as f:
        f.write(code)
        temp_path = f.name

    try:
        # Run semgrep
        result = subprocess.run(
            [
                "semgrep",
                "--config", ruleset,
                "--json",
                "--no-git-ignore",
                temp_path,
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        if result.returncode not in [0, 1]:  # 1 means findings were found
            return {
                "success": False,
                "error": result.stderr[:500],
                "findings": [],
            }

        # Parse JSON output
        try:
            output = json.loads(result.stdout)
            findings = output.get("results", [])
            return {
                "success": True,
                "findings": findings,
                "finding_count": len(findings),
                "rules_fired": list(set(f.get("check_id", "") for f in findings)),
            }
        except json.JSONDecodeError:
            return {
                "success": False,
                "error": "Failed to parse Semgrep output",
                "findings": [],
            }

    except subprocess.TimeoutExpired:
        return {
            "success": False,
            "error": "Semgrep timed out",
            "findings": [],
        }
    except FileNotFoundError:
        return {
            "success": False,
            "error": "Semgrep not installed. Run: pip install semgrep",
            "findings": [],
        }
    finally:
        os.unlink(temp_path)


def finding_matches_cwe(findings: List[Dict], cwe: str) -> bool:
    """
    Check if any finding matches the expected CWE.

    Args:
        findings: List of Semgrep findings
        cwe: Expected CWE

    Returns:
        True if any finding seems related to the CWE
    """
    keywords = CWE_TO_SEMGREP_CATEGORIES.get(cwe, [])

    for finding in findings:
        rule_id = finding.get("check_id", "").lower()
        message = finding.get("extra", {}).get("message", "").lower()

        # Check if rule ID or message contains relevant keywords
        for keyword in keywords:
            if keyword in rule_id or keyword in message:
                return True

        # Also check metadata for CWE references
        metadata = finding.get("extra", {}).get("metadata", {})
        finding_cwes = metadata.get("cwe", [])
        if isinstance(finding_cwes, str):
            finding_cwes = [finding_cwes]
        if any(cwe.lower() in str(c).lower() for c in finding_cwes):
            return True

    return len(findings) > 0  # Any finding counts as detection


def analyze_benchmark(
    benchmark: List[Dict],
    ruleset: str = "p/security-audit",
    max_samples: int = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Run Semgrep analysis on benchmark samples.

    Args:
        benchmark: List of benchmark samples
        ruleset: Semgrep ruleset to use
        max_samples: Maximum samples to analyze
        verbose: Print progress

    Returns:
        Dict with analysis results
    """
    samples = benchmark[:max_samples] if max_samples else benchmark

    # Track results
    by_cwe = defaultdict(lambda: {
        "total": 0,
        "detected_secure": 0,
        "detected_insecure": 0,
        "rules_fired": set(),
    })
    total_analyzed = 0
    semgrep_errors = 0

    for i, sample in enumerate(samples):
        if verbose and (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(samples)}")

        cwe = sample.get("cwe", "unknown")
        secure_code = sample.get("secure_code", "")
        insecure_code = sample.get("insecure_code", "")

        if not secure_code or not insecure_code:
            continue

        total_analyzed += 1
        by_cwe[cwe]["total"] += 1

        # Analyze secure code (should have fewer/no findings)
        secure_result = run_semgrep(secure_code, ruleset)
        if not secure_result["success"]:
            semgrep_errors += 1
            if verbose:
                print(f"  Warning: Semgrep error on {sample.get('id')}: {secure_result.get('error', '')[:50]}")
            continue

        if finding_matches_cwe(secure_result["findings"], cwe):
            by_cwe[cwe]["detected_secure"] += 1

        # Analyze insecure code (should have findings)
        insecure_result = run_semgrep(insecure_code, ruleset)
        if not insecure_result["success"]:
            semgrep_errors += 1
            continue

        if finding_matches_cwe(insecure_result["findings"], cwe):
            by_cwe[cwe]["detected_insecure"] += 1

        # Track rules
        for rule in insecure_result.get("rules_fired", []):
            by_cwe[cwe]["rules_fired"].add(rule)

    # Compute metrics
    total_insecure_detected = sum(s["detected_insecure"] for s in by_cwe.values())
    total_secure_detected = sum(s["detected_secure"] for s in by_cwe.values())

    # Convert sets to lists for JSON serialization
    by_cwe_serializable = {}
    for cwe, stats in by_cwe.items():
        by_cwe_serializable[cwe] = {
            "total": stats["total"],
            "detected_secure": stats["detected_secure"],
            "detected_insecure": stats["detected_insecure"],
            "detection_rate_insecure": stats["detected_insecure"] / stats["total"] if stats["total"] > 0 else 0,
            "false_positive_rate": stats["detected_secure"] / stats["total"] if stats["total"] > 0 else 0,
            "rules_fired": list(stats["rules_fired"]),
        }

    return {
        "summary": {
            "total_analyzed": total_analyzed,
            "total_insecure_detected": total_insecure_detected,
            "total_secure_detected": total_secure_detected,
            "detection_rate": total_insecure_detected / total_analyzed if total_analyzed > 0 else 0,
            "false_positive_rate": total_secure_detected / total_analyzed if total_analyzed > 0 else 0,
            "semgrep_errors": semgrep_errors,
            "ruleset": ruleset,
        },
        "by_cwe": by_cwe_serializable,
    }


def print_report(result: Dict[str, Any]):
    """Print formatted report."""
    summary = result["summary"]

    print("=" * 70)
    print("SEMGREP BASELINE ANALYSIS")
    print("=" * 70)

    print(f"\nRuleset: {summary['ruleset']}")
    print(f"\nOverall Statistics:")
    print(f"  Samples Analyzed:     {summary['total_analyzed']}")
    print(f"  Insecure Detected:    {summary['total_insecure_detected']} ({summary['detection_rate']:.1%})")
    print(f"  Secure Flagged (FP):  {summary['total_secure_detected']} ({summary['false_positive_rate']:.1%})")
    print(f"  Semgrep Errors:       {summary['semgrep_errors']}")

    print(f"\nPer-CWE Detection Rate (insecure code):")
    print(f"  {'CWE':<15} {'Total':>8} {'Detected':>10} {'Rate':>8} {'FP Rate':>8}")
    print("-" * 55)

    for cwe, stats in sorted(result["by_cwe"].items()):
        print(f"  {cwe:<15} {stats['total']:>8} {stats['detected_insecure']:>10} "
              f"{stats['detection_rate_insecure']:>7.1%} {stats['false_positive_rate']:>7.1%}")

    print("=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="Run Semgrep baseline analysis on SecMutBench"
    )
    parser.add_argument(
        "--dataset",
        default=None,
        help="Path to dataset file"
    )
    parser.add_argument(
        "--ruleset",
        default="p/security-audit",
        help="Semgrep ruleset (default: p/security-audit)"
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum samples to analyze"
    )
    parser.add_argument(
        "--cwe",
        default=None,
        help="Filter by CWE"
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress"
    )

    args = parser.parse_args()

    # Check if semgrep is installed
    try:
        subprocess.run(["semgrep", "--version"], capture_output=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        print("Error: Semgrep is not installed.")
        print("Install with: pip install semgrep")
        sys.exit(1)

    # Load benchmark
    print("Loading benchmark...")
    benchmark = load_benchmark(path=args.dataset, cwe=args.cwe)
    print(f"Loaded {len(benchmark)} samples")

    # Run analysis
    print(f"\nRunning Semgrep with ruleset: {args.ruleset}")
    result = analyze_benchmark(
        benchmark,
        ruleset=args.ruleset,
        max_samples=args.max_samples,
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
