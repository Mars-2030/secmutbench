#!/usr/bin/env python3
"""
Dataset Quality Analyzer for SecMutBench

Analyzes an existing dataset to report VD (Vulnerability Detection) correctness.
This is for analysis only - VD validation is also integrated into dataset_builder.py.

Usage:
    python scripts/validate_dataset_quality.py
    python scripts/validate_dataset_quality.py --cwe CWE-22 --verbose
    python scripts/validate_dataset_quality.py --output results/dataset_quality.json
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict

PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.test_runner import TestRunner
from evaluation.evaluate import load_benchmark


def analyze_vd(benchmark, runner, cwe_filter=None, verbose=False):
    """Analyze VD correctness for all samples."""
    results = {
        'correct': [],
        'both_pass': [],
        'both_fail': [],
        'inverted': [],
        'no_tests': [],
    }

    samples = benchmark
    if cwe_filter:
        samples = [s for s in samples if s.get('cwe') == cwe_filter]

    for i, sample in enumerate(samples):
        if (i + 1) % 50 == 0:
            print(f"  Progress: {i + 1}/{len(samples)}")

        sid = sample['id'][:12]
        cwe = sample.get('cwe', 'unknown')
        sec_tests = sample.get('security_tests', '')

        if not sec_tests:
            results['no_tests'].append((sid, cwe, 'No security tests'))
            continue

        secure_code = sample.get('secure_code', '')
        insecure_code = sample.get('insecure_code', '')

        try:
            secure_result = runner.run_tests(sec_tests, secure_code)
            insecure_result = runner.run_tests(sec_tests, insecure_code)

            secure_pass = secure_result.all_passed
            insecure_pass = insecure_result.all_passed

            if secure_pass and not insecure_pass:
                results['correct'].append((sid, cwe, 'VD correct'))
            elif secure_pass and insecure_pass:
                results['both_pass'].append((sid, cwe, 'Test passes on insecure'))
            elif not secure_pass and not insecure_pass:
                err = secure_result.tests[0].error if secure_result.tests else 'unknown'
                results['both_fail'].append((sid, cwe, err[:60]))
            else:
                results['inverted'].append((sid, cwe, 'Secure fails, insecure passes'))
        except Exception as e:
            results['both_fail'].append((sid, cwe, str(e)[:60]))

    return results


def main():
    parser = argparse.ArgumentParser(description="Analyze dataset VD quality")
    parser.add_argument("--cwe", help="Filter to specific CWE")
    parser.add_argument("--dataset", help="Path to dataset JSON file")
    parser.add_argument("--verbose", action="store_true")
    parser.add_argument("--output", help="Output JSON file")
    args = parser.parse_args()

    print("Loading benchmark...")
    if args.dataset:
        with open(args.dataset) as f:
            data = json.load(f)
        benchmark = data.get("samples", data) if isinstance(data, dict) else data
    else:
        benchmark = load_benchmark()
    print(f"Loaded {len(benchmark)} samples")

    runner = TestRunner(timeout=5.0)
    print("\nAnalyzing VD correctness...")
    results = analyze_vd(benchmark, runner, args.cwe, args.verbose)

    total = sum(len(v) for v in results.values())
    correct = len(results['correct'])

    print("\n" + "=" * 60)
    print("VD QUALITY REPORT")
    print("=" * 60)
    print(f"\nTotal samples analyzed: {total}")
    if total > 0:
        print(f"VD Correct: {correct} ({correct/total*100:.1f}%)")
    else:
        print("VD Correct: 0 (no samples)")
    print("\nBreakdown:")
    for cat, items in results.items():
        if items:
            pct = len(items)/total*100 if total > 0 else 0
            print(f"  {cat}: {len(items)} ({pct:.1f}%)")

    # By CWE
    by_cwe = defaultdict(lambda: {'correct': 0, 'issues': 0})
    for sid, cwe, _ in results['correct']:
        by_cwe[cwe]['correct'] += 1
    for cat in ['both_pass', 'both_fail', 'inverted']:
        for sid, cwe, _ in results[cat]:
            by_cwe[cwe]['issues'] += 1

    print("\nBy CWE:")
    for cwe in sorted(by_cwe.keys()):
        stats = by_cwe[cwe]
        total_cwe = stats['correct'] + stats['issues']
        pct = stats['correct'] / total_cwe * 100 if total_cwe > 0 else 0
        status = "✓" if pct >= 50 else "✗"
        print(f"  {status} {cwe}: {stats['correct']}/{total_cwe} ({pct:.0f}%)")

    if args.output:
        Path(args.output).parent.mkdir(parents=True, exist_ok=True)
        with open(args.output, 'w') as f:
            json.dump({
                'summary': {'total': total, 'correct': correct, 'correct_rate': correct/total if total else 0},
                'by_category': {k: len(v) for k, v in results.items()},
                'by_cwe': dict(by_cwe),
            }, f, indent=2)
        print(f"\nSaved to: {args.output}")


if __name__ == "__main__":
    main()
