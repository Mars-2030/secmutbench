#!/usr/bin/env python3
"""
Diagnose why operators aren't firing on external source samples.

This script analyzes samples that fail the "no mutants produced" check
and identifies what code patterns they have that operators should match.

Usage:
    python scripts/diagnose_operators.py
    python scripts/diagnose_operators.py --output results/operator_diagnosis.json
    python scripts/diagnose_operators.py --cwe CWE-89 --verbose
"""

import argparse
import json
import sys
from pathlib import Path
from collections import defaultdict
from datetime import datetime

# Add project paths
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(Path(__file__).parent))

from operators.operator_registry import CWE_OPERATOR_MAP, OPERATORS


def analyze_sample(sample: dict) -> dict:
    """Analyze why operators don't fire on a sample."""
    cwe = sample.get('cwe', '')
    code = sample.get('secure_code', '')

    # Get operators for this CWE
    cwe_ops = CWE_OPERATOR_MAP.get(cwe, [])

    analysis = {
        'id': sample.get('id', '')[:12],
        'cwe': cwe,
        'source': sample.get('source', 'unknown'),
        'cwe_operators': cwe_ops,
        'applies_to': [],
        'mutants_produced': [],
        'mutant_count': 0,
        'code_snippet': code[:200].replace('\n', '\\n'),
    }

    for op_name in cwe_ops:
        if op_name in OPERATORS:
            op = OPERATORS[op_name]
            if op.applies_to(code):
                analysis['applies_to'].append(op_name)
                mutants = op.generate_valid_mutants(code)
                if mutants:
                    analysis['mutants_produced'].append(op_name)
                    analysis['mutant_count'] += len(mutants)

    return analysis


def diagnose_dataset(cwe_filter=None, verbose=False):
    """Load raw samples and diagnose operator matching issues."""

    # Load dataset
    dataset_path = PROJECT_ROOT / 'data' / 'dataset.json'
    if not dataset_path.exists():
        print(f"Dataset not found: {dataset_path}")
        return None

    with open(dataset_path) as f:
        data = json.load(f)

    samples = data.get('samples', data) if isinstance(data, dict) else data
    print(f"Loaded {len(samples)} samples from dataset")

    # Apply CWE filter
    if cwe_filter:
        samples = [s for s in samples if s.get('cwe') == cwe_filter]
        print(f"Filtered to {len(samples)} samples for {cwe_filter}")

    # Group by CWE
    by_cwe = defaultdict(list)
    all_analyses = []
    for sample in samples:
        analysis = analyze_sample(sample)
        by_cwe[sample.get('cwe', 'unknown')].append(analysis)
        all_analyses.append(analysis)

    print(f"\n{'='*70}")
    print("OPERATOR COVERAGE ANALYSIS")
    print(f"{'='*70}\n")

    # Summary statistics
    total_no_mutants = 0
    total_no_applies = 0
    cwe_stats = {}

    for cwe in sorted(by_cwe.keys()):
        samples_list = by_cwe[cwe]
        ops = CWE_OPERATOR_MAP.get(cwe, [])

        no_applies = sum(1 for s in samples_list if not s['applies_to'])
        no_mutants = sum(1 for s in samples_list if not s['mutants_produced'])
        total_mutants = sum(s['mutant_count'] for s in samples_list)

        total_no_applies += no_applies
        total_no_mutants += no_mutants

        cwe_stats[cwe] = {
            'total_samples': len(samples_list),
            'operators': ops,
            'no_applies_to': no_applies,
            'no_mutants': no_mutants,
            'total_mutants': total_mutants,
        }

        print(f"\n{cwe} ({len(samples_list)} samples)")
        print(f"  Operators: {ops}")
        print(f"  No applies_to match: {no_applies}")
        print(f"  No mutants produced: {no_mutants}")
        print(f"  Total mutants: {total_mutants}")

        # Show sample code snippets for non-matching samples
        if verbose:
            non_matching = [s for s in samples_list if not s['mutants_produced']]
            if non_matching:
                print(f"  Example code patterns that don't match:")
                for s in non_matching[:2]:
                    print(f"    [{s['source']}] {s['code_snippet'][:100]}...")

    print(f"\n{'='*70}")
    print(f"SUMMARY: {total_no_applies} samples have no applies_to match")
    print(f"         {total_no_mutants} samples produce no mutants")
    print(f"{'='*70}\n")

    return {
        'summary': {
            'total_samples': len(samples),
            'no_applies_to': total_no_applies,
            'no_mutants_produced': total_no_mutants,
            'coverage_rate': (len(samples) - total_no_mutants) / len(samples) if samples else 0,
        },
        'by_cwe': cwe_stats,
        'samples': all_analyses if verbose else None,
    }


def analyze_external_sources(verbose=False):
    """Analyze raw external source data to understand patterns."""

    print(f"\n{'='*70}")
    print("ANALYZING EXTERNAL SOURCE PATTERNS")
    print(f"{'='*70}\n")

    external_stats = {}

    # Load CyberSecEval
    cybersec_path = PROJECT_ROOT / 'data' / 'raw' / 'cyberseceval_raw.json'
    if cybersec_path.exists():
        with open(cybersec_path) as f:
            cybersec = json.load(f)
        print(f"CyberSecEval: {len(cybersec)} samples")
        external_stats['CyberSecEval'] = analyze_source_patterns(cybersec, "CyberSecEval", verbose)

    # Load SecurityEval
    seceval_path = PROJECT_ROOT / 'data' / 'raw' / 'securityeval_raw.json'
    if seceval_path.exists():
        with open(seceval_path) as f:
            seceval = json.load(f)
        print(f"SecurityEval: {len(seceval)} samples")
        external_stats['SecurityEval'] = analyze_source_patterns(seceval, "SecurityEval", verbose)

    return external_stats


def analyze_source_patterns(samples: list, source_name: str, verbose=False):
    """Analyze code patterns in a source dataset."""

    # Look for common patterns by CWE
    pattern_stats = defaultdict(lambda: defaultdict(int))

    sql_patterns = [
        ('execute(', 'cursor.execute()'),
        ('SELECT ', 'SQL SELECT'),
        ('INSERT ', 'SQL INSERT'),
        ('query(', 'query()'),
        ('raw(', 'raw SQL'),
        ('%s', '%s placeholder'),
        ('?', '? placeholder'),
    ]

    cmd_patterns = [
        ('subprocess', 'subprocess module'),
        ('os.system', 'os.system()'),
        ('os.popen', 'os.popen()'),
        ('shell=True', 'shell=True'),
        ('Popen', 'Popen'),
        ('call(', 'subprocess.call()'),
        ('run(', 'subprocess.run()'),
    ]

    xss_patterns = [
        ('escape', 'escape function'),
        ('sanitize', 'sanitize function'),
        ('render', 'render template'),
        ('html', 'html processing'),
    ]

    for sample in samples:
        cwe = sample.get('cwe_identifier', sample.get('cwe', 'unknown'))
        code = sample.get('origin_code', sample.get('secure_code', sample.get('code', '')))

        if 'CWE-89' in str(cwe):
            for pattern, name in sql_patterns:
                if pattern in code:
                    pattern_stats[cwe][name] += 1
        elif 'CWE-78' in str(cwe) or 'CWE-77' in str(cwe):
            for pattern, name in cmd_patterns:
                if pattern in code:
                    pattern_stats[cwe][name] += 1
        elif 'CWE-79' in str(cwe):
            for pattern, name in xss_patterns:
                if pattern in code:
                    pattern_stats[cwe][name] += 1

    if verbose:
        print(f"\n  {source_name} Pattern Distribution:")
        for cwe in sorted(pattern_stats.keys()):
            print(f"    {cwe}:")
            for pattern, count in sorted(pattern_stats[cwe].items(), key=lambda x: -x[1]):
                print(f"      {pattern}: {count}")

    return dict(pattern_stats)


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose operator coverage issues in SecMutBench",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/diagnose_operators.py
    python scripts/diagnose_operators.py --output results/operator_diagnosis.json
    python scripts/diagnose_operators.py --cwe CWE-89 --verbose
        """,
    )

    parser.add_argument(
        "--output", type=str, default=None,
        help="Output JSON file for results",
    )
    parser.add_argument(
        "--cwe", type=str, default=None,
        help="Filter to specific CWE (e.g., CWE-89)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Show detailed output including code snippets",
    )
    parser.add_argument(
        "--analyze-external", action="store_true",
        help="Also analyze raw external source patterns",
    )

    args = parser.parse_args()

    print(f"\n{'='*70}")
    print("SecMutBench Operator Diagnosis Tool")
    print(f"{'='*70}\n")

    # Run diagnosis
    results = diagnose_dataset(cwe_filter=args.cwe, verbose=args.verbose)

    if results is None:
        sys.exit(1)

    # Analyze external sources if requested
    external_stats = None
    if args.analyze_external:
        external_stats = analyze_external_sources(verbose=args.verbose)

    # Save output if requested
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        output_data = {
            'metadata': {
                'generated': datetime.now().isoformat(),
                'cwe_filter': args.cwe,
            },
            'dataset_analysis': results,
        }
        if external_stats:
            output_data['external_sources'] = external_stats

        # Remove None values for cleaner JSON
        if output_data['dataset_analysis'].get('samples') is None:
            del output_data['dataset_analysis']['samples']

        with open(output_path, 'w') as f:
            json.dump(output_data, f, indent=2)

        print(f"\nSaved results to: {output_path}")


if __name__ == "__main__":
    main()
