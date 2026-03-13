#!/usr/bin/env python3
"""
LLM-as-Judge for SecMutBench (Local Ollama)

Runs LLM-as-Judge evaluation on saved experiment results using a local
Ollama model. No API keys required — fully offline.

Usage:
    # Judge a single results file
    python baselines/run_judge.py results/qwen3-coder_30b/baseline_results_20260312.json

    # Judge all results in a directory
    python baselines/run_judge.py results/

    # Use a specific judge model
    python baselines/run_judge.py results/ --model qwen3-coder:30b

    # Skip already-judged files
    python baselines/run_judge.py results/ --skip-judged
"""

import json
import os
import re
import sys
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.prompts import (
    SECURITY_RELEVANCE_SYSTEM_PROMPT,
    format_security_relevance_prompt,
    TEST_QUALITY_SYSTEM_PROMPT,
    format_test_quality_prompt,
)


def call_ollama(model: str, prompt: str, system_prompt: str, timeout: int = 120) -> str:
    """Call Ollama API to judge a sample."""
    try:
        from openai import OpenAI
    except ImportError:
        raise ImportError("openai package required: pip install openai")

    client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")

    response = client.chat.completions.create(
        model=model,
        messages=[
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt},
        ],
        temperature=0.0,
        timeout=timeout,
    )
    return response.choices[0].message.content


def parse_json_response(response: str) -> Dict[str, Any]:
    """Extract JSON from LLM response."""
    json_match = re.search(r'\{[\s\S]*\}', response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    return {}


def judge_security_relevance(
    model: str,
    secure_code: str,
    generated_tests: str,
    cwe: str,
    cwe_name: str,
) -> Dict[str, Any]:
    """Judge security relevance of generated tests."""
    prompt = format_security_relevance_prompt(
        code=secure_code,
        tests=generated_tests,
        cwe=cwe,
        cwe_name=cwe_name,
    )
    response = call_ollama(model, prompt, SECURITY_RELEVANCE_SYSTEM_PROMPT)
    parsed = parse_json_response(response)

    return {
        "score": parsed.get("score", 0) / 100 if parsed.get("score") else 0.0,
        "cwe_addressed": parsed.get("cwe_addressed", False),
        "attack_vectors_tested": parsed.get("attack_vectors_tested", []),
        "security_properties_checked": parsed.get("security_properties_checked", []),
        "reasoning": parsed.get("reasoning", ""),
        "confidence": parsed.get("confidence", 0) / 100 if parsed.get("confidence") else 0.0,
        "raw_response": response,
    }


def judge_test_quality(
    model: str,
    generated_tests: str,
    entry_point: str,
    cwe: str,
    difficulty: str,
) -> Dict[str, Any]:
    """Judge test quality."""
    prompt = format_test_quality_prompt(
        tests=generated_tests,
        entry_point=entry_point,
        cwe=cwe,
        difficulty=difficulty,
    )
    response = call_ollama(model, prompt, TEST_QUALITY_SYSTEM_PROMPT)
    parsed = parse_json_response(response)

    return {
        "score": parsed.get("score", 0) / 100 if parsed.get("score") else 0.0,
        "assertions_count": parsed.get("assertions_count", 0),
        "edge_cases_covered": parsed.get("edge_cases_covered", 0),
        "follows_best_practices": parsed.get("follows_best_practices", False),
        "issues_found": parsed.get("issues_found", []),
        "reasoning": parsed.get("reasoning", ""),
        "confidence": parsed.get("confidence", 0) / 100 if parsed.get("confidence") else 0.0,
        "raw_response": response,
    }


def judge_results_file(
    results_path: Path,
    model: str,
    output_path: Optional[Path] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Run LLM-as-Judge on a saved results file.

    Args:
        results_path: Path to baseline_results JSON
        model: Ollama model to use as judge
        output_path: Where to save judged results (default: auto)
        verbose: Print per-sample details

    Returns:
        Summary dict with judge scores
    """
    with open(results_path) as f:
        saved_data = json.load(f)

    model_results_list = saved_data.get("results", [saved_data])

    all_summaries = []

    for model_data in model_results_list:
        detailed = model_data.get("detailed_results", [])
        if not detailed:
            continue

        model_name = model_data.get("model_name", "unknown")
        print(f"\n  Judging: {model_name} ({len(detailed)} samples)")

        security_scores = []
        quality_scores = []
        judged_count = 0

        for i, r in enumerate(detailed, 1):
            tests = r.get("generated_tests", "")
            if not tests.strip():
                if verbose:
                    print(f"    [{i}/{len(detailed)}] {r['sample_id'][:12]}... SKIP (empty tests)")
                continue

            cwe = r.get("cwe", "")
            cwe_name = r.get("cwe_name", "vulnerability")
            secure_code = r.get("secure_code", "")
            entry_point = r.get("entry_point", "function")
            difficulty = r.get("difficulty", "unknown")

            print(f"    [{i}/{len(detailed)}] {r['sample_id'][:12]}... ", end="", flush=True)

            try:
                # Security relevance
                sec_result = judge_security_relevance(
                    model, secure_code, tests, cwe, cwe_name,
                )
                security_scores.append(sec_result["score"])

                # Test quality
                qual_result = judge_test_quality(
                    model, tests, entry_point, cwe, difficulty,
                )
                quality_scores.append(qual_result["score"])

                # Store in detailed results
                r["judge"] = {
                    "model": model,
                    "security_relevance": sec_result,
                    "test_quality": qual_result,
                    "composite": sec_result["score"] * 0.6 + qual_result["score"] * 0.4,
                }

                judged_count += 1
                print(f"Sec: {sec_result['score']:.0%}  Qual: {qual_result['score']:.0%}")

            except Exception as e:
                print(f"ERROR: {e}")
                continue

        # Compute averages
        summary = {
            "model_name": model_name,
            "judge_model": model,
            "samples_judged": judged_count,
            "samples_total": len(detailed),
        }

        if security_scores:
            summary["avg_security_relevance"] = sum(security_scores) / len(security_scores)
            model_data["avg_security_relevance"] = summary["avg_security_relevance"]
        if quality_scores:
            summary["avg_test_quality"] = sum(quality_scores) / len(quality_scores)
            model_data["avg_test_quality"] = summary["avg_test_quality"]
        if security_scores and quality_scores:
            composite = [s * 0.6 + q * 0.4 for s, q in zip(security_scores, quality_scores)]
            summary["avg_composite"] = sum(composite) / len(composite)
            model_data["avg_composite_score"] = summary["avg_composite"]

        all_summaries.append(summary)

    # Save judged results
    saved_data["judge_metadata"] = {
        "judge_model": model,
        "judge_provider": "ollama",
        "judged_at": datetime.now().isoformat(),
    }

    if output_path is None:
        output_path = results_path.with_name(
            results_path.stem + f"_judged" + results_path.suffix
        )

    with open(output_path, "w") as f:
        json.dump(saved_data, f, indent=2)

    print(f"\n  Saved to: {output_path}")

    return {"summaries": all_summaries, "output_path": str(output_path)}


def find_results_files(path: Path) -> List[Path]:
    """Find all baseline_results JSON files in a directory."""
    if path.is_file():
        return [path]

    files = sorted(path.rglob("baseline_results_*.json"))
    # Exclude already-judged files
    return [f for f in files if "_judged" not in f.stem]


def print_summary_table(summaries: List[Dict]):
    """Print a formatted summary table."""
    print(f"\n{'='*80}")
    print("LLM-as-Judge Results (Local Ollama)")
    print(f"{'='*80}")
    print(f"{'Model':<40} {'Sec Rel':<12} {'Quality':<12} {'Composite':<12} {'Judged':<10}")
    print(f"{'-'*80}")

    for s in summaries:
        sec = f"{s.get('avg_security_relevance', 0):.1%}" if 'avg_security_relevance' in s else "N/A"
        qual = f"{s.get('avg_test_quality', 0):.1%}" if 'avg_test_quality' in s else "N/A"
        comp = f"{s.get('avg_composite', 0):.1%}" if 'avg_composite' in s else "N/A"
        judged = f"{s['samples_judged']}/{s['samples_total']}"
        print(f"{s['model_name']:<40} {sec:<12} {qual:<12} {comp:<12} {judged:<10}")

    print(f"{'='*80}")


def main():
    parser = argparse.ArgumentParser(
        description="Run LLM-as-Judge on saved evaluation results (local Ollama, no API needed)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Judge a single results file
  python baselines/run_judge.py results/qwen3-coder_30b/baseline_results_20260312.json

  # Judge all results in results/ directory
  python baselines/run_judge.py results/

  # Use a specific judge model
  python baselines/run_judge.py results/ --model qwen3-coder:30b

  # Skip files that were already judged
  python baselines/run_judge.py results/ --skip-judged
""",
    )

    parser.add_argument(
        "input",
        help="Results file or directory containing results files",
    )
    parser.add_argument(
        "--model",
        default="qwen3-coder:30b",
        help="Ollama model to use as judge (default: qwen3-coder:30b)",
    )
    parser.add_argument(
        "--skip-judged",
        action="store_true",
        help="Skip files that already have a _judged counterpart",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed per-sample output",
    )

    args = parser.parse_args()

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} does not exist")
        sys.exit(1)

    # Find results files
    results_files = find_results_files(input_path)

    if args.skip_judged:
        before = len(results_files)
        results_files = [
            f for f in results_files
            if not f.with_name(f.stem + "_judged" + f.suffix).exists()
        ]
        skipped = before - len(results_files)
        if skipped:
            print(f"Skipping {skipped} already-judged files")

    if not results_files:
        print("No results files found to judge.")
        sys.exit(0)

    print(f"Found {len(results_files)} results file(s) to judge")
    print(f"Judge model: {args.model} (Ollama)")

    # Check Ollama is running
    try:
        from openai import OpenAI
        client = OpenAI(base_url="http://localhost:11434/v1", api_key="ollama")
        client.models.list()
    except Exception:
        print("Error: Ollama is not running. Start with: ollama serve")
        sys.exit(1)

    # Judge each file
    all_summaries = []
    for i, results_file in enumerate(results_files, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(results_files)}] {results_file}")
        print(f"{'='*60}")

        result = judge_results_file(
            results_file,
            model=args.model,
            verbose=args.verbose,
        )
        all_summaries.extend(result["summaries"])

    # Print final summary
    if all_summaries:
        print_summary_table(all_summaries)


if __name__ == "__main__":
    main()
