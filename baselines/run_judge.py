#!/usr/bin/env python3
"""
LLM-as-Judge for SecMutBench (Batch API)

Runs LLM-as-Judge evaluation on saved experiment results using
OpenAI or Anthropic Batch API for 50% cost savings.

Output files are named: *_openai_judged.json or *_anthropic_judged.json

Usage:
    # Judge with OpenAI (default: gpt-5.4-2026-03-05)
    python baselines/run_judge.py results/

    # Judge with Anthropic
    python baselines/run_judge.py results/ --provider anthropic --model claude-sonnet-4-5-20250929

    # Judge a single results file
    python baselines/run_judge.py results/qwen3-coder_30b/baseline_results_20260312.json

    # Skip already-judged files
    python baselines/run_judge.py results/ --skip-judged

    # Change poll interval (seconds between status checks)
    python baselines/run_judge.py results/ --poll-interval 120
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
from baselines.batch_api import OpenAIBatchProcessor, AnthropicBatchProcessor, BatchRequest


def parse_json_response(response: str) -> Dict[str, Any]:
    """Extract JSON from LLM response."""
    json_match = re.search(r'\{[\s\S]*\}', response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    return {}


def build_judge_requests(detailed_results: List[Dict]) -> tuple:
    """Build batch requests for security relevance and test quality judging.

    Returns:
        (requests_list, sample_index_map) where sample_index_map maps
        custom_id -> (index, judge_type) for reassembly.
    """
    requests = []
    index_map = {}  # custom_id -> (result_index, "security"|"quality")

    for i, r in enumerate(detailed_results):
        tests = r.get("generated_tests", "")
        if not tests.strip():
            continue

        cwe = r.get("cwe", "")
        cwe_name = r.get("cwe_name", "vulnerability")
        secure_code = r.get("secure_code", "")
        entry_point = r.get("entry_point", "function")
        difficulty = r.get("difficulty", "unknown")
        sample_id = r.get("sample_id", f"sample_{i}")

        # Security relevance request
        sec_id = f"sec_{i}_{sample_id[:20]}"
        sec_prompt = format_security_relevance_prompt(
            code=secure_code,
            tests=tests,
            cwe=cwe,
            cwe_name=cwe_name,
        )
        requests.append(BatchRequest(
            custom_id=sec_id,
            prompt=sec_prompt,
            system_prompt=SECURITY_RELEVANCE_SYSTEM_PROMPT,
            max_tokens=1024,
            temperature=0.0,
        ))
        index_map[sec_id] = (i, "security")

        # Test quality request
        qual_id = f"qual_{i}_{sample_id[:20]}"
        qual_prompt = format_test_quality_prompt(
            tests=tests,
            entry_point=entry_point,
            cwe=cwe,
            difficulty=difficulty,
        )
        requests.append(BatchRequest(
            custom_id=qual_id,
            prompt=qual_prompt,
            system_prompt=TEST_QUALITY_SYSTEM_PROMPT,
            max_tokens=1024,
            temperature=0.0,
        ))
        index_map[qual_id] = (i, "quality")

    return requests, index_map


def judge_results_file(
    results_path: Path,
    model: str,
    provider: str = "openai",
    output_path: Optional[Path] = None,
    poll_interval: int = 60,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Run LLM-as-Judge on a saved results file using Batch API.

    Args:
        results_path: Path to baseline_results JSON
        model: Model to use as judge
        provider: Judge provider — "openai" or "anthropic"
        output_path: Where to save judged results (default: auto)
        poll_interval: Seconds between batch status checks
        verbose: Print per-sample details

    Returns:
        Summary dict with judge scores
    """
    with open(results_path) as f:
        saved_data = json.load(f)

    model_results_list = saved_data.get("results", [saved_data])

    all_summaries = []
    if provider == "anthropic":
        processor = AnthropicBatchProcessor()
    else:
        processor = OpenAIBatchProcessor()

    for model_data in model_results_list:
        detailed = model_data.get("detailed_results", [])
        if not detailed:
            continue

        model_name = model_data.get("model_name", "unknown")
        print(f"\n  Judging: {model_name} ({len(detailed)} samples)")

        # Build all judge requests
        requests, index_map = build_judge_requests(detailed)
        samples_with_tests = len(set(idx for idx, _ in index_map.values()))

        if not requests:
            print("  No samples with generated tests to judge")
            continue

        print(f"  Total: {len(requests)} requests ({samples_with_tests} samples x 2 judges)")
        print(f"  Model: {model} ({provider} Batch API — 50% cost savings)")

        # Split into chunks to stay under token limits (200 requests per chunk)
        chunk_size = 200
        all_responses = []
        chunks = [requests[i:i + chunk_size] for i in range(0, len(requests), chunk_size)]

        for chunk_idx, chunk in enumerate(chunks, 1):
            print(f"\n  Batch {chunk_idx}/{len(chunks)} ({len(chunk)} requests)...")
            batch_result = processor.process_batch(
                requests=chunk,
                model=model,
                poll_interval=poll_interval,
            )
            print(f"  Batch {chunk_idx} complete: "
                  f"{batch_result.completed_requests}/{batch_result.total_requests} succeeded")
            all_responses.extend(batch_result.responses)

        print(f"\n  All batches done: {len(all_responses)} total responses")

        # Parse responses and reassemble into results
        # Initialize per-sample storage
        sec_results = {}  # index -> parsed security result
        qual_results = {}  # index -> parsed quality result

        for response in all_responses:
            if not response.success or not response.content:
                continue

            idx, judge_type = index_map.get(response.custom_id, (None, None))
            if idx is None:
                continue

            parsed = parse_json_response(response.content)

            if judge_type == "security":
                sec_results[idx] = {
                    "score": parsed.get("score", 0) / 100 if parsed.get("score") else 0.0,
                    "cwe_addressed": parsed.get("cwe_addressed", False),
                    "attack_vectors_tested": parsed.get("attack_vectors_tested", []),
                    "security_properties_checked": parsed.get("security_properties_checked", []),
                    "reasoning": parsed.get("reasoning", ""),
                    "confidence": parsed.get("confidence", 0) / 100 if parsed.get("confidence") else 0.0,
                    "raw_response": response.content,
                }
            elif judge_type == "quality":
                qual_results[idx] = {
                    "score": parsed.get("score", 0) / 100 if parsed.get("score") else 0.0,
                    "assertions_count": parsed.get("assertions_count", 0),
                    "edge_cases_covered": parsed.get("edge_cases_covered", 0),
                    "follows_best_practices": parsed.get("follows_best_practices", False),
                    "issues_found": parsed.get("issues_found", []),
                    "reasoning": parsed.get("reasoning", ""),
                    "confidence": parsed.get("confidence", 0) / 100 if parsed.get("confidence") else 0.0,
                    "raw_response": response.content,
                }

        # Merge results back into detailed_results
        security_scores = []
        quality_scores = []
        judged_count = 0

        for idx in sorted(set(list(sec_results.keys()) + list(qual_results.keys()))):
            sec = sec_results.get(idx)
            qual = qual_results.get(idx)

            if sec and qual:
                detailed[idx]["judge"] = {
                    "model": model,
                    "provider": provider,
                    "security_relevance": sec,
                    "test_quality": qual,
                    "composite": sec["score"] * 0.6 + qual["score"] * 0.4,
                }
                security_scores.append(sec["score"])
                quality_scores.append(qual["score"])
                judged_count += 1

                if verbose:
                    sample_id = detailed[idx].get("sample_id", f"sample_{idx}")
                    print(f"    {sample_id[:20]}  Sec: {sec['score']:.0%}  Qual: {qual['score']:.0%}")
            elif sec:
                detailed[idx]["judge"] = {
                    "model": model,
                    "provider": provider,
                    "security_relevance": sec,
                    "composite": sec["score"] * 0.6,
                }
                security_scores.append(sec["score"])
                judged_count += 1
            elif qual:
                detailed[idx]["judge"] = {
                    "model": model,
                    "provider": provider,
                    "test_quality": qual,
                    "composite": qual["score"] * 0.4,
                }
                quality_scores.append(qual["score"])
                judged_count += 1

        # Compute averages
        summary = {
            "model_name": model_name,
            "judge_model": model,
            "judge_provider": f"{provider} (batch)",
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

        print(f"  Judged: {judged_count}/{len(detailed)} samples")
        if security_scores:
            print(f"  Avg Security Relevance: {summary['avg_security_relevance']:.1%}")
        if quality_scores:
            print(f"  Avg Test Quality: {summary['avg_test_quality']:.1%}")
        if "avg_composite" in summary:
            print(f"  Avg Composite: {summary['avg_composite']:.1%}")

    # Save judged results
    saved_data["judge_metadata"] = {
        "judge_model": model,
        "judge_provider": f"{provider} (batch)",
        "judged_at": datetime.now().isoformat(),
    }

    if output_path is None:
        output_path = results_path.with_name(
            results_path.stem + f"_{provider}_judged" + results_path.suffix
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
    return [f for f in files if "_judged" not in f.name]


def print_summary_table(summaries: List[Dict]):
    """Print a formatted summary table."""
    print(f"\n{'='*80}")
    print("LLM-as-Judge Results (Batch API)")
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
        description="Run LLM-as-Judge on saved evaluation results (OpenAI Batch API, 50% savings)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Judge a single results file
  python baselines/run_judge.py results/qwen3-coder_30b/baseline_results_20260312.json

  # Judge all results in results/ directory
  python baselines/run_judge.py results/

  # Use a specific judge model
  python baselines/run_judge.py results/ --model gpt-5.4-2026-03-05

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
        default="gpt-5.4-2026-03-05",
        help="Model to use as judge (default: gpt-5.4-2026-03-05)",
    )
    parser.add_argument(
        "--provider",
        choices=["openai", "anthropic"],
        default="openai",
        help="Judge provider (default: openai)",
    )
    parser.add_argument(
        "--poll-interval",
        type=int,
        default=60,
        help="Seconds between batch status checks (default: 60)",
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

    # Check API key for selected provider
    provider = args.provider
    key_name = "OPENAI_API_KEY" if provider == "openai" else "ANTHROPIC_API_KEY"
    if not os.getenv(key_name):
        env_path = Path(".env")
        if env_path.exists():
            for line in env_path.read_text().splitlines():
                if line.startswith(f"{key_name}="):
                    os.environ[key_name] = line.split("=", 1)[1].strip()
                    break
    if not os.getenv(key_name):
        print(f"Error: {key_name} not set")
        sys.exit(1)

    input_path = Path(args.input)
    if not input_path.exists():
        print(f"Error: {input_path} does not exist")
        sys.exit(1)

    # Find results files
    results_files = find_results_files(input_path)

    if args.skip_judged:
        before = len(results_files)
        suffix = f"_{provider}_judged"
        results_files = [
            f for f in results_files
            if not f.with_name(f.stem + suffix + f.suffix).exists()
        ]
        skipped = before - len(results_files)
        if skipped:
            print(f"Skipping {skipped} already-judged files ({provider})")

    if not results_files:
        print("No results files found to judge.")
        sys.exit(0)

    print(f"Found {len(results_files)} results file(s) to judge")
    print(f"Judge model: {args.model} ({provider} Batch API — 50% cost savings)")

    # Judge each file
    all_summaries = []
    for i, results_file in enumerate(results_files, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(results_files)}] {results_file}")
        print(f"{'='*60}")

        result = judge_results_file(
            results_file,
            model=args.model,
            provider=provider,
            poll_interval=args.poll_interval,
            verbose=args.verbose,
        )
        all_summaries.extend(result["summaries"])

    # Print final summary
    if all_summaries:
        print_summary_table(all_summaries)


if __name__ == "__main__":
    main()
