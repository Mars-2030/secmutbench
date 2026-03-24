#!/usr/bin/env python3
"""
Recover and complete interrupted LLM-as-Judge batch runs.

Downloads results from completed OpenAI batch IDs, assembles them into
the judged results file, then submits and processes remaining batches.

Usage:
    # Recover gpt-oss judging (9 completed batches + 1 stuck + 2 not submitted)
    python baselines/recover_judge.py \
        results/gpt-oss-120b/baseline_results_20260314_183442.json \
        --batch-ids batch_id1,batch_id2,...

    # Check status of a batch before recovering
    python baselines/recover_judge.py --check-batch batch_69b7e8cc33cc8190b1129f6798285a01
"""

import json
import os
import re
import sys
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.prompts import (
    SECURITY_RELEVANCE_SYSTEM_PROMPT,
    format_security_relevance_prompt,
    TEST_QUALITY_SYSTEM_PROMPT,
    format_test_quality_prompt,
)
from baselines.batch_api import OpenAIBatchProcessor, BatchRequest, BatchResponse


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
    """Build batch requests for security + quality judging.
    Returns (requests_list, index_map) where index_map maps custom_id -> (index, type).
    """
    requests = []
    index_map = {}

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

        sec_id = f"sec_{i}_{sample_id[:20]}"
        sec_prompt = format_security_relevance_prompt(
            code=secure_code, tests=tests, cwe=cwe, cwe_name=cwe_name,
        )
        requests.append(BatchRequest(
            custom_id=sec_id, prompt=sec_prompt,
            system_prompt=SECURITY_RELEVANCE_SYSTEM_PROMPT,
            max_tokens=1024, temperature=0.0,
        ))
        index_map[sec_id] = (i, "security")

        qual_id = f"qual_{i}_{sample_id[:20]}"
        qual_prompt = format_test_quality_prompt(
            tests=tests, entry_point=entry_point, cwe=cwe, difficulty=difficulty,
        )
        requests.append(BatchRequest(
            custom_id=qual_id, prompt=qual_prompt,
            system_prompt=TEST_QUALITY_SYSTEM_PROMPT,
            max_tokens=1024, temperature=0.0,
        ))
        index_map[qual_id] = (i, "quality")

    return requests, index_map


def download_batch_responses(processor, batch_ids: List[str]) -> List[BatchResponse]:
    """Download responses from completed batches, skip failed/pending ones."""
    all_responses = []
    for bid in batch_ids:
        print(f"  Downloading {bid}...", end=" ", flush=True)
        try:
            status = processor.get_batch_status(bid)
            if status.status == "completed":
                result = processor.get_batch_results(bid)
                print(f"{result.completed_requests} responses")
                all_responses.extend(result.responses)
            elif status.status == "processing":
                print(f"still processing ({status.completed_requests}/{status.total_requests}) — skipping")
            elif status.status == "failed":
                print("FAILED — skipping")
            else:
                print(f"{status.status} — skipping")
        except Exception as e:
            print(f"ERROR: {e}")
    return all_responses


def apply_responses_to_detailed(
    detailed: List[Dict],
    responses: List[BatchResponse],
    index_map: Dict[str, tuple],
    model: str,
    provider: str,
) -> Dict[str, Any]:
    """Parse responses and merge judge scores into detailed_results.
    Returns summary dict.
    """
    sec_results = {}
    qual_results = {}

    for response in responses:
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

    security_scores = []
    quality_scores = []
    judged_count = 0

    for idx in sorted(set(list(sec_results.keys()) + list(qual_results.keys()))):
        sec = sec_results.get(idx)
        qual = qual_results.get(idx)

        if sec and qual:
            detailed[idx]["judge"] = {
                "model": model, "provider": provider,
                "security_relevance": sec, "test_quality": qual,
                "composite": sec["score"] * 0.6 + qual["score"] * 0.4,
            }
            security_scores.append(sec["score"])
            quality_scores.append(qual["score"])
            judged_count += 1
        elif sec:
            detailed[idx]["judge"] = {
                "model": model, "provider": provider,
                "security_relevance": sec, "composite": sec["score"] * 0.6,
            }
            security_scores.append(sec["score"])
            judged_count += 1
        elif qual:
            detailed[idx]["judge"] = {
                "model": model, "provider": provider,
                "test_quality": qual, "composite": qual["score"] * 0.4,
            }
            quality_scores.append(qual["score"])
            judged_count += 1

    summary = {
        "samples_judged": judged_count,
        "samples_total": len(detailed),
    }
    if security_scores:
        summary["avg_security_relevance"] = sum(security_scores) / len(security_scores)
    if quality_scores:
        summary["avg_test_quality"] = sum(quality_scores) / len(quality_scores)
    if security_scores and quality_scores:
        composite = [s * 0.6 + q * 0.4 for s, q in zip(security_scores, quality_scores)]
        summary["avg_composite"] = sum(composite) / len(composite)

    return summary


def check_batch(processor, batch_id: str):
    """Print status of a single batch."""
    status = processor.get_batch_status(batch_id)
    print(f"Batch: {batch_id}")
    print(f"  Status: {status.status}")
    print(f"  Completed: {status.completed_requests}/{status.total_requests}")
    print(f"  Failed: {status.failed_requests}")


def main():
    parser = argparse.ArgumentParser(
        description="Recover interrupted LLM-as-Judge batch runs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Check if a batch is done
  python baselines/recover_judge.py --check-batch batch_69b7e8cc...

  # Recover with completed batch IDs (comma-separated)
  python baselines/recover_judge.py results/gpt-oss-120b/baseline_results_20260314_183442.json \\
      --batch-ids batch_id1,batch_id2,batch_id3,...

  # Recover and also run remaining variants that have no batches
  python baselines/recover_judge.py results/gpt-oss-120b/baseline_results_20260314_183442.json \\
      --batch-ids batch_id1,... --complete-remaining
""",
    )

    parser.add_argument("input", nargs="?", help="Results file to recover judging for")
    parser.add_argument("--batch-ids", help="Comma-separated list of completed batch IDs to download")
    parser.add_argument("--check-batch", help="Check status of a single batch ID")
    parser.add_argument("--model", default="gpt-5.4-2026-03-05", help="Judge model (default: gpt-5.4-2026-03-05)")
    parser.add_argument("--provider", default="openai", choices=["openai", "anthropic"])
    parser.add_argument("--complete-remaining", action="store_true",
                        help="Submit new batches for variants that have no judge data yet")
    parser.add_argument("--poll-interval", type=int, default=60)

    args = parser.parse_args()

    # Load API key
    key_name = "OPENAI_API_KEY" if args.provider == "openai" else "ANTHROPIC_API_KEY"
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

    processor = OpenAIBatchProcessor()

    # Mode 1: Just check a batch status
    if args.check_batch:
        check_batch(processor, args.check_batch)
        return

    if not args.input:
        print("Error: provide a results file path")
        sys.exit(1)

    results_path = Path(args.input)
    if not results_path.exists():
        print(f"Error: {results_path} does not exist")
        sys.exit(1)

    # Load original results
    with open(results_path) as f:
        saved_data = json.load(f)

    model_results_list = saved_data.get("results", [saved_data])

    # Parse batch IDs
    batch_ids = []
    if args.batch_ids:
        batch_ids = [b.strip() for b in args.batch_ids.split(",") if b.strip()]

    # Step 1: Download all provided batch responses
    all_downloaded = []
    if batch_ids:
        print(f"\nStep 1: Downloading {len(batch_ids)} batch(es)...")
        all_downloaded = download_batch_responses(processor, batch_ids)
        print(f"  Total responses downloaded: {len(all_downloaded)}")

    # Step 2: For each variant, build its index_map and apply matching responses
    print(f"\nStep 2: Matching responses to variants...")
    all_summaries = []

    for variant_idx, model_data in enumerate(model_results_list):
        detailed = model_data.get("detailed_results", [])
        if not detailed:
            continue

        model_name = model_data.get("model_name", "unknown")

        # Check if already judged
        already_judged = sum(1 for r in detailed if r.get("judge"))
        if already_judged == len(detailed):
            print(f"\n  [{variant_idx+1}/{len(model_results_list)}] {model_name}: already fully judged ({already_judged}/{len(detailed)}), skipping")
            continue

        # Build index map for this variant's requests
        requests, index_map = build_judge_requests(detailed)
        if not requests:
            continue

        print(f"\n  [{variant_idx+1}/{len(model_results_list)}] {model_name}: {len(requests)} requests expected")

        # Match downloaded responses to this variant's custom_ids
        matching = [r for r in all_downloaded if r.custom_id in index_map]

        if matching:
            print(f"    Found {len(matching)}/{len(requests)} matching responses from downloaded batches")
            summary = apply_responses_to_detailed(
                detailed, matching, index_map, args.model, args.provider,
            )
            judged = summary["samples_judged"]
            print(f"    Judged: {judged}/{summary['samples_total']}")
            if "avg_security_relevance" in summary:
                print(f"    Avg Security Relevance: {summary['avg_security_relevance']:.1%}")
            if "avg_test_quality" in summary:
                print(f"    Avg Test Quality: {summary['avg_test_quality']:.1%}")
            if "avg_composite" in summary:
                print(f"    Avg Composite: {summary['avg_composite']:.1%}")

            summary["model_name"] = model_name
            summary["judge_model"] = args.model
            all_summaries.append(summary)

            # Update model_data averages
            if "avg_security_relevance" in summary:
                model_data["avg_security_relevance"] = summary["avg_security_relevance"]
            if "avg_test_quality" in summary:
                model_data["avg_test_quality"] = summary["avg_test_quality"]
            if "avg_composite" in summary:
                model_data["avg_composite_score"] = summary["avg_composite"]
        else:
            print(f"    No matching responses found in downloaded batches")

        # Step 3: If --complete-remaining, find unjudged requests and submit new batches
        if args.complete_remaining:
            unjudged_requests = [r for r in requests if r.custom_id not in {m.custom_id for m in matching}]
            if unjudged_requests:
                print(f"\n    Submitting {len(unjudged_requests)} remaining requests...")
                chunk_size = 200
                remaining_responses = []
                chunks = [unjudged_requests[i:i+chunk_size] for i in range(0, len(unjudged_requests), chunk_size)]

                for ci, chunk in enumerate(chunks, 1):
                    print(f"      Batch {ci}/{len(chunks)} ({len(chunk)} requests)...")
                    batch_result = processor.process_batch(
                        requests=chunk, model=args.model, poll_interval=args.poll_interval,
                    )
                    print(f"      Complete: {batch_result.completed_requests}/{batch_result.total_requests}")
                    remaining_responses.extend(batch_result.responses)

                # Apply remaining responses
                summary2 = apply_responses_to_detailed(
                    detailed, remaining_responses, index_map, args.model, args.provider,
                )
                # Re-count totals
                all_judged = sum(1 for r in detailed if r.get("judge"))
                print(f"    Total judged after completion: {all_judged}/{len(detailed)}")
            else:
                print(f"    All requests accounted for — nothing remaining")

    # Save results
    saved_data["judge_metadata"] = {
        "judge_model": args.model,
        "judge_provider": f"{args.provider} (batch)",
        "judged_at": datetime.now().isoformat(),
        "recovered": True,
        "batch_ids": batch_ids,
    }

    output_path = results_path.with_name(
        results_path.stem + f"_{args.provider}_judged" + results_path.suffix
    )

    with open(output_path, "w") as f:
        json.dump(saved_data, f, indent=2)

    print(f"\nSaved to: {output_path}")

    # Summary table
    if all_summaries:
        print(f"\n{'='*80}")
        print("Recovery Summary")
        print(f"{'='*80}")
        print(f"{'Variant':<40} {'Sec Rel':<12} {'Quality':<12} {'Composite':<12} {'Judged':<10}")
        print(f"{'-'*80}")
        for s in all_summaries:
            sec = f"{s['avg_security_relevance']:.1%}" if 'avg_security_relevance' in s else "N/A"
            qual = f"{s['avg_test_quality']:.1%}" if 'avg_test_quality' in s else "N/A"
            comp = f"{s['avg_composite']:.1%}" if 'avg_composite' in s else "N/A"
            judged = f"{s['samples_judged']}/{s['samples_total']}"
            print(f"{s['model_name']:<40} {sec:<12} {qual:<12} {comp:<12} {judged:<10}")
        print(f"{'='*80}")


if __name__ == "__main__":
    main()
