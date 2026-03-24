#!/usr/bin/env python3
"""
Standalone Batch LLM-as-Judge for SecMutBench

Reads already-completed result files and submits judge evaluations via batch API
(Anthropic or OpenAI) for 50% cost savings.

Usage:
    # Judge all unjudged files with Anthropic (default)
    python baselines/run_judge_batch.py results/

    # Judge specific file with OpenAI
    python baselines/run_judge_batch.py results/gpt-oss-120b/baseline_results_*.json --provider openai

    # Specify model
    python baselines/run_judge_batch.py results/ --provider openai --model gpt-4o

    # Re-judge already judged files
    python baselines/run_judge_batch.py results/ --force

    # Only run one dimension
    python baselines/run_judge_batch.py results/ --security-only
    python baselines/run_judge_batch.py results/ --quality-only
"""

import argparse
import json
import os
import re
import sys
import glob
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional

# Add project root to path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from baselines.batch_api import create_batch_processor, BatchRequest
from evaluation.prompts import (
    SECURITY_RELEVANCE_SYSTEM_PROMPT,
    format_security_relevance_prompt,
    TEST_QUALITY_SYSTEM_PROMPT,
    format_test_quality_prompt,
)

# Default models per provider
DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "openai": "gpt-5.4-2026-03-05",
}


def load_dotenv():
    """Load environment variables from .env file."""
    for env_path in [PROJECT_ROOT / ".env", Path.cwd() / ".env"]:
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        key = key.strip()
                        value = value.strip().strip('"').strip("'")
                        if key and value:
                            os.environ.setdefault(key, value)
            break


def find_result_files(paths: List[str], force: bool = False) -> List[Path]:
    """Find baseline result JSON files to judge."""
    files = []
    for p in paths:
        path = Path(p)
        if path.is_file() and path.suffix == ".json":
            files.append(path)
        elif path.is_dir():
            # Recurse into subdirectories looking for baseline_results_*.json
            for f in sorted(path.rglob("baseline_results_*.json")):
                # Skip already-judged files
                if "_judged_" in f.name:
                    continue
                files.append(f)
        else:
            # Try glob expansion
            expanded = glob.glob(p)
            for ep in sorted(expanded):
                ep = Path(ep)
                if ep.is_file() and ep.suffix == ".json" and "_judged_" not in ep.name:
                    files.append(ep)

    if not force:
        # Filter out files that already have a _judged_batch.json sibling
        filtered = []
        for f in files:
            judged_path = f.with_name(f.stem + "_judged_batch.json")
            if not judged_path.exists():
                filtered.append(f)
            else:
                print(f"  Skipping {f.name} (already judged, use --force to re-judge)")
        files = filtered

    return files


def extract_entry_point(secure_code: str) -> str:
    """Extract entry point function name from secure_code."""
    match = re.search(r'def\s+(\w+)\s*\(', secure_code)
    return match.group(1) if match else "function"


def parse_judge_response(response: str) -> Dict[str, Any]:
    """Parse JSON response from LLM judge, handling markdown fences."""
    # Try to extract JSON from response
    json_match = re.search(r'\{[\s\S]*\}', response)
    if json_match:
        try:
            return json.loads(json_match.group())
        except json.JSONDecodeError:
            pass
    return {}


def build_requests_for_file(
    data: Dict[str, Any],
    do_security: bool = True,
    do_quality: bool = True,
) -> tuple:
    """
    Build BatchRequest lists from a result file.

    Returns:
        (security_requests, quality_requests, sample_map)
        sample_map: dict mapping sample_id -> index in detailed_results
    """
    security_requests = []
    quality_requests = []
    sample_map = {}

    for variant in data.get("results", []):
        for i, sample in enumerate(variant.get("detailed_results", [])):
            sample_id = sample.get("sample_id", "")
            generated_tests = sample.get("generated_tests", "")
            secure_code = sample.get("secure_code", "")
            cwe = sample.get("cwe", "Unknown")
            cwe_name = sample.get("cwe_name", "vulnerability")
            difficulty = sample.get("difficulty", "unknown")

            if not generated_tests or not generated_tests.strip():
                continue

            sample_map[sample_id] = i
            entry_point = extract_entry_point(secure_code)

            if do_security:
                sec_prompt = format_security_relevance_prompt(
                    code=secure_code,
                    tests=generated_tests,
                    cwe=cwe,
                    cwe_name=cwe_name,
                )
                security_requests.append(BatchRequest(
                    custom_id=f"sec-{sample_id}",
                    prompt=sec_prompt,
                    system_prompt=SECURITY_RELEVANCE_SYSTEM_PROMPT,
                    max_tokens=1024,
                    temperature=0.0,
                    metadata={"sample_id": sample_id, "type": "security"},
                ))

            if do_quality:
                qual_prompt = format_test_quality_prompt(
                    tests=generated_tests,
                    entry_point=entry_point,
                    cwe=cwe,
                    difficulty=difficulty,
                )
                quality_requests.append(BatchRequest(
                    custom_id=f"qual-{sample_id}",
                    prompt=qual_prompt,
                    system_prompt=TEST_QUALITY_SYSTEM_PROMPT,
                    max_tokens=1024,
                    temperature=0.0,
                    metadata={"sample_id": sample_id, "type": "quality"},
                ))

    return security_requests, quality_requests, sample_map


def process_file(
    filepath: Path,
    provider: str,
    model: str,
    poll_interval: int,
    do_security: bool,
    do_quality: bool,
) -> Optional[Path]:
    """Process a single result file through batch judge evaluation."""
    print(f"\n{'='*70}")
    print(f"Processing: {filepath}")
    print(f"{'='*70}")

    with open(filepath) as f:
        data = json.load(f)

    security_requests, quality_requests, sample_map = build_requests_for_file(
        data, do_security, do_quality,
    )

    total_requests = len(security_requests) + len(quality_requests)
    if total_requests == 0:
        print("  No samples with generated tests found. Skipping.")
        return None

    print(f"  Samples with tests: {len(sample_map)}")
    print(f"  Batch requests: {len(security_requests)} security + {len(quality_requests)} quality = {total_requests}")
    print(f"  Provider: {provider}, Model: {model}")
    print(f"  Cost savings: ~50% vs real-time API")

    processor = create_batch_processor(provider)

    # Submit and wait for security batch
    sec_responses = {}
    if security_requests:
        print(f"\n  Submitting security relevance batch ({len(security_requests)} requests)...")
        sec_result = processor.process_batch(
            security_requests, model, poll_interval=poll_interval,
        )
        sec_responses = {r.custom_id: r for r in sec_result.responses}
        print(f"  Security batch complete: {sec_result.completed_requests}/{sec_result.total_requests} succeeded")

    # Submit and wait for quality batch
    qual_responses = {}
    if quality_requests:
        print(f"\n  Submitting test quality batch ({len(quality_requests)} requests)...")
        qual_result = processor.process_batch(
            quality_requests, model, poll_interval=poll_interval,
        )
        qual_responses = {r.custom_id: r for r in qual_result.responses}
        print(f"  Quality batch complete: {qual_result.completed_requests}/{qual_result.total_requests} succeeded")

    # Write judge results into data
    sec_scores = []
    qual_scores = []
    composite_scores = []

    for variant in data.get("results", []):
        for sample in variant.get("detailed_results", []):
            sample_id = sample.get("sample_id", "")
            if sample_id not in sample_map:
                continue

            judge_batch = {
                "model": model,
                "provider": provider,
            }

            # Parse security response
            sec_resp = sec_responses.get(f"sec-{sample_id}")
            if sec_resp and sec_resp.success:
                parsed = parse_judge_response(sec_resp.content)
                score = parsed.get("score", 0)
                if isinstance(score, (int, float)) and score > 1:
                    score = score / 100  # Normalize 0-100 to 0-1
                judge_batch["security_relevance"] = {
                    "score": round(score, 4),
                    "cwe_addressed": parsed.get("cwe_addressed", False),
                    "attack_vectors_tested": parsed.get("attack_vectors_tested", []),
                    "security_properties_checked": parsed.get("security_properties_checked", []),
                    "reasoning": parsed.get("reasoning", ""),
                    "confidence": round(parsed.get("confidence", 0) / 100, 4) if parsed.get("confidence", 0) > 1 else round(parsed.get("confidence", 0), 4),
                    "raw_response": sec_resp.content,
                }
                sec_scores.append(score)
            elif sec_resp and not sec_resp.success:
                judge_batch["security_relevance"] = {
                    "score": 0.0,
                    "error": sec_resp.error,
                }

            # Parse quality response
            qual_resp = qual_responses.get(f"qual-{sample_id}")
            if qual_resp and qual_resp.success:
                parsed = parse_judge_response(qual_resp.content)
                score = parsed.get("score", 0)
                if isinstance(score, (int, float)) and score > 1:
                    score = score / 100
                judge_batch["test_quality"] = {
                    "score": round(score, 4),
                    "assertions_count": parsed.get("assertions_count", 0),
                    "edge_cases_covered": parsed.get("edge_cases_covered", 0),
                    "follows_best_practices": parsed.get("follows_best_practices", False),
                    "issues_found": parsed.get("issues_found", []),
                    "reasoning": parsed.get("reasoning", ""),
                    "confidence": round(parsed.get("confidence", 0) / 100, 4) if parsed.get("confidence", 0) > 1 else round(parsed.get("confidence", 0), 4),
                    "raw_response": qual_resp.content,
                }
                qual_scores.append(score)

            # Composite score
            sec_val = judge_batch.get("security_relevance", {}).get("score", 0)
            qual_val = judge_batch.get("test_quality", {}).get("score", 0)
            if sec_val or qual_val:
                if sec_val and qual_val:
                    composite = 0.6 * sec_val + 0.4 * qual_val
                elif sec_val:
                    composite = sec_val
                else:
                    composite = qual_val
                judge_batch["composite"] = round(composite, 4)
                composite_scores.append(composite)

            sample["judge_batch"] = judge_batch

        # Update variant-level averages
        if sec_scores:
            variant["avg_security_relevance_batch"] = round(sum(sec_scores) / len(sec_scores), 4)
        if qual_scores:
            variant["avg_test_quality_batch"] = round(sum(qual_scores) / len(qual_scores), 4)
        if composite_scores:
            variant["avg_composite_batch"] = round(sum(composite_scores) / len(composite_scores), 4)

    # Add metadata
    data["judge_batch_metadata"] = {
        "provider": provider,
        "model": model,
        "timestamp": datetime.now().isoformat(),
        "total_requests": total_requests,
        "security_succeeded": len(sec_scores),
        "quality_succeeded": len(qual_scores),
        "cost_savings": "~50% (batch API)",
    }

    # Save output
    output_path = filepath.with_name(filepath.stem + "_judged_batch.json")
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\n  Output saved: {output_path.name}")

    # Print summary
    print(f"\n  {'Summary':=^50}")
    if sec_scores:
        print(f"  Security Relevance:  avg={sum(sec_scores)/len(sec_scores):.2%}  "
              f"(n={len(sec_scores)}, min={min(sec_scores):.2%}, max={max(sec_scores):.2%})")
    if qual_scores:
        print(f"  Test Quality:        avg={sum(qual_scores)/len(qual_scores):.2%}  "
              f"(n={len(qual_scores)}, min={min(qual_scores):.2%}, max={max(qual_scores):.2%})")
    if composite_scores:
        print(f"  Composite (0.6s+0.4q): avg={sum(composite_scores)/len(composite_scores):.2%}")

    return output_path


def main():
    parser = argparse.ArgumentParser(
        description="Run LLM-as-Judge evaluation on saved result files via batch API (50% savings)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python baselines/run_judge_batch.py results/
  python baselines/run_judge_batch.py results/gpt-oss-120b/ --provider openai
  python baselines/run_judge_batch.py results/ --provider openai --model gpt-4o
  python baselines/run_judge_batch.py results/ --force --security-only
        """,
    )
    parser.add_argument(
        "paths", nargs="+",
        help="Result file(s) or directory(ies) to judge",
    )
    parser.add_argument(
        "--provider", choices=["anthropic", "openai"], default="anthropic",
        help="API provider (default: anthropic)",
    )
    parser.add_argument(
        "--model", default=None,
        help="Judge model (default: provider-specific)",
    )
    parser.add_argument(
        "--force", action="store_true",
        help="Re-judge files that already have _judged_batch.json output",
    )
    parser.add_argument(
        "--poll-interval", type=int, default=60,
        help="Seconds between batch status checks (default: 60)",
    )
    parser.add_argument(
        "--security-only", action="store_true",
        help="Only evaluate security relevance",
    )
    parser.add_argument(
        "--quality-only", action="store_true",
        help="Only evaluate test quality",
    )

    args = parser.parse_args()

    # Load env
    load_dotenv()

    # Resolve model
    model = args.model or DEFAULT_MODELS.get(args.provider, "claude-opus-4-6")

    # Check API key
    if args.provider == "anthropic":
        if not os.getenv("ANTHROPIC_API_KEY"):
            print("Error: ANTHROPIC_API_KEY not set. Set it in .env or environment.")
            sys.exit(1)
    elif args.provider == "openai":
        if not os.getenv("OPENAI_API_KEY"):
            print("Error: OPENAI_API_KEY not set. Set it in .env or environment.")
            sys.exit(1)

    # Determine which dimensions to evaluate
    do_security = not args.quality_only
    do_quality = not args.security_only

    # Find files
    files = find_result_files(args.paths, force=args.force)
    if not files:
        print("No unjudged result files found. Use --force to re-judge.")
        sys.exit(0)

    print(f"Found {len(files)} file(s) to judge:")
    for f in files:
        print(f"  - {f.relative_to(f.parent.parent) if len(f.parts) > 2 else f.name}")

    print(f"\nProvider: {args.provider} | Model: {model}")
    print(f"Dimensions: {'security' if do_security else ''}{' + ' if do_security and do_quality else ''}{'quality' if do_quality else ''}")
    print(f"Poll interval: {args.poll_interval}s")

    # Process each file
    output_files = []
    for filepath in files:
        try:
            output = process_file(
                filepath, args.provider, model, args.poll_interval,
                do_security, do_quality,
            )
            if output:
                output_files.append(output)
        except Exception as e:
            print(f"\n  ERROR processing {filepath.name}: {e}")
            import traceback
            traceback.print_exc()

    # Final summary
    if output_files:
        print(f"\n{'='*70}")
        print(f"Batch judging complete. {len(output_files)} file(s) processed:")
        for f in output_files:
            print(f"  {f}")
        print(f"{'='*70}")


if __name__ == "__main__":
    main()
