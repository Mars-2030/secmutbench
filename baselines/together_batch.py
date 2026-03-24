#!/usr/bin/env python3
"""
Together.ai Batch API for SecMutBench

Submits all evaluation requests as a batch for 50% cost savings.
Results are processed asynchronously (usually within hours, max 24h).

Workflow:
    1. Generate prompts for all samples × prompt variants
    2. Write JSONL batch file
    3. Upload and submit batch to Together.ai
    4. Poll until complete
    5. Download results and run mutation testing locally
    6. Save results

Usage:
    # Submit batch for both models
    python baselines/together_batch.py --models "moonshotai/Kimi-K2.5" "zai-org/GLM-5" \
        --dataset data/dataset2.json --ablation --skip-invalid

    # Check status of a running batch
    python baselines/together_batch.py --status <batch_id>

    # Process results from a completed batch
    python baselines/together_batch.py --process <batch_id> --dataset data/dataset2.json
"""

import json
import os
import sys
import time
import argparse
import tempfile
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.evaluate import evaluate_generated_tests, evaluate_reference_tests, load_benchmark
from evaluation.prompts import (
    format_test_generation_prompt,
    format_prompt_no_hint,
    format_prompt_cwe_id_only,
)
from evaluation.metrics import calculate_kill_breakdown
from evaluation.version import get_version_info, __version__


# Load .env file
def load_dotenv():
    env_paths = [
        Path(__file__).parent.parent / ".env",
        Path.cwd() / ".env",
    ]
    for env_path in env_paths:
        if env_path.exists():
            with open(env_path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        key, _, value = line.partition("=")
                        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))
            break

load_dotenv()


def format_prompt(sample: Dict, variant: str) -> str:
    """Generate prompt based on variant."""
    if variant == "no-hint":
        return format_prompt_no_hint(
            code=sample["secure_code"],
            entry_point=sample.get("entry_point", "function"),
        )
    elif variant == "cwe-only":
        return format_prompt_cwe_id_only(
            code=sample["secure_code"],
            cwe=sample["cwe"],
            entry_point=sample.get("entry_point", "function"),
        )
    else:  # "full"
        return format_test_generation_prompt(
            code=sample["secure_code"],
            cwe=sample["cwe"],
            cwe_name=sample.get("cwe_name", "vulnerability"),
            include_mock_env=True,
        )


def build_batch_jsonl(
    samples: List[Dict],
    model: str,
    variants: List[str],
    output_path: str,
) -> int:
    """
    Build a JSONL file for Together.ai batch API.

    Each line: {"custom_id": "<sample_id>__<variant>", "body": {...}}

    Returns number of requests written.
    """
    count = 0

    # Kimi models need different settings
    is_kimi = "kimi" in model.lower()
    temp = 0.6 if is_kimi else 0.2
    max_tok = 8192 if is_kimi else 4096

    with open(output_path, "w") as f:
        for sample in samples:
            for variant in variants:
                prompt = format_prompt(sample, variant)
                custom_id = f"{sample['id']}__{variant}"

                # Truncate custom_id to 64 chars (Together.ai limit)
                if len(custom_id) > 64:
                    custom_id = custom_id[:64]

                request = {
                    "custom_id": custom_id,
                    "body": {
                        "model": model,
                        "messages": [
                            {
                                "role": "system",
                                "content": "You are a security testing expert. Generate only Python test code, no explanations.",
                            },
                            {"role": "user", "content": prompt},
                        ],
                        "temperature": temp,
                        "max_tokens": max_tok,
                    },
                }
                f.write(json.dumps(request) + "\n")
                count += 1

    return count


def submit_batch(jsonl_path: str) -> str:
    """Upload JSONL file and create a batch job. Returns batch ID."""
    from together import Together
    client = Together(api_key=os.getenv("TOGETHER_API_KEY"))

    print(f"  Uploading {jsonl_path}...")
    file_resp = client.files.upload(file=jsonl_path, purpose="batch-api", check=False)
    print(f"  File uploaded: {file_resp.id}")

    print(f"  Creating batch...")
    resp = client.batches.create(input_file_id=file_resp.id, endpoint="/v1/chat/completions")
    batch = resp.job  # BatchCreateResponse.job -> BatchJob
    print(f"  Batch created: {batch.id}")
    print(f"  Status: {batch.status}")

    return batch.id


def check_status(batch_id: str) -> dict:
    """Check batch status. Returns status dict."""
    from together import Together
    client = Together(api_key=os.getenv("TOGETHER_API_KEY"))

    batch = client.batches.retrieve(batch_id)
    return {
        "id": batch.id,
        "status": batch.status,
        "output_file_id": getattr(batch, "output_file_id", None),
        "error_file_id": getattr(batch, "error_file_id", None),
    }


def wait_for_completion(batch_id: str, poll_interval: int = 60, max_wait_hours: int = 24) -> dict:
    """Poll until batch completes. Returns final status."""
    from together import Together
    client = Together(api_key=os.getenv("TOGETHER_API_KEY"))

    max_polls = (max_wait_hours * 3600) // poll_interval
    print(f"  Polling every {poll_interval}s (max {max_wait_hours}h)...")

    for poll in range(max_polls):
        batch = client.batches.retrieve(batch_id)
        status = batch.status
        print(f"  [{poll+1}] Status: {status}", flush=True)

        if status == "COMPLETED":
            print(f"  Batch completed!")
            return {
                "id": batch.id,
                "status": status,
                "output_file_id": batch.output_file_id,
                "error_file_id": getattr(batch, "error_file_id", None),
            }
        elif status in ("FAILED", "CANCELLED", "EXPIRED"):
            raise RuntimeError(f"Batch {batch_id} {status}")

        time.sleep(poll_interval)

    raise TimeoutError(f"Batch {batch_id} did not complete within {max_wait_hours}h")


def download_results(batch_id: str, output_dir: str = "results") -> str:
    """Download batch results to a JSONL file. Returns output path."""
    from together import Together
    client = Together(api_key=os.getenv("TOGETHER_API_KEY"))

    batch = client.batches.retrieve(batch_id)
    if batch.status != "COMPLETED":
        raise RuntimeError(f"Batch not completed: {batch.status}")

    output_path = os.path.join(output_dir, f"batch_output_{batch_id}.jsonl")
    os.makedirs(output_dir, exist_ok=True)

    # v2 SDK: content() returns binary response, write manually
    content = client.files.content(id=batch.output_file_id)
    with open(output_path, "wb") as f:
        f.write(content.read() if hasattr(content, 'read') else content)
    print(f"  Results downloaded to: {output_path}")

    # Check for errors
    if getattr(batch, "error_file_id", None):
        error_path = os.path.join(output_dir, f"batch_errors_{batch_id}.jsonl")
        err_content = client.files.content(id=batch.error_file_id)
        with open(error_path, "wb") as f:
            f.write(err_content.read() if hasattr(err_content, 'read') else err_content)
        print(f"  Errors downloaded to: {error_path}")

    return output_path


def extract_test_code(response: str) -> str:
    """Extract test code from LLM response."""
    import re
    code_blocks = re.findall(r'```(?:python)?\s*\n(.*?)```', response, re.DOTALL)
    if code_blocks:
        return "\n\n".join(code_blocks)
    if "def test_" in response:
        match = re.search(r'(def test_.*)', response, re.DOTALL)
        if match:
            return match.group(1)
    return response


def process_results(
    output_jsonl: str,
    benchmark: List[Dict],
    model: str,
    max_mutants: int = 10,
) -> Dict:
    """
    Process batch results: extract tests, run mutation testing, compute metrics.

    Returns dict with results grouped by prompt variant.
    """
    # Parse batch output
    responses = {}
    with open(output_jsonl) as f:
        for line in f:
            entry = json.loads(line)
            custom_id = entry["custom_id"]
            content = ""
            if "response" in entry and entry["response"]:
                resp = entry["response"]
                # Together.ai nests choices under response.body
                body = resp.get("body", resp)
                choices = body.get("choices", [])
                if choices:
                    content = choices[0].get("message", {}).get("content", "") or ""
            responses[custom_id] = content

    print(f"  Loaded {len(responses)} responses")

    # Build sample lookup
    sample_lookup = {s["id"]: s for s in benchmark}

    # Group by variant
    variant_results = {}
    errors = 0

    for custom_id, raw_response in responses.items():
        # Parse custom_id: "<sample_id>__<variant>"
        parts = custom_id.rsplit("__", 1)
        if len(parts) != 2:
            errors += 1
            continue

        sample_id, variant = parts
        sample = sample_lookup.get(sample_id)
        if not sample:
            errors += 1
            continue

        generated_tests = extract_test_code(raw_response)
        if not generated_tests.strip():
            errors += 1
            continue

        # Run mutation testing (use 30s timeout to avoid hanging on bad tests)
        from evaluation.test_runner import TestRunner
        runner = TestRunner(timeout=30.0)
        eval_result = evaluate_generated_tests(sample, generated_tests, runner=runner, max_mutants=max_mutants)

        prompt = format_prompt(sample, variant)

        result_entry = {
            "sample_id": sample["id"],
            "cwe": sample["cwe"],
            "cwe_name": sample.get("cwe_name", ""),
            "difficulty": sample["difficulty"],
            "source_type": sample.get("source_type", "unknown"),
            "mutation_operators": sample.get("mutation_operators", []),
            "secure_code": sample["secure_code"],
            "insecure_code": sample.get("insecure_code", ""),
            "prompt": prompt,
            "raw_response": raw_response,
            "generated_tests": generated_tests,
            "metrics": eval_result["metrics"],
            "mutant_details": eval_result.get("mutant_details", []),
            "test_results": eval_result.get("test_results", []),
            "reference_tests": sample.get("security_tests", ""),
        }

        if variant not in variant_results:
            variant_results[variant] = []
        variant_results[variant].append(result_entry)

        # Progress
        total_done = sum(len(v) for v in variant_results.values()) + errors
        ms = eval_result["metrics"].get("mutation_score")
        if ms is not None:
            killed = eval_result["metrics"].get("mutants_killed", 0)
            total = eval_result["metrics"].get("mutants_total", 0)
            print(f"  [{total_done}/{len(responses)}] {sample_id[:12]}... [{variant}] MS={killed}/{total} ({ms:.1%})")
        else:
            print(f"  [{total_done}/{len(responses)}] {sample_id[:12]}... [{variant}] MS=N/A")

    return {"variant_results": variant_results, "errors": errors, "total_responses": len(responses)}


def save_results(model: str, variant_results: Dict, errors: int, eval_time: float = 0.0, output_dir: str = "results"):
    """Save results in same format as run_llm_baselines.py — single file, all variants."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    model_dir_name = model.replace("/", "_").replace(":", "_")
    model_dir = Path(output_dir) / model_dir_name
    model_dir.mkdir(parents=True, exist_ok=True)

    all_model_results = []

    for variant, results in variant_results.items():
        if not results:
            continue

        mutation_scores = [r["metrics"].get("mutation_score") for r in results]
        valid_ms = [ms for ms in mutation_scores if ms is not None]
        vuln_detections = [1 if r["metrics"].get("vuln_detected", False) else 0 for r in results]
        coverages = [r["metrics"].get("line_coverage", 0) or 0 for r in results]
        kill_breakdown = calculate_kill_breakdown(results)
        secure_passes = sum(1 for r in results if r["metrics"].get("secure_passes", False))
        vuln_detected = sum(1 for r in results if r["metrics"].get("vuln_detected", False))

        avg_ms = sum(valid_ms) / len(valid_ms) if valid_ms else 0.0
        avg_vd = sum(vuln_detections) / len(vuln_detections) if vuln_detections else 0.0
        sms = kill_breakdown.get("security_mutation_score")
        eff_ms = (avg_ms * avg_vd) ** 0.5 if avg_ms and avg_vd else 0.0

        model_result = {
            "model_name": f"{model} [{variant}]",
            "provider": "together",
            "samples_evaluated": len(results),
            "avg_mutation_score": avg_ms,
            "avg_vuln_detection": avg_vd,
            "avg_line_coverage": sum(coverages) / len(coverages) if coverages else 0.0,
            "avg_security_relevance": None,
            "avg_test_quality": None,
            "avg_composite_score": None,
            "avg_security_mutation_score": sms,
            "avg_incidental_score": kill_breakdown.get("incidental_score"),
            "avg_crash_score": kill_breakdown.get("crash_score"),
            "avg_security_precision": vuln_detected / secure_passes if secure_passes > 0 else None,
            "secure_pass_rate": secure_passes / len(results) if results else 0.0,
            "effective_mutation_score": eff_ms,
            "evaluation_time": eval_time,
            "errors": errors,
            "detailed_results": results,
        }

        all_model_results.append(model_result)

        print(f"  [{variant}] Samples: {len(results)}, MS: {avg_ms:.1%}, "
              f"Kills: Sem={kill_breakdown['semantic_kills']} Inc={kill_breakdown['incidental_kills']} "
              f"Crash={kill_breakdown['crash_kills']}")

    # Save single file with all variants (same format as run_llm_baselines.py)
    output_file = model_dir / f"baseline_results_{timestamp}.json"
    data = {
        "version_info": get_version_info(),
        "timestamp": timestamp,
        "results": all_model_results,
        "reference_baseline": {
            "avg_mutation_score": None,
            "avg_vuln_detection": None,
            "avg_line_coverage": None,
            "avg_security_relevance": None,
            "avg_test_quality": None,
        }
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"  Saved: {output_file}")


def main():
    parser = argparse.ArgumentParser(description="Together.ai Batch API for SecMutBench")
    parser.add_argument("--models", nargs="+", default=["moonshotai/Kimi-K2.5", "zai-org/GLM-5"],
                       help="Models to evaluate")
    parser.add_argument("--dataset", default="data/dataset2.json", help="Dataset path")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard"], help="Filter by difficulty")
    parser.add_argument("--cwe", help="Filter by CWE")
    parser.add_argument("--max-samples", type=int, help="Max samples")
    parser.add_argument("--skip-invalid", action="store_true", help="Skip invalid samples")
    parser.add_argument("--ablation", action="store_true", help="Run all 3 prompt variants")
    parser.add_argument("--prompt-variant", choices=["full", "no-hint", "cwe-only"], default="full")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--poll-interval", type=int, default=60, help="Seconds between status checks")
    parser.add_argument("--max-mutants", type=int, default=10, help="Max mutants per sample")

    # Batch management
    parser.add_argument("--submit-only", action="store_true",
                       help="Submit batch and exit (don't wait for results)")
    parser.add_argument("--status", type=str, help="Check status of a batch ID")
    parser.add_argument("--process", type=str,
                       help="Process results from a completed batch ID")
    parser.add_argument("--process-file", type=str,
                       help="Process results from a downloaded JSONL file")

    args = parser.parse_args()

    # === Status check mode ===
    if args.status:
        status = check_status(args.status)
        print(f"Batch: {status['id']}")
        print(f"Status: {status['status']}")
        if status['output_file_id']:
            print(f"Output file: {status['output_file_id']}")
        return

    # === Process completed batch ===
    if args.process or args.process_file:
        print("Loading benchmark...")
        benchmark = load_benchmark(path=args.dataset, difficulty=args.difficulty, cwe=args.cwe)
        if args.skip_invalid:
            benchmark = [s for s in benchmark if s.get("quality", {}).get("validation_passed", True)]
        if args.max_samples:
            benchmark = benchmark[:args.max_samples]
        print(f"Loaded {len(benchmark)} samples")

        if args.process:
            print(f"Downloading results for batch: {args.process}")
            output_jsonl = download_results(args.process, args.output)
        else:
            output_jsonl = args.process_file
            print(f"Processing results from: {output_jsonl}")

        # Determine model from the JSONL
        with open(output_jsonl) as f:
            first_line = json.loads(f.readline())
            model = first_line.get("response", {}).get("body", {}).get("model", "unknown")
            if model == "unknown" and "body" in first_line:
                model = first_line["body"].get("model", "unknown")

        print(f"Processing results for model: {model}")
        eval_start = time.time()
        result = process_results(output_jsonl, benchmark, model, max_mutants=args.max_mutants)
        eval_time = time.time() - eval_start
        save_results(model, result["variant_results"], result["errors"], eval_time, args.output)
        return

    # === Submit new batch ===
    print("Loading benchmark...")
    benchmark = load_benchmark(path=args.dataset, difficulty=args.difficulty, cwe=args.cwe)
    if args.skip_invalid:
        orig_count = len(benchmark)
        benchmark = [s for s in benchmark if s.get("quality", {}).get("validation_passed", True)]
        print(f"Skipped {orig_count - len(benchmark)} invalid samples")
    if args.max_samples:
        benchmark = benchmark[:args.max_samples]
    print(f"Loaded {len(benchmark)} samples")

    variants = ["full", "no-hint", "cwe-only"] if args.ablation else [args.prompt_variant]
    print(f"Prompt variants: {variants}")

    for model in args.models:
        print(f"\n{'='*60}")
        print(f"Model: {model}")
        print(f"{'='*60}")

        # Build JSONL
        jsonl_path = os.path.join(args.output, f"batch_input_{model.replace('/', '_')}.jsonl")
        os.makedirs(args.output, exist_ok=True)
        count = build_batch_jsonl(benchmark, model, variants, jsonl_path)
        print(f"  Created {jsonl_path} ({count} requests)")

        # Submit
        batch_id = submit_batch(jsonl_path)
        print(f"  Batch ID: {batch_id}")

        # Save batch metadata
        meta_path = os.path.join(args.output, f"batch_meta_{model.replace('/', '_')}.json")
        with open(meta_path, "w") as f:
            json.dump({
                "batch_id": batch_id,
                "model": model,
                "dataset": args.dataset,
                "samples": len(benchmark),
                "variants": variants,
                "total_requests": count,
                "submitted_at": datetime.now().isoformat(),
            }, f, indent=2)

        if args.submit_only:
            print(f"  Batch submitted. Check status later with:")
            print(f"    python baselines/together_batch.py --status {batch_id}")
            print(f"  Process results with:")
            print(f"    python baselines/together_batch.py --process {batch_id} --dataset {args.dataset}")
            continue

        # Wait for completion
        print(f"\n  Waiting for batch to complete...")
        result = wait_for_completion(batch_id, poll_interval=args.poll_interval)

        # Download and process
        output_jsonl = download_results(batch_id, args.output)
        eval_start = time.time()
        processed = process_results(output_jsonl, benchmark, model, max_mutants=args.max_mutants)
        eval_time = time.time() - eval_start
        save_results(model, processed["variant_results"], processed["errors"], eval_time, args.output)

    print(f"\nDone!")


if __name__ == "__main__":
    main()
