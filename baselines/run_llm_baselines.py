#!/usr/bin/env python3
"""
LLM Baseline Evaluation for SecMutBench

Standalone script for running LLM evaluations without the multi-agent system.
Use this for quick experiments or when you don't need the full orchestrator.

Supports:
1. Ollama (local models)
2. OpenAI API
3. Anthropic API

Results are evaluated using mutation testing and optionally LLM-as-Judge.

Usage:
    # Run with Ollama model
    python baselines/run_llm_baselines.py --models qwen2.5-coder:7b --max-samples 10

    # Run with OpenAI
    python baselines/run_llm_baselines.py --provider openai --max-samples 10 --use-judge

    # Run all Ollama models
    python baselines/run_llm_baselines.py --provider ollama --max-samples 5

For the full multi-agent system with feedback loops, use:
    python agentic_pipeline/agents/orchestrator.py --models E001 --samples 10
"""

import json
import os
import sys
import time
import argparse
from pathlib import Path
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.evaluate import evaluate_generated_tests, evaluate_reference_tests, load_benchmark
from evaluation.llm_judge import create_evaluator, format_multimodal_report
from evaluation.prompts import format_test_generation_prompt
from evaluation.metrics import calculate_kill_breakdown
from collections import defaultdict
import random as random_module


def stratified_sample(benchmark: List[Dict], max_samples: int, seed: int = 42) -> List[Dict]:
    """
    Sample proportionally from each CWE to ensure representative coverage.

    Instead of taking the first N samples (which may cluster on one CWE),
    this samples proportionally from each CWE category.

    Args:
        benchmark: Full list of samples
        max_samples: Target number of samples
        seed: Random seed for reproducibility

    Returns:
        List of samples with proportional CWE representation
    """
    rng = random_module.Random(seed)

    # Group by CWE
    by_cwe = defaultdict(list)
    for s in benchmark:
        by_cwe[s.get('cwe', 'unknown')].append(s)

    total = len(benchmark)
    selected = []

    # First pass: proportional allocation
    for cwe, cwe_samples in by_cwe.items():
        # Proportional allocation with minimum of 1
        n = max(1, round(len(cwe_samples) / total * max_samples))
        rng.shuffle(cwe_samples)
        selected.extend(cwe_samples[:n])

    # If we have too many, trim randomly
    if len(selected) > max_samples:
        rng.shuffle(selected)
        selected = selected[:max_samples]

    # If we have too few, add more randomly from remaining
    elif len(selected) < max_samples:
        used_ids = {s['id'] for s in selected}
        remaining = [s for s in benchmark if s['id'] not in used_ids]
        rng.shuffle(remaining)
        needed = max_samples - len(selected)
        selected.extend(remaining[:needed])

    # Final shuffle to mix CWEs
    rng.shuffle(selected)
    return selected


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


# Available models configuration
# These match the models in agentic_pipeline/agents/orchestrator.py
OLLAMA_MODELS = [
    "qwen2.5-coder:7b",           # E001 - Fast, good for testing
    "qwen2.5-coder:14b-instruct", # E002 - Better quality
    "codellama:13b",              # E003 - Meta's code model
    "qwen3-coder:latest",         # E004 - Latest Qwen
    "devstral:latest",            # E005 - Mistral's dev model
    "codestral:latest",           # E006 - Mistral code model
    "deepseek-coder-v2:latest",   # E007 - DeepSeek
    "deepseek-r1:14b",            # E008 - DeepSeek reasoning
    "gpt-oss:120b",               # E009 - OpenAI OSS model
]

API_MODELS = [
    {"name": "gpt-4o", "provider": "openai"},
    {"name": "gpt-5", "provider": "openai"},
    {"name": "gpt-5-mini-2025-08-07", "provider": "openai"},
    {"name": "claude-sonnet-4-5-20250929", "provider": "anthropic"},
    {"name": "gemini-3-flash-preview", "provider": "google"},
    {"name": "gemini-2.5-pro", "provider": "google"},
]


# Prompt template is now imported from evaluation.prompts for consistency
# Use format_test_generation_prompt() to generate prompts


@dataclass
class ModelResult:
    """Results for a single model evaluation."""
    model_name: str
    provider: str
    samples_evaluated: int
    avg_mutation_score: float
    avg_vuln_detection: float
    avg_line_coverage: float
    avg_security_relevance: Optional[float] = None
    avg_test_quality: Optional[float] = None
    avg_composite_score: Optional[float] = None
    avg_security_mutation_score: Optional[float] = None
    avg_incidental_score: Optional[float] = None
    avg_crash_score: Optional[float] = None
    avg_security_precision: Optional[float] = None
    evaluation_time: float = 0.0
    errors: int = 0
    detailed_results: List[Dict] = None

    def __post_init__(self):
        if self.detailed_results is None:
            self.detailed_results = []


def call_ollama(model: str, prompt: str, timeout: int = 300) -> str:
    """Call Ollama API to generate tests.

    Args:
        model: Ollama model name
        prompt: The prompt to send
        timeout: Request timeout in seconds (default 300 = 5 minutes)
    """
    import requests

    try:
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
            "options": {
                "temperature": 0.2,
                "num_predict": 2048,
            }
        }
        if model.startswith("gpt-oss"):
            payload["think"] = "high"
            payload["options"]["num_predict"] = 8192
        response = requests.post(
            "http://localhost:11434/api/generate",
            json=payload,
            timeout=timeout
        )
        response.raise_for_status()
        result = response.json()
        return result.get("response", "") or result.get("thinking", "")
    except requests.exceptions.Timeout:
        print(f"  Ollama timeout after {timeout}s - try increasing with --timeout")
        return ""
    except Exception as e:
        print(f"  Ollama error: {e}")
        return ""


def call_openai(model: str, prompt: str) -> str:
    """Call OpenAI API to generate tests."""
    try:
        from openai import OpenAI
        client = OpenAI(api_key=os.getenv("OPENAI_API_KEY"))

        # GPT-5 doesn't support temperature parameter
        if "gpt-5" in model.lower():
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                    {"role": "user", "content": prompt}
                ],
            )
        else:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
            )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  OpenAI error: {e}")
        return ""


def call_anthropic(model: str, prompt: str) -> str:
    """Call Anthropic API to generate tests."""
    try:
        import anthropic
        client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

        response = client.messages.create(
            model=model,
            max_tokens=2048,
            messages=[
                {"role": "user", "content": prompt}
            ],
            system="You are a security testing expert. Generate only Python test code, no explanations.",
            temperature=0.2,
        )
        return response.content[0].text
    except Exception as e:
        print(f"  Anthropic error: {e}")
        return ""


def call_google(model: str, prompt: str, max_retries: int = 3) -> str:
    """Call Google Gemini API to generate tests."""
    from google import genai
    client = genai.Client(api_key=os.getenv("GOOGLE_API_KEY"))
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=model,
                contents=prompt,
                config={"temperature": 0.2, "max_output_tokens": 2048},
            )
            return response.text
        except Exception as e:
            if "429" in str(e) or "RESOURCE_EXHAUSTED" in str(e):
                wait = 60
                print(f"  Google rate limit hit, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...")
                time.sleep(wait)
            else:
                print(f"  Google error: {e}")
                return ""
    print(f"  Google error: max retries ({max_retries}) exhausted")
    return ""


def generate_tests(model: str, provider: str, sample: Dict, timeout: int = 300) -> str:
    """Generate security tests using specified model."""
    # Use unified prompt from evaluation.prompts
    prompt = format_test_generation_prompt(
        code=sample["secure_code"],
        cwe=sample["cwe"],
        cwe_name=sample.get("cwe_name", "vulnerability"),
        include_mock_env=True,
    )

    if provider == "ollama":
        return call_ollama(model, prompt, timeout=timeout)
    elif provider == "openai":
        return call_openai(model, prompt)
    elif provider == "anthropic":
        return call_anthropic(model, prompt)
    elif provider == "google":
        return call_google(model, prompt)
    else:
        raise ValueError(f"Unknown provider: {provider}")


def extract_test_code(response: str) -> str:
    """Extract test code from LLM response."""
    # Try to extract code from markdown blocks
    import re

    # Look for ```python ... ``` blocks
    code_blocks = re.findall(r'```(?:python)?\s*\n(.*?)```', response, re.DOTALL)
    if code_blocks:
        return "\n\n".join(code_blocks)

    # If no code blocks, check if response looks like code
    if "def test_" in response:
        # Extract from first def test_ to end
        match = re.search(r'(def test_.*)', response, re.DOTALL)
        if match:
            return match.group(1)

    return response


def evaluate_model(
    model: str,
    provider: str,
    benchmark: List[Dict],
    use_judge: bool = False,
    judge_provider: str = "anthropic",
    max_samples: Optional[int] = None,
    start_sample: int = 0,
    max_mutants: int = 10,
    timeout: int = 300,
) -> ModelResult:
    """Evaluate a single model on the benchmark."""
    print(f"\n{'='*60}")
    print(f"Evaluating: {model} ({provider})")
    if start_sample > 0:
        print(f"Resuming from sample {start_sample}")
    print(f"{'='*60}")

    start_time = time.time()
    results = []
    errors = 0

    samples_to_eval = benchmark[:max_samples] if max_samples else benchmark
    # Skip to start_sample for resume support
    samples_to_eval = samples_to_eval[start_sample:]
    total_samples = len(benchmark[:max_samples] if max_samples else benchmark)

    for i, sample in enumerate(samples_to_eval, start=start_sample):
        print(f"  [{i+1}/{total_samples}] {sample['id']}...", end=" ", flush=True)

        try:
            # Generate tests
            raw_response = generate_tests(model, provider, sample, timeout=timeout)
            generated_tests = extract_test_code(raw_response)

            if not generated_tests.strip():
                print("EMPTY")
                errors += 1
                continue

            # Generate the prompt for logging
            prompt = format_test_generation_prompt(
                code=sample["secure_code"],
                cwe=sample["cwe"],
                cwe_name=sample.get("cwe_name", "vulnerability"),
                include_mock_env=True,
            )

            # Evaluate with mutation testing
            eval_result = evaluate_generated_tests(sample, generated_tests, max_mutants=max_mutants)

            # Build detailed result with all context needed for analysis
            results.append({
                # Sample context
                "sample_id": sample["id"],
                "cwe": sample["cwe"],
                "cwe_name": sample.get("cwe_name", ""),
                "difficulty": sample["difficulty"],
                "mutation_operators": sample.get("mutation_operators", []),

                # Original code (what the LLM was asked to test)
                "secure_code": sample["secure_code"],
                "insecure_code": sample.get("insecure_code", ""),

                # LLM interaction
                "prompt": prompt,
                "raw_response": raw_response,  # Full LLM response before extraction
                "generated_tests": generated_tests,  # Extracted test code

                # Evaluation results
                "metrics": eval_result["metrics"],
                "mutant_details": eval_result.get("mutant_details", []),
                "test_results": eval_result.get("test_results", []),  # Per-test pass/fail

                # Reference for comparison
                "reference_tests": sample.get("security_tests", ""),
            })

            # Show detailed mutation score with kill breakdown
            metrics = eval_result["metrics"]
            mutant_details = eval_result.get("mutant_details", [])
            killed = metrics.get("mutants_killed", 0)
            total = metrics.get("mutants_total", 0)
            ms = metrics.get("mutation_score")

            if ms is not None and total > 0:
                # Calculate kill breakdown for this sample
                semantic = sum(1 for m in mutant_details if m.get("killed") and m.get("kill_type") == "semantic")
                incidental = sum(1 for m in mutant_details if m.get("killed") and m.get("kill_type") == "assertion_incidental")
                crash = sum(1 for m in mutant_details if m.get("killed") and m.get("kill_type") == "crash")
                print(f"MS={killed}/{total} ({ms:.1%}) [Sec:{semantic} Inc:{incidental} Crash:{crash}]")
            elif total == 0:
                print(f"MS=N/A (0 mutants)")
            else:
                print(f"MS=N/A")

        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1
            continue

        # Rate limiting for API calls
        if provider in ["openai", "anthropic"]:
            time.sleep(1)

    # Calculate aggregates
    if results:
        # Handle None values in mutation_score (no mutants generated)
        mutation_scores = [r["metrics"].get("mutation_score") for r in results]
        valid_mutation_scores = [ms for ms in mutation_scores if ms is not None]

        vuln_detections = [1 if r["metrics"].get("vuln_detected", False) else 0 for r in results]
        coverages = [r["metrics"].get("line_coverage", 0) or 0 for r in results]

        # Calculate kill breakdown totals
        kill_breakdown = calculate_kill_breakdown(results)
        print(f"\n  Kill Breakdown: Semantic={kill_breakdown['semantic_kills']} "
              f"Incidental={kill_breakdown['incidental_kills']} "
              f"Crash={kill_breakdown['crash_kills']} "
              f"Other={kill_breakdown['other_kills']}")
        if kill_breakdown['security_mutation_score'] is not None:
            print(f"  Security Mutation Score: {kill_breakdown['security_mutation_score']:.1%} "
                  f"(vs Overall: {kill_breakdown['mutation_score']:.1%})")

        # Calculate security precision
        secure_passes_count = sum(1 for r in results if r["metrics"].get("secure_passes", False))
        vuln_detected_count = sum(1 for r in results if r["metrics"].get("vuln_detected", False))
        sec_precision = vuln_detected_count / secure_passes_count if secure_passes_count > 0 else None

        model_result = ModelResult(
            model_name=model,
            provider=provider,
            samples_evaluated=len(results),
            avg_mutation_score=sum(valid_mutation_scores) / len(valid_mutation_scores) if valid_mutation_scores else 0.0,
            avg_vuln_detection=sum(vuln_detections) / len(vuln_detections),
            avg_line_coverage=sum(coverages) / len(coverages),
            avg_security_mutation_score=kill_breakdown.get("security_mutation_score"),
            avg_incidental_score=kill_breakdown.get("incidental_score"),
            avg_crash_score=kill_breakdown.get("crash_score"),
            avg_security_precision=sec_precision,
            evaluation_time=time.time() - start_time,
            errors=errors,
            detailed_results=results,
        )
    else:
        model_result = ModelResult(
            model_name=model,
            provider=provider,
            samples_evaluated=0,
            avg_mutation_score=0,
            avg_vuln_detection=0,
            avg_line_coverage=0,
            evaluation_time=time.time() - start_time,
            errors=errors,
        )

    # Run LLM-as-Judge if requested
    if use_judge and results:
        print(f"\n  Running LLM-as-Judge ({judge_provider})...")
        try:
            evaluator = create_evaluator(provider=judge_provider)

            security_scores = []
            quality_scores = []
            composite_scores = []

            for r in results:
                sample = next(s for s in benchmark if s["id"] == r["sample_id"])
                judge_result = evaluator.evaluate(
                    sample,
                    r["generated_tests"],
                    {"metrics": r["metrics"]}
                )

                if judge_result.security_relevance:
                    security_scores.append(judge_result.security_relevance.score)
                if judge_result.test_quality:
                    quality_scores.append(judge_result.test_quality.score)
                composite_scores.append(judge_result.composite_score)

                time.sleep(0.5)  # Rate limiting

            if security_scores:
                model_result.avg_security_relevance = sum(security_scores) / len(security_scores)
            if quality_scores:
                model_result.avg_test_quality = sum(quality_scores) / len(quality_scores)
            if composite_scores:
                model_result.avg_composite_score = sum(composite_scores) / len(composite_scores)

        except Exception as e:
            print(f"  Judge error: {e}")

    return model_result


def print_results_table(results: List[ModelResult], ref_baseline: Optional[Dict] = None):
    """Print results as a formatted table."""
    print("\n" + "="*112)
    print("LLM BASELINE RESULTS")
    print("="*112)

    # Header
    print(f"{'Model':<35} {'Mutation':<12} {'Sec MS':<12} {'Vuln Det':<12} {'Coverage':<12} {'Sec Rel':<12} {'Quality':<12}")
    print("-"*112)

    # Sort by mutation score
    sorted_results = sorted(results, key=lambda x: x.avg_mutation_score, reverse=True)

    for r in sorted_results:
        sec_rel = f"{r.avg_security_relevance:>10.1%}" if r.avg_security_relevance is not None else f"{'N/A':>10}"
        quality = f"{r.avg_test_quality:>10.1%}" if r.avg_test_quality is not None else f"{'N/A':>10}"
        sms = f"{r.avg_security_mutation_score:>10.1%}" if r.avg_security_mutation_score is not None else f"{'N/A':>10}"
        print(f"{r.model_name:<35} {r.avg_mutation_score:>10.1%} {sms} {r.avg_vuln_detection:>10.1%} "
              f"{r.avg_line_coverage:>10.1%} {sec_rel} {quality}")

    print("-"*112)
    # Display reference baseline (computed or default)
    if ref_baseline:
        ms = ref_baseline.get('avg_mutation_score', 0)
        vd = ref_baseline.get('avg_vuln_detection', 0)
        cov = ref_baseline.get('avg_line_coverage', 0)
        sr = ref_baseline.get('avg_security_relevance')
        tq = ref_baseline.get('avg_test_quality')
        sr_str = f"{sr:>10.1%}" if sr is not None else f"{'N/A':>10}"
        tq_str = f"{tq:>10.1%}" if tq is not None else f"{'N/A':>10}"
        print(f"{'Reference Tests':<35} {ms:>10.1%} {'N/A':>10} {vd:>10.1%} {cov:>10.1%} {sr_str} {tq_str}")
    else:
        print(f"{'Reference Tests':<35} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12}")
    print("="*112)


def save_results(results: List[ModelResult], output_dir: Path, ref_baseline: Optional[Dict] = None):
    """Save results to JSON file."""
    output_dir.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    output_file = output_dir / f"baseline_results_{timestamp}.json"

    # Convert to serializable format
    data = {
        "timestamp": timestamp,
        "results": [asdict(r) for r in results],
        "reference_baseline": ref_baseline or {
            "avg_mutation_score": None,
            "avg_vuln_detection": None,
            "avg_line_coverage": None,
            "avg_security_relevance": None,
            "avg_test_quality": None,
        }
    }

    with open(output_file, "w") as f:
        json.dump(data, f, indent=2)

    print(f"\nResults saved to: {output_file}")
    return output_file


def main():
    parser = argparse.ArgumentParser(description="Run LLM baseline evaluations")
    parser.add_argument("--models", nargs="+", help="Specific models to evaluate")
    parser.add_argument("--provider", choices=["ollama", "openai", "anthropic", "google", "all"],
                       default="ollama", help="Model provider")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard"],
                       help="Filter by difficulty")
    parser.add_argument("--cwe", help="Filter by CWE (e.g., CWE-89)")
    parser.add_argument("--max-samples", type=int, help="Maximum samples to evaluate")
    parser.add_argument("--start-sample", type=int, default=0, help="Start from sample index (for resuming)")
    parser.add_argument("--use-judge", action="store_true", help="Run LLM-as-Judge evaluation")
    parser.add_argument("--judge-provider", choices=["anthropic", "openai"],
                       default="anthropic", help="Provider for LLM-as-Judge")
    parser.add_argument("--output", default="baselines/results", help="Output directory")
    parser.add_argument("--shuffle", action="store_true", default=True, help="Shuffle samples before slicing (ensures CWE diversity) - enabled by default")
    parser.add_argument("--no-shuffle", action="store_false", dest="shuffle", help="Disable shuffling (process samples in original order)")
    parser.add_argument("--stratified", action="store_true",
                       help="Use stratified sampling to ensure proportional CWE representation (recommended)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for shuffle/stratified sampling (default: 42)")
    parser.add_argument("--max-mutants", type=int, default=10, help="Maximum mutants per sample (default: 10)")
    parser.add_argument("--timeout", type=int, default=300, help="Ollama request timeout in seconds (default: 300 = 5 min)")
    parser.add_argument("--skip-invalid", action="store_true",
                       help="Skip samples where quality.validation_passed is False")

    args = parser.parse_args()

    # Load benchmark
    print("Loading benchmark...")
    benchmark = load_benchmark(difficulty=args.difficulty, cwe=args.cwe)
    print(f"Loaded {len(benchmark)} samples")

    # Filter out invalid samples if requested
    invalid_count = sum(1 for s in benchmark if not s.get("quality", {}).get("validation_passed", True))
    if invalid_count > 0:
        if args.skip_invalid:
            benchmark = [s for s in benchmark if s.get("quality", {}).get("validation_passed", True)]
            print(f"Skipped {invalid_count} samples with validation_passed=False ({len(benchmark)} remaining)")
        else:
            print(f"Warning: {invalid_count} samples have validation_passed=False. Use --skip-invalid to exclude them.")

    # Apply sampling strategy
    if args.stratified and args.max_samples:
        # Use stratified sampling for proportional CWE representation
        benchmark = stratified_sample(benchmark, args.max_samples, seed=args.seed)
        print(f"Stratified sampling: {len(benchmark)} samples with proportional CWE coverage (seed={args.seed})")
        # Clear max_samples since stratified already limited
        args.max_samples = None
    elif args.shuffle:
        # Simple shuffle (ensures CWE diversity when taking subsets)
        import random
        random.seed(args.seed)
        random.shuffle(benchmark)
        print(f"Shuffled with seed={args.seed}")

    # Determine models to evaluate
    models_to_eval = []

    if args.models:
        # Use specified models
        for m in args.models:
            if m in OLLAMA_MODELS or ":" in m:
                models_to_eval.append({"name": m, "provider": "ollama"})
            else:
                # Check API models
                for api_m in API_MODELS:
                    if api_m["name"] == m:
                        models_to_eval.append(api_m)
                        break
    elif args.provider == "all":
        # All available models
        for m in OLLAMA_MODELS:
            models_to_eval.append({"name": m, "provider": "ollama"})
        models_to_eval.extend(API_MODELS)
    elif args.provider == "ollama":
        for m in OLLAMA_MODELS:
            models_to_eval.append({"name": m, "provider": "ollama"})
    elif args.provider == "openai":
        models_to_eval.append({"name": "gpt-5", "provider": "openai"})
        models_to_eval.append({"name": "gpt-5-mini-2025-08-07", "provider": "openai"})
    elif args.provider == "anthropic":
        models_to_eval.append({"name": "claude-sonnet-4-5-20250929", "provider": "anthropic"})
    elif args.provider == "google":
        models_to_eval.append({"name": "gemini-3-flash-preview", "provider": "google"})
        models_to_eval.append({"name": "gemini-2.5-pro", "provider": "google"})

    print(f"\nModels to evaluate: {[m['name'] for m in models_to_eval]}")

    # Run evaluations
    all_results = []

    for model_config in models_to_eval:
        try:
            result = evaluate_model(
                model=model_config["name"],
                provider=model_config["provider"],
                benchmark=benchmark,
                use_judge=args.use_judge,
                judge_provider=args.judge_provider,
                max_samples=args.max_samples,
                start_sample=args.start_sample,
                max_mutants=args.max_mutants,
                timeout=args.timeout,
            )
            all_results.append(result)
        except Exception as e:
            print(f"Failed to evaluate {model_config['name']}: {e}")

    # Print and save results
    if all_results:
        # Compute reference baseline from actual reference tests
        print("\nComputing reference test baseline...")
        ref_results = evaluate_reference_tests(benchmark)
        ref_baseline = ref_results.get('summary', {})

        print_results_table(all_results, ref_baseline)
        save_results(all_results, Path(args.output), ref_baseline)


if __name__ == "__main__":
    main()
