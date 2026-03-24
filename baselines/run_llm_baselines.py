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
from evaluation.test_runner import TestRunner
from evaluation.llm_judge import create_evaluator, format_multimodal_report
from evaluation.prompts import (
    format_test_generation_prompt,
    format_prompt_no_hint,
    format_prompt_cwe_id_only,
)
from evaluation.metrics import calculate_kill_breakdown
from evaluation.version import get_version_info, __version__
from collections import defaultdict
import random as random_module

# Batch API support (lazy import to avoid dependency issues)
def get_batch_processor(provider: str):
    """Lazy import batch processor."""
    from baselines.batch_api import create_batch_processor, BatchRequest, prepare_batch_requests
    return create_batch_processor, BatchRequest, prepare_batch_requests


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
    "kimi-k2.5:cloud",            # E010 - Kimi K2.5 via Ollama cloud
    "glm-5:cloud",                # E011 - GLM-5 via Ollama cloud
]

API_MODELS = [
    {"name": "gpt-4o", "provider": "openai"},
    {"name": "gpt-5.2-2025-12-11", "provider": "openai"},
    {"name": "gpt-5-mini-2025-08-07", "provider": "openai"},
    {"name": "claude-sonnet-4-5-20250929", "provider": "anthropic"},
    {"name": "claude-opus-4-6", "provider": "anthropic"},
    {"name": "gemini-3-flash-preview", "provider": "google"},
    {"name": "gemini-3.1-pro-preview", "provider": "google"},
]

# ARC vLLM models (served via vLLM on ARC cluster, OpenAI-compatible API)
# Launch with SLURM, then SSH port-forward to access locally
VLLM_MODELS = [
    "gpt-oss-120b",
    "Kimi-K2.5",
    "GLM-5",
    "GLM-4.7",
    "Kimi-K2-Thinking",
]

# Together.ai models (OpenAI-compatible API at https://api.together.xyz/v1)
TOGETHER_MODELS = [
    "moonshotai/Kimi-K2.5",
    "zai-org/GLM-5",
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
    secure_pass_rate: Optional[float] = None
    effective_mutation_score: Optional[float] = None
    evaluation_time: float = 0.0
    errors: int = 0
    detailed_results: List[Dict] = None

    def __post_init__(self):
        if self.detailed_results is None:
            self.detailed_results = []


def call_ollama(model: str, prompt: str, timeout: int = 300, max_retries: int = 5) -> str:
    """Call Ollama API to generate tests with retry and backoff.

    For cloud models with hourly rate limits, automatically waits for the
    rate limit to reset and retries (up to 65 minutes per wait).

    Args:
        model: Ollama model name
        prompt: The prompt to send
        timeout: Request timeout in seconds (default 300 = 5 minutes)
        max_retries: Maximum retry attempts for rate limits / errors
    """
    import requests

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
    elif "kimi" in model.lower():
        payload["options"]["temperature"] = 0.6
        payload["options"]["num_predict"] = 8192
    elif "glm" in model.lower():
        payload["options"]["num_predict"] = 4096

    is_cloud = model.endswith(":cloud") or "cloud" in model.lower()

    for attempt in range(max_retries):
        try:
            response = requests.post(
                "http://localhost:11434/api/generate",
                json=payload,
                timeout=timeout
            )
            response.raise_for_status()
            result = response.json()
            content = result.get("response", "") or result.get("thinking", "")
            if content.strip():
                return content
            # Empty response — retry
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Empty response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
        except requests.exceptions.Timeout:
            print(f"  Ollama timeout after {timeout}s - try increasing with --timeout")
            return ""
        except Exception as e:
            err_str = str(e)
            is_rate_limit = "429" in err_str

            if is_rate_limit and is_cloud:
                # Cloud model hourly rate limit — wait for reset
                wait_minutes = _ollama_cloud_wait(err_str)
                print(f"\n  [Rate limit] Cloud model hourly limit hit. "
                      f"Waiting {wait_minutes} min for reset...", flush=True)
                _countdown_wait(wait_minutes * 60)
                print(f"  Rate limit should be reset, retrying...", flush=True)
                # Don't count this as an attempt — reset the loop
                continue
            elif is_rate_limit and attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Rate limited, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            elif attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Ollama error: {e}, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            else:
                print(f"  Ollama error: {e} (all {max_retries} attempts failed)")
                return ""
    return ""


def _ollama_cloud_wait(err_str: str) -> int:
    """Parse Ollama cloud rate limit error to determine wait time in minutes.

    Tries to extract retry-after or reset time from the error message.
    Falls back to 60 minutes (typical hourly reset).
    """
    import re
    # Try to find "retry after Xs" or "X seconds" patterns
    match = re.search(r'retry.?after[:\s]+(\d+)', err_str, re.IGNORECASE)
    if match:
        seconds = int(match.group(1))
        return max(1, seconds // 60)
    # Try "reset in X minutes"
    match = re.search(r'reset.*?(\d+)\s*min', err_str, re.IGNORECASE)
    if match:
        return int(match.group(1))
    # Default: wait 60 minutes for hourly reset
    return 60


def _countdown_wait(total_seconds: int):
    """Wait with a countdown timer displayed to the user."""
    import sys as _sys
    start = time.time()
    while True:
        elapsed = time.time() - start
        remaining = total_seconds - elapsed
        if remaining <= 0:
            print(flush=True)
            break
        mins, secs = divmod(int(remaining), 60)
        _sys.stderr.write(f"\r  Waiting: {mins:02d}:{secs:02d} remaining...  ")
        _sys.stderr.flush()
        time.sleep(min(10, remaining))  # Update every 10 seconds


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


def call_vllm(model: str, prompt: str, base_url: str = "http://localhost:8000/v1",
              api_key: str = "dummy", timeout: int = 600) -> str:
    """Call vLLM server (OpenAI-compatible API) to generate tests.

    Args:
        model: The --served-model-name used when starting vLLM
        prompt: The prompt to send
        base_url: vLLM server URL (default: http://localhost:8000/v1)
        api_key: API key set in vLLM --api-key flag
        timeout: Request timeout in seconds (default 600 = 10 min for large models)
    """
    try:
        from openai import OpenAI
        client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)

        response = client.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.2,
            max_tokens=2048,
        )
        return response.choices[0].message.content
    except Exception as e:
        print(f"  vLLM error: {e}")
        return ""


def call_together(model: str, prompt: str, max_retries: int = 5) -> str:
    """Call Together.ai API to generate tests with retry and backoff."""
    from together import Together
    client = Together(api_key=os.getenv("TOGETHER_API_KEY"), timeout=600)

    # Kimi models use thinking mode — need higher temperature and more tokens
    if "kimi" in model.lower():
        temp = 0.6
        max_tok = 8192
    else:
        temp = 0.2
        max_tok = 4096

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=temp,
                max_tokens=max_tok,
            )
            content = response.choices[0].message.content or ""
            if content.strip():
                return content
            # Empty content — retry
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Empty response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
        except Exception as e:
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Together.ai error: {e}, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            else:
                print(f"  Together.ai error: {e} (all {max_retries} attempts failed)")
                return ""
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


_zhipu_last_call = 0.0  # Rate limiter for Zhipu API (5 RPM = 12s between calls)

def call_zhipu(model: str, prompt: str, max_retries: int = 5) -> str:
    """Call Zhipu AI (Z.AI) API for GLM models with retry and backoff.

    Rate limited to 5 requests per minute (12s between calls).
    """
    global _zhipu_last_call
    from openai import OpenAI
    client = OpenAI(
        base_url="https://api.z.ai/api/paas/v4",
        api_key=os.getenv("ZHIPU_API_KEY"),
        timeout=600,
    )

    for attempt in range(max_retries):
        # Enforce 5 RPM rate limit (12s between calls)
        elapsed = time.time() - _zhipu_last_call
        if elapsed < 12:
            time.sleep(12 - elapsed)

        try:
            _zhipu_last_call = time.time()
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=4096,
            )
            content = response.choices[0].message.content or ""
            if content.strip():
                return content
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Empty response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
        except Exception as e:
            if "429" in str(e) and attempt < max_retries - 1:
                wait = max(12, 2 ** (attempt + 1))
                print(f"  Rate limited, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            elif attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Zhipu error: {e}, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            else:
                print(f"  Zhipu error: {e} (all {max_retries} attempts failed)")
                return ""
    return ""


def call_fireworks(model: str, prompt: str, max_retries: int = 5) -> str:
    """Call Fireworks AI API for inference with retry and backoff."""
    from openai import OpenAI
    client = OpenAI(
        base_url="https://api.fireworks.ai/inference/v1",
        api_key=os.getenv("FIREWORKS_API_KEY"),
        timeout=600,
    )

    for attempt in range(max_retries):
        try:
            response = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": "You are a security testing expert. Generate only Python test code, no explanations."},
                    {"role": "user", "content": prompt}
                ],
                temperature=0.2,
                max_tokens=4096,
            )
            content = response.choices[0].message.content or ""
            if content.strip():
                return content
            if attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Empty response, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
        except Exception as e:
            if "429" in str(e) and attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Rate limited, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            elif attempt < max_retries - 1:
                wait = 2 ** (attempt + 1)
                print(f"  Fireworks error: {e}, retrying in {wait}s (attempt {attempt + 1}/{max_retries})...", end=" ", flush=True)
                time.sleep(wait)
            else:
                print(f"  Fireworks error: {e} (all {max_retries} attempts failed)")
                return ""
    return ""


def generate_tests(
    model: str,
    provider: str,
    sample: Dict,
    timeout: int = 300,
    prompt_variant: str = "full",
) -> str:
    """Generate security tests using specified model.

    Args:
        model: Model name
        provider: Provider (ollama, openai, anthropic, google)
        sample: Benchmark sample
        timeout: Request timeout
        prompt_variant: Prompt variant for ablation study:
            - "full": Complete prompt with mock docs, attack vectors (default)
            - "no-hint": Generic "write tests" without security context
            - "cwe-only": Just CWE ID, no detailed guidance
    """
    # Select prompt based on variant
    if prompt_variant == "no-hint":
        prompt = format_prompt_no_hint(
            code=sample["secure_code"],
            entry_point=sample.get("entry_point", "function"),
        )
    elif prompt_variant == "cwe-only":
        prompt = format_prompt_cwe_id_only(
            code=sample["secure_code"],
            cwe=sample["cwe"],
            entry_point=sample.get("entry_point", "function"),
        )
    else:  # "full" or default
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
    elif provider == "vllm":
        return call_vllm(model, prompt,
                         base_url=os.getenv("VLLM_BASE_URL", "http://localhost:8000/v1"),
                         api_key=os.getenv("VLLM_API_KEY", "dummy"),
                         timeout=timeout)
    elif provider == "together":
        return call_together(model, prompt)
    elif provider == "anthropic":
        return call_anthropic(model, prompt)
    elif provider == "google":
        return call_google(model, prompt)
    elif provider == "zhipu":
        return call_zhipu(model, prompt)
    elif provider == "fireworks":
        return call_fireworks(model, prompt)
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


def _checkpoint_path(model: str, provider: str, prompt_variant: str, output_dir: str = "results") -> Path:
    """Get the checkpoint file path for a model + provider + variant combination."""
    safe_name = _sanitize_model_name(model, provider)
    return Path(output_dir) / safe_name / f".checkpoint_{prompt_variant}.json"


def _load_checkpoint(model: str, provider: str, prompt_variant: str, output_dir: str = "results") -> tuple:
    """Load checkpoint if it exists. Returns (results_list, completed_ids_set, errors_count)."""
    cp_path = _checkpoint_path(model, provider, prompt_variant, output_dir)
    if cp_path.exists():
        try:
            with open(cp_path) as f:
                cp = json.load(f)
            results = cp.get("results", [])
            completed_ids = set(cp.get("completed_ids", []))
            errors = cp.get("errors", 0)
            return results, completed_ids, errors
        except (json.JSONDecodeError, KeyError):
            pass
    return [], set(), 0


def _save_checkpoint(model: str, provider: str, prompt_variant: str, results: list,
                     completed_ids: set, errors: int, output_dir: str = "results"):
    """Save checkpoint after each sample for resume support."""
    cp_path = _checkpoint_path(model, provider, prompt_variant, output_dir)
    cp_path.parent.mkdir(parents=True, exist_ok=True)
    with open(cp_path, "w") as f:
        json.dump({
            "model": model,
            "provider": provider,
            "prompt_variant": prompt_variant,
            "results": results,
            "completed_ids": list(completed_ids),
            "errors": errors,
            "last_updated": datetime.now().isoformat(),
        }, f)


def _clear_checkpoint(model: str, provider: str, prompt_variant: str, output_dir: str = "results"):
    """Remove checkpoint file after successful completion."""
    cp_path = _checkpoint_path(model, provider, prompt_variant, output_dir)
    if cp_path.exists():
        cp_path.unlink()


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
    prompt_variant: str = "full",
    batch_judge: bool = False,
    output_dir: str = "results",
) -> ModelResult:
    """Evaluate a single model on the benchmark.

    Args:
        prompt_variant: Prompt variant for ablation study:
            - "full": Complete prompt with mock docs, attack vectors (default)
            - "no-hint": Generic "write tests" without security context
            - "cwe-only": Just CWE ID, no detailed guidance
        batch_judge: Use batch API for LLM-as-Judge (50% cost savings)
        output_dir: Output directory (used for checkpoint files)
    """
    print(f"\n{'='*60}")
    print(f"Evaluating: {model} ({provider})")
    print(f"Prompt variant: {prompt_variant}")

    # Load checkpoint if exists (auto-resume)
    results, completed_ids, errors = _load_checkpoint(model, provider, prompt_variant, output_dir)
    if completed_ids:
        print(f"Resuming from checkpoint: {len(completed_ids)} samples already done")
    elif start_sample > 0:
        print(f"Resuming from sample {start_sample}")
    print(f"{'='*60}")

    start_time = time.time()

    samples_to_eval = benchmark[:max_samples] if max_samples else benchmark
    # Skip to start_sample for manual resume support
    samples_to_eval = samples_to_eval[start_sample:]
    total_samples = len(benchmark[:max_samples] if max_samples else benchmark)

    for i, sample in enumerate(samples_to_eval, start=start_sample):
        # Skip samples already in checkpoint
        if sample["id"] in completed_ids:
            continue

        print(f"  [{i+1}/{total_samples}] {sample['id']}...", end=" ", flush=True)

        try:
            # Generate tests
            raw_response = generate_tests(model, provider, sample, timeout=timeout, prompt_variant=prompt_variant)
            generated_tests = extract_test_code(raw_response)

            if not generated_tests.strip():
                print("EMPTY")
                errors += 1
                completed_ids.add(sample["id"])
                _save_checkpoint(model, provider, prompt_variant, results, completed_ids, errors, output_dir)
                continue

            # Generate the prompt for logging
            prompt = format_test_generation_prompt(
                code=sample["secure_code"],
                cwe=sample["cwe"],
                cwe_name=sample.get("cwe_name", "vulnerability"),
                include_mock_env=True,
            )

            # Evaluate with mutation testing (30s timeout to avoid hanging on bad tests)
            runner = TestRunner(timeout=30.0)
            eval_result = evaluate_generated_tests(sample, generated_tests, runner=runner, max_mutants=max_mutants)

            # Build detailed result with all context needed for analysis
            results.append({
                # Sample context
                "sample_id": sample["id"],
                "cwe": sample["cwe"],
                "cwe_name": sample.get("cwe_name", ""),
                "difficulty": sample["difficulty"],
                "source_type": sample.get("source_type", "unknown"),
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
            else:
                reason = metrics.get("mutation_score_skipped_reason", "")
                if reason == "tests_fail_on_secure_code":
                    print(f"MS=N/A (tests fail on secure code)")
                elif total == 0:
                    print(f"MS=N/A (0 mutants)")
                else:
                    print(f"MS=N/A")

            # Save checkpoint after each successful sample
            completed_ids.add(sample["id"])
            _save_checkpoint(model, provider, prompt_variant, results, completed_ids, errors, output_dir)

        except Exception as e:
            print(f"ERROR: {e}")
            errors += 1
            completed_ids.add(sample["id"])
            _save_checkpoint(model, provider, prompt_variant, results, completed_ids, errors, output_dir)
            continue

        # Rate limiting for API calls
        if provider in ["openai", "anthropic", "together"]:
            time.sleep(1)

    # Clear checkpoint on successful completion
    _clear_checkpoint(model, provider, prompt_variant, output_dir)

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
        secure_fail_count = len(results) - secure_passes_count
        vuln_detected_count = sum(1 for r in results if r["metrics"].get("vuln_detected", False))
        sec_precision = vuln_detected_count / secure_passes_count if secure_passes_count > 0 else None
        avg_ms = sum(valid_mutation_scores) / len(valid_mutation_scores) if valid_mutation_scores else 0.0
        spr = secure_passes_count / len(results) if results else 0.0
        eff_ms = avg_ms * spr
        print(f"  Secure-Pass Rate: {secure_passes_count}/{len(results)} "
              f"({spr:.1%})"
              f"{f' — {secure_fail_count} skipped mutation testing' if secure_fail_count else ''}")
        print(f"  Effective MS: {eff_ms:.1%} (= {avg_ms:.1%} avg_MS * {spr:.1%} secure_pass_rate)")

        model_result = ModelResult(
            model_name=model,
            provider=provider,
            samples_evaluated=len(results),
            avg_mutation_score=avg_ms,
            avg_vuln_detection=sum(vuln_detections) / len(vuln_detections),
            avg_line_coverage=sum(coverages) / len(coverages),
            avg_security_mutation_score=kill_breakdown.get("security_mutation_score"),
            avg_incidental_score=kill_breakdown.get("incidental_score"),
            avg_crash_score=kill_breakdown.get("crash_score"),
            avg_security_precision=sec_precision,
            secure_pass_rate=spr,
            effective_mutation_score=eff_ms,
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
            effective_mutation_score=0,
            evaluation_time=time.time() - start_time,
            errors=errors,
        )

    # Run LLM-as-Judge if requested
    if use_judge and results:
        print(f"\n  Running LLM-as-Judge ({judge_provider})...")
        print(f"  Total samples to judge: {len(results)} (2 API calls each = {len(results) * 2} total)")
        try:
            evaluator = create_evaluator(provider=judge_provider)

            security_scores = []
            quality_scores = []
            composite_scores = []

            if batch_judge:
                # Use batch API for 50% cost savings
                print(f"  Using BATCH mode for judge (50% cost savings)...")

                # Prepare data for batch evaluation
                samples_to_judge = []
                tests_to_judge = []
                exec_results_to_judge = []

                for r in results:
                    sample = next(s for s in benchmark if s["id"] == r["sample_id"])
                    samples_to_judge.append(sample)
                    tests_to_judge.append(r["generated_tests"])
                    exec_results_to_judge.append({"metrics": r["metrics"]})

                # Run batch evaluation
                judge_results = evaluator.evaluate_batch_api(
                    samples=samples_to_judge,
                    generated_tests_list=tests_to_judge,
                    execution_results_list=exec_results_to_judge,
                    provider=judge_provider,
                )

                # Extract scores from batch results
                for judge_result in judge_results:
                    if judge_result.security_relevance:
                        security_scores.append(judge_result.security_relevance.score)
                    if judge_result.test_quality:
                        quality_scores.append(judge_result.test_quality.score)
                    composite_scores.append(judge_result.composite_score)

                print(f"  Batch judge complete: {len(judge_results)} samples evaluated")
            else:
                # Sequential evaluation (original behavior)
                for i, r in enumerate(results, 1):
                    print(f"    [{i}/{len(results)}] Judging {r['sample_id'][:12]}...", end=" ", flush=True)
                    sample = next(s for s in benchmark if s["id"] == r["sample_id"])
                    judge_result = evaluator.evaluate(
                        sample,
                        r["generated_tests"],
                        {"metrics": r["metrics"]}
                    )

                    if judge_result.security_relevance:
                        security_scores.append(judge_result.security_relevance.score)
                        sec_score = judge_result.security_relevance.score
                    else:
                        sec_score = 0
                    if judge_result.test_quality:
                        quality_scores.append(judge_result.test_quality.score)
                        qual_score = judge_result.test_quality.score
                    else:
                        qual_score = 0
                    composite_scores.append(judge_result.composite_score)
                    print(f"Security: {sec_score:.0%}, Quality: {qual_score:.0%}")

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


def evaluate_model_batch(
    model: str,
    provider: str,
    benchmark: List[Dict],
    max_samples: Optional[int] = None,
    max_mutants: int = 10,
    prompt_variant: str = "full",
    poll_interval: int = 60,
) -> ModelResult:
    """
    Evaluate a model using batch API for cost savings (50% for Anthropic/OpenAI).

    This submits all requests as a batch and waits for completion.
    Ideal for large evaluations where 24h turnaround is acceptable.
    """
    print(f"\n{'='*60}")
    print(f"BATCH Evaluating: {model} ({provider})")
    print(f"Prompt variant: {prompt_variant}")
    print(f"{'='*60}")

    create_batch_processor, BatchRequest, prepare_batch_requests = get_batch_processor(provider)

    start_time = time.time()
    samples_to_eval = benchmark[:max_samples] if max_samples else benchmark

    # Prepare batch requests
    print(f"  Preparing {len(samples_to_eval)} batch requests...")

    def format_prompt(sample: Dict) -> str:
        if prompt_variant == "no-hint":
            return format_prompt_no_hint(
                code=sample["secure_code"],
                entry_point=sample.get("entry_point", "function"),
            )
        elif prompt_variant == "cwe-only":
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

    batch_requests = prepare_batch_requests(samples_to_eval, format_prompt)

    # Process batch
    processor = create_batch_processor(provider)

    def progress_callback(status: str, completed: int, total: int):
        print(f"  Batch progress: {status} ({completed}/{total})")

    print(f"  Submitting batch to {provider}...")
    print(f"  Cost savings: 50% for Anthropic/OpenAI, concurrent for Google")

    batch_result = processor.process_batch(
        batch_requests,
        model,
        poll_interval=poll_interval,
        progress_callback=progress_callback,
    )

    print(f"  Batch completed: {batch_result.completed_requests}/{batch_result.total_requests}")

    # Map responses back to samples and evaluate
    response_map = {r.custom_id: r for r in batch_result.responses}

    results = []
    errors = 0

    for sample in samples_to_eval:
        response = response_map.get(sample["id"])
        if not response or not response.success:
            errors += 1
            continue

        generated_tests = extract_test_code(response.content)
        if not generated_tests.strip():
            errors += 1
            continue

        # Evaluate with mutation testing (30s timeout to avoid hanging on bad tests)
        runner = TestRunner(timeout=30.0)
        eval_result = evaluate_generated_tests(sample, generated_tests, runner=runner, max_mutants=max_mutants)

        prompt = format_prompt(sample)
        results.append({
            "sample_id": sample["id"],
            "cwe": sample["cwe"],
            "cwe_name": sample.get("cwe_name", ""),
            "difficulty": sample["difficulty"],
            "source_type": sample.get("source_type", "unknown"),
            "mutation_operators": sample.get("mutation_operators", []),
            "secure_code": sample["secure_code"],
            "insecure_code": sample.get("insecure_code", ""),
            "prompt": prompt,
            "raw_response": response.content,
            "generated_tests": generated_tests,
            "metrics": eval_result["metrics"],
            "mutant_details": eval_result.get("mutant_details", []),
            "test_results": eval_result.get("test_results", []),
            "reference_tests": sample.get("security_tests", ""),
        })

    # Calculate aggregates (same as evaluate_model)
    if results:
        mutation_scores = [r["metrics"].get("mutation_score") for r in results]
        valid_mutation_scores = [ms for ms in mutation_scores if ms is not None]
        vuln_detections = [1 if r["metrics"].get("vuln_detected", False) else 0 for r in results]
        coverages = [r["metrics"].get("line_coverage", 0) or 0 for r in results]

        kill_breakdown = calculate_kill_breakdown(results)
        print(f"\n  Kill Breakdown: Semantic={kill_breakdown['semantic_kills']} "
              f"Incidental={kill_breakdown['incidental_kills']} "
              f"Crash={kill_breakdown['crash_kills']}")

        secure_passes_count = sum(1 for r in results if r["metrics"].get("secure_passes", False))
        secure_fail_count = len(results) - secure_passes_count
        vuln_detected_count = sum(1 for r in results if r["metrics"].get("vuln_detected", False))
        sec_precision = vuln_detected_count / secure_passes_count if secure_passes_count > 0 else None
        avg_ms = sum(valid_mutation_scores) / len(valid_mutation_scores) if valid_mutation_scores else 0.0
        spr = secure_passes_count / len(results) if results else 0.0
        eff_ms = avg_ms * spr
        print(f"  Secure-Pass Rate: {secure_passes_count}/{len(results)} "
              f"({spr:.1%})"
              f"{f' — {secure_fail_count} skipped mutation testing' if secure_fail_count else ''}")
        print(f"  Effective MS: {eff_ms:.1%} (= {avg_ms:.1%} avg_MS * {spr:.1%} secure_pass_rate)")

        model_result = ModelResult(
            model_name=model,
            provider=provider,
            samples_evaluated=len(results),
            avg_mutation_score=avg_ms,
            avg_vuln_detection=sum(vuln_detections) / len(vuln_detections),
            avg_line_coverage=sum(coverages) / len(coverages),
            avg_security_mutation_score=kill_breakdown.get("security_mutation_score"),
            avg_incidental_score=kill_breakdown.get("incidental_score"),
            avg_crash_score=kill_breakdown.get("crash_score"),
            avg_security_precision=sec_precision,
            secure_pass_rate=spr,
            effective_mutation_score=eff_ms,
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
            effective_mutation_score=0,
            evaluation_time=time.time() - start_time,
            errors=errors,
        )

    return model_result


def print_results_table(results: List[ModelResult], ref_baseline: Optional[Dict] = None):
    """Print results as a formatted table."""
    print("\n" + "="*140)
    print("LLM BASELINE RESULTS")
    print("="*140)

    # Header — Eff MS is the primary metric (MS corrected for secure-pass rate)
    print(f"{'Model':<35} {'Eff MS':<12} {'Raw MS':<12} {'Sec MS':<12} {'Vuln Det':<12} {'Sec-Pass':<12} {'Coverage':<12} {'Sec Rel':<12} {'Quality':<12}")
    print("-"*140)

    # Sort by effective mutation score (the honest metric)
    sorted_results = sorted(results, key=lambda x: x.effective_mutation_score or 0, reverse=True)

    for r in sorted_results:
        sec_rel = f"{r.avg_security_relevance:>10.1%}" if r.avg_security_relevance is not None else f"{'N/A':>10}"
        quality = f"{r.avg_test_quality:>10.1%}" if r.avg_test_quality is not None else f"{'N/A':>10}"
        sms = f"{r.avg_security_mutation_score:>10.1%}" if r.avg_security_mutation_score is not None else f"{'N/A':>10}"
        spr = f"{r.secure_pass_rate:>10.1%}" if r.secure_pass_rate is not None else f"{'N/A':>10}"
        eff = f"{r.effective_mutation_score:>10.1%}" if r.effective_mutation_score is not None else f"{'N/A':>10}"
        print(f"{r.model_name:<35} {eff} {r.avg_mutation_score:>10.1%} {sms} {r.avg_vuln_detection:>10.1%} "
              f"{spr} {r.avg_line_coverage:>10.1%} {sec_rel} {quality}")

    print("-"*140)
    # Display reference baseline (computed or default)
    if ref_baseline:
        ms = ref_baseline.get('avg_mutation_score', 0)
        vd = ref_baseline.get('avg_vuln_detection', 0)
        cov = ref_baseline.get('avg_line_coverage', 0)
        sr = ref_baseline.get('avg_security_relevance')
        tq = ref_baseline.get('avg_test_quality')
        sr_str = f"{sr:>10.1%}" if sr is not None else f"{'N/A':>10}"
        tq_str = f"{tq:>10.1%}" if tq is not None else f"{'N/A':>10}"
        # Reference tests have 100% secure-pass, so eff MS = raw MS
        print(f"{'Reference Tests':<35} {ms:>10.1%} {ms:>10.1%} {'N/A':>10} {vd:>10.1%} {'100.0%':>10} {cov:>10.1%} {sr_str} {tq_str}")
    else:
        print(f"{'Reference Tests':<35} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12} {'N/A':>12}")
    print("="*140)


def _sanitize_model_name(name: str, provider: str = "") -> str:
    """Sanitize model name for use as directory/file name.

    Includes provider prefix so results from different providers
    (e.g. glm-5 via together vs fireworks) get separate directories.
    """
    clean = name.split("[")[0].strip().replace(":", "_").replace("/", "_").replace(" ", "")
    if provider:
        return f"{clean}_{provider}"
    return clean


def save_results(results: List[ModelResult], output_dir: Path, ref_baseline: Optional[Dict] = None):
    """Save results to JSON file under a model-specific subdirectory."""
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    if results:
        model_dir = output_dir / _sanitize_model_name(results[0].model_name, results[0].provider)
    else:
        model_dir = output_dir / "unknown"

    model_dir.mkdir(parents=True, exist_ok=True)
    output_file = model_dir / f"baseline_results_{timestamp}.json"

    # Convert to serializable format
    data = {
        "version_info": get_version_info(),
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
    parser.add_argument("--provider", choices=["ollama", "openai", "anthropic", "google", "vllm", "together", "zhipu", "fireworks", "all"],
                       default="ollama", help="Model provider")
    parser.add_argument("--vllm-base-url", default=None,
                       help="vLLM server URL (default: http://localhost:8000/v1). Sets VLLM_BASE_URL env var.")
    parser.add_argument("--vllm-api-key", default=None,
                       help="vLLM API key (default: from VLLM_API_KEY env var or 'dummy')")
    parser.add_argument("--difficulty", choices=["easy", "medium", "hard"],
                       help="Filter by difficulty")
    parser.add_argument("--cwe", help="Filter by CWE (e.g., CWE-89)")
    parser.add_argument("--dataset", help="Path to dataset file (default: auto-detect)")
    parser.add_argument("--max-samples", type=int, help="Maximum samples to evaluate")
    parser.add_argument("--start-sample", type=int, default=0, help="Start from sample index (for resuming)")
    parser.add_argument("--use-judge", action="store_true", help="Run LLM-as-Judge evaluation")
    parser.add_argument("--judge-provider", choices=["anthropic", "openai"],
                       default="anthropic", help="Provider for LLM-as-Judge")
    parser.add_argument("--output", default="results", help="Output directory")
    parser.add_argument("--shuffle", action="store_true", default=True, help="Shuffle samples before slicing (ensures CWE diversity) - enabled by default")
    parser.add_argument("--no-shuffle", action="store_false", dest="shuffle", help="Disable shuffling (process samples in original order)")
    parser.add_argument("--stratified", action="store_true",
                       help="Use stratified sampling to ensure proportional CWE representation (recommended)")
    parser.add_argument("--seed", type=int, default=42, help="Random seed for shuffle/stratified sampling (default: 42)")
    parser.add_argument("--max-mutants", type=int, default=10, help="Maximum mutants per sample (default: 10)")
    parser.add_argument("--timeout", type=int, default=300, help="Ollama request timeout in seconds (default: 300 = 5 min)")
    parser.add_argument("--skip-invalid", action="store_true",
                       help="Skip samples where quality.validation_passed is False")
    parser.add_argument("--prompt-variant", choices=["full", "no-hint", "cwe-only", "all"],
                       default="full",
                       help="Prompt variant for ablation study: full (default), no-hint, cwe-only, or all")
    parser.add_argument("--batch", action="store_true",
                       help="Use batch API for 50%% cost savings (Anthropic/OpenAI). "
                            "Submits all requests at once, results within 24h.")
    parser.add_argument("--batch-poll-interval", type=int, default=60,
                       help="Seconds between batch status checks (default: 60)")
    parser.add_argument("--batch-judge", action="store_true",
                       help="Use batch API for LLM-as-Judge (50%% cost savings). "
                            "Requires --use-judge flag.")
    parser.add_argument("--judge-only", type=str, default=None,
                       help="Run LLM-as-Judge on saved results file (skip LLM generation). "
                            "Example: --judge-only results/qwen3-coder_30b/baseline_results_20260312.json")

    args = parser.parse_args()

    # Set vLLM env vars from CLI args (so call_vllm picks them up)
    if args.vllm_base_url:
        os.environ["VLLM_BASE_URL"] = args.vllm_base_url
    if args.vllm_api_key:
        os.environ["VLLM_API_KEY"] = args.vllm_api_key

    # =========================================================================
    # Judge-only mode: run LLM-as-Judge on saved results
    # =========================================================================
    if args.judge_only:
        results_path = Path(args.judge_only)
        if not results_path.exists():
            print(f"Error: Results file not found: {results_path}")
            sys.exit(1)

        print(f"Loading saved results from: {results_path}")
        with open(results_path) as f:
            saved_data = json.load(f)

        # Handle both formats: list of ModelResult dicts, or single ModelResult
        model_results_list = saved_data.get("results", [saved_data])

        judge_provider = args.judge_provider
        use_batch = args.batch_judge

        for model_data in model_results_list:
            detailed = model_data.get("detailed_results", [])
            if not detailed:
                print(f"  Skipping {model_data.get('model_name', 'unknown')}: no detailed_results")
                continue

            model_name = model_data.get("model_name", "unknown")
            print(f"\nRunning LLM-as-Judge ({judge_provider}) on: {model_name}")
            print(f"  Samples to judge: {len(detailed)} (2 API calls each = {len(detailed) * 2} total)")

            try:
                evaluator = create_evaluator(provider=judge_provider)

                security_scores = []
                quality_scores = []
                composite_scores = []

                if use_batch:
                    print(f"  Using BATCH mode (50% cost savings)...")

                    samples_to_judge = []
                    tests_to_judge = []
                    exec_results_to_judge = []

                    for r in detailed:
                        # Reconstruct sample dict from saved fields
                        sample = {
                            "id": r["sample_id"],
                            "cwe": r.get("cwe", ""),
                            "cwe_name": r.get("cwe_name", ""),
                            "secure_code": r.get("secure_code", ""),
                            "entry_point": r.get("entry_point", "function"),
                            "difficulty": r.get("difficulty", "unknown"),
                        }
                        samples_to_judge.append(sample)
                        tests_to_judge.append(r.get("generated_tests", ""))
                        exec_results_to_judge.append({"metrics": r.get("metrics", {})})

                    judge_results = evaluator.evaluate_batch_api(
                        samples=samples_to_judge,
                        generated_tests_list=tests_to_judge,
                        execution_results_list=exec_results_to_judge,
                        provider=judge_provider,
                    )

                    for judge_result in judge_results:
                        if judge_result.security_relevance:
                            security_scores.append(judge_result.security_relevance.score)
                        if judge_result.test_quality:
                            quality_scores.append(judge_result.test_quality.score)
                        composite_scores.append(judge_result.composite_score)

                    print(f"  Batch judge complete: {len(judge_results)} samples evaluated")
                else:
                    # Sequential evaluation
                    for i, r in enumerate(detailed, 1):
                        print(f"    [{i}/{len(detailed)}] Judging {r['sample_id'][:12]}...", end=" ", flush=True)

                        sample = {
                            "id": r["sample_id"],
                            "cwe": r.get("cwe", ""),
                            "cwe_name": r.get("cwe_name", ""),
                            "secure_code": r.get("secure_code", ""),
                            "entry_point": r.get("entry_point", "function"),
                            "difficulty": r.get("difficulty", "unknown"),
                        }
                        judge_result = evaluator.evaluate(
                            sample,
                            r.get("generated_tests", ""),
                            {"metrics": r.get("metrics", {})}
                        )

                        sec_score = 0
                        qual_score = 0
                        if judge_result.security_relevance:
                            security_scores.append(judge_result.security_relevance.score)
                            sec_score = judge_result.security_relevance.score
                        if judge_result.test_quality:
                            quality_scores.append(judge_result.test_quality.score)
                            qual_score = judge_result.test_quality.score
                        composite_scores.append(judge_result.composite_score)
                        print(f"Security: {sec_score:.0%}, Quality: {qual_score:.0%}")

                        time.sleep(0.5)  # Rate limiting

                # Print summary
                print(f"\n  Judge Results for {model_name}:")
                if security_scores:
                    avg_sec = sum(security_scores) / len(security_scores)
                    print(f"    Avg Security Relevance: {avg_sec:.1%}")
                    model_data["avg_security_relevance"] = avg_sec
                if quality_scores:
                    avg_qual = sum(quality_scores) / len(quality_scores)
                    print(f"    Avg Test Quality:       {avg_qual:.1%}")
                    model_data["avg_test_quality"] = avg_qual
                if composite_scores:
                    avg_comp = sum(composite_scores) / len(composite_scores)
                    print(f"    Avg Composite Score:    {avg_comp:.1%}")
                    model_data["avg_composite_score"] = avg_comp

            except Exception as e:
                print(f"  Judge error: {e}")

        # Save updated results with judge scores
        output_path = results_path.with_name(
            results_path.stem + f"_judged_{judge_provider}" + results_path.suffix
        )
        with open(output_path, "w") as f:
            json.dump(saved_data, f, indent=2)
        print(f"\nJudged results saved to: {output_path}")
        sys.exit(0)

    # Load benchmark
    print("Loading benchmark...")
    benchmark = load_benchmark(path=args.dataset, difficulty=args.difficulty, cwe=args.cwe)
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
        # Use specified models with the given provider
        for m in args.models:
            if args.provider in ("openai", "anthropic", "google", "zhipu", "fireworks"):
                models_to_eval.append({"name": m, "provider": args.provider})
            elif args.provider == "together" or m in TOGETHER_MODELS:
                models_to_eval.append({"name": m, "provider": "together"})
            elif args.provider == "vllm" or m in VLLM_MODELS:
                models_to_eval.append({"name": m, "provider": "vllm"})
            elif m in OLLAMA_MODELS or ":" in m:
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
    elif args.provider == "vllm":
        if args.models:
            for m in args.models:
                models_to_eval.append({"name": m, "provider": "vllm"})
        else:
            for m in VLLM_MODELS:
                models_to_eval.append({"name": m, "provider": "vllm"})
    elif args.provider == "openai":
        models_to_eval.append({"name": "gpt-5", "provider": "openai"})
        models_to_eval.append({"name": "gpt-5-mini-2025-08-07", "provider": "openai"})
    elif args.provider == "anthropic":
        models_to_eval.append({"name": "claude-sonnet-4-5-20250929", "provider": "anthropic"})
        models_to_eval.append({"name": "claude-opus-4-6", "provider": "anthropic"})
    elif args.provider == "google":
        models_to_eval.append({"name": "gemini-3.0-flash", "provider": "google"})
        models_to_eval.append({"name": "gemini-2.5-pro", "provider": "google"})
    elif args.provider == "together":
        if args.models:
            for m in args.models:
                models_to_eval.append({"name": m, "provider": "together"})
        else:
            for m in TOGETHER_MODELS:
                models_to_eval.append({"name": m, "provider": "together"})

    print(f"\nModels to evaluate: {[m['name'] for m in models_to_eval]}")

    # Determine prompt variants to run
    if args.prompt_variant == "all":
        prompt_variants = ["full", "no-hint", "cwe-only"]
        print(f"Running ablation study with all prompt variants: {prompt_variants}")
    else:
        prompt_variants = [args.prompt_variant]

    # Run evaluations
    all_results = []

    for variant in prompt_variants:
        if len(prompt_variants) > 1:
            print(f"\n{'#'*60}")
            print(f"# ABLATION: Prompt variant = {variant}")
            print(f"{'#'*60}")

        for model_config in models_to_eval:
            try:
                # Check if batch mode is supported for this provider
                if args.batch and model_config["provider"] in ["anthropic", "openai", "google"]:
                    print(f"\n  Using BATCH API mode (50% cost savings for Anthropic/OpenAI)")
                    result = evaluate_model_batch(
                        model=model_config["name"],
                        provider=model_config["provider"],
                        benchmark=benchmark,
                        max_samples=args.max_samples,
                        max_mutants=args.max_mutants,
                        prompt_variant=variant,
                        poll_interval=args.batch_poll_interval,
                    )
                    # Run judge separately after batch generation (if requested)
                    if args.use_judge:
                        print("  Note: Running judge evaluation after batch generation...")
                        # Judge will be run in a follow-up sequential call or with --batch-judge
                elif args.batch and model_config["provider"] == "ollama":
                    print(f"\n  Warning: --batch not supported for Ollama (using sequential mode)")
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
                        prompt_variant=variant,
                        batch_judge=args.batch_judge,
                        output_dir=args.output,
                    )
                else:
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
                        prompt_variant=variant,
                        batch_judge=args.batch_judge,
                        output_dir=args.output,
                    )
                # Tag the result with the variant for tracking
                result.model_name = f"{result.model_name} [{variant}]"
                all_results.append(result)
            except Exception as e:
                print(f"Failed to evaluate {model_config['name']} with {variant}: {e}")

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
