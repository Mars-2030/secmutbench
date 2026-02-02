#!/usr/bin/env python3
"""
ModelRunner Sub-Agent

Runs test generation evaluation on different models using the REAL
SecMutBench evaluation code.

Tasks:
- E001: qwen2.5-coder:7b (local via Ollama)
- E002: codellama:13b (local via Ollama)
- E003: deepseek-coder:6.7b (local via Ollama)
- E004: starcoder2:7b (local via Ollama)
- E005: gemini-pro (API)
- E006: gpt-4 (API)
"""

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime


# Custom Exceptions for better error handling
class ModelRunnerError(Exception):
    """Base exception for ModelRunner errors."""
    pass


class OllamaNotRunningError(ModelRunnerError):
    """Ollama service is not running."""
    pass


class OllamaModelNotFoundError(ModelRunnerError):
    """Ollama model not found/pulled."""
    pass


class APIKeyMissingError(ModelRunnerError):
    """API key not configured."""
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(f"API key not set for provider: {provider}")


class APIRateLimitError(ModelRunnerError):
    """API rate limit exceeded."""
    def __init__(self, provider: str, retry_after: Optional[int] = None):
        self.provider = provider
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for {provider}")


class ModelTimeoutError(ModelRunnerError):
    """Model generation timed out."""
    pass

# Add SecMutBench root to path for imports
SECMUTBENCH_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(SECMUTBENCH_ROOT))

# Import real SecMutBench evaluation modules
try:
    from evaluation.evaluate import (
        load_benchmark,
        evaluate_generated_tests,
        evaluate_model,
        DEFAULT_PROMPT_TEMPLATE,
    )
    from evaluation.mutation_engine import MutationEngine
    from evaluation.test_runner import TestRunner
    from evaluation.sample_validator import SampleValidator, validate_sample
    from evaluation.attack_vectors import check_attack_coverage
    SECMUTBENCH_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import SecMutBench evaluation modules: {e}")
    SECMUTBENCH_AVAILABLE = False


@dataclass
class EvaluationResult:
    model: str
    sample_id: str
    cwe_id: str
    generated_test: str
    mutation_score: float
    mutations_killed: int
    mutations_total: int
    vuln_detected: bool
    line_coverage: float
    execution_time: float
    timestamp: str
    errors: List[str]


class ModelRunner:
    """Sub-agent for running model evaluations using real SecMutBench code."""

    BASE_DIR = SECMUTBENCH_ROOT
    DATASET_FILE = BASE_DIR / "data" / "dataset.json"
    OUTPUT_BASE = Path(__file__).parent.parent.parent / "outputs" / "experiments"

    # Model configurations
    MODELS = {
        "E001": {"name": "qwen2.5-coder:7b", "type": "ollama"},
        "E002": {"name": "codellama:13b", "type": "ollama"},
        "E003": {"name": "deepseek-coder:6.7b", "type": "ollama"},
        "E004": {"name": "qwen3-coder:latest", "type": "ollama"},
    }

    def __init__(self, experiment_id: str = None, sample_limit: int = None):
        """
        Initialize ModelRunner with timestamped experiment directory.

        Args:
            experiment_id: Optional ID for this experiment run.
                          If None, generates timestamp-based ID.
            sample_limit: Optional limit on number of samples to evaluate.
                         If None, evaluates all samples.
        """
        if experiment_id is None:
            experiment_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

        self.experiment_id = experiment_id
        self.sample_limit = sample_limit
        self.OUTPUT_DIR = self.OUTPUT_BASE / experiment_id
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

        # Initialize SecMutBench components if available
        if SECMUTBENCH_AVAILABLE:
            self.engine = MutationEngine()
            self.runner = TestRunner()
        else:
            self.engine = None
            self.runner = None

        # Save experiment metadata
        self._save_experiment_metadata()

    def _save_experiment_metadata(self):
        """Save metadata about this experiment run."""
        metadata = {
            "experiment_id": self.experiment_id,
            "started_at": datetime.now().isoformat(),
            "models_to_evaluate": list(self.MODELS.keys()),
            "dataset": str(self.DATASET_FILE),
            "output_dir": str(self.OUTPUT_DIR),
            "secmutbench_available": SECMUTBENCH_AVAILABLE,
            "environment": {
                "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
                "platform": sys.platform,
            }
        }
        with open(self.OUTPUT_DIR / "experiment_metadata.json", "w") as f:
            json.dump(metadata, f, indent=2)

    def run(self, task_id: str, description: str) -> Dict:
        """Execute a model evaluation task."""
        if task_id not in self.MODELS:
            raise ValueError(f"Unknown task: {task_id}")

        model_config = self.MODELS[task_id]
        return self.evaluate_model(model_config)

    def check_prerequisites(self, task_id: str) -> Tuple[bool, List[str]]:
        """
        Check if prerequisites are met before running a task.

        Returns:
            Tuple of (all_ok, list of issues)
        """
        issues = []

        if task_id not in self.MODELS:
            return False, [f"Unknown task: {task_id}"]

        config = self.MODELS[task_id]
        model_type = config["type"]
        model_name = config["name"]

        if model_type == "ollama":
            # Check Ollama is running
            if not self._check_ollama_running():
                issues.append("Ollama is not running. Start with 'ollama serve' or Ollama app.")

            # Check model is available
            if not issues:  # Only check if Ollama is running
                try:
                    result = subprocess.run(
                        ["ollama", "list"],
                        capture_output=True,
                        text=True,
                        timeout=5
                    )
                    if model_name not in result.stdout:
                        issues.append(f"Model '{model_name}' not pulled. Run: ollama pull {model_name}")
                except Exception:
                    pass

        elif model_type == "api":
            provider = config.get("provider", "openai")

            if provider == "openai":
                if not os.getenv("OPENAI_API_KEY"):
                    issues.append("OPENAI_API_KEY environment variable not set")

            elif provider == "google":
                if not (os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")):
                    issues.append("GOOGLE_API_KEY or GEMINI_API_KEY environment variable not set")

        return len(issues) == 0, issues

    @classmethod
    def check_all_prerequisites(cls) -> Dict[str, Tuple[bool, List[str]]]:
        """Check prerequisites for all configured models."""
        runner = cls.__new__(cls)
        runner.experiment_id = "prereq_check"
        runner.OUTPUT_DIR = Path("/tmp/prereq_check")
        runner.engine = None
        runner.runner = None

        results = {}
        for task_id in cls.MODELS:
            results[task_id] = runner.check_prerequisites(task_id)
        return results

    def evaluate_model(self, config: Dict) -> Dict:
        """Run evaluation for a specific model using real SecMutBench."""
        model_name = config["name"]
        model_type = config["type"]

        # Load dataset using real SecMutBench loader
        samples = self._load_samples()

        # Pre-check: Validate samples before expensive model runs
        valid_samples = []
        skipped_samples = []
        if SECMUTBENCH_AVAILABLE:
            validator = SampleValidator()
            print(f"Pre-checking {len(samples)} samples...")
            for sample in samples:
                validation = validator.validate(sample)
                if validation.is_valid:
                    valid_samples.append(sample)
                else:
                    skipped_samples.append({
                        "sample_id": sample.get("id", "unknown"),
                        "errors": validation.errors
                    })
            print(f"  Valid: {len(valid_samples)}, Skipped: {len(skipped_samples)}")
        else:
            valid_samples = samples

        # Apply sample limit if specified
        if self.sample_limit and len(valid_samples) > self.sample_limit:
            print(f"  Limiting to {self.sample_limit} samples (of {len(valid_samples)} valid)")
            valid_samples = valid_samples[:self.sample_limit]

        results = []
        start_time = time.time()

        # Create output directory for this model
        model_dir = self.OUTPUT_DIR / model_name.replace(":", "_").replace("/", "_")
        model_dir.mkdir(parents=True, exist_ok=True)

        # Save skipped samples info
        if skipped_samples:
            with open(model_dir / "skipped_samples.json", "w") as f:
                json.dump(skipped_samples, f, indent=2)

        print(f"Evaluating {model_name} on {len(valid_samples)} valid samples...")

        for i, sample in enumerate(valid_samples):
            sample_id = sample.get("id", f"sample_{i}")
            print(f"  [{i+1}/{len(valid_samples)}] {sample_id}...")

            try:
                result = self._evaluate_sample(sample, model_name, model_type, config)
                results.append(result)

                # Save intermediate results
                self._save_result(model_dir, result)

                # Print progress
                ms = result.get("mutation_score", 0)
                vd = result.get("vuln_detected", False)
                print(f"    Mutation Score: {ms:.2%}, Vuln Detected: {vd}")

            except Exception as e:
                print(f"    Error: {e}")
                results.append({
                    "sample_id": sample_id,
                    "model": model_name,
                    "error": str(e),
                    "timestamp": datetime.now().isoformat()
                })
                continue

        total_time = time.time() - start_time

        # Aggregate results
        summary = self._aggregate_results(results, model_name)
        summary["total_time"] = total_time

        # Save summary
        with open(model_dir / "summary.json", "w") as f:
            json.dump(summary, f, indent=2)

        return summary

    def _load_samples(self) -> List[Dict]:
        """Load samples using real SecMutBench loader."""
        if SECMUTBENCH_AVAILABLE:
            return load_benchmark(path=str(self.DATASET_FILE))
        else:
            # Fallback: direct JSON load
            if not self.DATASET_FILE.exists():
                raise FileNotFoundError(f"Dataset not found: {self.DATASET_FILE}")

            with open(self.DATASET_FILE) as f:
                data = json.load(f)

            if isinstance(data, dict) and "samples" in data:
                return data["samples"]
            return data if isinstance(data, list) else []

    def _evaluate_sample(
        self, sample: Dict, model_name: str, model_type: str, config: Dict
    ) -> Dict:
        """Evaluate a single sample with the model using real SecMutBench."""
        sample_id = sample.get("id", "unknown")
        cwe = sample.get("cwe", "")
        secure_code = sample.get("secure_code", "")

        # Generate test using the model
        start = time.time()
        generated_test = self._generate_test(sample, model_name, model_type, config)
        gen_time = time.time() - start

        # Use real SecMutBench evaluation if available
        if SECMUTBENCH_AVAILABLE and self.engine and self.runner:
            eval_result = evaluate_generated_tests(
                sample=sample,
                generated_tests=generated_test,
                engine=self.engine,
                runner=self.runner,
            )

            metrics = eval_result.get("metrics", {})

            # Check attack vector coverage (no LLM call needed)
            attack_coverage, covered_attacks, missing_attacks = check_attack_coverage(
                generated_test, cwe
            )

            return {
                "model": model_name,
                "sample_id": sample_id,
                "cwe_id": cwe,
                "code": secure_code,
                "generated_test": generated_test,
                "mutation_score": metrics.get("mutation_score", 0.0),
                "mutations_killed": metrics.get("mutants_killed", 0),
                "mutations_total": metrics.get("mutants_total", 0),
                "vuln_detected": metrics.get("vuln_detected", False),
                "secure_passes": metrics.get("secure_passes", False),
                "insecure_fails": metrics.get("insecure_fails", False),
                "line_coverage": metrics.get("line_coverage", 0.0),
                "tests_count": metrics.get("tests_count", 0),
                "valid_tests": metrics.get("valid_tests", False),
                "attack_coverage": attack_coverage,
                "covered_attacks": [a["name"] for a in covered_attacks],
                "missing_attacks": [a["name"] for a in missing_attacks],
                "execution_time": gen_time,
                "errors": eval_result.get("errors", []),
                "mutant_details": eval_result.get("mutant_details", []),
                "timestamp": datetime.now().isoformat()
            }
        else:
            # Fallback simulation
            return self._simulate_evaluation(sample, generated_test, model_name, gen_time)

    def _generate_test(
        self, sample: Dict, model_name: str, model_type: str, config: Dict
    ) -> str:
        """Generate test using the specified model."""
        prompt = self._build_prompt(sample)

        if model_type == "ollama":
            return self._generate_with_ollama(prompt, model_name)
        else:
            return self._generate_with_api(prompt, model_name, config)

    def _build_prompt(self, sample: Dict) -> str:
        """Build prompt for test generation using SecMutBench template."""
        return DEFAULT_PROMPT_TEMPLATE.format(
            cwe=sample.get("cwe", "unknown"),
            cwe_name=sample.get("cwe_name", sample.get("cwe", "vulnerability")),
            code=sample.get("secure_code", ""),
            entry_point=sample.get("entry_point", "function"),
        )

    def _generate_with_ollama(self, prompt: str, model: str) -> str:
        """Generate test using local Ollama model."""
        # First check if Ollama is running
        if not self._check_ollama_running():
            raise OllamaNotRunningError(
                "Ollama is not running. Start it with 'ollama serve' or the Ollama app."
            )

        try:
            result = subprocess.run(
                ["ollama", "run", model, prompt],
                capture_output=True,
                text=True,
                timeout=300  # Increased from 120s for slower models
            )

            # Check for model not found error
            if result.returncode != 0:
                stderr = result.stderr.lower()
                if "not found" in stderr or "pull" in stderr:
                    raise OllamaModelNotFoundError(
                        f"Model '{model}' not found. Pull it with: ollama pull {model}"
                    )
                # Other errors
                if result.stderr:
                    raise ModelRunnerError(f"Ollama error: {result.stderr}")

            return result.stdout.strip()

        except subprocess.TimeoutExpired:
            raise ModelTimeoutError(f"Ollama model '{model}' timed out after 300s")
        except FileNotFoundError:
            raise OllamaNotRunningError(
                "Ollama CLI not found. Install from https://ollama.ai"
            )

    def _check_ollama_running(self) -> bool:
        """Check if Ollama service is running."""
        try:
            result = subprocess.run(
                ["ollama", "list"],
                capture_output=True,
                text=True,
                timeout=5
            )
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False

    def _generate_with_api(self, prompt: str, model: str, config: Dict) -> str:
        """Generate test using API model."""
        provider = config.get("provider", "openai")

        if provider == "openai":
            return self._call_openai(prompt, model)
        elif provider == "google":
            return self._call_gemini(prompt, model)
        else:
            return f"# Unknown provider: {provider}"

    def _call_openai(self, prompt: str, model: str) -> str:
        """Call OpenAI API."""
        # Check API key first
        api_key = os.getenv("OPENAI_API_KEY")
        if not api_key:
            raise APIKeyMissingError("openai")

        try:
            import openai
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=1000,
                temperature=0.2
            )
            return response.choices[0].message.content

        except ImportError:
            raise ModelRunnerError("OpenAI package not installed. Run: pip install openai")

        except Exception as e:
            error_str = str(e).lower()
            # Check for rate limit
            if "rate" in error_str and "limit" in error_str:
                raise APIRateLimitError("openai")
            # Check for auth errors
            if "auth" in error_str or "api key" in error_str or "invalid" in error_str:
                raise APIKeyMissingError("openai")
            # Re-raise as ModelRunnerError
            raise ModelRunnerError(f"OpenAI API error: {e}")

    def _call_gemini(self, prompt: str, model: str) -> str:
        """Call Google Gemini API."""
        # Check API key first (supports both GOOGLE_API_KEY and GEMINI_API_KEY)
        api_key = os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")
        if not api_key:
            raise APIKeyMissingError("google")

        try:
            import google.generativeai as genai
            genai.configure(api_key=api_key)
            model_instance = genai.GenerativeModel(model)
            response = model_instance.generate_content(prompt)
            return response.text

        except ImportError:
            raise ModelRunnerError(
                "Google Generative AI package not installed. Run: pip install google-generativeai"
            )

        except Exception as e:
            error_str = str(e).lower()
            # Check for rate limit
            if "rate" in error_str or "quota" in error_str or "429" in error_str:
                raise APIRateLimitError("google")
            # Check for auth errors
            if "api key" in error_str or "auth" in error_str or "invalid" in error_str:
                raise APIKeyMissingError("google")
            # Re-raise as ModelRunnerError
            raise ModelRunnerError(f"Gemini API error: {e}")

    def _simulate_evaluation(
        self, sample: Dict, generated_test: str, model_name: str, gen_time: float
    ) -> Dict:
        """Simulate evaluation when SecMutBench is not available."""
        sample_id = sample.get("id", "unknown")
        cwe = sample.get("cwe", "")

        # Basic heuristic evaluation
        has_assertion = "assert" in generated_test and "assert True" not in generated_test
        has_security_check = any(kw in generated_test.lower() for kw in [
            "injection", "xss", "escape", "sanitize", "validate",
            "parameterized", "shell", "traversal", "credential"
        ])

        if has_assertion and has_security_check:
            score = 0.6 + (0.3 * min(len(generated_test) / 500, 1.0))
            score = min(score, 0.95)
        elif has_assertion:
            score = 0.3
        else:
            score = 0.0

        total = 10
        killed = int(score * total)

        return {
            "model": model_name,
            "sample_id": sample_id,
            "cwe_id": cwe,
            "code": sample.get("secure_code", ""),
            "generated_test": generated_test,
            "mutation_score": score,
            "mutations_killed": killed,
            "mutations_total": total,
            "vuln_detected": has_assertion and has_security_check,
            "line_coverage": 0.5 if has_assertion else 0.0,
            "execution_time": gen_time,
            "errors": ["SecMutBench evaluation modules not available - using simulation"],
            "timestamp": datetime.now().isoformat()
        }

    def _save_result(self, model_dir: Path, result: Dict):
        """Save individual result."""
        results_dir = model_dir / "results"
        results_dir.mkdir(exist_ok=True)

        filename = f"{result.get('sample_id', 'unknown')}.json"
        with open(results_dir / filename, "w") as f:
            json.dump(result, f, indent=2)

    def _aggregate_results(self, results: List[Dict], model_name: str) -> Dict:
        """Aggregate results into summary."""
        # Filter out error-only results
        valid_results = [r for r in results if "mutation_score" in r]

        if not valid_results:
            return {
                "experiment_id": self.experiment_id,
                "model": model_name,
                "total_samples": len(results),
                "valid_samples": 0,
                "avg_mutation_score": 0.0,
                "error_count": len(results)
            }

        # Overall metrics
        scores = [r["mutation_score"] for r in valid_results]
        vuln_detected = [r.get("vuln_detected", False) for r in valid_results]
        coverage = [r.get("line_coverage", 0) for r in valid_results]

        avg_score = sum(scores) / len(scores)
        avg_vuln_rate = sum(vuln_detected) / len(vuln_detected)
        avg_coverage = sum(coverage) / len(coverage)

        # Per-CWE metrics
        cwe_scores = {}
        for result in valid_results:
            cwe = result.get("cwe_id", "unknown")
            if cwe not in cwe_scores:
                cwe_scores[cwe] = []
            cwe_scores[cwe].append(result["mutation_score"])

        cwe_averages = {cwe: sum(s)/len(s) for cwe, s in cwe_scores.items()}

        return {
            "experiment_id": self.experiment_id,
            "model": model_name,
            "total_samples": len(results),
            "valid_samples": len(valid_results),
            "error_count": len(results) - len(valid_results),
            "avg_mutation_score": avg_score,
            "avg_vuln_detection_rate": avg_vuln_rate,
            "avg_line_coverage": avg_coverage,
            "min_score": min(scores),
            "max_score": max(scores),
            "cwe_scores": cwe_averages,
            "started_at": valid_results[0]["timestamp"] if valid_results else None,
            "completed_at": datetime.now().isoformat(),
            "output_directory": str(self.OUTPUT_DIR / model_name.replace(":", "_").replace("/", "_"))
        }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        # Check prerequisites
        if arg == "--check":
            print("Checking prerequisites for all models...\n")
            results = ModelRunner.check_all_prerequisites()
            all_ok = True
            for task_id, (ok, issues) in results.items():
                model = ModelRunner.MODELS[task_id]
                status = "✅" if ok else "❌"
                print(f"{status} {task_id}: {model['name']}")
                if not ok:
                    all_ok = False
                    for issue in issues:
                        print(f"   └─ {issue}")
            print()
            if all_ok:
                print("All prerequisites met!")
            else:
                print("Some prerequisites not met. Fix the issues above before running.")
            sys.exit(0 if all_ok else 1)

        # Run specific task
        task_id = arg
        runner = ModelRunner()
        try:
            result = runner.run(task_id, "")
            print(json.dumps(result, indent=2))
        except ModelRunnerError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        print("Usage: python model_runner.py <task_id>")
        print("       python model_runner.py --check")
        print("\nTasks: E001-E004")
        print("  E001: qwen2.5-coder:7b (Ollama)")
        print("  E002: codellama:13b (Ollama)")
        print("  E003: deepseek-coder:6.7b (Ollama)")
        print("  E004: qwen3-coder:latest (Ollama)")
        print(f"\nSecMutBench available: {SECMUTBENCH_AVAILABLE}")
