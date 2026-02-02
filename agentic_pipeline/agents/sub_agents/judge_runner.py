#!/usr/bin/env python3
"""
JudgeRunner Sub-Agent

Runs LLM-as-Judge evaluation on generated tests using the REAL
SecMutBench llm_judge module.

Tasks:
- E007: Run LLM Judge on all generated tests
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime


# Custom Exceptions for better error handling
class JudgeRunnerError(Exception):
    """Base exception for JudgeRunner errors."""
    pass


class APIKeyMissingError(JudgeRunnerError):
    """API key not configured."""
    def __init__(self, provider: str):
        self.provider = provider
        super().__init__(f"API key not set for provider: {provider}")


class APIRateLimitError(JudgeRunnerError):
    """API rate limit exceeded."""
    def __init__(self, provider: str, retry_after: Optional[int] = None):
        self.provider = provider
        self.retry_after = retry_after
        super().__init__(f"Rate limit exceeded for {provider}")


class NoResultsError(JudgeRunnerError):
    """No experiment results to evaluate."""
    pass

# Add SecMutBench root to path for imports
SECMUTBENCH_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(SECMUTBENCH_ROOT))

# Import real SecMutBench LLM judge modules
try:
    from evaluation.llm_judge import (
        create_evaluator,
        MultiModalEvaluator,
        SecurityRelevanceJudge,
        TestQualityJudge,
        format_multimodal_report,
        MultiModalEvaluation,
    )
    LLM_JUDGE_AVAILABLE = True
except ImportError as e:
    print(f"Warning: Could not import SecMutBench llm_judge modules: {e}")
    LLM_JUDGE_AVAILABLE = False


class JudgeRunner:
    """Sub-agent for running LLM judge evaluations using real SecMutBench code."""

    BASE_DIR = SECMUTBENCH_ROOT
    OUTPUT_BASE = Path(__file__).parent.parent.parent / "outputs" / "experiments"

    # Judge configurations
    JUDGES = [
        {"name": "claude-4.5-opus", "provider": "anthropic"},
        {"name": "gpt-5", "provider": "openai"},
        {"name": "gemini-3-pro", "provider": "google"},
    ]

    def __init__(self, experiment_id: str = None):
        """
        Initialize JudgeRunner with experiment directory.

        Args:
            experiment_id: The experiment ID to evaluate.
                          If None, uses the most recent experiment.
        """
        if experiment_id is None:
            # Find most recent experiment
            if self.OUTPUT_BASE.exists():
                experiments = sorted([d for d in self.OUTPUT_BASE.iterdir() if d.is_dir()])
                if experiments:
                    self.experiment_id = experiments[-1].name
                else:
                    self.experiment_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            else:
                self.experiment_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        else:
            self.experiment_id = experiment_id

        self.OUTPUT_DIR = self.OUTPUT_BASE / self.experiment_id

    def run(self, task_id: str, description: str, judges: List[str] = None) -> Dict:
        """Execute judge evaluation.

        Args:
            task_id: Should be "E007"
            description: Task description
            judges: Optional list of specific judge names to use
        """
        if task_id != "E007":
            raise ValueError(f"Unknown task: {task_id}")

        return self.run_all_judges(judges=judges)

    def check_prerequisites(self, judges: List[str] = None) -> Tuple[bool, List[str]]:
        """
        Check if prerequisites are met before running.

        Args:
            judges: Optional list of specific judges to check

        Returns:
            Tuple of (all_ok, list of issues)
        """
        issues = []

        # Check experiment directory exists
        if not self.OUTPUT_DIR.exists():
            issues.append(f"Experiment directory not found: {self.OUTPUT_DIR}")
            return False, issues

        # Check for model results
        model_dirs = [d for d in self.OUTPUT_DIR.iterdir()
                     if d.is_dir() and d.name not in ["checkpoints", "charts", "reports"]]
        if not model_dirs:
            issues.append("No model evaluation results found")

        # Check API keys for judges
        judges_to_check = judges or [j["name"] for j in self.JUDGES]
        for judge_config in self.JUDGES:
            if judge_config["name"] not in judges_to_check:
                continue

            provider = judge_config["provider"]
            if provider == "anthropic":
                if not os.getenv("ANTHROPIC_API_KEY"):
                    issues.append(f"ANTHROPIC_API_KEY not set (needed for {judge_config['name']})")
            elif provider == "openai":
                if not os.getenv("OPENAI_API_KEY"):
                    issues.append(f"OPENAI_API_KEY not set (needed for {judge_config['name']})")
            elif provider == "google":
                if not (os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")):
                    issues.append(f"GOOGLE_API_KEY/GEMINI_API_KEY not set (needed for {judge_config['name']})")

        return len(issues) == 0, issues

    @classmethod
    def check_all_prerequisites(cls, experiment_id: str = None) -> Dict[str, Tuple[bool, List[str]]]:
        """Check prerequisites for all configured judges."""
        runner = cls(experiment_id=experiment_id)

        results = {}
        for judge_config in cls.JUDGES:
            judge_name = judge_config["name"]
            ok, issues = runner.check_prerequisites(judges=[judge_name])
            results[judge_name] = (ok, issues)
        return results

    def run_all_judges(self, judges: List[str] = None) -> Dict:
        """Run all LLM judges on all experiment results.

        Args:
            judges: Optional list of specific judge names to use
        """
        results = {}

        if not self.OUTPUT_DIR.exists():
            raise NoResultsError(f"Experiment directory not found: {self.OUTPUT_DIR}")

        # Find all model experiment directories (exclude non-model dirs)
        excluded_dirs = {"checkpoints", "charts", "reports"}
        model_dirs = [d for d in self.OUTPUT_DIR.iterdir()
                     if d.is_dir() and d.name not in excluded_dirs]

        if not model_dirs:
            raise NoResultsError("No model evaluation results found in experiment directory")

        print(f"Found {len(model_dirs)} model directories to evaluate")

        # Filter judges if specified
        judges_to_run = self.JUDGES
        if judges:
            judges_to_run = [j for j in self.JUDGES if j["name"] in judges]
            if not judges_to_run:
                raise ValueError(f"No valid judges found. Available: {[j['name'] for j in self.JUDGES]}")
            print(f"Running with selected judges: {[j['name'] for j in judges_to_run]}")

        for model_dir in model_dirs:
            model_name = model_dir.name
            print(f"\nEvaluating model: {model_name}")
            results[model_name] = {}

            # Load results for this model
            results_dir = model_dir / "results"
            if not results_dir.exists():
                print(f"  No results directory found, skipping")
                continue

            sample_results = list(results_dir.glob("*.json"))
            print(f"  Found {len(sample_results)} sample results")

            if not sample_results:
                continue

            # Load all sample results
            samples_data = []
            for result_file in sample_results:
                try:
                    with open(result_file) as f:
                        sample_result = json.load(f)
                    samples_data.append(sample_result)
                except Exception as e:
                    print(f"  Error loading {result_file.name}: {e}")

            # Run each judge
            for judge_config in judges_to_run:
                judge_name = judge_config["name"]
                provider = judge_config["provider"]
                print(f"  Running judge: {judge_name} ({provider})")

                judge_results = self._run_judge_on_samples(
                    samples_data, judge_name, provider
                )

                if judge_results:
                    # Aggregate judge scores
                    scores = [r.get("composite_score", 0) for r in judge_results if "composite_score" in r]
                    security_scores = [r.get("security_relevance_score", 0) for r in judge_results if "security_relevance_score" in r]
                    quality_scores = [r.get("test_quality_score", 0) for r in judge_results if "test_quality_score" in r]

                    results[model_name][judge_name] = {
                        "avg_composite_score": sum(scores) / len(scores) if scores else 0,
                        "avg_security_relevance": sum(security_scores) / len(security_scores) if security_scores else 0,
                        "avg_test_quality": sum(quality_scores) / len(quality_scores) if quality_scores else 0,
                        "evaluations": len(judge_results),
                        "details": judge_results
                    }

                    print(f"    Avg composite: {results[model_name][judge_name]['avg_composite_score']:.2%}")

            # Save judge results for this model
            with open(model_dir / "judge_scores.json", "w") as f:
                json.dump(results[model_name], f, indent=2)

        # Generate summary report
        summary = self._generate_summary(results)

        return {
            "status": "completed",
            "experiment_id": self.experiment_id,
            "models_evaluated": len(results),
            "judges_used": len(self.JUDGES),
            "llm_judge_available": LLM_JUDGE_AVAILABLE,
            "summary": summary,
            "results": {m: {j: r.get("avg_composite_score", 0) for j, r in judges.items()}
                       for m, judges in results.items()}
        }

    def _run_judge_on_samples(
        self, samples_data: List[Dict], judge_model: str, provider: str
    ) -> List[Dict]:
        """Run a specific judge on all samples."""
        results = []

        for sample_result in samples_data:
            try:
                evaluation = self._judge_sample(sample_result, judge_model, provider)
                results.append(evaluation)
            except Exception as e:
                print(f"    Error judging sample {sample_result.get('sample_id', 'unknown')}: {e}")
                results.append({
                    "sample_id": sample_result.get("sample_id", "unknown"),
                    "error": str(e),
                    "composite_score": 0,
                })

        return results

    def _judge_sample(
        self, sample_result: Dict, judge_model: str, provider: str
    ) -> Dict:
        """Get judge evaluation for a single sample using real SecMutBench."""
        code = sample_result.get("code", sample_result.get("secure_code", ""))
        test = sample_result.get("generated_test", "")
        cwe_id = sample_result.get("cwe_id", sample_result.get("cwe", "Unknown"))
        sample_id = sample_result.get("sample_id", "unknown")

        # Create sample dict in SecMutBench format
        sample = {
            "id": sample_id,
            "cwe": cwe_id,
            "cwe_name": sample_result.get("cwe_name", cwe_id),
            "secure_code": code,
            "entry_point": sample_result.get("entry_point", "function"),
            "difficulty": sample_result.get("difficulty", "unknown"),
        }

        # Create execution results from model evaluation
        execution_results = {
            "metrics": {
                "mutation_score": sample_result.get("mutation_score", 0),
                "line_coverage": sample_result.get("line_coverage", 0),
            }
        }

        if LLM_JUDGE_AVAILABLE and test.strip():
            # Check API key first
            self._check_api_key(provider)

            try:
                # Create evaluator using real SecMutBench code
                evaluator = create_evaluator(
                    provider=provider,
                    model=judge_model,
                )

                # Run multi-modal evaluation
                mm_result = evaluator.evaluate(
                    sample=sample,
                    generated_tests=test,
                    execution_results=execution_results,
                )

                return {
                    "sample_id": sample_id,
                    "cwe_id": cwe_id,
                    "judge": judge_model,
                    "provider": provider,
                    "composite_score": mm_result.composite_score,
                    "mutation_score": mm_result.mutation_score,
                    "coverage_score": mm_result.coverage_score,
                    "security_relevance_score": mm_result.security_relevance.score if mm_result.security_relevance else 0,
                    "security_relevance_reasoning": mm_result.security_relevance.reasoning if mm_result.security_relevance else "",
                    "test_quality_score": mm_result.test_quality.score if mm_result.test_quality else 0,
                    "test_quality_reasoning": mm_result.test_quality.reasoning if mm_result.test_quality else "",
                    "timestamp": datetime.now().isoformat()
                }

            except ValueError as e:
                # API key not set - raise specific error
                if "api" in str(e).lower() or "key" in str(e).lower():
                    raise APIKeyMissingError(provider)
                raise JudgeRunnerError(f"Judge error: {e}")

            except Exception as e:
                error_str = str(e).lower()
                # Check for rate limit
                if "rate" in error_str or "quota" in error_str or "429" in error_str:
                    raise APIRateLimitError(provider)
                # Check for auth errors
                if "auth" in error_str or "api key" in error_str or "invalid" in error_str:
                    raise APIKeyMissingError(provider)
                # Re-raise as JudgeRunnerError
                raise JudgeRunnerError(f"Judge {judge_model} error: {e}")
        else:
            # Fallback when LLM judge not available
            return self._fallback_scoring(sample_result, judge_model)

    def _check_api_key(self, provider: str) -> None:
        """Check if API key is set for the provider."""
        if provider == "anthropic":
            if not os.getenv("ANTHROPIC_API_KEY"):
                raise APIKeyMissingError("anthropic")
        elif provider == "openai":
            if not os.getenv("OPENAI_API_KEY"):
                raise APIKeyMissingError("openai")
        elif provider == "google":
            if not (os.getenv("GOOGLE_API_KEY") or os.getenv("GEMINI_API_KEY")):
                raise APIKeyMissingError("google")

    def _fallback_scoring(self, sample_result: Dict, judge_model: str) -> Dict:
        """Fallback scoring when LLM judge is not available."""
        sample_id = sample_result.get("sample_id", "unknown")
        cwe_id = sample_result.get("cwe_id", "Unknown")
        test = sample_result.get("generated_test", "")

        # Use execution-based metrics only
        mutation_score = sample_result.get("mutation_score", 0)
        coverage = sample_result.get("line_coverage", 0)

        # Simple heuristic for security relevance
        security_keywords = ["injection", "xss", "escape", "sanitize", "validate",
                            "parameterized", "shell", "traversal", "credential"]
        has_security_check = any(kw in test.lower() for kw in security_keywords)
        security_score = 0.7 if has_security_check else 0.3

        # Simple heuristic for test quality
        has_assertion = "assert" in test and "assert True" not in test
        quality_score = 0.6 if has_assertion else 0.2

        # Calculate composite (using default weights)
        composite = (
            mutation_score * 0.50 +
            security_score * 0.20 +
            quality_score * 0.15 +
            coverage * 0.15
        )

        return {
            "sample_id": sample_id,
            "cwe_id": cwe_id,
            "judge": judge_model,
            "composite_score": composite,
            "mutation_score": mutation_score,
            "coverage_score": coverage,
            "security_relevance_score": security_score,
            "security_relevance_reasoning": "Fallback heuristic scoring (API not available)",
            "test_quality_score": quality_score,
            "test_quality_reasoning": "Fallback heuristic scoring (API not available)",
            "fallback": True,
            "timestamp": datetime.now().isoformat()
        }

    def _generate_summary(self, results: Dict) -> Dict:
        """Generate summary across all models and judges."""
        if not results:
            return {"error": "No results to summarize"}

        # Calculate averages across all models
        all_composites = []
        all_security = []
        all_quality = []

        model_rankings = {}

        for model_name, judges in results.items():
            model_composites = []
            for judge_name, judge_result in judges.items():
                if "avg_composite_score" in judge_result:
                    model_composites.append(judge_result["avg_composite_score"])
                    all_composites.append(judge_result["avg_composite_score"])
                if "avg_security_relevance" in judge_result:
                    all_security.append(judge_result["avg_security_relevance"])
                if "avg_test_quality" in judge_result:
                    all_quality.append(judge_result["avg_test_quality"])

            if model_composites:
                model_rankings[model_name] = sum(model_composites) / len(model_composites)

        # Sort models by average score
        ranked_models = sorted(model_rankings.items(), key=lambda x: x[1], reverse=True)

        return {
            "total_models": len(results),
            "total_judges": len(self.JUDGES),
            "overall_avg_composite": sum(all_composites) / len(all_composites) if all_composites else 0,
            "overall_avg_security_relevance": sum(all_security) / len(all_security) if all_security else 0,
            "overall_avg_test_quality": sum(all_quality) / len(all_quality) if all_quality else 0,
            "model_rankings": ranked_models,
            "best_model": ranked_models[0] if ranked_models else None,
        }


if __name__ == "__main__":
    if len(sys.argv) > 1:
        arg = sys.argv[1]

        # Check prerequisites
        if arg == "--check":
            experiment_id = sys.argv[2] if len(sys.argv) > 2 else None
            print("Checking prerequisites for all judges...\n")
            results = JudgeRunner.check_all_prerequisites(experiment_id=experiment_id)
            all_ok = True
            for judge_name, (ok, issues) in results.items():
                status = "✅" if ok else "❌"
                print(f"{status} {judge_name}")
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

        # Run E007 task
        task_id = arg
        experiment_id = sys.argv[2] if len(sys.argv) > 2 else None
        runner = JudgeRunner(experiment_id=experiment_id)

        try:
            result = runner.run(task_id, "")
            print(json.dumps(result, indent=2))
        except JudgeRunnerError as e:
            print(f"Error: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        runner = JudgeRunner()
        print("Usage: python judge_runner.py E007 [experiment_id]")
        print("       python judge_runner.py --check [experiment_id]")
        print("\nAvailable judges:")
        for judge in JudgeRunner.JUDGES:
            print(f"  - {judge['name']} ({judge['provider']})")
        print(f"\nLLM Judge available: {LLM_JUDGE_AVAILABLE}")
        print(f"Default experiment directory: {runner.OUTPUT_DIR}")
