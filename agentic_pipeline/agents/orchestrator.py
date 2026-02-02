#!/usr/bin/env python3
"""
SecMutBench Orchestrator

Coordinator for running experiments with feedback loop. Uses real SecMutBench evaluation.

Sub-agents:
- DataGenerator: Generate samples using rebuild_dataset.py
- ModelRunner: Run model evaluations (uses real MutationEngine/TestRunner)
- JudgeRunner: Run LLM judges (uses real llm_judge module)
- StatAgent: Statistical analysis
- ChartAgent: Generate visualizations
- ReportAgent: Generate reports
- ResultReviewer: Review results and identify improvement opportunities
- DatasetImprover: Implement improvements based on review

Phases:
1. improvement: Generate/improve dataset samples
2. experiment: Run model evaluations and LLM judges
3. analysis: Statistical analysis, charts, reports
4. feedback: Review results and improve dataset

Usage:
    python orchestrator.py                              # Run all phases with feedback
    python orchestrator.py --models E001,E003           # Run specific models only
    python orchestrator.py --judges gpt-4,gemini-1.5-pro # Run specific judges only
    python orchestrator.py --no-feedback                # Run without feedback loop
    python orchestrator.py --retry 3                    # Retry failed tasks 3 times
    python orchestrator.py --status                     # Check SecMutBench availability
"""

import json
import sys
import os
import time
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add paths for imports
AGENTS_DIR = Path(__file__).parent
FIXES_DIR = AGENTS_DIR.parent
SECMUTBENCH_ROOT = FIXES_DIR.parent

sys.path.insert(0, str(SECMUTBENCH_ROOT))
sys.path.insert(0, str(AGENTS_DIR))

# Import ImprovementsLogger for tracking changes
try:
    from sub_agents.dataset_improver import ImprovementsLogger
    LOGGER_AVAILABLE = True
except ImportError:
    LOGGER_AVAILABLE = False


# Available models and judges
AVAILABLE_MODELS = {
    "E001": {"name": "qwen2.5-coder:7b", "type": "ollama"},
    "E002": {"name": "codellama:13b", "type": "ollama"},
    "E003": {"name": "deepseek-coder:6.7b", "type": "ollama"},
    "E004": {"name": "qwen3-coder:latest", "type": "ollama"},
}

AVAILABLE_JUDGES = {
    "claude-4.5-opus": {"provider": "anthropic"},
    "gpt-5": {"provider": "openai"},
    "gemini-3-pro": {"provider": "google"},
}

# Default configuration
DEFAULT_RETRY_COUNT = 3
DEFAULT_RETRY_DELAY = 5  # seconds


def get_tasks(selected_models: List[str] = None, selected_judges: List[str] = None) -> Dict:
    """Generate task definitions based on selected models and judges."""

    # Filter models
    if selected_models:
        model_tasks = [
            (task_id, f"Run evaluation on {config['name']}", "ModelRunner")
            for task_id, config in AVAILABLE_MODELS.items()
            if task_id in selected_models
        ]
    else:
        model_tasks = [
            (task_id, f"Run evaluation on {config['name']}", "ModelRunner")
            for task_id, config in AVAILABLE_MODELS.items()
        ]

    return {
        "improvement": [
            ("I001", "Generate samples for Tier 1 CWEs", "DataGenerator"),
            ("I002", "Generate samples for Tier 2 CWEs", "DataGenerator"),
        ],
        "experiment": model_tasks + [
            ("E007", "Run LLM Judge on all generated tests", "JudgeRunner"),
        ],
        "analysis": [
            ("A001", "Calculate Cohen's d effect sizes", "StatAgent"),
            ("A002", "Run ANOVA across CWEs", "StatAgent"),
            ("A003", "Calculate ICC for judge agreement", "StatAgent"),
            ("A004", "Generate mutation score heatmap", "ChartAgent"),
            ("A005", "Generate model comparison charts", "ChartAgent"),
            ("A006", "Generate CWE distribution plots", "ChartAgent"),
            ("A007", "Create evaluation report (Markdown)", "ReportAgent"),
            ("A008", "Create paper tables (LaTeX)", "ReportAgent"),
        ],
        "feedback": [
            ("F001", "Identify weak CWEs", "ResultReviewer"),
            ("F002", "Flag problematic samples", "ResultReviewer"),
            ("F003", "Analyze operator effectiveness", "ResultReviewer"),
            ("F004", "Generate improvement recommendations", "ResultReviewer"),
            ("F005", "Add samples for weak CWEs", "DatasetImprover"),
            ("F006", "Fix or remove problematic samples", "DatasetImprover"),
            ("F007", "Update mutation operators", "DatasetImprover"),
            ("F008", "Apply all improvements and rebuild dataset", "DatasetImprover"),
        ],
    }


class ErrorHandler:
    """Handles common errors and provides auto-fix capabilities."""

    @staticmethod
    def check_ollama_running() -> bool:
        """Check if Ollama is running."""
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

    @staticmethod
    def start_ollama() -> bool:
        """Try to start Ollama."""
        try:
            print("    Attempting to start Ollama...")
            subprocess.Popen(
                ["ollama", "serve"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            time.sleep(3)  # Wait for startup
            return ErrorHandler.check_ollama_running()
        except FileNotFoundError:
            print("    Ollama not installed")
            return False

    @staticmethod
    def check_api_key(provider: str) -> bool:
        """Check if API key is set for provider."""
        key_names = {
            "openai": ["OPENAI_API_KEY"],
            "anthropic": ["ANTHROPIC_API_KEY"],
            "google": ["GOOGLE_API_KEY", "GEMINI_API_KEY"],
        }
        keys = key_names.get(provider, [])
        return any(os.getenv(k) for k in keys)

    @staticmethod
    def diagnose_error(error: Exception, task_id: str, agent: str) -> Tuple[str, Optional[str]]:
        """
        Diagnose error and suggest fix.

        Returns:
            Tuple of (diagnosis, suggested_action)
            suggested_action can be: "retry", "skip", "fix_ollama", "skip_no_key", None
        """
        error_str = str(error).lower()

        # Ollama errors
        if "ollama" in error_str or "connection refused" in error_str:
            if not ErrorHandler.check_ollama_running():
                return "Ollama not running", "fix_ollama"
            return "Ollama connection error", "retry"

        # API key errors
        if "api key" in error_str or "authentication" in error_str or "unauthorized" in error_str:
            return "API key missing or invalid", "skip_no_key"

        # Rate limit errors
        if "rate limit" in error_str or "too many requests" in error_str:
            return "Rate limit exceeded", "retry"

        # Timeout errors
        if "timeout" in error_str or "timed out" in error_str:
            return "Request timed out", "retry"

        # Import errors
        if "import" in error_str or "module" in error_str:
            return "Missing module", "skip"

        # Sample validation errors
        if "validation" in error_str or "invalid sample" in error_str:
            return "Sample validation failed", "skip"

        # Generic network errors
        if "connection" in error_str or "network" in error_str:
            return "Network error", "retry"

        return "Unknown error", "retry"

    @staticmethod
    def attempt_fix(action: str) -> bool:
        """
        Attempt to fix the issue.

        Returns:
            True if fix was successful, False otherwise
        """
        if action == "fix_ollama":
            return ErrorHandler.start_ollama()
        return False


def check_secmutbench() -> bool:
    """Check if SecMutBench modules are available."""
    try:
        from evaluation.evaluate import load_benchmark
        from evaluation.mutation_engine import MutationEngine
        from evaluation.test_runner import TestRunner
        from evaluation.llm_judge import create_evaluator
        return True
    except ImportError:
        return False


def check_prerequisites(selected_models: List[str] = None, selected_judges: List[str] = None) -> Dict:
    """Check all prerequisites before running."""
    status = {
        "secmutbench": check_secmutbench(),
        "ollama": ErrorHandler.check_ollama_running(),
        "api_keys": {},
        "models_available": {},
        "judges_available": {},
    }

    # Check API keys
    for provider in ["openai", "anthropic", "google"]:
        status["api_keys"][provider] = ErrorHandler.check_api_key(provider)

    # Check which models can run
    models_to_check = selected_models or list(AVAILABLE_MODELS.keys())
    for task_id in models_to_check:
        config = AVAILABLE_MODELS.get(task_id)
        if not config:
            status["models_available"][task_id] = False
            continue

        if config["type"] == "ollama":
            status["models_available"][task_id] = status["ollama"]
        else:
            provider = config.get("provider", "openai")
            status["models_available"][task_id] = status["api_keys"].get(provider, False)

    # Check which judges can run
    judges_to_check = selected_judges or list(AVAILABLE_JUDGES.keys())
    for judge_name in judges_to_check:
        config = AVAILABLE_JUDGES.get(judge_name)
        if not config:
            status["judges_available"][judge_name] = False
            continue
        provider = config.get("provider", "openai")
        status["judges_available"][judge_name] = status["api_keys"].get(provider, False)

    return status


def run_task(
    task_id: str,
    description: str,
    agent: str,
    experiment_id: str,
    selected_models: List[str] = None,
    selected_judges: List[str] = None,
    retry_count: int = DEFAULT_RETRY_COUNT,
    retry_delay: int = DEFAULT_RETRY_DELAY,
    sample_limit: int = None
) -> Dict:
    """Run a single task with retry and error handling."""
    print(f"  [{task_id}] {description}")

    last_error = None

    for attempt in range(retry_count + 1):
        try:
            if attempt > 0:
                print(f"    Retry attempt {attempt}/{retry_count}...")
                time.sleep(retry_delay * attempt)  # Exponential backoff

            result = _execute_task(task_id, description, agent, experiment_id,
                                   selected_models, selected_judges, sample_limit)
            return {"status": "completed", "result": result, "attempts": attempt + 1}

        except Exception as e:
            last_error = e
            diagnosis, action = ErrorHandler.diagnose_error(e, task_id, agent)
            print(f"    Error: {diagnosis} - {e}")

            if action == "skip" or action == "skip_no_key":
                print(f"    Skipping task (cannot be fixed automatically)")
                return {
                    "status": "skipped",
                    "error": str(e),
                    "diagnosis": diagnosis,
                    "attempts": attempt + 1
                }

            if action == "fix_ollama" and attempt == 0:
                if ErrorHandler.attempt_fix(action):
                    print("    Fix applied, retrying...")
                    continue

            if action != "retry" or attempt >= retry_count:
                break

    return {
        "status": "failed",
        "error": str(last_error),
        "attempts": retry_count + 1
    }


def _execute_task(
    task_id: str,
    description: str,
    agent: str,
    experiment_id: str,
    selected_models: List[str] = None,
    selected_judges: List[str] = None,
    sample_limit: int = None
) -> Dict:
    """Execute the actual task."""

    if agent == "DataGenerator":
        from sub_agents.data_generator import DataGenerator
        return DataGenerator().run(task_id, description)

    elif agent == "ModelRunner":
        from sub_agents.model_runner import ModelRunner
        runner = ModelRunner(experiment_id=experiment_id, sample_limit=sample_limit)
        # Filter to selected models if specified
        if selected_models and task_id in AVAILABLE_MODELS:
            if task_id not in selected_models:
                return {"status": "skipped", "reason": "Model not selected"}
        return runner.run(task_id, description)

    elif agent == "JudgeRunner":
        from sub_agents.judge_runner import JudgeRunner
        runner = JudgeRunner(experiment_id=experiment_id)
        # Pass selected judges
        if selected_judges:
            runner.JUDGES = [
                {"name": name, **AVAILABLE_JUDGES[name]}
                for name in selected_judges
                if name in AVAILABLE_JUDGES
            ]
        return runner.run(task_id, description)

    elif agent == "StatAgent":
        from sub_agents.stat_agent import StatAgent
        return StatAgent(experiment_id=experiment_id).run(task_id, description)

    elif agent == "ChartAgent":
        from sub_agents.chart_agent import ChartAgent
        return ChartAgent(experiment_id=experiment_id).run(task_id, description)

    elif agent == "ReportAgent":
        from sub_agents.report_agent import ReportAgent
        return ReportAgent(experiment_id=experiment_id).run(task_id, description)

    elif agent == "ResultReviewer":
        from sub_agents.result_reviewer import ResultReviewer
        return ResultReviewer(experiment_id=experiment_id).run(task_id, description)

    elif agent == "DatasetImprover":
        from sub_agents.dataset_improver import DatasetImprover
        return DatasetImprover(experiment_id=experiment_id).run(task_id, description)

    else:
        raise ValueError(f"Unknown agent: {agent}")


def run_phase(
    phase: str,
    experiment_id: str,
    selected_models: List[str] = None,
    selected_judges: List[str] = None,
    retry_count: int = DEFAULT_RETRY_COUNT,
    sample_limit: int = None
) -> List[Dict]:
    """Run all tasks in a phase."""
    print(f"\n{'='*50}")
    print(f"PHASE: {phase.upper()}")
    print('='*50)

    results = []
    tasks = get_tasks(selected_models, selected_judges).get(phase, [])

    for task_id, description, agent in tasks:
        result = run_task(
            task_id, description, agent, experiment_id,
            selected_models, selected_judges, retry_count,
            sample_limit=sample_limit
        )
        result["task_id"] = task_id
        results.append(result)

        status_icon = "✓" if result["status"] == "completed" else "○" if result["status"] == "skipped" else "✗"
        print(f"    {status_icon} {result['status'].capitalize()}")

    # Print phase summary
    completed = sum(1 for r in results if r["status"] == "completed")
    skipped = sum(1 for r in results if r["status"] == "skipped")
    failed = sum(1 for r in results if r["status"] == "failed")
    print(f"\n  Phase Summary: {completed} completed, {skipped} skipped, {failed} failed")

    return results


def run_all(
    phases: List[str] = None,
    include_feedback: bool = True,
    selected_models: List[str] = None,
    selected_judges: List[str] = None,
    retry_count: int = DEFAULT_RETRY_COUNT,
    sample_limit: int = None
):
    """Run the orchestrator."""
    experiment_id = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

    print("\n" + "="*50)
    print("SECMUTBENCH ORCHESTRATOR")
    print("="*50)
    print(f"Experiment ID: {experiment_id}")
    print(f"SecMutBench Available: {'YES' if check_secmutbench() else 'NO'}")
    print(f"Feedback Loop: {'ENABLED' if include_feedback else 'DISABLED'}")
    print(f"Retry Count: {retry_count}")

    if selected_models:
        print(f"Selected Models: {', '.join(selected_models)}")
    else:
        print(f"Models: ALL ({len(AVAILABLE_MODELS)})")

    if selected_judges:
        print(f"Selected Judges: {', '.join(selected_judges)}")
    else:
        print(f"Judges: ALL ({len(AVAILABLE_JUDGES)})")

    if sample_limit:
        print(f"Sample Limit: {sample_limit}")

    # Check prerequisites
    print("\nChecking prerequisites...")
    prereq = check_prerequisites(selected_models, selected_judges)

    if not prereq["secmutbench"]:
        print("  ✗ SecMutBench modules not available")
    else:
        print("  ✓ SecMutBench modules available")

    if not prereq["ollama"]:
        print("  ○ Ollama not running (will attempt to start if needed)")
    else:
        print("  ✓ Ollama running")

    for provider, available in prereq["api_keys"].items():
        status = "✓" if available else "○"
        print(f"  {status} {provider.capitalize()} API key: {'set' if available else 'not set'}")

    if phases is None:
        phases = ["improvement", "experiment", "analysis"]
        if include_feedback:
            phases.append("feedback")

    all_results = {}
    for phase in phases:
        all_results[phase] = run_phase(
            phase, experiment_id,
            selected_models, selected_judges,
            retry_count, sample_limit
        )

    # Save results
    output_dir = FIXES_DIR / "outputs" / "experiments" / experiment_id
    output_dir.mkdir(parents=True, exist_ok=True)

    # Save orchestrator results
    results_summary = {
        "experiment_id": experiment_id,
        "timestamp": datetime.now().isoformat(),
        "config": {
            "selected_models": selected_models,
            "selected_judges": selected_judges,
            "retry_count": retry_count,
            "include_feedback": include_feedback,
        },
        "prerequisites": prereq,
        "phases": all_results,
    }

    with open(output_dir / "orchestrator_results.json", "w") as f:
        json.dump(results_summary, f, indent=2, default=str)

    # Print summary
    print("\n" + "="*50)
    print("COMPLETE")
    print("="*50)
    print(f"Results saved to: {output_dir}")

    # Overall summary
    total_completed = sum(
        sum(1 for r in phase_results if r["status"] == "completed")
        for phase_results in all_results.values()
    )
    total_skipped = sum(
        sum(1 for r in phase_results if r["status"] == "skipped")
        for phase_results in all_results.values()
    )
    total_failed = sum(
        sum(1 for r in phase_results if r["status"] == "failed")
        for phase_results in all_results.values()
    )

    print(f"\nOverall: {total_completed} completed, {total_skipped} skipped, {total_failed} failed")

    # Log experiment completion to improvements log
    if LOGGER_AVAILABLE and (total_completed > 0 or total_failed > 0):
        changes = [f"Ran {len(phases)} phases: {', '.join(phases)}"]
        changes.append(f"Completed: {total_completed} tasks")
        if total_skipped > 0:
            changes.append(f"Skipped: {total_skipped} tasks")
        if total_failed > 0:
            changes.append(f"Failed: {total_failed} tasks")
        if selected_models:
            changes.append(f"Models: {', '.join(selected_models)}")
        if selected_judges:
            changes.append(f"Judges: {', '.join(selected_judges)}")

        ImprovementsLogger.log_improvement(
            improvement_type="EXPERIMENT",
            component="Orchestrator",
            author="Orchestrator",
            experiment_id=experiment_id,
            description=f"Completed experiment run with {total_completed} tasks.",
            changes=changes
        )

    # If feedback was run, show improvement summary
    if "feedback" in all_results:
        for result in all_results["feedback"]:
            if result.get("task_id") == "F008" and result.get("status") == "completed":
                r = result.get("result", {})
                print(f"\nFeedback Summary:")
                print(f"  Samples Added: {r.get('samples_added', 0)}")
                print(f"  Samples Fixed: {r.get('samples_fixed', 0)}")
                print(f"  Samples Removed: {r.get('samples_removed', 0)}")
                print(f"  Dataset Rebuilt: {r.get('dataset_rebuilt', False)}")

    print("="*50)

    return all_results


def print_status():
    """Print system status."""
    print("\n" + "="*50)
    print("SECMUTBENCH STATUS")
    print("="*50)

    # Check SecMutBench
    available = check_secmutbench()
    print(f"\nSecMutBench Modules: {'AVAILABLE' if available else 'NOT AVAILABLE'}")

    if available:
        from evaluation.evaluate import load_benchmark
        samples = load_benchmark()
        print(f"Dataset Samples: {len(samples)}")

    # Check prerequisites
    prereq = check_prerequisites()

    print(f"\nOllama: {'RUNNING' if prereq['ollama'] else 'NOT RUNNING'}")

    print("\nAPI Keys:")
    for provider, has_key in prereq["api_keys"].items():
        status = "✓ SET" if has_key else "✗ NOT SET"
        print(f"  {provider.capitalize()}: {status}")

    print("\nAvailable Models:")
    for task_id, config in AVAILABLE_MODELS.items():
        can_run = prereq["models_available"].get(task_id, False)
        status = "✓" if can_run else "✗"
        print(f"  {status} [{task_id}] {config['name']} ({config['type']})")

    print("\nAvailable Judges:")
    for name, config in AVAILABLE_JUDGES.items():
        can_run = prereq["judges_available"].get(name, False)
        status = "✓" if can_run else "✗"
        print(f"  {status} {name} ({config['provider']})")

    print("\nPhases & Tasks:")
    tasks = get_tasks()
    for phase, phase_tasks in tasks.items():
        print(f"  {phase.upper()}: {len(phase_tasks)} tasks")

    print("\nUsage Examples:")
    print("  python orchestrator.py                              # Run all")
    print("  python orchestrator.py --models E001,E003           # Specific models")
    print("  python orchestrator.py --judges gpt-4               # Specific judge")
    print("  python orchestrator.py --retry 5                    # 5 retries")
    print("  python orchestrator.py --no-feedback                # Skip feedback")

    print("="*50)


def main():
    parser = argparse.ArgumentParser(
        description="SecMutBench Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python orchestrator.py                              # Run all phases
  python orchestrator.py --models E001,E003,E005      # Run specific models
  python orchestrator.py --judges gpt-4,gemini-1.5-pro # Run specific judges
  python orchestrator.py --phase experiment           # Run single phase
  python orchestrator.py --retry 5                    # Set retry count
  python orchestrator.py --no-feedback                # Disable feedback loop

Available Models:
  E001: qwen2.5-coder:7b (Ollama)
  E002: codellama:13b (Ollama)
  E003: deepseek-coder:6.7b (Ollama)
  E004: starcoder2:7b (Ollama)
  E005: gemini-pro (API)
  E006: gpt-4 (API)

Available Judges:
  claude-3-opus, claude-sonnet-4-5-20250929 (Anthropic)
  gpt-4, gpt-5 (OpenAI)
  gemini-1.5-pro (Google)
        """
    )

    parser.add_argument(
        "--phase",
        choices=["improvement", "experiment", "analysis", "feedback"],
        help="Run specific phase only"
    )
    parser.add_argument(
        "--models",
        type=str,
        help="Comma-separated list of models to run (e.g., E001,E003,E005)"
    )
    parser.add_argument(
        "--judges",
        type=str,
        help="Comma-separated list of judges to use (e.g., gpt-4,gemini-1.5-pro)"
    )
    parser.add_argument(
        "--retry",
        type=int,
        default=DEFAULT_RETRY_COUNT,
        help=f"Number of retry attempts for failed tasks (default: {DEFAULT_RETRY_COUNT})"
    )
    parser.add_argument(
        "--samples",
        type=int,
        default=None,
        help="Limit number of samples to evaluate (for testing)"
    )
    parser.add_argument(
        "--no-feedback",
        action="store_true",
        help="Run without feedback loop"
    )
    parser.add_argument(
        "--feedback-only",
        action="store_true",
        help="Run only the feedback phase on most recent experiment"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show system status and available models/judges"
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="Check prerequisites without running"
    )

    args = parser.parse_args()

    # Parse model selection
    selected_models = None
    if args.models:
        selected_models = [m.strip() for m in args.models.split(",")]
        # Validate
        invalid = [m for m in selected_models if m not in AVAILABLE_MODELS]
        if invalid:
            print(f"Error: Unknown models: {', '.join(invalid)}")
            print(f"Available: {', '.join(AVAILABLE_MODELS.keys())}")
            sys.exit(1)

    # Parse judge selection
    selected_judges = None
    if args.judges:
        selected_judges = [j.strip() for j in args.judges.split(",")]
        # Validate
        invalid = [j for j in selected_judges if j not in AVAILABLE_JUDGES]
        if invalid:
            print(f"Error: Unknown judges: {', '.join(invalid)}")
            print(f"Available: {', '.join(AVAILABLE_JUDGES.keys())}")
            sys.exit(1)

    if args.status:
        print_status()
    elif args.check:
        prereq = check_prerequisites(selected_models, selected_judges)
        print(json.dumps(prereq, indent=2))
    elif args.feedback_only:
        run_all(["feedback"], include_feedback=True,
                selected_models=selected_models, selected_judges=selected_judges,
                retry_count=args.retry, sample_limit=args.samples)
    elif args.phase:
        run_all([args.phase], include_feedback=False,
                selected_models=selected_models, selected_judges=selected_judges,
                retry_count=args.retry, sample_limit=args.samples)
    elif args.no_feedback:
        run_all(include_feedback=False,
                selected_models=selected_models, selected_judges=selected_judges,
                retry_count=args.retry, sample_limit=args.samples)
    else:
        run_all(include_feedback=True,
                selected_models=selected_models, selected_judges=selected_judges,
                retry_count=args.retry, sample_limit=args.samples)


if __name__ == "__main__":
    main()
