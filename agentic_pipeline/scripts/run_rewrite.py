#!/usr/bin/env python3
"""
SecMutBench Agentic Rewrite Orchestrator

This script orchestrates the rewrite of SecMutBench following the agentic plan.
It reads the features.json file, executes tasks in order, and updates progress.

Based on Anthropic's "Effective Harnesses for Long-Running Agents" guidelines.
"""

import json
import os
import sys
import argparse
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, List, Any

# Add parent paths for imports
SCRIPT_DIR = Path(__file__).parent
REWRITE_DIR = SCRIPT_DIR.parent
SECMUTBENCH_DIR = REWRITE_DIR.parent
sys.path.insert(0, str(SECMUTBENCH_DIR))

STATE_DIR = REWRITE_DIR / ".agent_state"
FEATURES_FILE = STATE_DIR / "features.json"
PROGRESS_FILE = STATE_DIR / "progress.txt"
CONTEXT_FILE = STATE_DIR / "context_summary.md"


def load_features() -> Dict:
    """Load the features.json file."""
    with open(FEATURES_FILE, 'r') as f:
        return json.load(f)


def save_features(features: Dict):
    """Save the features.json file."""
    with open(FEATURES_FILE, 'w') as f:
        json.dump(features, f, indent=2)


def update_progress(message: str):
    """Append a message to the progress log."""
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open(PROGRESS_FILE, 'a') as f:
        f.write(f"\n[{timestamp}] {message}")


def get_next_task(features: Dict) -> Optional[Dict]:
    """Get the next task to work on."""
    # First, check for in-progress tasks
    for feature in features["features"]:
        if feature["status"] == "in_progress":
            return feature

    # Then, find first pending task with satisfied dependencies
    for feature in features["features"]:
        if feature["status"] == "pending":
            deps = feature.get("depends_on", [])
            deps_satisfied = all(
                any(f["id"] == dep and f["status"] == "completed"
                    for f in features["features"])
                for dep in deps
            )
            if deps_satisfied:
                return feature

    return None


def run_tests(test_patterns: List[str]) -> bool:
    """Run pytest with given test patterns."""
    if not test_patterns:
        return True

    test_dir = REWRITE_DIR / "tests"
    if not test_dir.exists():
        print(f"  Warning: Test directory {test_dir} does not exist")
        return True

    for pattern in test_patterns:
        test_file = test_dir / pattern.split("::")[0]
        if not test_file.exists():
            print(f"  Warning: Test file {test_file} does not exist, skipping")
            continue

        result = subprocess.run(
            ["python", "-m", "pytest", str(test_dir / pattern), "-v"],
            capture_output=True,
            text=True
        )
        if result.returncode != 0:
            print(f"  Test failed: {pattern}")
            print(result.stdout)
            print(result.stderr)
            return False

    return True


def execute_bug_fix(feature: Dict) -> bool:
    """Execute a bug fix task."""
    print(f"\n{'='*60}")
    print(f"Executing: {feature['id']} - {feature['title']}")
    print(f"{'='*60}")

    file_path = SECMUTBENCH_DIR / feature["file"]

    if not file_path.exists():
        print(f"  Error: File not found: {file_path}")
        return False

    if "fix" not in feature:
        print(f"  Warning: No fix defined, marking as manual")
        return False

    # Read current content
    with open(file_path, 'r') as f:
        content = f.read()

    # Check if fix is needed
    if feature["fix"]["old"] not in content:
        if feature["fix"]["new"] in content:
            print(f"  Already fixed!")
            return True
        else:
            print(f"  Warning: Old pattern not found in file")
            print(f"  Looking for: {feature['fix']['old'][:50]}...")
            return False

    # Apply fix
    new_content = content.replace(
        feature["fix"]["old"],
        feature["fix"]["new"]
    )

    # Write back
    with open(file_path, 'w') as f:
        f.write(new_content)

    print(f"  Applied fix to {feature['file']}")

    # Run tests
    if feature.get("tests"):
        print(f"  Running tests...")
        if not run_tests(feature["tests"]):
            # Rollback
            with open(file_path, 'w') as f:
                f.write(content)
            print(f"  Tests failed, rolled back changes")
            return False

    print(f"  Success!")
    return True


def execute_task(feature: Dict) -> bool:
    """Execute a single task based on its category."""
    category = feature.get("category", "unknown")

    if category == "bug_fix":
        return execute_bug_fix(feature)
    elif category == "dataset":
        print(f"  Dataset tasks require manual execution")
        print(f"  See: AGENTIC_REWRITE_PLAN.md for instructions")
        return False
    elif category == "operators":
        print(f"  Operator tasks require manual execution")
        print(f"  See: AGENTIC_REWRITE_PLAN.md for instructions")
        return False
    elif category == "evaluation":
        print(f"  Evaluation tasks require manual execution")
        print(f"  See: AGENTIC_REWRITE_PLAN.md for instructions")
        return False
    elif category == "validation":
        print(f"  Validation tasks require manual execution")
        print(f"  See: AGENTIC_REWRITE_PLAN.md for instructions")
        return False
    elif category == "documentation":
        print(f"  Documentation tasks require manual execution")
        return False
    else:
        print(f"  Unknown category: {category}")
        return False


def update_summary(features: Dict):
    """Update the summary counts."""
    summary = {"total": 0, "pending": 0, "in_progress": 0, "completed": 0, "blocked": 0}

    for feature in features["features"]:
        summary["total"] += 1
        status = feature.get("status", "pending")
        if status in summary:
            summary[status] += 1

    features["summary"] = summary


def run_phase(phase_num: int, features: Dict):
    """Run all tasks in a specific phase."""
    phase_key = f"phase_{phase_num}_{'bugs' if phase_num == 1 else 'dataset' if phase_num == 2 else 'operators' if phase_num == 3 else 'evaluation' if phase_num == 4 else 'validation'}"

    phase_tasks = features.get("phases", {}).get(phase_key, [])

    if not phase_tasks:
        print(f"No tasks found for phase {phase_num}")
        return

    print(f"\n{'#'*60}")
    print(f"Running Phase {phase_num}: {phase_key}")
    print(f"Tasks: {phase_tasks}")
    print(f"{'#'*60}")

    for task_id in phase_tasks:
        feature = next((f for f in features["features"] if f["id"] == task_id), None)
        if not feature:
            print(f"Task {task_id} not found")
            continue

        if feature["status"] == "completed":
            print(f"\n{task_id}: Already completed, skipping")
            continue

        feature["status"] = "in_progress"
        save_features(features)
        update_progress(f"Started: {task_id} - {feature['title']}")

        success = execute_task(feature)

        if success:
            feature["status"] = "completed"
            update_progress(f"Completed: {task_id}")
        else:
            feature["status"] = "pending"  # Reset for retry
            update_progress(f"Failed/Skipped: {task_id}")

        update_summary(features)
        save_features(features)

    print(f"\nPhase {phase_num} complete!")
    print_summary(features)


def print_summary(features: Dict):
    """Print current progress summary."""
    summary = features.get("summary", {})

    print(f"\n{'='*40}")
    print("Progress Summary")
    print(f"{'='*40}")
    print(f"Total Tasks:    {summary.get('total', 0)}")
    print(f"Completed:      {summary.get('completed', 0)}")
    print(f"In Progress:    {summary.get('in_progress', 0)}")
    print(f"Pending:        {summary.get('pending', 0)}")
    print(f"Blocked:        {summary.get('blocked', 0)}")

    completion = summary.get('completed', 0) / max(summary.get('total', 1), 1)
    print(f"\nCompletion:     {completion:.1%}")


def main():
    parser = argparse.ArgumentParser(
        description="SecMutBench Agentic Rewrite Orchestrator"
    )
    parser.add_argument(
        "--phase",
        type=int,
        choices=[1, 2, 3, 4, 5],
        help="Run specific phase (1-5)"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last in-progress task"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current status only"
    )
    parser.add_argument(
        "--task",
        type=str,
        help="Run specific task by ID (e.g., F001)"
    )

    args = parser.parse_args()

    # Ensure state directory exists
    STATE_DIR.mkdir(parents=True, exist_ok=True)

    # Load features
    if not FEATURES_FILE.exists():
        print("Error: features.json not found. Run initialize_rewrite.py first.")
        sys.exit(1)

    features = load_features()

    if args.status:
        print_summary(features)
        print("\nTask Details:")
        for f in features["features"]:
            status_icon = "✓" if f["status"] == "completed" else "◐" if f["status"] == "in_progress" else "○"
            print(f"  [{status_icon}] {f['id']}: {f['title']}")
        sys.exit(0)

    if args.task:
        feature = next((f for f in features["features"] if f["id"] == args.task), None)
        if not feature:
            print(f"Task {args.task} not found")
            sys.exit(1)

        feature["status"] = "in_progress"
        save_features(features)
        success = execute_task(feature)
        feature["status"] = "completed" if success else "pending"
        update_summary(features)
        save_features(features)
        sys.exit(0 if success else 1)

    if args.phase:
        run_phase(args.phase, features)
        sys.exit(0)

    if args.resume:
        next_task = get_next_task(features)
        if not next_task:
            print("No tasks remaining!")
            print_summary(features)
            sys.exit(0)

        print(f"Resuming with: {next_task['id']} - {next_task['title']}")
        next_task["status"] = "in_progress"
        save_features(features)
        success = execute_task(next_task)
        next_task["status"] = "completed" if success else "pending"
        update_summary(features)
        save_features(features)
        sys.exit(0 if success else 1)

    # Default: run all phases in order
    for phase in range(1, 6):
        run_phase(phase, features)


if __name__ == "__main__":
    main()
