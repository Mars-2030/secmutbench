#!/usr/bin/env python3
"""
SecMutBench Multi-Agent System Runner

This is the main entry point for running the multi-agent system.
It provides a CLI for starting, monitoring, and resuming agents.

Usage:
    # Run full pipeline
    python run_agents.py

    # Run specific phase
    python run_agents.py --phase improvement
    python run_agents.py --phase experiment
    python run_agents.py --phase analysis

    # Check status
    python run_agents.py --status

    # Resume from checkpoint
    python run_agents.py --resume

    # Reset and start fresh
    python run_agents.py --reset

    # Run in Claude Code (recommended)
    claude "python /path/to/run_agents.py"
"""

import argparse
import json
import os
import sys
from pathlib import Path
from datetime import datetime

# Add agents to path
sys.path.insert(0, str(Path(__file__).parent / "agents"))


def print_banner():
    """Print welcome banner."""
    print("""
╔═══════════════════════════════════════════════════════════════╗
║        SecMutBench Multi-Agent System                        ║
║        Security Test Generation Benchmark                     ║
╚═══════════════════════════════════════════════════════════════╝
""")


def check_prerequisites():
    """Check if required dependencies are available."""
    issues = []

    # Check Python version
    if sys.version_info < (3, 8):
        issues.append("Python 3.8+ required")

    # Check for Ollama
    import shutil
    if not shutil.which("ollama"):
        issues.append("Ollama not found (needed for local models)")

    # Check for API keys
    if not os.getenv("OPENAI_API_KEY"):
        issues.append("OPENAI_API_KEY not set (needed for GPT-4/5)")
    if not os.getenv("GOOGLE_API_KEY"):
        issues.append("GOOGLE_API_KEY not set (needed for Gemini)")

    if issues:
        print("⚠️  Prerequisites Check:")
        for issue in issues:
            print(f"   - {issue}")
        print()

    return len(issues) == 0


def run_full_pipeline():
    """Run the complete multi-agent pipeline."""
    from orchestrator import Orchestrator

    print("Starting full pipeline...")
    print("This will run: Improvement → Experiment → Analysis\n")

    orchestrator = Orchestrator()
    orchestrator.run("all")


def run_phase(phase: str):
    """Run a specific phase."""
    from orchestrator import Orchestrator

    print(f"Starting {phase} phase...\n")

    orchestrator = Orchestrator()
    orchestrator.run(phase)


def show_status():
    """Show current status of all agents."""
    state_file = Path(__file__).parent / ".agent_state" / "orchestrator_state.json"

    print_banner()

    if not state_file.exists():
        print("No agent state found. Run with --reset to initialize.\n")
        return

    with open(state_file) as f:
        state = json.load(f)

    print(f"Current Phase: {state.get('current_phase', 'unknown').upper()}")
    print(f"Started: {state.get('started_at', 'N/A')}")
    print(f"Last Checkpoint: {state.get('last_checkpoint', 'N/A')}")
    print("-" * 60)

    # Task summary
    tasks = state.get("tasks", [])
    phases = {}

    for task in tasks:
        phase = task.get("phase", "unknown")
        if phase not in phases:
            phases[phase] = {"total": 0, "completed": 0, "in_progress": 0, "failed": 0}
        phases[phase]["total"] += 1
        status = task.get("status", "pending")
        if status in phases[phase]:
            phases[phase][status] += 1

    for phase, info in phases.items():
        completed = info["completed"]
        total = info["total"]
        pct = 100 * completed // total if total else 0

        icon = "✓" if completed == total else "~" if completed > 0 else " "
        print(f"[{icon}] {phase.upper()}: {completed}/{total} ({pct}%)")

        if info["in_progress"] > 0:
            print(f"    ⏳ In Progress: {info['in_progress']}")
        if info["failed"] > 0:
            print(f"    ❌ Failed: {info['failed']}")

    print("-" * 60)

    # Show current task
    current = [t for t in tasks if t.get("status") == "in_progress"]
    if current:
        print("Currently Running:")
        for task in current:
            print(f"  → {task['id']}: {task['description']}")
    print()


def resume_agents():
    """Resume agents from last checkpoint."""
    from orchestrator import Orchestrator

    print("Resuming from last checkpoint...\n")

    orchestrator = Orchestrator()
    orchestrator.resume()


def reset_state():
    """Reset all agent state."""
    state_dir = Path(__file__).parent / ".agent_state"

    if state_dir.exists():
        # Clear state files
        for f in state_dir.glob("*.json"):
            f.unlink()
        for f in state_dir.glob("*.log"):
            f.unlink()
        # Clear checkpoints
        checkpoint_dir = state_dir / "checkpoints"
        if checkpoint_dir.exists():
            for f in checkpoint_dir.glob("*.json"):
                f.unlink()

    print("✓ State reset. All tasks set to pending.\n")


def main():
    parser = argparse.ArgumentParser(
        description="SecMutBench Multi-Agent System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python run_agents.py                    # Run full pipeline
    python run_agents.py --phase improvement  # Run improvement phase only
    python run_agents.py --status           # Check current status
    python run_agents.py --resume           # Resume from checkpoint

For Claude Code:
    claude "Run the SecMutBench multi-agent system"
        """
    )

    parser.add_argument(
        "--phase",
        choices=["improvement", "experiment", "analysis"],
        help="Run specific phase only"
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current status of all agents"
    )
    parser.add_argument(
        "--resume",
        action="store_true",
        help="Resume from last checkpoint"
    )
    parser.add_argument(
        "--reset",
        action="store_true",
        help="Reset all state and start fresh"
    )
    parser.add_argument(
        "--skip-checks",
        action="store_true",
        help="Skip prerequisite checks"
    )

    args = parser.parse_args()

    print_banner()

    # Handle commands
    if args.status:
        show_status()
        return

    if args.reset:
        reset_state()
        return

    # Check prerequisites
    if not args.skip_checks:
        check_prerequisites()

    if args.resume:
        resume_agents()
    elif args.phase:
        run_phase(args.phase)
    else:
        run_full_pipeline()


if __name__ == "__main__":
    main()
