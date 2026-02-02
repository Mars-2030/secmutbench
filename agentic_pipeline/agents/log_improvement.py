#!/usr/bin/env python3
"""
Utility script to manually log improvements to SecMutBench.

Usage:
    python log_improvement.py --type FEATURE --component "Component Name" \
        --description "Description of the change" \
        --changes "Change 1" "Change 2" "Change 3"

    # Interactive mode
    python log_improvement.py --interactive

    # View recent improvements
    python log_improvement.py --view
"""

import argparse
import sys
from pathlib import Path
from datetime import datetime

# Add parent to path
sys.path.insert(0, str(Path(__file__).parent))

from sub_agents.dataset_improver import ImprovementsLogger


def interactive_log():
    """Interactive mode for logging improvements."""
    print("\n=== Log SecMutBench Improvement ===\n")

    # Get improvement type
    print("Improvement Types: FEATURE, FIX, DATASET, OPERATOR, CONFIG, DOC")
    improvement_type = input("Type [FEATURE]: ").strip().upper() or "FEATURE"

    # Get component
    component = input("Component (e.g., Dataset, ModelRunner, Orchestrator): ").strip()
    if not component:
        print("Error: Component is required")
        return

    # Get author
    author = input("Author [Manual]: ").strip() or "Manual"

    # Get experiment ID
    experiment_id = input("Experiment ID [N/A]: ").strip() or "N/A"

    # Get description
    description = input("Description: ").strip()
    if not description:
        print("Error: Description is required")
        return

    # Get changes
    print("\nEnter changes (one per line, empty line to finish):")
    changes = []
    while True:
        change = input("  - ").strip()
        if not change:
            break
        changes.append(change)

    if not changes:
        print("Error: At least one change is required")
        return

    # Confirm
    print("\n--- Preview ---")
    print(f"Type: {improvement_type}")
    print(f"Component: {component}")
    print(f"Author: {author}")
    print(f"Experiment: {experiment_id}")
    print(f"Description: {description}")
    print("Changes:")
    for c in changes:
        print(f"  - {c}")

    confirm = input("\nLog this improvement? [Y/n]: ").strip().lower()
    if confirm and confirm != 'y':
        print("Cancelled.")
        return

    # Log it
    success = ImprovementsLogger.log_improvement(
        improvement_type=improvement_type,
        component=component,
        author=author,
        experiment_id=experiment_id,
        description=description,
        changes=changes
    )

    if success:
        print("\nImprovement logged successfully!")
    else:
        print("\nFailed to log improvement.")


def view_improvements(count: int = 10):
    """View recent improvements from the log."""
    log_file = ImprovementsLogger.LOG_FILE

    if not log_file.exists():
        print("No improvements log found.")
        return

    content = log_file.read_text()

    # Split by entries (### markers)
    entries = content.split("\n### ")

    # Get recent entries (skip header)
    recent = entries[1:count+1] if len(entries) > 1 else []

    if not recent:
        print("No improvements logged yet.")
        return

    print(f"\n=== Recent Improvements ({len(recent)} shown) ===\n")
    for entry in recent:
        print(f"### {entry}")
        print()


def main():
    parser = argparse.ArgumentParser(description="Log improvements to SecMutBench")
    parser.add_argument("--interactive", "-i", action="store_true",
                       help="Interactive mode")
    parser.add_argument("--view", "-v", action="store_true",
                       help="View recent improvements")
    parser.add_argument("--view-count", type=int, default=10,
                       help="Number of recent improvements to view")
    parser.add_argument("--type", "-t", default="FEATURE",
                       help="Improvement type (FEATURE, FIX, DATASET, etc.)")
    parser.add_argument("--component", "-c",
                       help="Component affected")
    parser.add_argument("--author", "-a", default="Manual",
                       help="Author of the improvement")
    parser.add_argument("--experiment", "-e", default="N/A",
                       help="Related experiment ID")
    parser.add_argument("--description", "-d",
                       help="Description of the improvement")
    parser.add_argument("--changes", nargs="+",
                       help="List of changes made")

    args = parser.parse_args()

    if args.view:
        view_improvements(args.view_count)
        return

    if args.interactive:
        interactive_log()
        return

    # Command-line mode
    if not args.component or not args.description or not args.changes:
        print("Error: --component, --description, and --changes are required")
        print("Use --interactive for guided input or --help for usage")
        sys.exit(1)

    success = ImprovementsLogger.log_improvement(
        improvement_type=args.type,
        component=args.component,
        author=args.author,
        experiment_id=args.experiment,
        description=args.description,
        changes=args.changes
    )

    if success:
        print("Improvement logged successfully!")
    else:
        print("Failed to log improvement.")
        sys.exit(1)


if __name__ == "__main__":
    main()
