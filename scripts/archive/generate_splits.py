#!/usr/bin/env python3
"""
Generate difficulty-based splits from samples.json
"""

import json
import os
from pathlib import Path


def generate_splits():
    """Generate easy/medium/hard split files."""
    base_dir = Path(__file__).parent.parent
    samples_path = base_dir / "data" / "samples.json"
    splits_dir = base_dir / "data" / "splits"

    # Create splits directory
    splits_dir.mkdir(exist_ok=True)

    # Load samples
    with open(samples_path, "r") as f:
        samples = json.load(f)

    # Split by difficulty
    splits = {"easy": [], "medium": [], "hard": []}

    for sample in samples:
        difficulty = sample.get("difficulty", "medium")
        if difficulty in splits:
            splits[difficulty].append(sample)

    # Save splits
    for difficulty, split_samples in splits.items():
        output_path = splits_dir / f"{difficulty}.json"
        with open(output_path, "w") as f:
            json.dump(split_samples, f, indent=2)
        print(f"Generated {output_path}: {len(split_samples)} samples")

    # Generate summary
    print("\nSplit Summary:")
    print(f"  Easy:   {len(splits['easy'])} samples")
    print(f"  Medium: {len(splits['medium'])} samples")
    print(f"  Hard:   {len(splits['hard'])} samples")
    print(f"  Total:  {len(samples)} samples")


if __name__ == "__main__":
    generate_splits()
