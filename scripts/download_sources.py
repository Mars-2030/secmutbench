#!/usr/bin/env python3
"""
Download source datasets for SecMutBench

Sources:
1. SecurityEval - https://huggingface.co/datasets/s2e-lab/SecurityEval
2. CyberSecEval - https://huggingface.co/datasets/walledai/CyberSecEval
"""

import json
import os
from pathlib import Path
from typing import List, Dict, Any


def download_security_eval() -> List[Dict]:
    """
    Download SecurityEval dataset from HuggingFace.

    Returns:
        List of sample dicts
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("Please install datasets: pip install datasets")
        return []

    print("Downloading SecurityEval dataset...")
    dataset = load_dataset("s2e-lab/SecurityEval")

    samples = []
    for item in dataset["train"]:
        samples.append({
            "id": item["ID"],
            "prompt": item["Prompt"],
            "insecure_code": item["Insecure_code"],
            "source": "SecurityEval",
        })

    print(f"Downloaded {len(samples)} samples from SecurityEval")
    return samples


def download_cybersec_eval() -> List[Dict]:
    """
    Download CyberSecEval dataset from HuggingFace.

    Returns:
        List of sample dicts
    """
    try:
        from datasets import load_dataset
    except ImportError:
        print("Please install datasets: pip install datasets")
        return []

    print("Downloading CyberSecEval dataset...")
    try:
        dataset = load_dataset("walledai/CyberSecEval", "instruct", split="python")
    except Exception as e:
        print(f"Failed to download CyberSecEval: {e}")
        return []

    samples = []
    for item in dataset:
        samples.append({
            "prompt": item.get("prompt", ""),
            "source": "CyberSecEval",
            "raw": dict(item),
        })

    print(f"Downloaded {len(samples)} samples from CyberSecEval")
    return samples


def filter_by_cwe(samples: List[Dict], target_cwes: List[str]) -> List[Dict]:
    """Filter samples by target CWEs."""
    filtered = []
    for sample in samples:
        sample_id = sample.get("id", "")
        cwe = extract_cwe(sample_id)
        if cwe in target_cwes:
            sample["cwe"] = cwe
            filtered.append(sample)
    return filtered


def extract_cwe(sample_id: str) -> str:
    """Extract CWE from sample ID."""
    # SecurityEval format: CWE-089_codeql_1.py
    if sample_id.startswith("CWE"):
        parts = sample_id.split("_")
        if parts:
            cwe = parts[0].replace("-0", "-")  # CWE-089 -> CWE-89
            return cwe
    return ""


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Download source datasets")
    parser.add_argument(
        "--output",
        default="data/raw",
        help="Output directory for downloaded data",
    )
    parser.add_argument(
        "--sources",
        nargs="+",
        default=["securityeval"],
        choices=["securityeval", "cyberseceval", "all"],
        help="Which sources to download",
    )

    args = parser.parse_args()

    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)

    sources_to_download = args.sources
    if "all" in sources_to_download:
        sources_to_download = ["securityeval", "cyberseceval"]

    all_samples = []

    if "securityeval" in sources_to_download:
        samples = download_security_eval()
        if samples:
            output_path = output_dir / "securityeval_raw.json"
            with open(output_path, "w") as f:
                json.dump(samples, f, indent=2)
            print(f"Saved to {output_path}")
            all_samples.extend(samples)

    if "cyberseceval" in sources_to_download:
        samples = download_cybersec_eval()
        if samples:
            output_path = output_dir / "cyberseceval_raw.json"
            with open(output_path, "w") as f:
                json.dump(samples, f, indent=2)
            print(f"Saved to {output_path}")
            all_samples.extend(samples)

    print(f"\nTotal: {len(all_samples)} samples downloaded")

    # Target CWEs for filtering
    target_cwes = [
        "CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-20",
        "CWE-287", "CWE-798", "CWE-327", "CWE-502", "CWE-918",
    ]

    # Filter SecurityEval samples
    se_samples = [s for s in all_samples if s.get("source") == "SecurityEval"]
    filtered = filter_by_cwe(se_samples, target_cwes)
    print(f"Filtered to {len(filtered)} samples matching target CWEs")

    if filtered:
        output_path = output_dir / "filtered_samples.json"
        with open(output_path, "w") as f:
            json.dump(filtered, f, indent=2)
        print(f"Saved filtered samples to {output_path}")


if __name__ == "__main__":
    main()
