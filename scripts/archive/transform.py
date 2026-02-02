#!/usr/bin/env python3
"""
Transform downloaded datasets to SecMutBench schema

Takes raw samples from SecurityEval/CyberSecEval and transforms them
to the standardized SecMutBench format.
"""

import json
import re
from pathlib import Path
from typing import Dict, List, Optional


# CWE name mappings
CWE_NAMES = {
    "CWE-89": "SQL Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-78": "OS Command Injection",
    "CWE-22": "Path Traversal",
    "CWE-20": "Improper Input Validation",
    "CWE-287": "Improper Authentication",
    "CWE-306": "Missing Authentication",
    "CWE-798": "Hardcoded Credentials",
    "CWE-327": "Weak Cryptography",
    "CWE-502": "Insecure Deserialization",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-77": "Command Injection",
    "CWE-94": "Code Injection",
    "CWE-116": "Improper Encoding",
    "CWE-319": "Cleartext Transmission",
    "CWE-1004": "Sensitive Cookie Without HttpOnly",
}

# CWE to mutation operator mappings
CWE_OPERATORS = {
    "CWE-89": ["PSQLI", "RVALID"],
    "CWE-79": ["RVALID", "RHTTPO"],
    "CWE-78": ["CMDINJECT", "RVALID"],
    "CWE-22": ["PATHCONCAT", "RVALID"],
    "CWE-20": ["RVALID"],
    "CWE-287": ["RMAUTH"],
    "CWE-306": ["RMAUTH"],
    "CWE-798": ["HARDCODE"],
    "CWE-327": ["WEAKCRYPTO"],
    "CWE-502": ["DESERIAL"],
}


def extract_function_name(prompt: str) -> str:
    """Extract function name from prompt."""
    # Look for 'def function_name('
    match = re.search(r'def\s+(\w+)\s*\(', prompt)
    if match:
        return match.group(1)
    return "unknown_function"


def normalize_cwe(cwe_raw: str) -> str:
    """Normalize CWE format (CWE-089 -> CWE-89)."""
    # Remove leading zeros
    match = re.match(r'CWE-0*(\d+)', cwe_raw)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe_raw


def estimate_difficulty(code: str) -> str:
    """Estimate difficulty based on code complexity."""
    lines = len(code.strip().split('\n'))

    if lines <= 15:
        return "easy"
    elif lines <= 35:
        return "medium"
    else:
        return "hard"


def transform_security_eval_sample(
    sample: Dict,
    index: int,
) -> Optional[Dict]:
    """
    Transform a SecurityEval sample to SecMutBench format.

    Args:
        sample: Raw SecurityEval sample
        index: Sample index for unique ID

    Returns:
        Transformed sample or None if invalid
    """
    sample_id = sample.get("id", sample.get("ID", ""))
    cwe_raw = sample_id.split("_")[0] if sample_id else ""
    cwe = normalize_cwe(cwe_raw)

    if not cwe or cwe not in CWE_NAMES:
        return None

    prompt = sample.get("prompt", sample.get("Prompt", ""))
    insecure_code = sample.get("insecure_code", sample.get("Insecure_code", ""))

    if not prompt or not insecure_code:
        return None

    return {
        "id": f"{cwe}_{index:03d}",
        "cwe": cwe,
        "cwe_name": CWE_NAMES.get(cwe, cwe),
        "difficulty": estimate_difficulty(insecure_code),
        "source": sample.get("source", "SecurityEval"),
        "original_id": sample_id,
        "prompt": prompt,
        "entry_point": extract_function_name(prompt),
        "insecure_code": insecure_code,
        # These need to be filled in manually
        "secure_code": None,
        "functional_tests": None,
        "security_tests": None,
        "mutation_operators": CWE_OPERATORS.get(cwe, []),
    }


def transform_samples(
    input_path: str,
    output_path: str,
    source: str = "SecurityEval",
) -> int:
    """
    Transform raw samples to SecMutBench format.

    Args:
        input_path: Path to raw samples JSON
        output_path: Path to save transformed samples
        source: Source dataset name

    Returns:
        Number of transformed samples
    """
    with open(input_path, "r") as f:
        raw_samples = json.load(f)

    transformed = []
    skipped = 0

    for i, sample in enumerate(raw_samples):
        if source == "SecurityEval":
            result = transform_security_eval_sample(sample, i + 1)
        else:
            result = None  # Add other source transformers

        if result:
            transformed.append(result)
        else:
            skipped += 1

    with open(output_path, "w") as f:
        json.dump(transformed, f, indent=2)

    print(f"Transformed: {len(transformed)} samples")
    print(f"Skipped: {skipped} samples")
    print(f"Saved to: {output_path}")

    return len(transformed)


def merge_samples(
    existing_path: str,
    new_path: str,
    output_path: str,
) -> int:
    """
    Merge new transformed samples with existing samples.

    Args:
        existing_path: Path to existing samples.json
        new_path: Path to new transformed samples
        output_path: Path to save merged samples

    Returns:
        Total number of samples
    """
    with open(existing_path, "r") as f:
        existing = json.load(f)

    with open(new_path, "r") as f:
        new_samples = json.load(f)

    # Get existing IDs
    existing_ids = {s["id"] for s in existing}

    # Add new samples with unique IDs
    added = 0
    for sample in new_samples:
        if sample["id"] not in existing_ids:
            existing.append(sample)
            existing_ids.add(sample["id"])
            added += 1

    with open(output_path, "w") as f:
        json.dump(existing, f, indent=2)

    print(f"Added {added} new samples")
    print(f"Total: {len(existing)} samples")
    print(f"Saved to: {output_path}")

    return len(existing)


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Transform samples to SecMutBench format")
    parser.add_argument(
        "input",
        help="Path to raw samples JSON",
    )
    parser.add_argument(
        "--output",
        default="data/samples_draft.json",
        help="Output path for transformed samples",
    )
    parser.add_argument(
        "--source",
        default="SecurityEval",
        choices=["SecurityEval", "CyberSecEval"],
        help="Source dataset",
    )
    parser.add_argument(
        "--merge",
        default=None,
        help="Path to existing samples to merge with",
    )

    args = parser.parse_args()

    if args.merge:
        merge_samples(args.merge, args.input, args.output)
    else:
        transform_samples(args.input, args.output, args.source)


if __name__ == "__main__":
    main()
