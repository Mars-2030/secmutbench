#!/usr/bin/env python3
"""
SecMutBench Unified Benchmark Generator

Combines the best of both approaches:
1. Hand-crafted templates from generate_samples.py (guaranteed quality)
2. Scalable generation from generate_dataset.py (volume)
3. Validation gate that runs actual tests (quality assurance)
4. Shuffle before output (CWE diversity)

Usage:
    python scripts/generate_benchmark.py --max 300 --validate --output data/dataset.json
"""

import json
import hashlib
import sys
import os
import argparse
import random
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field
from collections import defaultdict

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import from existing modules
from scripts.generate_samples import (
    CWE89_SAMPLES, CWE78_SAMPLES, CWE22_SAMPLES, CWE79_SAMPLES,
    CWE327_SAMPLES, CWE798_SAMPLES, CWE502_SAMPLES, CWE20_SAMPLES,
    CWE89_ADDITIONAL, CWE78_ADDITIONAL, CWE22_ADDITIONAL, CWE79_ADDITIONAL,
    CWE327_ADDITIONAL, CWE798_ADDITIONAL,
    Sample, validate_sample, generate_sample_id, create_sample,
)

# Import contamination prevention
from scripts.contamination_prevention import (
    PerturbationPipeline,
    TemporalFilter,
    ContaminationAuditor,
    NovelSampleTracker,
)


# ============================================================================
# CWE Information
# ============================================================================

CWE_INFO = {
    "CWE-89": {"name": "SQL Injection", "difficulty_pool": ["easy", "medium", "hard"]},
    "CWE-78": {"name": "OS Command Injection", "difficulty_pool": ["medium", "hard"]},
    "CWE-22": {"name": "Path Traversal", "difficulty_pool": ["easy", "medium", "hard"]},
    "CWE-79": {"name": "Cross-site Scripting (XSS)", "difficulty_pool": ["easy", "medium", "hard"]},
    "CWE-327": {"name": "Use of Weak Cryptographic Algorithm", "difficulty_pool": ["easy", "medium"]},
    "CWE-798": {"name": "Use of Hard-coded Credentials", "difficulty_pool": ["easy", "medium"]},
    "CWE-502": {"name": "Deserialization of Untrusted Data", "difficulty_pool": ["medium", "hard"]},
    "CWE-20": {"name": "Improper Input Validation", "difficulty_pool": ["easy", "medium"]},
}


# ============================================================================
# Template Registry - All hand-crafted samples
# ============================================================================

TEMPLATE_REGISTRY = {
    "CWE-89": CWE89_SAMPLES + CWE89_ADDITIONAL,
    "CWE-78": CWE78_SAMPLES + CWE78_ADDITIONAL,
    "CWE-22": CWE22_SAMPLES + CWE22_ADDITIONAL,
    "CWE-79": CWE79_SAMPLES + CWE79_ADDITIONAL,
    "CWE-327": CWE327_SAMPLES + CWE327_ADDITIONAL,
    "CWE-798": CWE798_SAMPLES + CWE798_ADDITIONAL,
    "CWE-502": CWE502_SAMPLES,
    "CWE-20": CWE20_SAMPLES,
}


# ============================================================================
# Additional Templates for Scaling
# ============================================================================

ADDITIONAL_TEMPLATES = {
    "CWE-89": [
        {
            "variant": "authenticate_user",
            "prompt": "Write a function that authenticates a user by checking username and password.",
            "entry_point": "authenticate_user",
            "insecure_code": '''
def authenticate_user(username, password):
    """Authenticate user (INSECURE)."""
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    result = db.execute(query)
    return len(result) > 0
''',
            "secure_code": '''
def authenticate_user(username, password):
    """Authenticate user using parameterized query."""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    result = db.execute(query, (username, password))
    return len(result) > 0
''',
            "functional_tests": '''
def test_authenticate_valid():
    """Test authenticating valid user."""
    db.reset()
    db.add_row("users", {"username": "alice", "password": "secret"})
    result = authenticate_user("alice", "secret")
    assert result == True

def test_authenticate_invalid():
    """Test invalid credentials."""
    db.reset()
    result = authenticate_user("nonexistent", "wrong")
    assert result == False
''',
            "security_tests": '''
def test_auth_sql_injection():
    """Test SQL injection in authentication."""
    db.reset()
    db.add_row("users", {"username": "admin", "password": "secret"})
    # Try to bypass authentication with SQL injection
    result = authenticate_user("admin'--", "anything")
    assert db.last_params is not None, "SQL injection: not parameterized"
    # With parameterization, this should fail (no user with that exact username)
''',
            "mutation_operators": ["PSQLI", "RVALID"],
        },
        {
            "variant": "get_orders",
            "prompt": "Write a function that gets all orders for a customer ID.",
            "entry_point": "get_orders",
            "insecure_code": '''
def get_orders(customer_id):
    """Get orders for customer (INSECURE)."""
    query = f"SELECT * FROM orders WHERE customer_id = {customer_id}"
    return db.execute(query)
''',
            "secure_code": '''
def get_orders(customer_id):
    """Get orders using parameterized query."""
    query = "SELECT * FROM orders WHERE customer_id = ?"
    return db.execute(query, (customer_id,))
''',
            "functional_tests": '''
def test_get_orders_basic():
    """Test getting orders."""
    db.reset()
    db.add_row("orders", {"id": 1, "customer_id": 100})
    result = get_orders(100)
    assert result is not None

def test_get_orders_empty():
    """Test with no orders."""
    db.reset()
    result = get_orders(999)
    assert len(result) == 0
''',
            "security_tests": '''
def test_orders_sql_injection():
    """Test SQL injection in orders query."""
    db.reset()
    result = get_orders("1 OR 1=1")
    assert db.last_params is not None, "SQL injection: not parameterized"
''',
            "mutation_operators": ["PSQLI", "RVALID"],
        },
    ],
    "CWE-79": [
        {
            "variant": "render_profile",
            "prompt": "Write a function that renders a user profile with name and bio.",
            "entry_point": "render_profile",
            "insecure_code": '''
def render_profile(name, bio):
    """Render user profile (INSECURE - no escaping)."""
    return f"<div class='profile'><h1>{name}</h1><p>{bio}</p></div>"
''',
            "secure_code": '''
import html

def render_profile(name, bio):
    """Render user profile with HTML escaping."""
    safe_name = html.escape(name)
    safe_bio = html.escape(bio)
    return f"<div class='profile'><h1>{safe_name}</h1><p>{safe_bio}</p></div>"
''',
            "functional_tests": '''
def test_render_profile_basic():
    """Test basic profile rendering."""
    result = render_profile("Alice", "Hello world")
    assert "Alice" in result
    assert "Hello world" in result

def test_render_profile_structure():
    """Test profile HTML structure."""
    result = render_profile("Bob", "Bio text")
    assert "<h1>" in result
    assert "<p>" in result
''',
            "security_tests": '''
def test_profile_xss_name():
    """Test XSS in name field."""
    result = render_profile("<script>alert('XSS')</script>", "Normal bio")
    assert "<script>" not in result, "XSS: unescaped script in name"

def test_profile_xss_bio():
    """Test XSS in bio field."""
    result = render_profile("Normal name", '<img onerror="alert(1)" src=x>')
    assert 'onerror=' not in result, "XSS: unescaped event handler in bio"
''',
            "mutation_operators": ["RVALID", "RHTTPO"],
        },
        {
            "variant": "render_search_result",
            "prompt": "Write a function that renders a search result with title and snippet.",
            "entry_point": "render_search_result",
            "insecure_code": '''
def render_search_result(title, snippet):
    """Render search result (INSECURE)."""
    return f"<li><a href='#'>{title}</a><span>{snippet}</span></li>"
''',
            "secure_code": '''
import html

def render_search_result(title, snippet):
    """Render search result with escaping."""
    safe_title = html.escape(title)
    safe_snippet = html.escape(snippet)
    return f"<li><a href='#'>{safe_title}</a><span>{safe_snippet}</span></li>"
''',
            "functional_tests": '''
def test_render_search_result():
    """Test rendering search result."""
    result = render_search_result("Title", "Snippet text")
    assert "Title" in result
    assert "<li>" in result
''',
            "security_tests": '''
def test_search_result_xss():
    """Test XSS in search result."""
    result = render_search_result("<script>evil()</script>", "text")
    assert "<script>" not in result, "XSS: unescaped script tag"
''',
            "mutation_operators": ["RVALID", "RHTTPO"],
        },
    ],
    "CWE-78": [
        {
            "variant": "run_system_command",
            "prompt": "Write a function that runs a system diagnostic command.",
            "entry_point": "run_diagnostic",
            "insecure_code": '''
def run_diagnostic(tool_name):
    """Run diagnostic tool (INSECURE)."""
    command = f"{tool_name} --check"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
''',
            "secure_code": '''
import re

def run_diagnostic(tool_name):
    """Run diagnostic tool safely."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', tool_name):
        raise ValueError("Invalid tool name")
    result = subprocess.run([tool_name, "--check"], capture_output=True, text=True)
    return result.stdout
''',
            "functional_tests": '''
def test_run_diagnostic():
    """Test running diagnostic."""
    subprocess.reset()
    result = run_diagnostic("healthcheck")
    assert result is not None
''',
            "security_tests": '''
def test_diagnostic_injection():
    """Test command injection in diagnostic."""
    subprocess.reset()
    try:
        result = run_diagnostic("tool; cat /etc/passwd")
    except ValueError:
        pass  # Expected
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True"
''',
            "mutation_operators": ["CMDINJECT", "RVALID"],
        },
    ],
    "CWE-22": [
        {
            "variant": "download_attachment",
            "prompt": "Write a function that downloads an attachment by filename.",
            "entry_point": "download_attachment",
            "insecure_code": '''
import os

def download_attachment(filename):
    """Download attachment (INSECURE)."""
    path = os.path.join("/var/attachments", filename)
    return fs.read_file(path)
''',
            "secure_code": '''
import os

def download_attachment(filename):
    """Download attachment with path validation."""
    base_dir = "/var/attachments"
    path = os.path.normpath(os.path.join(base_dir, filename))
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Invalid path")
    return fs.read_file(path)
''',
            "functional_tests": '''
def test_download_attachment():
    """Test downloading attachment."""
    fs.reset()
    fs.write_file("/var/attachments/doc.pdf", "PDF content")
    result = download_attachment("doc.pdf")
    assert result == "PDF content"
''',
            "security_tests": '''
def test_attachment_traversal():
    """Test path traversal in attachment download."""
    fs.reset()
    try:
        result = download_attachment("../../../etc/passwd")
    except ValueError:
        pass  # Expected
    else:
        assert fs.last_path is None or fs.last_path.startswith("/var/attachments")
''',
            "mutation_operators": ["PATHCONCAT", "RVALID"],
        },
    ],
}


def count_available_templates() -> Dict[str, int]:
    """Count templates available for each CWE."""
    counts = {}
    for cwe in CWE_INFO.keys():
        base = len(TEMPLATE_REGISTRY.get(cwe, []))
        additional = len(ADDITIONAL_TEMPLATES.get(cwe, []))
        counts[cwe] = base + additional
    return counts


def generate_samples_from_templates(
    max_samples: int,
    validate: bool = True,
    seed: int = 42,
) -> List[Dict]:
    """Generate samples from hand-crafted templates."""
    random.seed(seed)

    all_samples = []
    generated_ids = set()

    # Calculate distribution
    template_counts = count_available_templates()
    total_templates = sum(template_counts.values())

    print(f"\n{'='*60}")
    print("SecMutBench Unified Benchmark Generator")
    print(f"{'='*60}")
    print(f"Target samples: {max_samples}")
    print(f"Available templates: {total_templates}")
    print(f"Validation: {'enabled' if validate else 'disabled'}")

    # Generate samples for each CWE
    for cwe, info in CWE_INFO.items():
        templates = TEMPLATE_REGISTRY.get(cwe, []) + ADDITIONAL_TEMPLATES.get(cwe, [])
        difficulties = info["difficulty_pool"]

        for i, template in enumerate(templates):
            if len(all_samples) >= max_samples:
                break

            difficulty = difficulties[i % len(difficulties)]
            sample = create_sample(cwe, info["name"], difficulty, template)
            sample_dict = asdict(sample)

            if sample_dict["id"] in generated_ids:
                continue

            # Validate if requested
            if validate:
                validation = validate_sample(sample_dict)
                if not validation["valid"]:
                    print(f"  [SKIP] {sample_dict['id']}: {validation['errors'][:1]}")
                    continue

            generated_ids.add(sample_dict["id"])
            all_samples.append(sample_dict)
            print(f"  [+] {sample_dict['id']} ({cwe}, {difficulty})")

    # Shuffle for CWE diversity
    random.shuffle(all_samples)

    print(f"\n{'='*60}")
    print(f"Generated {len(all_samples)} samples")
    print(f"{'='*60}")

    return all_samples


def apply_contamination_prevention(
    samples: List[Dict],
    enabled: bool = True,
) -> Tuple[List[Dict], Dict]:
    """Apply contamination prevention pipeline."""
    if not enabled:
        return samples, {}

    print(f"\n{'='*60}")
    print("Applying Contamination Prevention")
    print(f"{'='*60}")

    stats = {
        "original_count": len(samples),
        "final_count": 0,
    }

    # Track novelty
    tracker = NovelSampleTracker()
    novelty = tracker.generate_report(samples)
    stats["novel_ratio"] = novelty.get("novel_ratio", 0.0)
    print(f"  Novel ratio: {stats['novel_ratio']:.1%}")

    # Apply temporal filter
    temporal = TemporalFilter(cutoff_year=2024)
    samples, filtered = temporal.filter_samples(samples)
    print(f"  Temporal filter: {len(samples)} passed, {len(filtered)} filtered")

    # Run audit
    auditor = ContaminationAuditor(n=5)
    audit = auditor.audit_dataset(samples, contamination_threshold=0.3)
    stats["contamination_rate"] = audit.get("contamination_rate", 0.0)
    print(f"  Contamination rate: {stats['contamination_rate']:.1%}")

    stats["final_count"] = len(samples)

    return samples, stats


def create_output(
    samples: List[Dict],
    output_path: str,
    stats: Dict = None,
) -> None:
    """Create output dataset file."""
    # Calculate distributions
    cwe_dist = defaultdict(int)
    diff_dist = defaultdict(int)
    for s in samples:
        cwe_dist[s["cwe"]] += 1
        diff_dist[s["difficulty"]] += 1

    output = {
        "metadata": {
            "version": "2.1",
            "generated": datetime.now().isoformat(),
            "generator": "generate_benchmark.py",
            "total_samples": len(samples),
            "cwe_distribution": dict(cwe_dist),
            "difficulty_distribution": dict(diff_dist),
            "contamination_prevention": stats if stats else {},
        },
        "samples": samples,
    }

    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)

    with open(output_file, "w") as f:
        json.dump(output, f, indent=2)

    print(f"\nWrote {len(samples)} samples to {output_path}")


def main():
    parser = argparse.ArgumentParser(
        description="SecMutBench Unified Benchmark Generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Generate 50 validated samples
    python scripts/generate_benchmark.py --max 50 --validate

    # Generate without validation (faster)
    python scripts/generate_benchmark.py --max 100 --no-validate

    # With specific seed for reproducibility
    python scripts/generate_benchmark.py --max 50 --seed 123
        """
    )

    parser.add_argument("--max", type=int, default=50, help="Maximum samples to generate")
    parser.add_argument("--output", "-o", default="data/dataset.json", help="Output file")
    parser.add_argument("--validate", action="store_true", help="Validate samples before output")
    parser.add_argument("--no-validate", action="store_true", help="Skip validation")
    parser.add_argument("--seed", type=int, default=42, help="Random seed")
    parser.add_argument("--no-contamination-prevention", action="store_true", help="Skip contamination prevention")

    args = parser.parse_args()

    # Generate samples
    validate = args.validate and not args.no_validate
    samples = generate_samples_from_templates(
        max_samples=args.max,
        validate=validate,
        seed=args.seed,
    )

    # Apply contamination prevention
    stats = {}
    if not args.no_contamination_prevention:
        samples, stats = apply_contamination_prevention(samples)

    # Write output
    create_output(samples, args.output, stats)

    # Summary
    print(f"\n{'='*60}")
    print("GENERATION COMPLETE")
    print(f"{'='*60}")
    print(f"Total samples: {len(samples)}")
    print(f"Output: {args.output}")

    # CWE distribution
    print("\nCWE Distribution:")
    cwe_counts = defaultdict(int)
    for s in samples:
        cwe_counts[s["cwe"]] += 1
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")


if __name__ == "__main__":
    main()
