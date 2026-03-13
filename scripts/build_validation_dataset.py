#!/usr/bin/env python3
"""
CWEval Validation Dataset Builder

Parses CWEval's expert-verified task/test pairs from data/raw/CWE-eval/
and converts them to SecMutBench's Sample schema. Saves as data/validation.json.

CWEval provides 24 pairs across 19 CWEs, with 7 CWEs overlapping SecMutBench.
Each pair with N unsafe variants produces N samples in validation.json.

Usage:
    python scripts/build_validation_dataset.py
    python scripts/build_validation_dataset.py --output data/custom_validation.json
    python scripts/build_validation_dataset.py --cwe CWE-78
    python scripts/build_validation_dataset.py --verbose
"""

import argparse
import ast
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Add project root and scripts dir to path
PROJECT_ROOT = Path(__file__).parent.parent
SCRIPTS_DIR = Path(__file__).parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from source_ingestion import CWE_REGISTRY, normalize_cwe

# Import operators for validation
try:
    from operators.operator_registry import OPERATORS
    OPERATORS_AVAILABLE = True
except ImportError:
    OPERATORS = {}
    OPERATORS_AVAILABLE = False

# Import mutation engine for pre-generating mutants
try:
    from evaluation.mutation_engine import MutationEngine
    MUTATION_ENGINE_AVAILABLE = True
except ImportError:
    MUTATION_ENGINE_AVAILABLE = False
    print("Warning: mutation_engine not available, mutants will not be pre-generated")


# =============================================================================
# CWE Name Lookup (for CWEs not in CWE_REGISTRY)
# =============================================================================

CWEVAL_CWE_NAMES = {
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Path Traversal",
    "CWE-78": "OS Command Injection",
    "CWE-79": "Cross-Site Scripting (XSS)",
    "CWE-95": "Eval Injection",
    "CWE-113": "HTTP Response Splitting",
    "CWE-117": "Improper Output Neutralization for Logs",
    "CWE-326": "Inadequate Encryption Strength",
    "CWE-327": "Weak Cryptography",
    "CWE-329": "Not Using an Unpredictable IV with CBC Mode",
    "CWE-347": "Improper Verification of Cryptographic Signature",
    "CWE-377": "Insecure Temporary File",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-502": "Insecure Deserialization",
    "CWE-643": "XPath Injection",
    "CWE-732": "Incorrect Permission Assignment for Critical Resource",
    "CWE-760": "Use of a One-Way Hash with a Predictable Salt",
    "CWE-918": "Server-Side Request Forgery (SSRF)",
    "CWE-1333": "Inefficient Regular Expression Complexity",
}

# Difficulty heuristic: CWEs with more complex secure implementations
CWEVAL_DIFFICULTY = {
    "CWE-20": "medium",
    "CWE-22": "medium",
    "CWE-78": "medium",
    "CWE-79": "easy",
    "CWE-95": "hard",
    "CWE-113": "medium",
    "CWE-117": "easy",
    "CWE-326": "hard",
    "CWE-327": "easy",
    "CWE-329": "hard",
    "CWE-347": "hard",
    "CWE-377": "medium",
    "CWE-400": "medium",
    "CWE-502": "medium",
    "CWE-643": "hard",
    "CWE-732": "medium",
    "CWE-760": "medium",
    "CWE-918": "medium",
    "CWE-1333": "hard",
}


# =============================================================================
# Task File Parser
# =============================================================================

def parse_task_file(filepath: Path) -> Dict[str, Any]:
    """
    Parse a CWEval task file.

    Extracts:
    - pair_id: e.g., "cwe_918_1"
    - func_name: the main function name
    - module_imports: imports before the function definition
    - prompt: function signature + docstring (before BEGIN SOLUTION)
    - secure_code: full function with solution (including module imports)

    Args:
        filepath: Path to the task file

    Returns:
        Dict with parsed components
    """
    content = filepath.read_text()
    lines = content.split("\n")

    # Extract pair_id from filename: cwe_918_1_task.py -> cwe_918_1
    pair_id = filepath.stem.replace("_task", "")

    # Find the function definition
    func_start_line = None
    func_name = None
    for i, line in enumerate(lines):
        match = re.match(r'^def\s+(\w+)\s*\(', line)
        if match:
            func_start_line = i
            func_name = match.group(1)
            break

    if func_start_line is None:
        raise ValueError(f"No function definition found in {filepath}")

    # Module imports = everything before the function
    module_imports = "\n".join(lines[:func_start_line]).strip()

    # Find BEGIN SOLUTION marker
    solution_line = None
    for i, line in enumerate(lines):
        if "# BEGIN SOLUTION" in line:
            solution_line = i
            break

    if solution_line is None:
        raise ValueError(f"No # BEGIN SOLUTION marker in {filepath}")

    # Prompt = function def through BEGIN SOLUTION (exclusive)
    prompt_lines = lines[func_start_line:solution_line]
    prompt = "\n".join(prompt_lines).rstrip()

    # Secure code = module imports + full function (including solution body)
    func_lines = lines[func_start_line:]
    # Remove trailing empty lines
    while func_lines and not func_lines[-1].strip():
        func_lines.pop()

    if module_imports:
        secure_code = module_imports + "\n\n\n" + "\n".join(func_lines)
    else:
        secure_code = "\n".join(func_lines)

    return {
        "pair_id": pair_id,
        "func_name": func_name,
        "module_imports": module_imports,
        "prompt": prompt,
        "secure_code": secure_code,
        "raw_source": content,
    }


# =============================================================================
# Test File Parser
# =============================================================================

def parse_test_file(filepath: Path) -> Dict[str, Any]:
    """
    Parse a CWEval test file.

    Extracts:
    - cwe_id: e.g., "CWE-918"
    - cwe_description: text after CWE number
    - codeql_url: CodeQL reference URL
    - unsafe_functions: list of {name, source, start_line, end_line}
    - uses_tmp_path: whether tests use the tmp_path fixture
    - raw_source: full file content

    Args:
        filepath: Path to the test file

    Returns:
        Dict with parsed components
    """
    content = filepath.read_text()
    lines = content.split("\n")

    # Extract CWE from docstring or comment at top
    cwe_id = None
    cwe_description = ""
    codeql_url = ""

    for line in lines[:10]:
        # Match CWE-XXX pattern
        cwe_match = re.search(r'CWE-(\d+)(?:\s*:\s*(.+?))?(?:\s*$|""")', line)
        if cwe_match and cwe_id is None:
            cwe_num = cwe_match.group(1)
            cwe_id = f"CWE-{cwe_num}"
            cwe_description = (cwe_match.group(2) or "").strip()

        # Match CodeQL URL
        url_match = re.search(r'(https://codeql\.github\.com\S+)', line)
        if url_match:
            codeql_url = url_match.group(1)

    # Prefer filename-derived CWE (more reliable than docstring)
    fname_match = re.match(r'cwe_(\d+)', filepath.stem)
    if fname_match:
        filename_cwe = f"CWE-{fname_match.group(1)}"
        if cwe_id is None:
            cwe_id = filename_cwe
        elif normalize_cwe(cwe_id) != normalize_cwe(filename_cwe):
            # Docstring CWE disagrees with filename — trust filename
            cwe_id = filename_cwe

    # Parse AST to find unsafe functions
    try:
        tree = ast.parse(content)
    except SyntaxError as e:
        raise ValueError(f"Syntax error in {filepath}: {e}")

    unsafe_functions = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef) and "unsafe" in node.name:
            # Skip test functions — only want the actual unsafe implementations
            if node.name.startswith("test_"):
                continue

            # Get source lines for this function
            start = node.lineno - 1  # 0-indexed
            end = node.end_lineno  # end_lineno is 1-indexed, inclusive
            func_source = "\n".join(lines[start:end])

            unsafe_functions.append({
                "name": node.name,
                "source": func_source,
                "start_line": start,
                "end_line": end,
            })

    # Check for tmp_path usage
    uses_tmp_path = "tmp_path" in content

    return {
        "cwe_id": cwe_id,
        "cwe_description": cwe_description,
        "codeql_url": codeql_url,
        "unsafe_functions": unsafe_functions,
        "uses_tmp_path": uses_tmp_path,
        "raw_source": content,
    }


# =============================================================================
# Expert Test Reconstruction
# =============================================================================

def reconstruct_expert_tests(
    test_raw_source: str,
    task_import_name: str,
    func_name: str,
) -> str:
    """
    Reconstruct CWEval expert tests as standalone pytest code.

    Transforms:
    1. Rewrites `from cwe_XXX_task import func` -> `from target_module import func`
    2. Removes all functions with 'unsafe' in their name (using AST line ranges)
    3. Removes test functions that test unsafe variants
    4. Keeps: helpers (_test_*), params (pytest_params_*), module-level code, _safe funcs

    Args:
        test_raw_source: Original test file content
        task_import_name: The task module name (e.g., "cwe_918_1_task")
        func_name: The main function name being tested

    Returns:
        Reconstructed pytest-compatible test code
    """
    lines = test_raw_source.split("\n")

    # Step 1: Rewrite task import
    rewritten_lines = []
    for line in lines:
        # Replace: from cwe_XXX_Y_task import func -> from target_module import func
        new_line = re.sub(
            rf'from\s+{re.escape(task_import_name)}\s+import\s+',
            'from target_module import ',
            line,
        )
        rewritten_lines.append(new_line)

    rewritten_source = "\n".join(rewritten_lines)

    # Step 2: Parse AST and find functions to remove
    try:
        tree = ast.parse(rewritten_source)
    except SyntaxError:
        # If AST parsing fails, do regex-based removal
        return _regex_based_removal(rewritten_source)

    remove_ranges = []
    for node in ast.iter_child_nodes(tree):
        if isinstance(node, ast.FunctionDef):
            should_remove = False

            # Remove functions with 'unsafe' in name (but NOT helper _test_ functions)
            if "unsafe" in node.name and not node.name.startswith("_test_"):
                should_remove = True

            # Remove test functions that test unsafe variants
            if node.name.startswith("test_") and "unsafe" in node.name:
                should_remove = True

            if should_remove:
                # Include decorators in the removal range
                if node.decorator_list:
                    start = node.decorator_list[0].lineno - 1
                else:
                    start = node.lineno - 1
                end = node.end_lineno
                remove_ranges.append((start, end))

    # Step 3: Rebuild source excluding removed ranges
    result_lines = rewritten_source.split("\n")
    keep_lines = []
    for i, line in enumerate(result_lines):
        in_removed = any(start <= i < end for start, end in remove_ranges)
        if not in_removed:
            keep_lines.append(line)

    # Clean up excessive blank lines
    cleaned = "\n".join(keep_lines)
    cleaned = re.sub(r'\n{3,}', '\n\n\n', cleaned)

    return cleaned.strip() + "\n"


def _regex_based_removal(source: str) -> str:
    """Fallback: remove unsafe functions using regex when AST fails."""
    # Remove function blocks starting with def *unsafe*
    cleaned = re.sub(
        r'^def\s+\w*unsafe\w*\s*\(.*?\n(?=\S|\Z)',
        '',
        source,
        flags=re.MULTILINE | re.DOTALL,
    )
    # Remove test functions for unsafe
    cleaned = re.sub(
        r'^@pytest\.mark\.parametrize.*?\ndef\s+test_\w*unsafe\w*\s*\(.*?\n(?=\S|\Z)',
        '',
        cleaned,
        flags=re.MULTILINE | re.DOTALL,
    )
    return cleaned.strip() + "\n"


# =============================================================================
# Insecure Code Assembly
# =============================================================================

def assemble_insecure_code(
    module_imports: str,
    unsafe_func_source: str,
    unsafe_name: str,
    func_name: str,
) -> str:
    """
    Assemble insecure code from an unsafe function variant.

    Renames the unsafe function to the original function name.

    Args:
        module_imports: Module-level imports from the task file
        unsafe_func_source: Source code of the unsafe function
        unsafe_name: Name of the unsafe function (e.g., "get_url_for_query_unsafe")
        func_name: Original function name (e.g., "get_url_for_query")

    Returns:
        Complete insecure code with function renamed
    """
    # Rename: def func_unsafe( -> def func(
    renamed = re.sub(
        rf'def\s+{re.escape(unsafe_name)}\s*\(',
        f'def {func_name}(',
        unsafe_func_source,
    )

    if module_imports:
        return module_imports + "\n\n\n" + renamed
    return renamed


# =============================================================================
# Operator Assignment
# =============================================================================

def assign_operators(cwe_id: str, secure_code: str) -> List[str]:
    """
    Assign mutation operators for a CWEval sample.

    Looks up CWE in CWE_REGISTRY, validates against secure code.

    Args:
        cwe_id: CWE identifier (e.g., "CWE-918")
        secure_code: The secure implementation

    Returns:
        List of operator names that apply
    """
    # Look up in registry
    registry_entry = CWE_REGISTRY.get(cwe_id, {})
    assigned = registry_entry.get("operators", [])

    if not OPERATORS_AVAILABLE or not assigned:
        return assigned

    # Filter to operators that actually fire on this code
    firing = [
        op for op in assigned
        if op in OPERATORS and OPERATORS[op].applies_to(secure_code)
    ]

    if firing:
        return firing

    # Fallback: try all operators
    fallback = [
        name for name, inst in OPERATORS.items()
        if inst.applies_to(secure_code)
    ]

    return fallback[:3] if fallback else assigned


# =============================================================================
# Mutant Pre-generation
# =============================================================================

def pregenerate_mutants(
    secure_code: str,
    operators: List[str],
    max_mutants: int = 10,
) -> List[Dict]:
    """
    Pre-generate mutants for a validation sample.

    Args:
        secure_code: Code to mutate
        operators: Assigned operator names
        max_mutants: Maximum mutants to generate

    Returns:
        List of mutant dicts with id, operator, description, mutated_code
    """
    if not MUTATION_ENGINE_AVAILABLE:
        return []

    engine = MutationEngine(operators if operators else None)
    try:
        result = engine.generate_mutants(
            secure_code, cwe=None, max_mutants=max_mutants
        )
        return [
            {
                "id": m.id,
                "operator": m.operator,
                "description": m.description,
                "mutated_code": m.mutated_code,
            }
            for m in result.mutants
        ]
    except Exception as e:
        print(f"  Warning: mutant generation failed: {e}")
        return []


# =============================================================================
# Main Builder
# =============================================================================

def build_validation_dataset(
    cweval_dir: Path,
    cwe_filter: Optional[str] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Build the CWEval validation dataset.

    Args:
        cweval_dir: Path to data/raw/CWE-eval/
        cwe_filter: Optional CWE to filter to (e.g., "CWE-78")
        verbose: Print detailed output

    Returns:
        Dataset dict with metadata and samples
    """
    # Discover all task/test pairs
    task_files = sorted(cweval_dir.glob("cwe_*_task.py"))

    if not task_files:
        raise FileNotFoundError(f"No CWEval task files found in {cweval_dir}")

    print(f"Found {len(task_files)} CWEval task/test pairs")

    samples = []
    stats = defaultdict(int)
    cwe_set = set()

    for task_path in task_files:
        pair_id = task_path.stem.replace("_task", "")
        test_path = task_path.parent / f"{pair_id}_test.py"

        if not test_path.exists():
            print(f"  Warning: No test file for {pair_id}, skipping")
            stats["missing_test"] += 1
            continue

        # Parse task and test files
        try:
            task_data = parse_task_file(task_path)
            test_data = parse_test_file(test_path)
        except (ValueError, SyntaxError) as e:
            print(f"  Warning: Parse error for {pair_id}: {e}")
            stats["parse_error"] += 1
            continue

        cwe_id = normalize_cwe(test_data["cwe_id"])

        # Apply CWE filter
        if cwe_filter and normalize_cwe(cwe_filter) != cwe_id:
            continue

        cwe_set.add(cwe_id)
        func_name = task_data["func_name"]
        task_import_name = f"{pair_id}_task"

        if verbose:
            print(f"\n  Parsing {pair_id} ({cwe_id})")
            print(f"    Function: {func_name}")
            print(f"    Unsafe variants: {len(test_data['unsafe_functions'])}")

        # Reconstruct expert tests (shared across variants)
        security_tests = reconstruct_expert_tests(
            test_data["raw_source"],
            task_import_name,
            func_name,
        )

        # Get CWE name
        cwe_name = CWE_REGISTRY.get(cwe_id, {}).get(
            "name", CWEVAL_CWE_NAMES.get(cwe_id, "Unknown")
        )

        # Get difficulty
        difficulty = CWEVAL_DIFFICULTY.get(cwe_id, "medium")

        # Create one sample per unsafe variant
        unsafe_funcs = test_data["unsafe_functions"]
        if not unsafe_funcs:
            # No explicit unsafe function — skip
            print(f"  Warning: No unsafe functions in {pair_id}_test.py, skipping")
            stats["no_unsafe"] += 1
            continue

        for uf in unsafe_funcs:
            unsafe_name = uf["name"]
            variant_suffix = unsafe_name.replace(func_name, "").strip("_")
            if not variant_suffix:
                variant_suffix = "unsafe"

            sample_id = f"cweval_{pair_id}_{variant_suffix}"

            # Assemble insecure code
            insecure_code = assemble_insecure_code(
                task_data["module_imports"],
                uf["source"],
                unsafe_name,
                func_name,
            )

            # Assign operators
            operators = assign_operators(cwe_id, task_data["secure_code"])

            # Pre-generate mutants
            mutants = pregenerate_mutants(
                task_data["secure_code"], operators
            )

            if verbose:
                print(f"    Variant: {unsafe_name} -> {sample_id}")
                print(f"    Operators: {operators}")
                print(f"    Mutants: {len(mutants)}")

            sample = {
                "id": sample_id,
                "cwe": cwe_id,
                "cwe_name": cwe_name,
                "difficulty": difficulty,
                "prompt": task_data["prompt"],
                "entry_point": func_name,
                "insecure_code": insecure_code,
                "secure_code": task_data["secure_code"],
                "security_tests": security_tests,
                "functional_tests": "",  # CWEval tests include both in one file
                "mutation_operators": operators,
                "source": "CWEval",
                "original_id": pair_id,
                "mutants": mutants,
                "metadata": {
                    "cweval_pair_id": pair_id,
                    "unsafe_variant": unsafe_name,
                    "cwe_description": test_data["cwe_description"],
                    "codeql_url": test_data["codeql_url"],
                    "uses_tmp_path": test_data["uses_tmp_path"],
                    "test_raw_source": test_data["raw_source"],
                },
            }

            samples.append(sample)
            stats["samples_created"] += 1

    stats["total_pairs"] = len(task_files)
    stats["total_cwes"] = len(cwe_set)

    # Count overlapping CWEs with main dataset
    main_cwes = set(CWE_REGISTRY.keys())
    overlapping = cwe_set & main_cwes
    stats["overlapping_cwes"] = len(overlapping)

    total_mutants = sum(len(s.get("mutants", [])) for s in samples)

    # Build output
    dataset = {
        "metadata": {
            "source": "CWEval",
            "version": "1.0.0",
            "generated": datetime.now().isoformat(),
            "total_pairs": stats["total_pairs"],
            "total_samples": len(samples),
            "total_mutants": total_mutants,
            "cwes": sorted(list(cwe_set)),
            "overlapping_cwes": sorted(list(overlapping)),
            "non_overlapping_cwes": sorted(list(cwe_set - main_cwes)),
        },
        "samples": samples,
    }

    return dataset


# =============================================================================
# CLI
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Build CWEval validation dataset for SecMutBench",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    python scripts/build_validation_dataset.py
    python scripts/build_validation_dataset.py --output data/custom_validation.json
    python scripts/build_validation_dataset.py --cwe CWE-78 --verbose
        """,
    )

    default_output = PROJECT_ROOT / "data" / "validation.json"
    default_cweval_dir = PROJECT_ROOT / "data" / "raw" / "CWE-eval"

    parser.add_argument(
        "--output", type=str, default=str(default_output),
        help=f"Output file path (default: {default_output})",
    )
    parser.add_argument(
        "--cweval-dir", type=str, default=str(default_cweval_dir),
        help="Path to CWE-eval directory",
    )
    parser.add_argument(
        "--cwe", type=str, default=None,
        help="Filter to a single CWE (e.g., CWE-78)",
    )
    parser.add_argument(
        "--verbose", action="store_true",
        help="Print detailed output",
    )

    args = parser.parse_args()

    cweval_dir = Path(args.cweval_dir)
    if not cweval_dir.exists():
        print(f"Error: CWEval directory not found: {cweval_dir}")
        sys.exit(1)

    print(f"\n{'='*60}")
    print("CWEval Validation Dataset Builder")
    print(f"{'='*60}\n")

    # Build dataset
    dataset = build_validation_dataset(
        cweval_dir,
        cwe_filter=args.cwe,
        verbose=args.verbose,
    )

    meta = dataset["metadata"]
    samples = dataset["samples"]

    # Print summary
    print(f"\n{'='*60}")
    print("Summary")
    print(f"{'='*60}")
    print(f"  Total pairs parsed: {meta['total_pairs']}")
    print(f"  Total samples: {meta['total_samples']}")
    print(f"  Total mutants: {meta['total_mutants']}")
    print(f"  CWEs: {len(meta['cwes'])}")
    print(f"  Overlapping with SecMutBench: {len(meta['overlapping_cwes'])}")
    print(f"    {', '.join(meta['overlapping_cwes'])}")
    print(f"  Non-overlapping: {len(meta['non_overlapping_cwes'])}")
    print(f"    {', '.join(meta['non_overlapping_cwes'])}")

    # Per-CWE breakdown
    by_cwe = defaultdict(int)
    for s in samples:
        by_cwe[s["cwe"]] += 1
    print(f"\n  Per CWE:")
    for cwe in sorted(by_cwe.keys()):
        overlap_marker = " *" if cwe in meta["overlapping_cwes"] else ""
        print(f"    {cwe}: {by_cwe[cwe]} samples{overlap_marker}")

    # Save
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"\nSaved {len(samples)} samples to {output_path}")


if __name__ == "__main__":
    main()
