#!/usr/bin/env python3
"""
Local (No-API) Sample Variation Generator for SecMutBench

Generates 5 code variations per sample using purely local AST-based
transformations — no LLM API calls required.

Transformation strategies:
  1. Domain rename (e-commerce context)
  2. Alternate domain rename (document management context)
  3. Structural perturbation + rename (inventory context)
  4. Wrapper function + rename (messaging context)
  5. Hash-based rename + cosmetic transforms (analytics context)

Reuses PerturbationPipeline / IdentifierRenamer from contamination_prevention.py.
Output format matches generate_variations.py so it feeds directly into
  dataset_builder.py --include-variations data/variations2.json
"""

import ast
import argparse
import hashlib
import json
import re
import sys
import textwrap
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# Add parent directory for imports
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from contamination_prevention import PerturbationPipeline, IdentifierRenamer

try:
    from sample_generator import generate_security_test, generate_functional_test
except ImportError:
    generate_security_test = None
    generate_functional_test = None

try:
    from operators.operator_registry import CWE_OPERATOR_MAP
except ImportError:
    CWE_OPERATOR_MAP = {}

from generate_variations import (
    Variation,
    CWE_VULNERABILITY_NAMES,
    validate_variation,
    load_dataset,
)


# =============================================================================
# Domain Rename Tables
# =============================================================================
# Each set maps common security-sample identifiers to a different domain.
# Keys are substrings matched against identifiers (case-insensitive prefix match).

DOMAIN_SETS: List[Dict[str, str]] = [
    # Set 0: E-commerce
    {
        "user": "product",
        "username": "product_id",
        "name": "title",
        "email": "sku",
        "password": "price",
        "query": "search",
        "get": "fetch",
        "create": "add",
        "delete": "remove",
        "update": "modify",
        "login": "checkout",
        "register": "list_item",
        "profile": "catalog",
        "account": "cart",
        "token": "coupon_code",
        "session": "order",
        "role": "category",
        "admin": "manager",
        "data": "inventory",
        "record": "listing",
        "message": "review",
        "comment": "feedback",
        "post": "offer",
        "item": "goods",
        "file": "asset",
        "path": "route",
        "url": "endpoint",
        "input": "payload",
        "output": "receipt",
        "result": "transaction",
        "response": "confirmation",
        "request": "inquiry",
        "content": "description",
        "text": "label",
        "value": "amount",
        "key": "serial",
    },
    # Set 1: Document management
    {
        "user": "document",
        "username": "doc_name",
        "name": "doc_title",
        "email": "author_email",
        "password": "access_key",
        "query": "lookup",
        "get": "load",
        "create": "draft",
        "delete": "archive",
        "update": "revise",
        "login": "open_doc",
        "register": "index_doc",
        "profile": "metadata",
        "account": "repository",
        "token": "revision_id",
        "session": "workspace",
        "role": "permission",
        "admin": "editor",
        "data": "content_data",
        "record": "entry",
        "message": "annotation",
        "comment": "note",
        "post": "publish",
        "item": "page",
        "file": "attachment",
        "path": "doc_path",
        "url": "doc_url",
        "input": "raw_text",
        "output": "rendered",
        "result": "doc_result",
        "response": "doc_response",
        "request": "doc_request",
        "content": "body",
        "text": "paragraph",
        "value": "field_value",
        "key": "field_key",
    },
    # Set 2: Inventory / warehouse
    {
        "user": "item",
        "username": "item_code",
        "name": "label",
        "email": "supplier_email",
        "password": "warehouse_key",
        "query": "scan",
        "get": "retrieve",
        "create": "stock",
        "delete": "discard",
        "update": "recount",
        "login": "check_in",
        "register": "catalog_item",
        "profile": "spec_sheet",
        "account": "warehouse",
        "token": "barcode",
        "session": "shipment",
        "role": "tier",
        "admin": "supervisor",
        "data": "stock_data",
        "record": "log_entry",
        "message": "alert",
        "comment": "remark",
        "post": "dispatch",
        "item": "unit",
        "file": "manifest",
        "path": "aisle",
        "url": "tracking_url",
        "input": "scan_input",
        "output": "pick_list",
        "result": "count_result",
        "response": "ack",
        "request": "requisition",
        "content": "details",
        "text": "notation",
        "value": "quantity",
        "key": "lot_number",
    },
    # Set 3: Messaging / chat
    {
        "user": "message",
        "username": "sender_id",
        "name": "subject",
        "email": "recipient",
        "password": "encryption_key",
        "query": "search_msg",
        "get": "read",
        "create": "compose",
        "delete": "purge",
        "update": "edit_msg",
        "login": "connect",
        "register": "subscribe",
        "profile": "contact",
        "account": "mailbox",
        "token": "msg_token",
        "session": "conversation",
        "role": "channel",
        "admin": "moderator",
        "data": "payload_data",
        "record": "thread",
        "message": "notification",
        "comment": "reply",
        "post": "broadcast",
        "item": "attachment",
        "file": "media",
        "path": "thread_path",
        "url": "link",
        "input": "draft_text",
        "output": "sent_msg",
        "result": "delivery_status",
        "response": "read_receipt",
        "request": "send_request",
        "content": "msg_body",
        "text": "snippet",
        "value": "priority",
        "key": "msg_key",
    },
    # Set 4: Analytics / reporting
    {
        "user": "report",
        "username": "report_id",
        "name": "metric",
        "email": "stakeholder",
        "password": "api_secret",
        "query": "aggregate",
        "get": "generate",
        "create": "build_report",
        "delete": "expire",
        "update": "refresh",
        "login": "authenticate",
        "register": "enroll",
        "profile": "dashboard",
        "account": "tenant",
        "token": "access_token",
        "session": "analysis",
        "role": "scope",
        "admin": "analyst",
        "data": "dataset",
        "record": "data_point",
        "message": "insight",
        "comment": "observation",
        "post": "export",
        "item": "widget",
        "file": "csv_file",
        "path": "report_path",
        "url": "source_url",
        "input": "raw_input",
        "output": "chart",
        "result": "finding",
        "response": "summary",
        "request": "query_request",
        "content": "narrative",
        "text": "caption",
        "value": "measure",
        "key": "dimension",
    },
]

# Identifiers that must never be renamed (builtins, modules, etc.)
PRESERVED_IDENTIFIERS = {
    "self", "cls", "True", "False", "None",
    "print", "len", "range", "str", "int", "float", "list", "dict", "set",
    "tuple", "bool", "bytes", "type", "object", "super", "isinstance",
    "open", "read", "write", "close", "append", "extend", "format",
    "Exception", "ValueError", "TypeError", "KeyError", "RuntimeError",
    "AttributeError", "ImportError", "OSError", "IOError", "IndexError",
    "os", "sys", "json", "re", "subprocess", "hashlib", "hmac",
    "sqlite3", "pickle", "yaml", "xml", "html", "base64",
    "logging", "pathlib", "shutil", "tempfile", "io", "collections",
    "functools", "itertools", "math", "random", "time", "datetime",
    "requests", "flask", "django", "urllib", "http", "socket",
    "pytest", "unittest", "mock", "patch",
    "db", "conn", "cursor", "connection", "engine",
    "app", "request", "response", "session",
    "hashlib", "bcrypt", "scrypt", "argon2",
    "lxml", "etree", "defusedxml",
    "Path", "PurePath",
    # common security-related names that shouldn't be renamed
    "sanitize", "escape", "validate", "verify", "check",
    "encode", "decode", "encrypt", "decrypt", "hash",
    "parameterized", "prepared", "safe", "unsafe",
}


# =============================================================================
# Domain-Based AST Renamer
# =============================================================================

def build_domain_rename_map(
    code: str,
    entry_point: str,
    domain_set: Dict[str, str],
) -> Dict[str, str]:
    """
    Build a rename map by matching identifiers in *code* against *domain_set*.

    Matching rules (applied in order):
      1. Exact match on the full identifier (e.g. "username" -> "product_id")
      2. Prefix compound match: split on _ and replace the first component
         that matches a domain key (e.g. "user_id" -> "product_id")
      3. Entry point gets its first matching component replaced
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return {}

    functions = set()
    variables = set()

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef):
            functions.add(node.name)
            for arg in node.args.args:
                variables.add(arg.arg)
        elif isinstance(node, ast.Name) and isinstance(node.ctx, ast.Store):
            variables.add(node.id)

    all_ids = functions | variables
    rename_map: Dict[str, str] = {}

    for ident in sorted(all_ids):
        if ident in PRESERVED_IDENTIFIERS or ident.startswith("_"):
            continue

        # Try exact match
        lower = ident.lower()
        if lower in domain_set:
            new_name = domain_set[lower]
            # Preserve original casing style
            if ident[0].isupper():
                new_name = new_name[0].upper() + new_name[1:]
            rename_map[ident] = new_name
            continue

        # Try component-level match (split on _)
        parts = ident.split("_")
        changed = False
        for i, part in enumerate(parts):
            pl = part.lower()
            if pl in domain_set:
                replacement = domain_set[pl]
                # Preserve casing of first char
                if part[0].isupper():
                    replacement = replacement[0].upper() + replacement[1:]
                parts[i] = replacement
                changed = True
                break  # only replace first matching component
        if changed:
            new_name = "_".join(parts)
            if new_name != ident:
                rename_map[ident] = new_name

    return rename_map


def apply_rename_map(code: str, rename_map: Dict[str, str]) -> str:
    """Apply a rename map to code via AST transformation."""
    if not rename_map:
        return code
    try:
        tree = ast.parse(code)
        renamer = IdentifierRenamer(rename_map)
        new_tree = renamer.visit(tree)
        ast.fix_missing_locations(new_tree)
        return ast.unparse(new_tree)
    except Exception:
        # Fallback: regex-based renaming (less safe but resilient)
        result = code
        # Sort by length descending to avoid partial replacements
        for old, new in sorted(rename_map.items(), key=lambda x: -len(x[0])):
            result = re.sub(rf'\b{re.escape(old)}\b', new, result)
        return result


def get_new_entry_point(entry_point: str, rename_map: Dict[str, str]) -> str:
    """Determine the new entry point name after renaming."""
    return rename_map.get(entry_point, entry_point)


# =============================================================================
# Wrapper Function Strategy
# =============================================================================

def wrap_entry_point(code: str, entry_point: str) -> Tuple[str, str]:
    """
    Wrap the entry_point function in a dispatcher/handler pattern.

    Returns (new_code, new_entry_point) where new_entry_point is the
    outer wrapper function name.
    """
    try:
        tree = ast.parse(code)
    except SyntaxError:
        return code, entry_point

    # Find the function definition
    func_def = None
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name == entry_point:
            func_def = node
            break

    if func_def is None:
        return code, entry_point

    # Extract argument names (without defaults/annotations for the call)
    arg_names = [arg.arg for arg in func_def.args.args if arg.arg != "self"]

    inner_name = f"_{entry_point}_impl"
    wrapper_name = entry_point

    # Rename original function to inner_name
    new_code = re.sub(
        rf'\bdef {re.escape(entry_point)}\b',
        f'def {inner_name}',
        code,
        count=1,
    )

    # Build wrapper with same signature
    try:
        # Re-parse to get the full signature string
        tree2 = ast.parse(new_code)
        for node in ast.walk(tree2):
            if isinstance(node, ast.FunctionDef) and node.name == inner_name:
                # Use ast.unparse on the arguments
                sig = ast.unparse(node.args) if hasattr(ast, 'unparse') else ", ".join(arg_names)
                break
        else:
            sig = ", ".join(arg_names)
    except Exception:
        sig = ", ".join(arg_names)

    call_args = ", ".join(arg_names)
    wrapper = f"\n\ndef {wrapper_name}({sig}):\n    return {inner_name}({call_args})\n"

    new_code = new_code + wrapper

    return new_code, wrapper_name


# =============================================================================
# Strategy Implementations
# =============================================================================

def strategy_domain_rename(
    sample: Dict,
    domain_idx: int,
    pipeline: PerturbationPipeline,
) -> Optional[Dict]:
    """
    Strategies 1 & 2: Apply domain-specific identifier renaming.

    domain_idx selects which DOMAIN_SETS entry to use (0-4).
    """
    domain_set = DOMAIN_SETS[domain_idx]
    entry_point = sample["entry_point"]
    secure = sample["secure_code"]
    insecure = sample["insecure_code"]

    # Build rename map from secure code (primary)
    rename_map = build_domain_rename_map(secure, entry_point, domain_set)

    if not rename_map:
        return None

    new_secure = apply_rename_map(secure, rename_map)
    new_insecure = apply_rename_map(insecure, rename_map)
    new_ep = get_new_entry_point(entry_point, rename_map)

    return {
        "secure_code": new_secure,
        "insecure_code": new_insecure,
        "entry_point": new_ep,
        "strategy": f"domain_rename_{domain_idx}",
    }


def strategy_structural_rename(
    sample: Dict,
    pipeline: PerturbationPipeline,
) -> Optional[Dict]:
    """
    Strategy 3: CWE-specific structural perturbation + domain rename (set 2).
    """
    cwe = sample.get("cwe", "")
    secure = sample["secure_code"]
    insecure = sample["insecure_code"]
    entry_point = sample["entry_point"]

    # Apply structural perturbation
    new_secure, transform_name = pipeline.apply_structural_perturbation(secure, cwe)
    new_insecure, _ = pipeline.apply_structural_perturbation(insecure, cwe)

    # Then apply domain rename (set 2 = inventory)
    domain_set = DOMAIN_SETS[2]
    rename_map = build_domain_rename_map(new_secure, entry_point, domain_set)

    if rename_map:
        new_secure = apply_rename_map(new_secure, rename_map)
        new_insecure = apply_rename_map(new_insecure, rename_map)

    new_ep = get_new_entry_point(entry_point, rename_map) if rename_map else entry_point

    return {
        "secure_code": new_secure,
        "insecure_code": new_insecure,
        "entry_point": new_ep,
        "strategy": f"structural_{transform_name}",
    }


def strategy_wrapper(
    sample: Dict,
    pipeline: PerturbationPipeline,
) -> Optional[Dict]:
    """
    Strategy 4: Wrap entry_point in a dispatcher + apply domain rename (set 3).
    """
    secure = sample["secure_code"]
    insecure = sample["insecure_code"]
    entry_point = sample["entry_point"]

    new_secure, new_ep_s = wrap_entry_point(secure, entry_point)
    new_insecure, new_ep_i = wrap_entry_point(insecure, entry_point)

    # Apply domain rename (set 3 = messaging)
    domain_set = DOMAIN_SETS[3]
    rename_map = build_domain_rename_map(new_secure, new_ep_s, domain_set)

    if rename_map:
        new_secure = apply_rename_map(new_secure, rename_map)
        new_insecure = apply_rename_map(new_insecure, rename_map)

    new_ep = get_new_entry_point(new_ep_s, rename_map) if rename_map else new_ep_s

    return {
        "secure_code": new_secure,
        "insecure_code": new_insecure,
        "entry_point": new_ep,
        "strategy": "wrapper_function",
    }


def strategy_hash_cosmetic(
    sample: Dict,
    pipeline: PerturbationPipeline,
) -> Optional[Dict]:
    """
    Strategy 5: PerturbationPipeline MD5-based rename + cosmetic transforms.

    Uses rename_identifiers() (hash-based), modify_comments(),
    vary_string_literals(), and restructure_control_flow().
    """
    secure = sample["secure_code"]
    insecure = sample["insecure_code"]
    entry_point = sample["entry_point"]

    # Apply hash-based renaming to secure code
    new_secure, rename_map = pipeline.rename_identifiers(secure)

    if not rename_map:
        return None

    # Apply same rename map to insecure code via regex
    new_insecure = insecure
    for old_name, new_name in rename_map.items():
        new_insecure = re.sub(rf'\b{re.escape(old_name)}\b', new_name, new_insecure)

    # Apply cosmetic transforms (wrapped in try/except for robustness)
    new_secure = pipeline.modify_comments(new_secure)
    new_insecure = pipeline.modify_comments(new_insecure)

    try:
        new_secure = pipeline.vary_string_literals(new_secure)
        new_insecure = pipeline.vary_string_literals(new_insecure)
    except (IndexError, re.error):
        pass  # vary_string_literals has a regex group bug; skip gracefully

    new_secure = pipeline.restructure_control_flow(new_secure)
    new_insecure = pipeline.restructure_control_flow(new_insecure)

    new_ep = rename_map.get(entry_point, entry_point)

    return {
        "secure_code": new_secure,
        "insecure_code": new_insecure,
        "entry_point": new_ep,
        "strategy": "hash_cosmetic",
    }


# =============================================================================
# Variation Pipeline
# =============================================================================

STRATEGIES = [
    ("domain_rename_0", lambda s, p: strategy_domain_rename(s, 0, p)),
    ("domain_rename_1", lambda s, p: strategy_domain_rename(s, 1, p)),
    ("structural_rename", lambda s, p: strategy_structural_rename(s, p)),
    ("wrapper_function", lambda s, p: strategy_wrapper(s, p)),
    ("hash_cosmetic", lambda s, p: strategy_hash_cosmetic(s, p)),
]


def generate_variation_id(source_id: str, strategy_idx: int, secure_code: str) -> str:
    """Generate a unique variation ID."""
    return hashlib.md5(
        f"{source_id}_{strategy_idx}_{secure_code[:100]}".encode()
    ).hexdigest()[:12]


def validate_code(code: str, entry_point: str) -> bool:
    """Check that code compiles and contains the entry_point function."""
    try:
        compile(code, "<variation>", "exec")
    except SyntaxError:
        return False
    return f"def {entry_point}(" in code


def generate_variations_for_sample(
    sample: Dict,
    pipeline: PerturbationPipeline,
    do_validate: bool = False,
) -> List[Variation]:
    """Generate up to 5 variations for a single sample."""
    cwe = sample.get("cwe", "")
    source_id = sample.get("id", "unknown")
    difficulty = sample.get("difficulty", "medium")

    variations = []

    for strategy_idx, (strategy_name, strategy_fn) in enumerate(STRATEGIES):
        result = strategy_fn(sample, pipeline)

        if result is None:
            continue

        new_secure = result["secure_code"]
        new_insecure = result["insecure_code"]
        new_ep = result["entry_point"]

        # Validate both codes compile and contain entry_point
        if not validate_code(new_secure, new_ep):
            continue
        if not validate_code(new_insecure, new_ep):
            continue

        # Skip if secure == insecure (transformation broke the vulnerability diff)
        if new_secure.strip() == new_insecure.strip():
            continue

        # Generate tests
        security_tests = ""
        functional_tests = ""
        if generate_security_test:
            security_tests = generate_security_test(new_ep, cwe, new_secure)
        if generate_functional_test:
            functional_tests = generate_functional_test(new_ep, cwe, new_secure)

        operators = CWE_OPERATOR_MAP.get(cwe, [])
        var_id = generate_variation_id(source_id, strategy_idx, new_secure)

        var = Variation(
            id=var_id,
            cwe=cwe,
            cwe_name=CWE_VULNERABILITY_NAMES.get(cwe, cwe),
            entry_point=new_ep,
            prompt=f"Local variation ({result['strategy']}) of {source_id}",
            secure_code=new_secure,
            insecure_code=new_insecure,
            difficulty=difficulty,
            functional_tests=functional_tests,
            security_tests=security_tests,
            mutation_operators=operators,
            source_sample_id=source_id,
            source="Local_Variation",
        )

        # Optional VD validation
        if do_validate:
            is_valid, msg = validate_variation(var)
            if not is_valid:
                continue

        variations.append(var)

    return variations


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Generate local (no-API) variations of security code samples"
    )
    parser.add_argument(
        "--dataset", "-d",
        default="data/dataset.json",
        help="Input dataset path",
    )
    parser.add_argument(
        "--output", "-o",
        default="data/variations2.json",
        help="Output file for variations",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of source samples to process",
    )
    parser.add_argument(
        "--cwes",
        nargs="+",
        default=None,
        help="Filter to specific CWEs (e.g., CWE-89 CWE-79)",
    )
    parser.add_argument(
        "--validate",
        action="store_true",
        help="Run VD validation on generated variations",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=42,
        help="Random seed for PerturbationPipeline (default: 42)",
    )

    args = parser.parse_args()

    print(f"Loading dataset from {args.dataset}...")
    samples = load_dataset(args.dataset)
    print(f"Loaded {len(samples)} samples")

    # Filter by CWE
    if args.cwes:
        samples = [s for s in samples if s.get("cwe") in args.cwes]
        print(f"Filtered to {len(samples)} samples for CWEs: {args.cwes}")

    # Limit samples
    if args.max_samples:
        samples = samples[:args.max_samples]
        print(f"Limited to {len(samples)} samples")

    pipeline = PerturbationPipeline(seed=args.seed)

    all_variations: List[Variation] = []
    total_attempted = 0
    strategy_counts = {name: 0 for name, _ in STRATEGIES}

    for i, sample in enumerate(samples):
        sample_id = sample.get("id", f"sample_{i}")[:12]
        cwe = sample.get("cwe", "unknown")
        ep = sample.get("entry_point", "?")
        print(f"[{i+1}/{len(samples)}] {sample_id} ({cwe}, {ep})...", end=" ")

        variations = generate_variations_for_sample(
            sample, pipeline, do_validate=args.validate
        )

        total_attempted += len(STRATEGIES)

        for v in variations:
            # Track which strategy succeeded (match by unique substring)
            prompt = v.prompt
            if "domain_rename_0" in prompt:
                strategy_counts["domain_rename_0"] += 1
            elif "domain_rename_1" in prompt:
                strategy_counts["domain_rename_1"] += 1
            elif "structural_" in prompt:
                strategy_counts["structural_rename"] += 1
            elif "wrapper" in prompt:
                strategy_counts["wrapper_function"] += 1
            elif "hash_cosmetic" in prompt:
                strategy_counts["hash_cosmetic"] += 1

        all_variations.extend(variations)
        print(f"{len(variations)}/5 variations")

    # Save results
    output_data = {
        "metadata": {
            "generator": "local_transform",
            "source_dataset": args.dataset,
            "variations_per_sample": 5,
            "total_source_samples": len(samples),
            "total_variations": len(all_variations),
            "validated": args.validate,
            "seed": args.seed,
            "strategy_counts": strategy_counts,
        },
        "variations": [asdict(v) for v in all_variations],
    }

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with open(output_path, "w") as f:
        json.dump(output_data, f, indent=2)

    # Summary
    print(f"\n{'='*60}")
    print(f"Generated {len(all_variations)} variations from {len(samples)} samples")
    print(f"Success rate: {len(all_variations)}/{total_attempted} "
          f"({100*len(all_variations)/max(total_attempted,1):.1f}%)")
    print(f"\nPer-strategy counts:")
    for sname, count in strategy_counts.items():
        print(f"  {sname}: {count}")
    if args.validate:
        print(f"  (all variations passed VD validation)")
    print(f"\nSaved to {args.output}")


if __name__ == "__main__":
    main()
