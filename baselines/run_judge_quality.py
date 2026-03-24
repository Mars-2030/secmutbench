#!/usr/bin/env python3
"""
Test Quality Judge for SecMutBench (/judge-quality skill)

Evaluates test craftsmanship: assertion quality, structure, edge cases,
best practices, mock usage, and anti-patterns. Does NOT judge security
relevance (that's /judge-security).

Scoring dimensions (100 points total):
1. Test Count & Diversity    (0-15 pts)
2. Assertion Quality         (0-25 pts)
3. Pytest Best Practices     (0-15 pts)
4. Structure & Readability   (0-15 pts)
5. Edge Cases                (0-10 pts)
6. Mock Environment Usage    (0-10 pts)
7. Target Function Call      (0-10 pts)

Usage:
    python baselines/run_judge_quality.py results/              # All unjudged
    python baselines/run_judge_quality.py results/gpt-oss*.json # Specific file
    python baselines/run_judge_quality.py results/ --force      # Re-judge all
"""

import ast
import json
import re
import sys
import argparse
from collections import Counter
from datetime import datetime
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# =============================================================================
# CWE → Expected Mock Mapping
# =============================================================================

CWE_EXPECTED_MOCKS = {
    "CWE-89":  ["db"],
    "CWE-78":  ["subprocess"],
    "CWE-22":  ["fs"],
    "CWE-327": ["hashlib"],
    "CWE-328": ["hashlib"],
    "CWE-502": ["pickle", "yaml"],
    "CWE-918": ["requests"],
    "CWE-611": ["xml_parser"],
    "CWE-798": ["env", "mysql"],
    "CWE-94":  ["mock_eval"],
    "CWE-95":  ["mock_eval"],
    "CWE-338": ["mock_random", "secrets"],
    "CWE-287": ["auth"],
    "CWE-306": ["auth"],
    "CWE-295": ["requests"],
    "CWE-319": ["requests"],
    "CWE-347": ["jwt"],
}

# Mocks that would be WRONG for a given CWE
CWE_WRONG_MOCKS = {
    "CWE-89":  ["subprocess", "fs", "pickle"],
    "CWE-78":  ["db", "fs", "pickle"],
    "CWE-22":  ["db", "subprocess"],
    "CWE-502": ["db", "subprocess", "fs"],
    "CWE-918": ["db", "subprocess"],
    "CWE-611": ["db", "subprocess", "pickle"],
}


# =============================================================================
# AST-Based Test Parsing
# =============================================================================

def extract_test_functions(code: str) -> List[Dict[str, Any]]:
    """Parse code and extract test functions with metadata."""
    tests = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Fallback to regex
        for match in re.finditer(
            r"def\s+(test_\w+)\s*\([^)]*\):\s*\n((?:\s+[^\n]+\n?)*)", code
        ):
            body = match.group(2)
            tests.append({
                "name": match.group(1),
                "body": body,
                "full": match.group(0),
                "has_docstring": '"""' in body or "'''" in body,
            })
        return tests

    lines = code.split("\n")
    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            start = node.lineno - 1
            end = node.end_lineno if hasattr(node, "end_lineno") and node.end_lineno else start + 30
            body_lines = lines[start:end]
            body = "\n".join(body_lines)

            # Check for docstring
            has_doc = False
            if node.body and isinstance(node.body[0], ast.Expr):
                if isinstance(node.body[0].value, (ast.Constant, ast.Str)):
                    has_doc = True

            tests.append({
                "name": node.name,
                "body": body,
                "full": body,
                "has_docstring": has_doc,
            })

    return tests


def extract_entry_point(secure_code: str) -> str:
    """Extract function name from secure code."""
    match = re.search(r"def\s+(\w+)\s*\(", secure_code)
    return match.group(1) if match else ""


# =============================================================================
# Duplicate Detection
# =============================================================================

def detect_duplicates(tests: List[Dict]) -> List[Tuple[str, str, float]]:
    """Find pairs of test functions with >85% body similarity."""
    duplicates = []
    for i in range(len(tests)):
        for j in range(i + 1, len(tests)):
            # Strip the function signature line for body comparison
            body_i = "\n".join(tests[i]["body"].split("\n")[1:]).strip()
            body_j = "\n".join(tests[j]["body"].split("\n")[1:]).strip()
            if not body_i or not body_j:
                continue
            ratio = SequenceMatcher(None, body_i, body_j).ratio()
            if ratio > 0.85:
                duplicates.append((tests[i]["name"], tests[j]["name"], ratio))
    return duplicates


# =============================================================================
# Assertion Analysis
# =============================================================================

def analyze_assertions(code: str) -> Dict[str, Any]:
    """Analyze assertion statements in detail."""
    lines = code.split("\n")
    assertions = []
    assert_true_count = 0
    assert_false_count = 0
    is_not_none_count = 0
    bare_assert_count = 0
    tautology_count = 0
    with_messages = 0
    pytest_fail_count = 0

    for line in lines:
        stripped = line.strip()

        # Standard assertions
        if stripped.startswith("assert "):
            assertions.append(stripped)

            # Check patterns
            if re.match(r"assert\s+True\s*$", stripped):
                assert_true_count += 1
            elif re.match(r"assert\s+False\s*$", stripped):
                assert_false_count += 1
            elif re.match(r"assert\s+\w+\s+is\s+not\s+None\s*$", stripped):
                is_not_none_count += 1
            elif re.match(r"assert\s+\w+\s*$", stripped):
                bare_assert_count += 1
            elif re.match(r"assert\s+1\s*==\s*1", stripped):
                tautology_count += 1

            # Check for assertion message
            if ',"' in stripped or ", '" in stripped or ',\n' in stripped:
                with_messages += 1
            elif re.search(r',\s*["\']', stripped):
                with_messages += 1
            elif re.search(r',\s*f["\']', stripped):
                with_messages += 1

        # pytest.fail
        if "pytest.fail" in stripped:
            pytest_fail_count += 1
            assertions.append(stripped)

    return {
        "total": len(assertions),
        "assert_true": assert_true_count,
        "assert_false": assert_false_count,
        "is_not_none": is_not_none_count,
        "bare_assert": bare_assert_count,
        "tautology": tautology_count,
        "with_messages": with_messages,
        "pytest_fail": pytest_fail_count,
        "lines": assertions,
    }


# =============================================================================
# Edge Case Detection
# =============================================================================

def detect_edge_cases(code: str) -> List[str]:
    """Detect edge cases tested in the code."""
    edge_cases = []
    patterns = [
        (r'""(?!\w)', "empty string"),
        (r"''(?!\w)", "empty string"),
        (r"\bNone\b", "None/null input"),
        (r"\b0\b(?!\.\d)", "zero value"),
        (r"-\d+", "negative number"),
        (r"boundary|edge|limit|overflow|underflow", "boundary condition"),
        (r"max_|min_|MAX|MIN", "min/max values"),
        (r"special.*char|[<>&\"'\\]", "special characters"),
        (r"\*\s*\d{3,}|10{5,}|\"a\"\s*\*", "large/long input"),
        (r"empty|blank|whitespace", "empty/blank handling"),
        (r"unicode|utf|\\u[0-9a-f]", "unicode characters"),
        (r"\[\s*\]", "empty list/array"),
        (r"\{\s*\}", "empty dict/object"),
        (r"\\n|\\r|\\t", "control characters"),
        (r"float\(|inf|nan|NaN", "float edge cases"),
    ]
    for pat, name in patterns:
        if re.search(pat, code, re.IGNORECASE):
            if name not in edge_cases:
                edge_cases.append(name)
    return edge_cases


# =============================================================================
# Anti-Pattern Detection
# =============================================================================

def detect_anti_patterns(code: str) -> List[str]:
    """Detect test anti-patterns."""
    issues = []

    # try/except pass — swallows errors
    if re.search(r"except\s*.*:\s*\n\s*pass", code):
        count = len(re.findall(r"except\s*.*:\s*\n\s*pass", code))
        issues.append(f"try/except pass swallows errors (x{count})")

    # Class definitions (not allowed in test sandbox)
    if re.search(r"^class\s+\w+", code, re.MULTILINE):
        issues.append("Contains class definition (not allowed)")

    # Import of real dangerous modules
    bad_imports = re.findall(
        r"^(?:from\s+|import\s+)(subprocess|socket|http\.client|urllib\.request|sqlite3)\b",
        code, re.MULTILINE
    )
    if bad_imports:
        issues.append(f"Imports real modules instead of using mocks: {', '.join(set(bad_imports))}")

    # Infinite loops
    if re.search(r"while\s+True:", code):
        issues.append("while True loop (potential hang)")

    # Global state mutation
    if re.search(r"^[a-z_]\w+\s*=\s*", code, re.MULTILINE):
        # Check for module-level variable assignments (not inside functions)
        # This is approximate — only flag if outside def blocks
        pass

    # sleep calls
    if "time.sleep" in code:
        issues.append("time.sleep() in tests (slows execution)")

    # print statements (not assertions)
    print_lines = len(re.findall(r"^\s+print\s*\(", code, re.MULTILINE))
    if print_lines >= 3:
        issues.append(f"Excessive print statements ({print_lines}) instead of assertions")

    return issues


# =============================================================================
# Pytest Best Practices
# =============================================================================

def check_pytest_practices(code: str) -> Dict[str, Any]:
    """Check pytest best practice usage."""
    return {
        "pytest_raises": "pytest.raises" in code,
        "pytest_raises_context": bool(re.search(r"with\s+pytest\.raises\s*\(", code)),
        "redundant_import_pytest": bool(re.search(r"^import\s+pytest\s*$", code, re.MULTILINE)),
        "has_fixture": "@pytest.fixture" in code,
        "parametrize": "@pytest.mark.parametrize" in code,
        "mock_reset": ".reset()" in code,
    }


# =============================================================================
# Main Quality Judge
# =============================================================================

def judge_test_quality(
    generated_tests: str,
    cwe: str,
    entry_point: str,
    difficulty: str = "",
) -> Dict[str, Any]:
    """
    Judge test quality using step-by-step reasoning.

    Steps (from /judge-quality skill):
    a. How many test functions? Distinct or copy-pasted?
    b. Are assertions specific and meaningful?
    c. Does it use pytest.raises correctly?
    d. Descriptive names and docstrings?
    e. Edge cases and boundary conditions?
    f. Anti-patterns?
    g. Mock environment usage correct?
    h. Calls the target function?
    """
    if not generated_tests or not generated_tests.strip():
        return {
            "score": 0.0,
            "assertions_count": 0,
            "edge_cases_covered": 0,
            "follows_best_practices": False,
            "issues_found": ["No tests generated"],
            "reasoning": "No tests generated",
            "confidence": 1.0,
        }

    reasoning = []
    issues = []
    score = 0.0

    # --- Parse tests ---
    test_funcs = extract_test_functions(generated_tests)
    n_tests = len(test_funcs)

    # =============================================
    # 1. Test Count & Diversity (0-15 pts)
    # =============================================
    if n_tests >= 5:
        test_score = 15
    elif n_tests == 4:
        test_score = 12
    elif n_tests == 3:
        test_score = 10
    elif n_tests == 2:
        test_score = 7
    elif n_tests == 1:
        test_score = 3
    else:
        test_score = 0
        issues.append("No test functions found")

    # Check for duplicates
    duplicates = detect_duplicates(test_funcs) if n_tests >= 2 else []
    if duplicates:
        dup_penalty = min(15, len(duplicates) * 5)
        test_score = max(0, test_score - dup_penalty)
        dup_names = [f"{a}≈{b} ({r:.0%})" for a, b, r in duplicates[:3]]
        issues.append(f"Duplicate test bodies: {'; '.join(dup_names)}")
        reasoning.append(f"{n_tests} tests but {len(duplicates)} duplicate pair(s)")
    else:
        reasoning.append(f"{n_tests} distinct test function(s)")

    score += test_score

    # =============================================
    # 2. Assertion Quality (0-25 pts)
    # =============================================
    assertions = analyze_assertions(generated_tests)
    n_assertions = assertions["total"]

    if n_assertions >= 8:
        assert_score = 25
    elif n_assertions >= 5:
        assert_score = 20
    elif n_assertions >= 3:
        assert_score = 15
    elif n_assertions >= 1:
        assert_score = 8
    else:
        assert_score = 0
        issues.append("No assertions")

    # Assertion message bonus
    if n_assertions > 0 and assertions["with_messages"] >= n_assertions * 0.5:
        assert_score = min(30, assert_score + 5)
        reasoning.append(f"Good assertion messages ({assertions['with_messages']}/{n_assertions})")

    # assert True penalty
    if assertions["assert_true"] > 0:
        penalty = assertions["assert_true"] * 10
        assert_score = max(0, assert_score - penalty)
        issues.append(f"assert True (x{assertions['assert_true']}) — trivial assertion")

    # assert False penalty (always fails unless in pytest.raises)
    if assertions["assert_false"] > 0:
        # Only penalize if not inside pytest.raises context
        issues.append(f"assert False (x{assertions['assert_false']})")
        assert_score = max(0, assert_score - assertions["assert_false"] * 3)

    # is not None penalty (if majority of assertions)
    if n_assertions > 0 and assertions["is_not_none"] >= n_assertions * 0.6:
        assert_score = max(0, assert_score - 5)
        issues.append(f"Most assertions are 'is not None' ({assertions['is_not_none']}/{n_assertions})")

    # tautology penalty
    if assertions["tautology"] > 0:
        assert_score = max(0, assert_score - assertions["tautology"] * 10)
        issues.append(f"Tautological assertion (x{assertions['tautology']})")

    if n_assertions > 0 and assertions["assert_true"] == 0 and assertions["tautology"] == 0:
        reasoning.append(f"{n_assertions} meaningful assertions")
    elif n_assertions > 0:
        reasoning.append(f"{n_assertions} assertions ({assertions['assert_true']} trivial)")

    score += max(0, assert_score)

    # =============================================
    # 3. Pytest Best Practices (0-15 pts)
    # =============================================
    bp = check_pytest_practices(generated_tests)
    bp_score = 0

    if bp["pytest_raises"]:
        bp_score += 5
        reasoning.append("Uses pytest.raises")
    if bp["pytest_raises_context"]:
        bp_score += 5
        reasoning.append("with pytest.raises() context manager")
    if not bp["redundant_import_pytest"]:
        bp_score += 3
    else:
        pass  # Minor issue, don't penalize heavily

    # Class definition penalty
    if re.search(r"^class\s+\w+", generated_tests, re.MULTILINE):
        bp_score = max(0, bp_score - 5)
        issues.append("Contains class definition (not allowed in sandbox)")

    score += min(15, bp_score)

    # =============================================
    # 4. Structure & Readability (0-15 pts)
    # =============================================
    struct_score = 0

    # Docstrings
    tests_with_docs = sum(1 for t in test_funcs if t["has_docstring"])
    if n_tests > 0 and tests_with_docs >= n_tests * 0.6:
        struct_score += 8
        reasoning.append("Good documentation (docstrings)")
    elif tests_with_docs > 0:
        struct_score += 4
    elif "# " in generated_tests:
        struct_score += 3
        reasoning.append("Has inline comments")

    # Descriptive test names (>15 chars)
    descriptive = sum(1 for t in test_funcs if len(t["name"]) > 15)
    if n_tests > 0 and descriptive >= n_tests * 0.5:
        struct_score += 7
        reasoning.append("Descriptive test names")
    elif descriptive > 0:
        struct_score += 3

    # try/except pass penalty
    anti = detect_anti_patterns(generated_tests)
    try_except_pass = any("try/except pass" in a for a in anti)
    if try_except_pass:
        struct_score = max(0, struct_score - 5)

    issues.extend(anti)
    score += min(15, struct_score)

    # =============================================
    # 5. Edge Cases (0-10 pts)
    # =============================================
    edge_cases = detect_edge_cases(generated_tests)
    n_edges = len(edge_cases)

    if n_edges >= 4:
        edge_score = 10
        reasoning.append(f"Good edge case coverage ({n_edges}: {', '.join(edge_cases[:4])})")
    elif n_edges >= 2:
        edge_score = 5
        reasoning.append(f"Some edge cases ({', '.join(edge_cases[:3])})")
    elif n_edges >= 1:
        edge_score = 3
    else:
        edge_score = 0
        reasoning.append("No edge cases tested")

    score += edge_score

    # =============================================
    # 6. Mock Environment Usage (0-10 pts)
    # =============================================
    mock_score = 0
    expected_mocks = CWE_EXPECTED_MOCKS.get(cwe, [])
    wrong_mocks = CWE_WRONG_MOCKS.get(cwe, [])

    # Reset calls
    if bp["mock_reset"]:
        mock_score += 5
        reasoning.append("Calls .reset() for test isolation")

    # Correct mock usage
    if expected_mocks:
        uses_correct = any(m in generated_tests for m in expected_mocks)
        if uses_correct:
            mock_score += 5
        else:
            reasoning.append(f"Expected mock(s) not used: {', '.join(expected_mocks)}")

    # Wrong mock penalty
    uses_wrong = [m for m in wrong_mocks if re.search(rf"\b{m}\.", generated_tests)]
    if uses_wrong:
        mock_score = max(0, mock_score - 5)
        issues.append(f"Uses wrong mock for {cwe}: {', '.join(uses_wrong)}")

    score += min(10, mock_score)

    # =============================================
    # 7. Target Function Call (0-10 pts)
    # =============================================
    if not entry_point:
        entry_point = extract_entry_point(generated_tests)

    if entry_point and entry_point in generated_tests:
        # Count how many test functions call it
        callers = sum(1 for t in test_funcs if entry_point in t["body"])
        if callers >= n_tests * 0.5 and callers > 0:
            score += 10
            reasoning.append(f"Calls target function in {callers}/{n_tests} tests")
        elif callers > 0:
            score += 5
            reasoning.append(f"Calls target in {callers}/{n_tests} tests (some miss it)")
        else:
            issues.append("Target function defined but never called in test bodies")
    elif entry_point:
        score -= 5  # Can go below section score since this is important
        issues.append(f"Never calls target function '{entry_point}'")
    else:
        score += 5  # Can't verify, give partial credit

    # =============================================
    # Normalize
    # =============================================
    score = min(1.0, max(0.0, score / 100))

    follows_bp = (
        bp["pytest_raises"] and
        not any("assert True" in i for i in issues) and
        not any("class definition" in i for i in issues)
    )

    confidence = min(1.0, 0.5 + n_tests * 0.05 + n_assertions * 0.02 + n_edges * 0.03)

    return {
        "score": round(score, 2),
        "assertions_count": n_assertions,
        "edge_cases_covered": n_edges,
        "follows_best_practices": follows_bp,
        "issues_found": issues[:6],
        "reasoning": "; ".join(reasoning),
        "confidence": round(confidence, 2),
    }


# =============================================================================
# File Processing
# =============================================================================

def judge_results_file(
    results_path: Path,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Judge all samples in a results file for test quality."""
    print(f"\nLoading: {results_path}")
    with open(results_path) as f:
        data = json.load(f)

    model_results = data.get("results", [data])
    all_summaries = []

    for model_data in model_results:
        detailed = model_data.get("detailed_results", [])
        if not detailed:
            continue

        model_name = model_data.get("model_name", "unknown")
        print(f"  Judging: {model_name} ({len(detailed)} samples)")

        scores = []
        judged = 0
        cwe_scores = {}
        issue_counter = Counter()

        for i, r in enumerate(detailed, 1):
            tests = r.get("generated_tests", "")
            if not tests or not tests.strip():
                continue

            cwe = r.get("cwe", "")
            secure_code = r.get("secure_code", "")
            entry_point = extract_entry_point(secure_code)
            difficulty = r.get("difficulty", "")

            result = judge_test_quality(tests, cwe, entry_point, difficulty)

            r["judge_quality"] = {
                "model": "claude",
                "score": result["score"],
                "assertions_count": result["assertions_count"],
                "edge_cases_covered": result["edge_cases_covered"],
                "follows_best_practices": result["follows_best_practices"],
                "issues_found": result["issues_found"],
                "reasoning": result["reasoning"],
                "confidence": result["confidence"],
            }

            scores.append(result["score"])
            judged += 1

            if cwe not in cwe_scores:
                cwe_scores[cwe] = []
            cwe_scores[cwe].append(result["score"])

            for iss in result["issues_found"]:
                # Normalize issue text for counting
                key = re.sub(r"\(x\d+\)", "", iss).strip()
                key = re.sub(r"\d+/\d+", "N/M", key)
                issue_counter[key] += 1

            if verbose and i % 50 == 0:
                print(f"    [{i}/{len(detailed)}] {r['sample_id'][:12]}... "
                      f"Score: {result['score']:.0%}")

        avg_score = sum(scores) / len(scores) if scores else 0.0
        model_data["avg_test_quality"] = round(avg_score, 4)

        cwe_summary = {}
        for cwe, sc in sorted(cwe_scores.items()):
            cwe_summary[cwe] = {
                "avg_score": round(sum(sc) / len(sc), 3),
                "count": len(sc),
            }

        summary = {
            "model_name": model_name,
            "samples_judged": judged,
            "samples_total": len(detailed),
            "avg_test_quality": avg_score,
            "per_cwe": cwe_summary,
            "top_issues": issue_counter.most_common(5),
        }
        all_summaries.append(summary)

        print(f"    Judged {judged}/{len(detailed)} — Avg: {avg_score:.1%}")

        if verbose:
            print(f"\n    Top issues:")
            for iss, count in issue_counter.most_common(5):
                print(f"      {count:>3}x  {iss}")

            print(f"\n    {'CWE':<10} {'Avg Score':<12} {'Count':<8}")
            print(f"    {'-'*30}")
            for cwe, info in sorted(cwe_summary.items(),
                                     key=lambda x: x[1]["avg_score"], reverse=True):
                print(f"    {cwe:<10} {info['avg_score']:.1%}{'':<6} {info['count']}")

    # Save
    data["judge_quality_metadata"] = {
        "judge_model": "claude",
        "judge_method": "ast_quality_analysis",
        "skill": "/judge-quality",
        "judged_at": datetime.now().isoformat(),
        "scoring_dimensions": {
            "test_count_diversity": "0-15 pts (count, duplicate detection)",
            "assertion_quality": "0-25 pts (count, messages, anti-patterns)",
            "pytest_best_practices": "0-15 pts (raises, context managers)",
            "structure_readability": "0-15 pts (docstrings, naming)",
            "edge_cases": "0-10 pts (boundary, null, special chars)",
            "mock_usage": "0-10 pts (correct mock, reset calls)",
            "target_function": "0-10 pts (calls entry point)",
        },
    }

    output_path = results_path.with_name(
        results_path.stem + "_judged_quality" + results_path.suffix
    )
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"    Saved: {output_path}")

    return {"summaries": all_summaries, "output_path": str(output_path)}


def find_unjudged_files(base_path: Path) -> List[Path]:
    """Find result files without _judged_quality counterpart."""
    if base_path.is_file():
        return [base_path]

    all_files = sorted(base_path.rglob("baseline_results_*.json"))
    unjudged = []
    for f in all_files:
        if "_judged" in f.stem:
            continue
        judged_path = f.with_name(f.stem + "_judged_quality" + f.suffix)
        if not judged_path.exists():
            unjudged.append(f)
    return unjudged


def print_summary_table(summaries: List[Dict]):
    """Print formatted cross-model/variant comparison."""
    print(f"\n{'='*90}")
    print("Test Quality Judge Results (Claude /judge-quality)")
    print(f"{'='*90}")
    print(f"{'Variant':<50} {'Quality':<12} {'Judged':<12} {'Top Issue':<30}")
    print(f"{'-'*90}")

    for s in summaries:
        qual = f"{s['avg_test_quality']:.1%}"
        judged = f"{s['samples_judged']}/{s['samples_total']}"
        top_issue = s["top_issues"][0][0][:28] if s["top_issues"] else "—"
        print(f"{s['model_name']:<50} {qual:<12} {judged:<12} {top_issue:<30}")

    print(f"{'='*90}")


def main():
    parser = argparse.ArgumentParser(
        description="Test Quality Judge for SecMutBench (/judge-quality skill)",
    )
    parser.add_argument("input", help="Results file or directory")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-CWE and issue breakdown")
    parser.add_argument("--force", action="store_true",
                        help="Re-judge already judged files")

    args = parser.parse_args()
    input_path = Path(args.input)

    if not input_path.exists():
        print(f"Error: {input_path} does not exist")
        sys.exit(1)

    if args.force:
        if input_path.is_file():
            files = [input_path]
        else:
            files = sorted(f for f in input_path.rglob("baseline_results_*.json")
                           if "_judged" not in f.stem)
    else:
        files = find_unjudged_files(input_path)

    if not files:
        print("No unjudged results files found.")
        sys.exit(0)

    print(f"Found {len(files)} file(s) to judge")
    print(f"Judge: Claude /judge-quality (AST-based quality analysis)")

    all_summaries = []
    for i, f in enumerate(files, 1):
        print(f"\n{'='*60}")
        print(f"[{i}/{len(files)}] {f}")
        print(f"{'='*60}")
        result = judge_results_file(f, verbose=args.verbose)
        all_summaries.extend(result["summaries"])

    if all_summaries:
        print_summary_table(all_summaries)


if __name__ == "__main__":
    main()
