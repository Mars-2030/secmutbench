#!/usr/bin/env python3
"""
Claude Code LLM-as-Judge for SecMutBench

Judges security relevance and test quality of LLM-generated security tests
using programmatic analysis that encodes Claude's security reasoning.

Three judgment dimensions (matching /judge, /judge-security, /judge-quality):
1. Security Relevance: CWE-specific attack patterns, mock usage, security assertions
2. Test Quality: Assertion specificity, edge cases, best practices, anti-patterns
3. Composite: Weighted combination (60% security, 40% quality)

Usage:
    python baselines/run_judge_claude.py results/          # Judge all unjudged files
    python baselines/run_judge_claude.py results/gpt-oss-120b/baseline_results_*.json
"""

import json
import re
import sys
import argparse
from collections import Counter
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# =============================================================================
# CWE-Specific Mock & Attack Pattern Registry
# =============================================================================

# Which mock objects should be used for each CWE
CWE_EXPECTED_MOCKS = {
    "CWE-89":  {"db": ["last_params", "last_query"]},
    "CWE-78":  {"subprocess": ["injection_detected", "last_shell", "dangerous_command_detected"]},
    "CWE-22":  {"fs": ["last_path"]},
    "CWE-327": {"hashlib": ["weak_algorithm_used", "last_algorithm", "strong_algorithm_used"]},
    "CWE-328": {"hashlib": ["weak_algorithm_used", "last_algorithm"]},
    "CWE-502": {"pickle": ["unsafe_load_called"], "yaml": ["unsafe_load_called", "safe_loader_used"]},
    "CWE-918": {"requests": ["ssrf_attempted", "last_url"]},
    "CWE-611": {"xml_parser": ["external_entities_resolved"]},
    "CWE-798": {"env": ["access_log", "sensitive_accessed"], "mysql": ["last_password"]},
    "CWE-94":  {"mock_eval": ["unsafe_eval_called", "injection_detected"]},
    "CWE-95":  {"mock_eval": ["unsafe_eval_called", "unsafe_exec_called"]},
    "CWE-338": {"mock_random": ["weak_prng_used", "secure_prng_used"], "secrets": []},
    "CWE-287": {"auth": ["auth_attempts", "failed_attempts"]},
    "CWE-306": {"auth": ["auth_attempts"], "request": ["is_authenticated"]},
    "CWE-295": {"requests": ["last_kwargs"]},  # verify=False detection
    "CWE-319": {"requests": ["last_url"]},  # http vs https
    "CWE-79":  {},  # html.escape output checking
    "CWE-20":  {},  # ValueError/input validation
    "CWE-117": {},  # log injection - newline detection
    "CWE-209": {},  # error message exposure
    "CWE-400": {},  # resource exhaustion / regex DoS
    "CWE-434": {},  # file upload validation
    "CWE-601": {},  # open redirect URL validation
    "CWE-639": {},  # IDOR
    "CWE-643": {},  # LDAP/XPath injection
    "CWE-732": {},  # file permissions
    "CWE-862": {},  # missing authorization
    "CWE-863": {},  # incorrect authorization
    "CWE-915": {},  # mass assignment
    "CWE-352": {},  # CSRF
    "CWE-326": {},  # weak key size
    "CWE-347": {"jwt": ["decode_called", "verify_signature"]},
    "CWE-74":  {},  # injection
}

# CWE-specific attack payload patterns that indicate security awareness
CWE_ATTACK_PATTERNS = {
    "CWE-89":  [r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1", r"UNION\s+SELECT", r"DROP\s+TABLE",
                 r";\s*--", r"admin'", r"SELECT\s+\*\s+FROM"],
    "CWE-78":  [r";\s*(cat|ls|rm|wget|curl|nc|whoami)", r"\|\s*(cat|nc)", r"\$\(",
                 r"`[^`]+`", r"&&\s*(cat|rm)", r"/etc/passwd"],
    "CWE-22":  [r"\.\./", r"\.\.\\/", r"/etc/passwd", r"%2e%2e", r"\.\.%c0%af"],
    "CWE-79":  [r"<script>", r"onerror\s*=", r"onload\s*=", r"javascript:", r"alert\("],
    "CWE-502": [r"pickle", r"yaml\.load", r"unsafe_load", r"marshal", r"eval\("],
    "CWE-918": [r"127\.0\.0\.1", r"localhost", r"169\.254\.169\.254", r"192\.168\.",
                 r"10\.\d", r"metadata"],
    "CWE-611": [r"<!ENTITY", r"<!DOCTYPE", r"SYSTEM", r"file://", r"xxe"],
    "CWE-798": [r"password", r"admin123", r"hardcoded", r"secret", r"api_key",
                 r"os\.environ", r"env\.get"],
    "CWE-327": [r"md5", r"sha1", r"weak.*algorithm", r"sha256", r"sha512", r"bcrypt"],
    "CWE-328": [r"md5", r"sha1", r"weak", r"sha256"],
    "CWE-338": [r"random\.", r"secrets\.", r"token_urlsafe", r"urandom", r"seed\("],
    "CWE-94":  [r"eval\(", r"exec\(", r"__import__", r"os\.system", r"compile\("],
    "CWE-95":  [r"eval\(", r"exec\(", r"literal_eval", r"ast\.parse"],
    "CWE-117": [r"\\n", r"\\r", r"newline", r"log.*inject", r"\\x0a"],
    "CWE-209": [r"traceback", r"stack.*trace", r"error.*detail", r"debug", r"internal"],
    "CWE-295": [r"verify\s*=\s*False", r"verify\s*=\s*True", r"certificate", r"ssl"],
    "CWE-319": [r"https?://", r"http://", r"verify", r"encrypt"],
    "CWE-20":  [r"ValueError", r"validation", r"sanitiz", r"invalid", r"malicious"],
    "CWE-400": [r"size.*limit", r"max.*size", r"too.*large", r"timeout", r"resource"],
    "CWE-434": [r"\.exe", r"\.php", r"extension", r"mime", r"file.*type", r"upload"],
    "CWE-601": [r"redirect", r"evil\.com", r"attacker", r"://", r"netloc"],
    "CWE-639": [r"user_id", r"current_user", r"PermissionError", r"unauthorized", r"other.*user"],
    "CWE-643": [r"xpath", r"ldap", r"injection", r"f['\"]", r"format\("],
    "CWE-732": [r"0o777", r"0o666", r"0o644", r"0o600", r"chmod", r"permission"],
    "CWE-862": [r"PermissionError", r"authorization", r"admin", r"role", r"is_admin"],
    "CWE-863": [r"PermissionError", r"role", r"privilege", r"escalat"],
    "CWE-915": [r"mass.*assign", r"__dict__", r"is_admin", r"role", r"allowed_fields"],
    "CWE-352": [r"csrf", r"token", r"cross.*site", r"request.*forgery"],
    "CWE-306": [r"authenticat", r"login", r"session", r"PermissionError", r"is_authenticated"],
    "CWE-287": [r"authenticat", r"password", r"credential", r"verify", r"token"],
    "CWE-326": [r"key.*size", r"2048", r"512", r"1024", r"RSA", r"generate"],
    "CWE-347": [r"jwt", r"signature", r"decode", r"verify", r"algorithm", r"none"],
    "CWE-74":  [r"inject", r"sanitiz", r"escape", r"special.*char"],
}

# Security-specific assertion keywords (indicates genuine security testing)
SECURITY_ASSERTION_KEYWORDS = [
    "injection", "inject", "vulnerable", "vuln", "exploit",
    "malicious", "attack", "payload", "unsafe", "insecure",
    "security", "sanitiz", "escape", "xss", "sqli", "ssrf",
    "traversal", "bypass", "unauthorized", "permission", "auth",
    "hardcoded", "weak", "sensitive", "leak", "expos",
    "parameterized", "shell", "eval", "pickle", "deserializ",
    "csrf", "redirect", "certificate", "encrypt", "hash",
    "random", "secret", "token", "credential",
]

# Anti-patterns that reduce test quality
TEST_ANTI_PATTERNS = [
    (r"assert\s+True\b", "assert True"),
    (r"assert\s+False\b", "assert False (may be intentional)"),
    (r"assert\s+result\s+is\s+not\s+None\b", "weak assertion (not None)"),
    (r"assert\s+len\(result\)\s*>\s*0", "weak assertion (len > 0)"),
    (r"assert\s+result\b\s*$", "bare assert on result"),
    (r"pass\s*$", "empty test body"),
    (r"assert\s+1\s*==\s*1", "tautological assertion"),
]


# =============================================================================
# Judging Functions
# =============================================================================

def judge_security_relevance(
    generated_tests: str,
    cwe: str,
    secure_code: str,
    entry_point: str = "",
) -> Dict[str, Any]:
    """
    Judge security relevance of generated tests.

    Analyzes:
    1. CWE-specific attack vector usage
    2. Mock object usage (correct mocks for the CWE)
    3. Security-specific assertions
    4. Overall security awareness
    """
    if not generated_tests or not generated_tests.strip():
        return {
            "score": 0.0,
            "cwe_addressed": False,
            "attack_vectors_tested": [],
            "security_properties_checked": [],
            "reasoning": "No tests generated",
            "confidence": 1.0,
        }

    tests_lower = generated_tests.lower()
    score = 0.0
    reasoning_parts = []
    attack_vectors = []
    security_props = []

    # --- 1. CWE-specific attack patterns (0-35 points) ---
    patterns = CWE_ATTACK_PATTERNS.get(cwe, [])
    pattern_hits = 0
    for pat in patterns:
        if re.search(pat, generated_tests, re.IGNORECASE):
            pattern_hits += 1
    if patterns:
        pattern_ratio = pattern_hits / len(patterns)
        pattern_score = min(35, pattern_ratio * 50)  # up to 35
        score += pattern_score
        if pattern_hits >= 3:
            reasoning_parts.append(f"Strong attack coverage ({pattern_hits} vectors)")
            attack_vectors = [p for p in patterns[:pattern_hits]]
        elif pattern_hits >= 1:
            reasoning_parts.append(f"Some attack vectors ({pattern_hits})")
        else:
            reasoning_parts.append("No CWE-specific attack patterns")
    else:
        # Unknown CWE — check for generic security patterns
        generic_hits = sum(1 for kw in SECURITY_ASSERTION_KEYWORDS
                          if kw in tests_lower)
        score += min(20, generic_hits * 3)
        if generic_hits >= 3:
            reasoning_parts.append(f"Generic security keywords ({generic_hits})")

    # --- 2. Mock usage (0-25 points) ---
    expected_mocks = CWE_EXPECTED_MOCKS.get(cwe, {})
    if expected_mocks:
        mock_hits = 0
        mock_total = 0
        for mock_name, attrs in expected_mocks.items():
            mock_total += 1
            if mock_name in generated_tests:
                mock_hits += 1
                for attr in attrs:
                    if attr in generated_tests:
                        security_props.append(f"{mock_name}.{attr}")
        if mock_total > 0:
            mock_ratio = mock_hits / mock_total
            mock_score = mock_ratio * 25
            score += mock_score
            if mock_hits > 0:
                reasoning_parts.append(f"Uses {mock_hits}/{mock_total} mocks")
            else:
                reasoning_parts.append("No expected mock objects used")
    else:
        # No mocks expected — check for source inspection or exception testing
        if "inspect.getsource" in generated_tests or "inspect.getmodule" in generated_tests:
            score += 20
            security_props.append("source_inspection")
            reasoning_parts.append("Uses source inspection")
        elif "pytest.raises" in generated_tests or "raises(" in generated_tests:
            score += 15
            security_props.append("exception_testing")
            reasoning_parts.append("Tests exception behavior")
        elif "ValueError" in generated_tests or "PermissionError" in generated_tests:
            score += 12
            security_props.append("error_checking")
            reasoning_parts.append("Checks for security exceptions")
        else:
            score += 5
            reasoning_parts.append("No mock or exception testing")

    # --- 3. Security-specific assertions (0-25 points) ---
    assertion_lines = [line.strip() for line in generated_tests.split("\n")
                       if line.strip().startswith("assert ") or "pytest.fail" in line]
    security_assertions = 0
    for line in assertion_lines:
        line_lower = line.lower()
        if any(kw in line_lower for kw in SECURITY_ASSERTION_KEYWORDS):
            security_assertions += 1

    if assertion_lines:
        sec_ratio = security_assertions / len(assertion_lines)
        assertion_score = min(25, sec_ratio * 35)
        score += assertion_score
        if security_assertions >= 2:
            reasoning_parts.append(f"Strong security assertions ({security_assertions})")
        elif security_assertions >= 1:
            reasoning_parts.append(f"Some security assertions ({security_assertions})")
        else:
            reasoning_parts.append("Assertions lack security keywords")
    else:
        reasoning_parts.append("No assertions found")

    # --- 4. CWE addressed check (0-15 points) ---
    cwe_num = cwe.replace("CWE-", "")
    cwe_addressed = (
        cwe in generated_tests or
        cwe_num in generated_tests or
        pattern_hits >= 1 or
        len(security_props) >= 1
    )
    if cwe_addressed:
        score += 15
    else:
        reasoning_parts.append("CWE not directly addressed")

    # --- Anti-pattern deductions ---
    anti_hits = 0
    for pat, name in TEST_ANTI_PATTERNS:
        matches = re.findall(pat, generated_tests, re.MULTILINE)
        if matches:
            anti_hits += len(matches)
            reasoning_parts.append(f"{name} (x{len(matches)})")
    score = max(0, score - anti_hits * 3)

    # Normalize to 0-1
    score = min(1.0, max(0.0, score / 100))

    # Confidence based on how much evidence we have
    confidence = min(1.0, 0.5 + len(reasoning_parts) * 0.05 + len(security_props) * 0.1)

    return {
        "score": round(score, 2),
        "cwe_addressed": cwe_addressed,
        "attack_vectors_tested": attack_vectors[:5],
        "security_properties_checked": security_props[:5],
        "reasoning": "; ".join(reasoning_parts),
        "confidence": round(confidence, 2),
    }


def judge_test_quality(
    generated_tests: str,
    entry_point: str = "",
    cwe: str = "",
    difficulty: str = "",
) -> Dict[str, Any]:
    """
    Judge test quality.

    Analyzes:
    1. Assertion count and specificity
    2. Edge case coverage
    3. Best practices (naming, structure, documentation)
    4. Anti-patterns
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

    lines = generated_tests.split("\n")
    test_funcs = re.findall(r"def\s+(test_\w+)", generated_tests)
    assertion_lines = [l.strip() for l in lines
                       if re.match(r"\s*(assert\s|pytest\.fail|pytest\.raises)", l.strip())]
    issues = []
    reasoning_parts = []
    score = 0.0

    # --- 1. Assertion count and specificity (0-30 points) ---
    n_assertions = len(assertion_lines)
    if n_assertions >= 6:
        score += 25
        reasoning_parts.append(f"Good assertion count ({n_assertions})")
    elif n_assertions >= 3:
        score += 18
        reasoning_parts.append(f"Adequate assertions ({n_assertions})")
    elif n_assertions >= 1:
        score += 10
        reasoning_parts.append(f"Few assertions ({n_assertions})")
    else:
        issues.append("No assertions")
        reasoning_parts.append("No assertions")

    # Assertion messages (descriptive = better)
    assertions_with_msg = sum(1 for a in assertion_lines
                              if ',' in a and ('"' in a or "'" in a))
    if n_assertions > 0 and assertions_with_msg / n_assertions >= 0.5:
        score += 5
        reasoning_parts.append("Descriptive assertion messages")

    # --- 2. Test count and variety (0-15 points) ---
    n_tests = len(test_funcs)
    if n_tests >= 4:
        score += 15
        reasoning_parts.append(f"Good test count ({n_tests})")
    elif n_tests >= 2:
        score += 10
        reasoning_parts.append(f"Some tests ({n_tests})")
    elif n_tests >= 1:
        score += 5
    else:
        issues.append("No test functions found")

    # --- 3. Edge cases (0-15 points) ---
    edge_cases = 0
    edge_patterns = [
        (r'""', "empty string"),
        (r"None\b", "None input"),
        (r"\b0\b", "zero"),
        (r"-\d+", "negative number"),
        (r"boundary|edge|limit|overflow|max|min", "boundary"),
        (r"special.*char|[<>&\"']", "special characters"),
        (r"long|huge|large|overflow|\*\s*\d{3,}", "large input"),
        (r"empty|blank|whitespace", "empty/blank"),
    ]
    for pat, name in edge_patterns:
        if re.search(pat, generated_tests, re.IGNORECASE):
            edge_cases += 1
    if edge_cases >= 3:
        score += 15
        reasoning_parts.append(f"Good edge case coverage ({edge_cases})")
    elif edge_cases >= 1:
        score += 8
        reasoning_parts.append(f"Some edge cases ({edge_cases})")
    else:
        reasoning_parts.append("No edge cases")

    # --- 4. Best practices (0-20 points) ---
    bp_score = 0

    # Descriptive test names
    descriptive_names = sum(1 for t in test_funcs if len(t) > 15)
    if descriptive_names >= n_tests * 0.5 and n_tests > 0:
        bp_score += 5
        reasoning_parts.append("Descriptive names")

    # reset() calls (proper test isolation)
    if ".reset()" in generated_tests:
        bp_score += 5
        reasoning_parts.append("Mock reset (isolation)")

    # Docstrings or comments
    if '"""' in generated_tests or "'''" in generated_tests or "# " in generated_tests:
        bp_score += 5
        reasoning_parts.append("Good documentation")

    # pytest.raises usage
    if "pytest.raises" in generated_tests:
        bp_score += 5
        reasoning_parts.append("Uses pytest.raises")

    score += bp_score
    follows_bp = bp_score >= 10

    # --- 5. Anti-patterns (deductions) ---
    for pat, name in TEST_ANTI_PATTERNS:
        matches = re.findall(pat, generated_tests, re.MULTILINE)
        if matches:
            count = len(matches)
            issues.append(f"{name} (x{count})")
            score -= count * 2

    # Syntax issues
    if "import " in generated_tests:
        # Check for problematic imports
        bad_imports = re.findall(r"import\s+(subprocess|os|socket|http|urllib)", generated_tests)
        if bad_imports:
            issues.append(f"Imports real modules: {', '.join(bad_imports)}")
            score -= len(bad_imports) * 2

    # Class definitions (not allowed)
    if re.search(r"^class\s+\w+", generated_tests, re.MULTILINE):
        issues.append("Contains class definition")
        score -= 5

    # --- 6. Code structure (0-5 points) ---
    # Well-structured = multiple test functions with clear separation
    if n_tests >= 3 and n_assertions >= n_tests:
        score += 5
        reasoning_parts.append("Well-structured")

    # Normalize
    score = min(1.0, max(0.0, score / 100))

    confidence = min(1.0, 0.6 + n_tests * 0.05 + n_assertions * 0.02)

    return {
        "score": round(score, 2),
        "assertions_count": n_assertions,
        "edge_cases_covered": edge_cases,
        "follows_best_practices": follows_bp,
        "issues_found": issues[:5],
        "reasoning": "; ".join(reasoning_parts),
        "confidence": round(confidence, 2),
    }


# =============================================================================
# File Processing
# =============================================================================

def judge_results_file(
    results_path: Path,
    output_suffix: str = "_judged_claude",
    verbose: bool = False,
) -> Dict[str, Any]:
    """Judge all samples in a results file."""
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

        sec_scores = []
        qual_scores = []
        composite_scores = []
        judged = 0

        for i, r in enumerate(detailed, 1):
            tests = r.get("generated_tests", "")
            if not tests or not tests.strip():
                continue

            cwe = r.get("cwe", "")
            secure_code = r.get("secure_code", "")
            entry_point = r.get("entry_point", "")
            difficulty = r.get("difficulty", "")

            # Security relevance
            sec = judge_security_relevance(tests, cwe, secure_code, entry_point)
            sec_scores.append(sec["score"])

            # Test quality
            qual = judge_test_quality(tests, entry_point, cwe, difficulty)
            qual_scores.append(qual["score"])

            # Composite (60% security, 40% quality)
            comp = sec["score"] * 0.6 + qual["score"] * 0.4
            composite_scores.append(comp)

            # Store in detailed results
            r["judge"] = {
                "model": "claude",
                "security_relevance": sec,
                "test_quality": qual,
                "composite": round(comp, 3),
            }

            # Also store separate fields for compatibility
            r["judge_security"] = {
                "model": "claude",
                "score": sec["score"],
                "cwe_addressed": sec["cwe_addressed"],
                "attack_vectors_tested": sec["attack_vectors_tested"],
                "security_properties_checked": sec["security_properties_checked"],
                "reasoning": sec["reasoning"],
                "confidence": sec["confidence"],
            }
            r["judge_quality"] = {
                "model": "claude",
                "score": qual["score"],
                "assertions_count": qual["assertions_count"],
                "edge_cases_covered": qual["edge_cases_covered"],
                "follows_best_practices": qual["follows_best_practices"],
                "issues_found": qual["issues_found"],
                "reasoning": qual["reasoning"],
                "confidence": qual["confidence"],
            }

            judged += 1

            if verbose and i % 50 == 0:
                print(f"    [{i}/{len(detailed)}] Sec: {sec['score']:.0%}  "
                      f"Qual: {qual['score']:.0%}  Comp: {comp:.0%}")

        # Compute averages
        def safe_mean(lst):
            return sum(lst) / len(lst) if lst else 0.0

        avg_sec = safe_mean(sec_scores)
        avg_qual = safe_mean(qual_scores)
        avg_comp = safe_mean(composite_scores)

        model_data["avg_security_relevance"] = round(avg_sec, 4)
        model_data["avg_test_quality"] = round(avg_qual, 4)
        model_data["avg_composite_score"] = round(avg_comp, 4)

        summary = {
            "model_name": model_name,
            "samples_judged": judged,
            "samples_total": len(detailed),
            "avg_security_relevance": avg_sec,
            "avg_test_quality": avg_qual,
            "avg_composite": avg_comp,
        }
        all_summaries.append(summary)

        print(f"    Judged {judged}/{len(detailed)} samples")
        print(f"    Avg Sec: {avg_sec:.1%}  Qual: {avg_qual:.1%}  Comp: {avg_comp:.1%}")

    # Add metadata
    data["judge_metadata"] = {
        "judge_model": "claude-code",
        "judge_method": "programmatic_analysis",
        "judged_at": datetime.now().isoformat(),
        "dimensions": ["security_relevance", "test_quality", "composite"],
        "composite_weights": {"security_relevance": 0.6, "test_quality": 0.4},
    }

    # Save
    output_path = results_path.with_name(
        results_path.stem + output_suffix + results_path.suffix
    )
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"    Saved: {output_path}")

    return {"summaries": all_summaries, "output_path": str(output_path)}


def find_unjudged_files(base_path: Path) -> List[Path]:
    """Find result files without _judged_claude counterpart."""
    if base_path.is_file():
        return [base_path]

    all_files = sorted(base_path.rglob("baseline_results_*.json"))
    unjudged = []
    for f in all_files:
        if "_judged" in f.stem:
            continue
        judged_path = f.with_name(f.stem + "_judged_claude" + f.suffix)
        if not judged_path.exists():
            unjudged.append(f)
    return unjudged


def print_summary_table(summaries: List[Dict]):
    """Print formatted cross-model/variant comparison."""
    print(f"\n{'='*90}")
    print("Claude Code LLM-as-Judge Results")
    print(f"{'='*90}")
    print(f"{'Variant':<45} {'Sec Rel':<10} {'Quality':<10} {'Composite':<10} {'Judged':<10}")
    print(f"{'-'*90}")

    for s in summaries:
        sec = f"{s['avg_security_relevance']:.1%}"
        qual = f"{s['avg_test_quality']:.1%}"
        comp = f"{s['avg_composite']:.1%}"
        judged = f"{s['samples_judged']}/{s['samples_total']}"
        print(f"{s['model_name']:<45} {sec:<10} {qual:<10} {comp:<10} {judged:<10}")

    print(f"{'='*90}")


def main():
    parser = argparse.ArgumentParser(
        description="Claude Code LLM-as-Judge for SecMutBench",
    )
    parser.add_argument("input", help="Results file or directory")
    parser.add_argument("--verbose", action="store_true", help="Print per-sample progress")
    parser.add_argument("--force", action="store_true", help="Re-judge already judged files")

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
