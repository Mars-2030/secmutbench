"""
Main Evaluation Script for SecMutBench

Evaluates LLM-generated security tests using mutation testing.
Supports multi-modal evaluation with LLM-as-judge metrics.
"""

import json
import argparse
import re
import time
from typing import Dict, List, Any, Optional
from pathlib import Path
from dataclasses import dataclass, asdict

# Import evaluation modules - works when package is installed via pip install -e .
try:
    from evaluation.mutation_engine import MutationEngine, generate_mutants
    from evaluation.test_runner import TestRunner, run_tests, check_vulnerability_detection
    from evaluation.metrics import (
        calculate_mutation_score,
        calculate_metrics,
        aggregate_by_cwe,
        aggregate_by_difficulty,
        aggregate_by_operator,
        analyze_survival_patterns,
        format_metrics_report,
        calculate_kill_breakdown,
        calculate_security_precision,
    )
    from evaluation.llm_judge import (
        MultiModalEvaluator,
        MultiModalEvaluation,
        create_evaluator,
        format_multimodal_report,
    )
    from evaluation.version import get_version_info, __version__
    from evaluation.prompts import format_test_generation_prompt
except ImportError:
    # Fallback for running scripts directly without package installation
    import os
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    from evaluation.mutation_engine import MutationEngine, generate_mutants
    from evaluation.test_runner import TestRunner, run_tests, check_vulnerability_detection
    from evaluation.metrics import (
        calculate_mutation_score,
        calculate_metrics,
        aggregate_by_cwe,
        aggregate_by_difficulty,
        aggregate_by_operator,
        analyze_survival_patterns,
        format_metrics_report,
        calculate_kill_breakdown,
        calculate_security_precision,
    )
    from evaluation.llm_judge import (
        MultiModalEvaluator,
        MultiModalEvaluation,
        create_evaluator,
        format_multimodal_report,
    )
    from evaluation.version import get_version_info, __version__
    from evaluation.prompts import format_test_generation_prompt


# =============================================================================
# Kill Classification — Operator-Aware
# =============================================================================

# Operator-specific security patterns for accurate kill classification
# Each operator maps to keywords that indicate genuine security awareness
OPERATOR_SECURITY_PATTERNS = {
    # CWE-89: SQL Injection
    "PSQLI": [
        "parameterized", "prepared", "placeholder", "bind",
        "sql", "quer", "inject", "sqli",
        "last_params", "string.*concat", "interpolat",
        "execute", "cursor", "database",
    ],
    # CWE-78: Command Injection
    "CMDINJECT": [
        "shell", "command", "inject", "subprocess",
        "exec", "last_shell", "injection_detected",
        "shlex", "sanitize.*command", "popen",
        "os.system", "pipe", "backtick",
    ],
    # CWE-22: Path Traversal
    "PATHCONCAT": [
        "traversal", r"\.\./", r"\.\.\\\\", "path",
        "base_dir", "realpath", "abspath", "normalize",
        "directory", "file.*access", "startswith",
        "parent", "escape.*dir",
    ],
    # CWE-327/328: Weak Cryptography
    "WEAKCRYPTO": [
        "md5", "sha1", "weak.*algorithm", "hash",
        "encrypt", "bcrypt", "salt", "iteration",
        "weak_algorithm_used", "last_algorithm",
        "crypto", "digest", "pbkdf",
    ],
    # CWE-502: Insecure Deserialization
    "DESERIAL": [
        "pickle", "deserial", "yaml", "safe_load",
        "literal_eval", "unsafe_load", "safeloader",
        "marshal", "shelve", "unpickle",
    ],
    # CWE-918: SSRF
    "SSRF": [
        "ssrf", "internal.*url", "localhost", "127.0.0.1",
        "169.254", "metadata", "ssrf_attempted",
        "url.*valid", "scheme", "private.*ip",
        "blocked.*host", "allowlist",
    ],
    # CWE-611: XXE
    "XXE": [
        "xxe", "external.*entit", "xml.*parse",
        "doctype", "entity", "dtd",
        "external_entities_resolved", "defused",
    ],
    # CWE-798: Hardcoded Credentials
    "HARDCODE": [
        "hardcoded", "credential", "password", "secret",
        "api_key", "token", "environ", "env.*var",
        "access_log", "sensitive_accessed",
        "getenv", "was_accessed",
    ],
    # CWE-79: XSS / Input Validation
    "RVALID": [
        "xss", "script", "escape", "sanitize",
        "html.*escape", "encode", "cross.*site",
        "injection", "markup", "bleach",
    ],
    # CWE-20: Input Validation
    "INPUTVAL": [
        "validate", "sanitize", "filter", "whitelist",
        "blacklist", "allow", "deny", "regex",
        "clean", "input.*check", "boundary",
        "range", "type.*error", "invalid",
    ],
    # CWE-20: Subdomain Spoofing
    "SUBDOMAIN_SPOOF": [
        "subdomain", "domain", "host", "url",
        "spoof", "endswith", "startswith",
        "validate.*url", "allow.*domain",
    ],
    # CWE-1004: HttpOnly Cookie
    "RHTTPO": [
        "httponly", "cookie", "secure.*flag",
        "session", "xss", "javascript",
    ],
    # CWE-287/306: Auth Removal
    "RMAUTH": [
        "auth", "login", "session", "permission",
        "access.*control", "is_authenticated",
        "credential", "token.*valid", "bypass",
        "unauthorized", "decorator",
    ],
    # CWE-319/311: Encryption Removal
    "RENCRYPT": [
        "encrypt", "decrypt", "cipher", "aes",
        "rsa", "key", "plaintext", "ssl",
        "tls", "https", "verify",
    ],
    # CWE-639/284: IDOR
    "IDOR": [
        "auth", "owner", "permission", "access",
        "user_id", "session", "unauthorized",
        "belongs.*to", "ownership", "forbidden",
    ],
    # CWE-1336/94: SSTI
    "SSTI": [
        "template", "render", "jinja", "inject",
        "expression", "sandbox", "autoescape",
    ],
    # CWE-942/346: Weak CORS
    "CORS_WEAK": [
        "cors", "origin", "access-control", "cross.*origin",
        "wildcard", "header", "credential",
    ],
    # CWE-352: CSRF
    "CSRF_REMOVE": [
        "csrf", "token", "cross.*site.*request",
        "forgery", "session", "csrftoken",
    ],
    # CWE-338/330/331: Weak Random
    "WEAKRANDOM": [
        "random", "seed", "urandom", "secrets",
        "cryptographic", "predictable", "entropy",
        "prng", "secure.*random",
    ],
    # === New operators added in v2.5.0 ===
    # CWE-95: Code Injection via eval
    "EVALINJECT": [
        "eval", "exec", "compile", "code.*inject",
        "literal_eval", "ast", "safe_eval",
        "unsafe_eval_called", "injection_detected",
        "__import__", "builtins",
    ],
    # CWE-601: Open Redirect
    "OPENREDIRECT": [
        "redirect", "url", "location", "302",
        "next", "return_url", "continue",
        "domain", "host", "validate.*url",
        "same_origin", "allowed_hosts",
    ],
    # CWE-295: Certificate Validation
    "NOCERTVALID": [
        "verify", "certificate", "ssl", "tls",
        "cert_none", "check_hostname", "insecure",
        "unverified", "https", "trust",
    ],
    # CWE-209: Information Exposure
    "INFOEXPOSE": [
        "traceback", "stack", "error", "debug",
        "exception", "sensitive", "expose",
        "message", "detail", "verbose",
    ],
    # CWE-400/1333: ReDoS
    "REGEXDOS": [
        "regex", "pattern", "timeout", "backtrack",
        "catastrophic", "redos", "quantifier",
        "re.match", "re.search", "compile",
    ],
    # CWE-862: Missing Authorization
    "MISSINGAUTH": [
        "authori", "permission", "access.*control",
        "role", "privilege", "admin", "owner",
        "forbidden", "403", "acl",
    ],
    # CWE-778: Insufficient Logging
    "INSUFFLOG": [
        "log", "audit", "monitor", "track",
        "record", "security.*event", "alert",
    ],
    # CWE-352: CSRF (already exists as CSRF_REMOVE, adding alias patterns)
    "CSRF": [
        "csrf", "token", "cross.*site.*request",
        "forgery", "session", "csrftoken",
        "x-csrf", "validate.*token",
    ],
}

# Fallback patterns for operators not in the dict or when operator is unknown
GENERIC_SECURITY_PATTERNS = [
    "inject", "malicious", "attack", "vulnerability",
    "secure", "unsafe", "dangerous", "tainted",
    "exploit", "bypass", "unauthorized",
]


# =============================================================================
# Layer 1.5: Operator-to-Mock Mapping for Observability-Based Classification
# =============================================================================
# Maps each operator to the mock objects and security-relevant attributes
# that would indicate genuine security awareness if accessed during a test

OPERATOR_MOCK_MAPPING = {
    # CWE-89: SQL Injection
    # MockDatabase.SECURITY_ATTRS = {"last_query", "last_params", "query_count"}
    "PSQLI": {"db": {"last_query", "last_params", "query_count"}},

    # CWE-78: Command Injection
    # MockSubprocess.SECURITY_ATTRS = {"last_shell", "last_command", "injection_detected", "dangerous_command_detected"}
    "CMDINJECT": {"subprocess": {"last_shell", "last_command", "injection_detected", "dangerous_command_detected"}},

    # CWE-22: Path Traversal
    # MockFileSystem.SECURITY_ATTRS = {"last_path", "base_dir"}
    "PATHCONCAT": {"fs": {"last_path", "base_dir"}},

    # CWE-327/328: Weak Cryptography
    # MockCrypto.SECURITY_ATTRS = {"last_algorithm", "weak_algorithm_used", "strong_algorithm_used", "algorithms_used"}
    "WEAKCRYPTO": {"crypto": {"last_algorithm", "weak_algorithm_used", "strong_algorithm_used", "algorithms_used"}},

    # CWE-502: Insecure Deserialization
    # MockPickle.SECURITY_ATTRS = {"unsafe_load_called", "last_data", "load_count"}
    # MockYAML.SECURITY_ATTRS = {"unsafe_load_called", "safe_loader_used", "last_data", "load_count"}
    "DESERIAL": {
        "pickle": {"last_data", "unsafe_load_called", "load_count"},
        "yaml": {"last_data", "unsafe_load_called", "safe_loader_used", "load_count"},
    },

    # CWE-918: SSRF
    # MockHTTPClient.SECURITY_ATTRS = {"last_url", "ssrf_attempted", "last_method"}
    "SSRF": {"http": {"last_url", "ssrf_attempted", "last_method"}},

    # CWE-611: XXE
    # MockXMLParser.SECURITY_ATTRS = {"last_xml", "external_entities_resolved", "dtd_processed"}
    "XXE": {"xml": {"last_xml", "external_entities_resolved", "dtd_processed"}},

    # CWE-798: Hardcoded Credentials
    # MockEnvironment.SECURITY_ATTRS = {"last_key", "sensitive_accessed", "access_log"}
    "HARDCODE": {"env": {"last_key", "sensitive_accessed", "access_log"}},

    # CWE-287/306: Authentication Removal
    # MockAuthenticator.SECURITY_ATTRS = {"last_username", "last_password", "last_token", "auth_attempts", "failed_attempts"}
    "RMAUTH": {"auth": {"last_username", "last_password", "last_token", "auth_attempts", "failed_attempts"}},

    # CWE-94: Code Injection (SSTI/eval)
    # MockEval.SECURITY_ATTRS = {"last_code", "unsafe_eval_called", "unsafe_exec_called", "injection_detected"}
    "SSTI": {"eval": {"last_code", "unsafe_eval_called", "unsafe_exec_called", "injection_detected"}},
    "EVALINJECT": {"eval": {"last_code", "unsafe_eval_called", "unsafe_exec_called", "injection_detected"}},

    # Operators without dedicated mock state (rely on keyword matching only)
    "RVALID": {},
    "INPUTVAL": {},
    "SUBDOMAIN_SPOOF": {},
    "RHTTPO": {},
    "RENCRYPT": {},
    "IDOR": {},
    "CORS_WEAK": {},
    "CSRF_REMOVE": {},
    "WEAKRANDOM": {},
}


# =============================================================================
# Layer 1.25: Operator-Specific Attack Payloads for Bare Assertion Classification
# =============================================================================
# When a test uses a bare assertion (no descriptive message), pytest shows the
# actual values in the error repr. If the assertion checks for attack payload
# presence/absence in output, the payload appears in the error message.
# This layer catches those cases when Layer 1 keyword matching doesn't fire.
#
# Example: assert "<script>" not in result
# Error:   AssertionError: assert '<script>' not in '<div><script>alert(1)</script></div>'
#          ↑ Contains "<script>" - this is a legitimate XSS check
#
# These payloads are operator-specific to prevent coincidental matches
# (e.g., "<script>" in a CWE-327 crypto test error would be coincidental)

OPERATOR_ATTACK_PAYLOADS = {
    # CWE-79: XSS - Check for script injection in output
    "RVALID": [
        "<script", "</script>", "javascript:", "onerror=", "onload=",
        "onclick=", "onmouseover=", "alert(", "document.cookie",
        "<img src=", "<svg onload",
    ],
    # CWE-22: Path Traversal - Check for directory escape in paths
    "PATHCONCAT": [
        "../", "..\\", "/etc/passwd", "/etc/shadow", "..%2f",
        "%2e%2e/", "....//", "/proc/self",
    ],
    # CWE-89: SQL Injection - Check for SQL attack patterns in queries
    "PSQLI": [
        "' OR '1'='1", "'; DROP", "UNION SELECT", "1=1", "' OR ''='",
        "'; DELETE", "' OR 1=1--", "admin'--",
    ],
    # CWE-78: Command Injection - Check for shell metacharacters
    "CMDINJECT": [
        "; rm", "&& cat", "| ls", "; cat /etc", "$(", "`whoami`",
        "| nc ", "; wget", "&& wget", "; curl",
    ],
    # CWE-918: SSRF - Check for internal/metadata URLs
    "SSRF": [
        "127.0.0.1", "169.254.169.254", "localhost", "0.0.0.0",
        "metadata.google", "169.254.", "[::1]", "file://",
    ],
    # CWE-502: Insecure Deserialization - Check for serialization markers
    "DESERIAL": [
        "__reduce__", "pickle.loads", "yaml.load", "!!python",
        "yaml.unsafe_load", "marshal.loads",
    ],
    # CWE-611: XXE - Check for entity injection
    "XXE": [
        "<!ENTITY", "<!DOCTYPE", "SYSTEM", "file:///",
        "expect://", "php://",
    ],
    # CWE-798: Hardcoded Credentials - Check for credential patterns
    "HARDCODE": [
        "password123", "admin123", "secret123", "api_key=",
        "AWS_SECRET", "PRIVATE_KEY",
    ],
    # CWE-20: Input Validation / Subdomain Spoofing
    "SUBDOMAIN_SPOOF": [
        "attacker.com", "evil.com", ".attacker.", "attack-",
        "@evil", "#evil",
    ],
    "INPUTVAL": [
        "attacker.com", "evil.com", ".attacker.",
    ],
    # CWE-94: Code Injection
    "SSTI": [
        "{{", "}}", "__class__", "__mro__", "__globals__",
        "__builtins__", "config.items",
    ],
    "EVALINJECT": [
        "__import__", "exec(", "eval(", "compile(",
        "os.system", "subprocess",
    ],
}


def classify_kill(error: str, operator: str = None, mock_access: dict = None) -> str:
    """
    Classify the type of kill based on the error message, mutation operator,
    and mock state observability.

    Classification Layers (in order):
    - Layer 0: Crash detection (syntax/import errors)
    - Layer 0.5: Functional detection (pytest.raises failures - "DID NOT RAISE")
    - Layer 1.5: Mock-state observability (if test accessed security-relevant mock attrs)
    - Layer 1: Operator-aware keyword matching (test author described security property)
    - Layer 1.25: Attack payload detection (bare assertion contains attack payload in repr)

    Layer 1 fires before 1.25 because explicit security descriptions are stronger
    evidence of security awareness than payload presence in assertion repr.

    Kill types:
    - semantic: AssertionError with security awareness (via mock, keyword, or payload)
    - functional: Test expected specific exception that wasn't raised (behavioral detection)
    - assertion_incidental: AssertionError without security awareness
    - crash: ImportError, TypeError, NameError, SyntaxError, AttributeError
    - other: Any other exception

    Args:
        error: The error message from the failing test
        operator: The mutation operator that produced this mutant (e.g., "PSQLI")
        mock_access: Dict mapping mock names to list of accessed security attrs

    Returns:
        One of: "semantic", "functional", "assertion_incidental", "crash", "other"
    """
    if not error:
        return "other"

    error_lower = error.lower()

    # --- Layer 0: Crash detection ---
    crash_types = [
        "ImportError", "TypeError", "NameError", "SyntaxError",
        "AttributeError", "IndentationError", "ModuleNotFoundError",
    ]
    if any(ct in error for ct in crash_types):
        return "crash"

    # Also catch syntax-like errors from execution failures
    syntax_indicators = [
        "failed to execute target code",
        "failed to parse test code",
        "unterminated string",
        "f-string:",
        "invalid syntax",
        "unexpected eof",
        "expected ':'",
        "expected ')'",
        "expected '}'",
    ]
    if any(ind in error_lower for ind in syntax_indicators):
        return "crash"

    # --- Layer 0.5: Functional detection (pytest.raises failures) ---
    # "DID NOT RAISE <class 'ValueError'>" indicates test expected an exception
    # that the mutant didn't raise - this is a legitimate behavioral/functional detection
    if "did not raise" in error_lower:
        # Check if the expected exception was security-related
        security_exceptions = ["valueerror", "securityerror", "permissionerror",
                               "invalidinputerror", "validationerror"]
        if any(exc in error_lower for exc in security_exceptions):
            return "functional"
        # Even non-security exceptions are functional detections
        return "functional"

    # --- Assertion classification ---
    if "AssertionError" in error or "Assertion failed" in error:
        # --- Layer 1.5: Mock-state observability check ---
        if mock_access and operator:
            relevant_mocks = OPERATOR_MOCK_MAPPING.get(operator, {})
            for mock_name, required_attrs in relevant_mocks.items():
                accessed = set(mock_access.get(mock_name, []))
                if accessed & required_attrs:  # intersection - any overlap
                    return "semantic"

        # --- Layer 1: Keyword matching ---
        # Get operator-specific patterns
        patterns = OPERATOR_SECURITY_PATTERNS.get(operator, [])

        # Check for operator-relevant security terms first
        for pattern in patterns:
            if re.search(pattern, error_lower):
                return "semantic"

        # Always check generic patterns as fallback (even when operator is known)
        # This catches cases where the error matches a generic security term
        # that isn't in the operator-specific list
        for term in GENERIC_SECURITY_PATTERNS:
            if term in error_lower:
                return "semantic"

        # --- Layer 1.25: Attack payload detection in assertion repr ---
        # When a bare assertion like `assert "<script>" not in result` fails,
        # pytest shows the actual values in the error repr. If the assertion
        # checks for attack payload presence/absence, the payload appears in
        # the error message. This is a legitimate security test, even without
        # an explicit descriptive message.
        #
        # Example error: AssertionError: assert '<script>' not in '<div><script>...'
        #
        # Payloads are operator-specific to prevent coincidental matches.
        if operator:
            payloads = OPERATOR_ATTACK_PAYLOADS.get(operator, [])
            for payload in payloads:
                if payload.lower() in error_lower:
                    return "semantic"

        return "assertion_incidental"

    return "other"


def load_benchmark(
    path: Optional[str] = None,
    difficulty: Optional[str] = None,
    cwe: Optional[str] = None,
) -> List[Dict]:
    """
    Load the benchmark dataset.

    Args:
        path: Path to dataset file (default: data/dataset.json, fallback: data/samples.json)
        difficulty: Filter by difficulty level
        cwe: Filter by CWE type

    Returns:
        List of sample dicts
    """
    if path is None:
        base_dir = Path(__file__).parent.parent
        # Try dataset.json first (new format), then samples.json (legacy)
        dataset_path = base_dir / "data" / "dataset.json"
        samples_path = base_dir / "data" / "samples.json"
        path = dataset_path if dataset_path.exists() else samples_path

    with open(path, "r") as f:
        data = json.load(f)

    # Handle both formats: new format (with metadata/samples) and legacy (list)
    if isinstance(data, dict) and "samples" in data:
        samples = data["samples"]
    elif isinstance(data, list):
        samples = data
    else:
        raise ValueError(f"Unknown dataset format in {path}")

    # Apply filters
    if difficulty:
        samples = [s for s in samples if s.get("difficulty") == difficulty]

    if cwe:
        samples = [s for s in samples if s.get("cwe") == cwe]

    return samples


def evaluate_generated_tests(
    sample: Dict,
    generated_tests: str,
    engine: Optional[MutationEngine] = None,
    runner: Optional[TestRunner] = None,
    max_mutants: int = 10,
) -> Dict[str, Any]:
    """
    Evaluate LLM-generated security tests for a single sample.

    Args:
        sample: Benchmark sample dict
        generated_tests: String of pytest-style tests generated by LLM
        engine: Optional MutationEngine instance
        runner: Optional TestRunner instance
        max_mutants: Maximum number of mutants to generate per sample (default: 10)

    Returns:
        Dictionary of evaluation metrics
    """
    # Get sample-specific operators
    sample_operators = sample.get("mutation_operators", [])

    # Create engine with sample operators if specified, otherwise use passed engine or default
    if sample_operators:
        engine = MutationEngine(sample_operators)
    elif engine is None:
        engine = MutationEngine()

    if runner is None:
        runner = TestRunner()

    result = {
        "sample_id": sample["id"],
        "cwe": sample["cwe"],
        "difficulty": sample.get("difficulty", "unknown"),
        "metrics": {},
        "mutant_details": [],
        "errors": [],
    }

    start_time = time.time()

    # 1. Check if tests compile/parse
    try:
        compile(generated_tests, "<string>", "exec")
    except SyntaxError as e:
        result["errors"].append(f"Test syntax error: {str(e)}")
        result["metrics"]["valid_tests"] = False
        return result

    result["metrics"]["valid_tests"] = True

    # 2. Vulnerability Detection
    # Validate required sample fields exist
    if "secure_code" not in sample:
        result["errors"].append("Sample missing required field: secure_code")
        result["metrics"]["vuln_detected"] = False
        return result
    if "insecure_code" not in sample:
        result["errors"].append("Sample missing required field: insecure_code")
        result["metrics"]["vuln_detected"] = False
        return result

    try:
        secure_result = runner.run_tests(generated_tests, sample["secure_code"])
        insecure_result = runner.run_tests(generated_tests, sample["insecure_code"])

        result["metrics"]["secure_passes"] = secure_result.all_passed
        result["metrics"]["insecure_fails"] = not insecure_result.all_passed
        result["metrics"]["vuln_detected"] = (
            secure_result.all_passed and not insecure_result.all_passed
        )
        result["metrics"]["tests_count"] = secure_result.total
        result["metrics"]["line_coverage"] = secure_result.line_coverage
        result["metrics"]["lines_covered"] = secure_result.lines_covered
        result["metrics"]["lines_total"] = secure_result.lines_total

    except Exception as e:
        result["errors"].append(f"Test execution error: {str(e)}")
        result["metrics"]["vuln_detected"] = False
        result["metrics"]["line_coverage"] = 0.0

    # 3. Mutation Score
    # Set defaults so these fields exist even if mutation generation fails
    result["metrics"]["mutants_total"] = 0
    result["metrics"]["mutants_killed"] = 0

    try:
        # Use pre-generated mutants if available, otherwise generate on-the-fly
        if "mutants" in sample and sample["mutants"]:
            from evaluation.mutation_engine import Mutant
            mutants = [
                Mutant(
                    id=m["id"],
                    original_code=sample["secure_code"],
                    mutated_code=m["mutated_code"],
                    operator=m["operator"],
                    description=m["description"],
                )
                for m in sample["mutants"]
            ]
        else:
            # Fallback: generate at evaluation time (backward compatibility)
            mutants = engine.generate_mutants(
                sample["secure_code"],
                cwe=None,  # Engine already has sample-specific operators
                max_mutants=max_mutants,
            ).mutants

        killed = 0
        for mutant in mutants:
            mutant_result = runner.run_tests(generated_tests, mutant.mutated_code)
            is_killed = not mutant_result.all_passed

            kill_type = None
            kill_reason = None
            mock_access = None
            classification_layer = None

            if is_killed:
                killed += 1
                # Get the first failing test's error for classification
                for test_result in mutant_result.tests:
                    if not test_result.passed and test_result.error:
                        kill_reason = test_result.error
                        mock_access = test_result.mock_security_access
                        # Pass operator and mock_access for observability-aware classification
                        kill_type = classify_kill(
                            kill_reason,
                            operator=mutant.operator,
                            mock_access=mock_access
                        )
                        # Determine which layer triggered the classification
                        if kill_type == "semantic" and mock_access:
                            # Check if mock observability triggered it
                            relevant_mocks = OPERATOR_MOCK_MAPPING.get(mutant.operator, {})
                            for mock_name, required_attrs in relevant_mocks.items():
                                accessed = set(mock_access.get(mock_name, []))
                                if accessed & required_attrs:
                                    classification_layer = "mock_observability"
                                    break
                            if classification_layer is None:
                                classification_layer = "keyword"
                        elif kill_type == "semantic":
                            classification_layer = "keyword"
                        elif kill_type == "crash":
                            classification_layer = "crash"
                        else:
                            classification_layer = "none"
                        break
                # Default if no error found
                if kill_type is None:
                    kill_type = "other"
                    classification_layer = "none"

            # Collect per-test results for detailed logging
            test_results = []
            for test in mutant_result.tests:
                test_results.append({
                    "name": test.name,
                    "passed": test.passed,
                    "error": test.error if not test.passed else None,
                })

            result["mutant_details"].append({
                "id": mutant.id,
                "operator": mutant.operator,
                "killed": is_killed,
                "kill_type": kill_type,
                "kill_reason": kill_reason,
                "classification_layer": classification_layer,  # NEW: Which layer triggered classification
                "mock_security_access": mock_access,  # NEW: What mock attrs were accessed
                "description": mutant.description,
                "mutated_code": mutant.mutated_code,  # Full mutant code for analysis
                "test_results": test_results,  # Per-test pass/fail breakdown
            })

        result["metrics"]["mutants_total"] = len(mutants)
        result["metrics"]["mutants_killed"] = killed
        # Distinguish between 0 killed (0.0) and no mutants generated (None)
        if mutants:
            result["metrics"]["mutation_score"] = killed / len(mutants)
            result["metrics"]["mutation_score_valid"] = True
        else:
            result["metrics"]["mutation_score"] = None  # No mutants = undefined score
            result["metrics"]["mutation_score_valid"] = False

    except Exception as e:
        result["errors"].append(f"Mutation testing error: {str(e)}")
        result["metrics"]["mutation_score"] = None
        result["metrics"]["mutation_score_valid"] = False
        result["metrics"]["mutants_total"] = 0
        result["metrics"]["mutants_killed"] = 0

    result["metrics"]["execution_time"] = time.time() - start_time

    return result


def evaluate_model(
    model_name: str,
    benchmark: List[Dict],
    prompt_template: str = None,
    llm_client: Any = None,
    output_dir: Optional[str] = None,
    use_unified_prompts: bool = True,
) -> Dict[str, Any]:
    """
    Evaluate an LLM on the full benchmark.

    Args:
        model_name: Name of the model to evaluate
        benchmark: List of benchmark samples
        prompt_template: Legacy template for generating prompts (deprecated)
        llm_client: Client for calling the LLM API
        output_dir: Directory to save results
        use_unified_prompts: If True, use format_test_generation_prompt from prompts module
                            (recommended for consistency with baselines)

    Returns:
        Dict with summary and detailed results
    """
    results = []
    engine = MutationEngine()
    runner = TestRunner()

    for i, sample in enumerate(benchmark):
        print(f"Evaluating sample {i+1}/{len(benchmark)}: {sample['id']}")

        # Generate prompt - prefer unified prompts module for consistency
        if use_unified_prompts:
            prompt = format_test_generation_prompt(
                code=sample["secure_code"],
                cwe=sample["cwe"],
                cwe_name=sample.get("cwe_name", sample["cwe"]),
                include_mock_env=True,
            )
        elif prompt_template:
            # Legacy path - use provided template
            prompt = prompt_template.format(
                cwe=sample["cwe"],
                cwe_name=sample.get("cwe_name", sample["cwe"]),
                code=sample["secure_code"],
                entry_point=sample.get("entry_point", "function"),
            )
        else:
            raise ValueError("Either prompt_template or use_unified_prompts=True required")

        # Call LLM (if client provided)
        if llm_client:
            try:
                generated_tests = llm_client.generate(prompt)
            except Exception as e:
                print(f"  Error calling LLM: {e}")
                generated_tests = ""
        else:
            # Use reference tests for testing
            generated_tests = sample.get("security_tests", "")

        # Evaluate
        sample_result = evaluate_generated_tests(
            sample, generated_tests, engine, runner
        )
        results.append(sample_result)

        # Print progress
        ms = sample_result["metrics"].get("mutation_score", 0)
        vd = sample_result["metrics"].get("vuln_detected", False)
        print(f"  Mutation Score: {ms:.2%}, Vuln Detected: {vd}")

    # Aggregate metrics
    summary = {
        "model": model_name,
        "samples": len(results),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    }
    summary.update(calculate_metrics(results))

    by_cwe = aggregate_by_cwe(results)
    by_difficulty = aggregate_by_difficulty(results)
    by_operator = aggregate_by_operator(results)
    survival_analysis = analyze_survival_patterns(results)
    kill_breakdown = calculate_kill_breakdown(results)
    security_precision = calculate_security_precision(results)

    summary["kill_breakdown"] = kill_breakdown
    summary["security_mutation_score"] = kill_breakdown.get("security_mutation_score")
    summary["incidental_score"] = kill_breakdown.get("incidental_score")
    summary["crash_score"] = kill_breakdown.get("crash_score")
    summary["security_precision"] = security_precision.get("security_precision")

    output = {
        "version_info": get_version_info(),
        "summary": summary,
        "by_cwe": by_cwe,
        "by_difficulty": by_difficulty,
        "by_operator": by_operator,
        "survival_analysis": survival_analysis,
        "kill_breakdown": kill_breakdown,
        "security_precision": security_precision,
        "details": results,
    }

    # Save results
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, f"{model_name}_results.json")
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to: {output_path}")

    # Print report
    print("\n" + format_metrics_report(summary, by_cwe, by_difficulty, survival_analysis))

    return output


def evaluate_reference_tests(benchmark: List[Dict]) -> Dict[str, Any]:
    """
    Evaluate the reference security tests in the benchmark.

    This establishes a baseline for what perfect tests should achieve.

    Args:
        benchmark: List of benchmark samples

    Returns:
        Dict with evaluation results
    """
    results = []
    engine = MutationEngine()
    runner = TestRunner()

    print(f"Evaluating {len(benchmark)} samples...")
    for i, sample in enumerate(benchmark):
        security_tests = sample.get("security_tests", "")
        if not security_tests:
            continue

        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(benchmark)}")

        result = evaluate_generated_tests(sample, security_tests, engine, runner)
        results.append(result)

    summary = calculate_metrics(results)
    summary["model"] = "reference_tests"

    by_cwe = aggregate_by_cwe(results)
    by_difficulty = aggregate_by_difficulty(results)
    by_operator = aggregate_by_operator(results)
    survival_analysis = analyze_survival_patterns(results)
    kill_breakdown = calculate_kill_breakdown(results)
    security_precision = calculate_security_precision(results)

    summary["kill_breakdown"] = kill_breakdown
    summary["security_mutation_score"] = kill_breakdown.get("security_mutation_score")
    summary["incidental_score"] = kill_breakdown.get("incidental_score")
    summary["crash_score"] = kill_breakdown.get("crash_score")
    summary["security_precision"] = security_precision.get("security_precision")

    return {
        "summary": summary,
        "by_cwe": by_cwe,
        "by_difficulty": by_difficulty,
        "by_operator": by_operator,
        "survival_analysis": survival_analysis,
        "kill_breakdown": kill_breakdown,
        "security_precision": security_precision,
        "details": results,
    }


def evaluate_multimodal(
    benchmark: List[Dict],
    generated_tests_map: Optional[Dict[str, str]] = None,
    use_llm_judge: bool = True,
    judge_provider: str = "anthropic",
    judge_model: Optional[str] = None,
    weights: Optional[Dict[str, float]] = None,
    output_dir: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Perform multi-modal evaluation combining execution and LLM-as-judge metrics.

    Evaluation Components:
    - Mutation Score (50% default weight)
    - Security Relevance - LLM Judge (20% default weight)
    - Test Quality - LLM Judge (15% default weight)
    - Coverage (15% default weight)

    Args:
        benchmark: List of benchmark samples
        generated_tests_map: Dict mapping sample_id to generated tests
        use_llm_judge: Whether to use LLM-as-judge (requires API key)
        judge_provider: "anthropic" for Claude (default) or "openai" for GPT-4
        judge_model: Model to use for judging (defaults based on provider)
        weights: Custom weights for metrics
        output_dir: Directory to save results

    Returns:
        Dict with multi-modal evaluation results
    """
    engine = MutationEngine()
    runner = TestRunner()

    # Create multi-modal evaluator
    if use_llm_judge:
        evaluator = create_evaluator(
            provider=judge_provider,
            model=judge_model,
            weights=weights,
        )
        if judge_provider == "anthropic":
            print(f"Using Claude ({judge_model or 'claude-sonnet-4-5-20250929'}) as LLM-as-Judge")
        else:
            print(f"Using OpenAI ({judge_model or 'gpt-4'}) as LLM-as-Judge")
    else:
        evaluator = create_evaluator(use_mock=True, weights=weights)
        print("Using mock LLM-as-Judge evaluation")

    execution_results = []
    multimodal_results = []

    print(f"\nPhase 1: Execution-based evaluation ({len(benchmark)} samples)...")
    for i, sample in enumerate(benchmark):
        sample_id = sample.get("id", f"sample_{i}")

        # Get tests (generated or reference)
        if generated_tests_map and sample_id in generated_tests_map:
            tests = generated_tests_map[sample_id]
        else:
            tests = sample.get("security_tests", "")

        if not tests:
            continue

        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(benchmark)}")

        # Run execution-based evaluation
        exec_result = evaluate_generated_tests(sample, tests, engine, runner)
        execution_results.append(exec_result)

        # Store for multi-modal evaluation
        multimodal_results.append({
            "sample": sample,
            "tests": tests,
            "exec_result": exec_result,
        })

    print(f"\nPhase 2: LLM-as-Judge evaluation ({len(multimodal_results)} samples)...")
    final_results = []

    for i, item in enumerate(multimodal_results):
        if (i + 1) % 10 == 0:
            print(f"  Progress: {i + 1}/{len(multimodal_results)}")

        mm_result = evaluator.evaluate(
            sample=item["sample"],
            generated_tests=item["tests"],
            execution_results=item["exec_result"],
        )
        final_results.append(mm_result)

    # Aggregate results
    aggregate = evaluator.aggregate_results(final_results)

    # Combine with execution-based metrics
    exec_summary = calculate_metrics(execution_results)
    by_cwe = aggregate_by_cwe(execution_results)
    by_difficulty = aggregate_by_difficulty(execution_results)
    by_operator = aggregate_by_operator(execution_results)
    survival_analysis = analyze_survival_patterns(execution_results)
    kill_breakdown = calculate_kill_breakdown(execution_results)
    security_precision = calculate_security_precision(execution_results)

    exec_summary["kill_breakdown"] = kill_breakdown
    exec_summary["security_mutation_score"] = kill_breakdown.get("security_mutation_score")
    exec_summary["security_precision"] = security_precision.get("security_precision")

    output = {
        "version_info": get_version_info(),
        "evaluation_mode": "multimodal",
        "weights": evaluator.weights,
        "multimodal_summary": aggregate,
        "execution_summary": exec_summary,
        "kill_breakdown": kill_breakdown,
        "security_precision": security_precision,
        "by_cwe": by_cwe,
        "by_difficulty": by_difficulty,
        "by_operator": by_operator,
        "survival_analysis": survival_analysis,
        "details": [
            {
                "sample_id": r.sample_id,
                "mutation_score": r.mutation_score,
                "coverage_score": r.coverage_score,
                "security_relevance": r.security_relevance.score if r.security_relevance else 0,
                "test_quality": r.test_quality.score if r.test_quality else 0,
                "composite_score": r.composite_score,
            }
            for r in final_results
        ],
    }

    # Save results
    if output_dir:
        os.makedirs(output_dir, exist_ok=True)
        output_path = os.path.join(output_dir, "multimodal_results.json")
        with open(output_path, "w") as f:
            json.dump(output, f, indent=2)
        print(f"\nResults saved to: {output_path}")

    # Print report
    print("\n" + format_multimodal_report(aggregate))

    return output


# Legacy prompt template - kept for backwards compatibility
# For new evaluations, use format_test_generation_prompt() from evaluation.prompts
# which includes mock environment docs and CWE-specific attack vectors
DEFAULT_PROMPT_TEMPLATE = """
Generate security tests for the following Python function to detect {cwe_name} ({cwe}) vulnerabilities.

Function to test:
```python
{code}
```

Entry point: {entry_point}

Write pytest-style tests that would detect if this function were vulnerable to {cwe_name}.
Focus on edge cases and attack vectors specific to {cwe}.

Requirements:
1. Tests should PASS on secure implementations
2. Tests should FAIL on vulnerable implementations
3. Include at least 3 different attack vectors
4. Use assertions to verify security properties

Output only the Python test code, no explanations.
"""


def main():
    parser = argparse.ArgumentParser(
        description="Evaluate security tests on SecMutBench"
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="Show version information and exit"
    )
    parser.add_argument(
        "--benchmark",
        default=None,
        help="Path to benchmark samples.json"
    )
    parser.add_argument(
        "--model",
        default="reference",
        help="Model to evaluate (or 'reference' for reference tests)"
    )
    parser.add_argument(
        "--difficulty",
        choices=["easy", "medium", "hard"],
        help="Filter samples by difficulty"
    )
    parser.add_argument(
        "--cwe",
        help="Filter samples by CWE (e.g., CWE-89)"
    )
    parser.add_argument(
        "--output",
        default="results",
        help="Output directory for results"
    )
    parser.add_argument(
        "--multimodal",
        action="store_true",
        help="Use multi-modal evaluation with LLM-as-Judge"
    )
    parser.add_argument(
        "--judge-provider",
        default="anthropic",
        choices=["anthropic", "openai"],
        help="LLM provider for judge (default: anthropic for Claude)"
    )
    parser.add_argument(
        "--judge-model",
        default=None,
        help="Model for LLM-as-Judge (default: claude-sonnet-4-5-20250929 for Anthropic, gpt-4 for OpenAI)"
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print detailed output"
    )
    parser.add_argument(
        "--skip-invalid",
        action="store_true",
        help="Skip samples where quality.validation_passed is False"
    )

    args = parser.parse_args()

    # Handle --version flag
    if args.version:
        from evaluation.version import format_version_string
        print(format_version_string())
        return

    # Load benchmark
    print("Loading benchmark...")
    try:
        benchmark = load_benchmark(
            path=args.benchmark,
            difficulty=args.difficulty,
            cwe=args.cwe,
        )
        print(f"Loaded {len(benchmark)} samples")

        # Filter out invalid samples if requested
        invalid_count = sum(1 for s in benchmark if not s.get("quality", {}).get("validation_passed", True))
        if invalid_count > 0:
            if args.skip_invalid:
                benchmark = [s for s in benchmark if s.get("quality", {}).get("validation_passed", True)]
                print(f"Skipped {invalid_count} samples with validation_passed=False ({len(benchmark)} remaining)")
            else:
                print(f"Warning: {invalid_count} samples have validation_passed=False. Use --skip-invalid to exclude them.")

    except FileNotFoundError:
        print("Error: Benchmark file not found.")
        print("Make sure data/samples.json exists.")
        sys.exit(1)

    if not benchmark:
        print("No samples matched the filters.")
        sys.exit(1)

    # Evaluate
    if args.multimodal:
        print("\nRunning multi-modal evaluation...")
        print(f"Judge: {args.judge_provider} ({args.judge_model or 'default model'})")
        print("Weights: Mutation(50%), Security Relevance(20%), Test Quality(15%), Coverage(15%)")
        results = evaluate_multimodal(
            benchmark,
            use_llm_judge=True,
            judge_provider=args.judge_provider,
            judge_model=args.judge_model,
            output_dir=args.output,
        )
        # Print multi-modal summary
        summary = results.get("multimodal_summary", {})
        print("\n" + "=" * 70)
        print("Multi-Modal Evaluation Complete")
        print("=" * 70)
        print(f"Samples:                  {summary.get('samples', 0)}")
        print(f"Avg Composite Score:      {summary.get('composite', {}).get('avg_composite_score', 0):.2%}")
        print(f"Avg Mutation Score:       {summary.get('execution_metrics', {}).get('avg_mutation_score', 0):.2%}")
        print(f"Avg Security Relevance:   {summary.get('llm_judge_metrics', {}).get('avg_security_relevance', 0):.2%}")
        print(f"Avg Test Quality:         {summary.get('llm_judge_metrics', {}).get('avg_test_quality', 0):.2%}")
    elif args.model == "reference":
        print("\nEvaluating reference security tests...")
        results = evaluate_reference_tests(benchmark)
        # Print summary
        summary = results["summary"]
        print("\n" + "=" * 60)
        print("Evaluation Complete")
        print("=" * 60)
        print(f"Model:              {summary.get('model', 'unknown')}")
        print(f"Samples:            {summary.get('samples', 0)}")
        print(f"Avg Mutation Score: {summary.get('avg_mutation_score', 0):.2%}")
        print(f"Avg Vuln Detection: {summary.get('avg_vuln_detection', 0):.2%}")
    else:
        print(f"\nEvaluating model: {args.model}")
        results = evaluate_model(
            args.model,
            benchmark,
            prompt_template=None,  # Use unified prompts from prompts module
            output_dir=args.output,
            use_unified_prompts=True,
        )
        # Print summary
        summary = results["summary"]
        print("\n" + "=" * 60)
        print("Evaluation Complete")
        print("=" * 60)
        print(f"Model:              {summary.get('model', 'unknown')}")
        print(f"Samples:            {summary.get('samples', 0)}")
        print(f"Avg Mutation Score: {summary.get('avg_mutation_score', 0):.2%}")
        print(f"Avg Vuln Detection: {summary.get('avg_vuln_detection', 0):.2%}")


if __name__ == "__main__":
    main()
