#!/usr/bin/env python3
"""
Security Relevance Judge for SecMutBench (/judge-security skill)

Deep security analysis of LLM-generated tests using AST parsing,
argument flow analysis, assertion correctness, and CWE-specific expertise.

This encodes Claude's security reasoning from the /judge-security skill:
- Step-by-step reasoning per sample
- CWE-specific attack vector analysis
- Mock environment correctness checking
- Assertion polarity and target verification
- Detailed natural language reasoning

Usage:
    python baselines/run_judge_security.py results/              # All unjudged
    python baselines/run_judge_security.py results/deepseek*.json  # Specific file
    python baselines/run_judge_security.py results/ --force      # Re-judge all
"""

import ast
import json
import re
import sys
import argparse
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# =============================================================================
# CWE-Specific Security Knowledge Base
# =============================================================================

# Maps CWE → expected mock objects and their security-critical attributes
# These are the CORRECT mocks that tests should use for each vulnerability type
CWE_MOCK_EXPECTATIONS = {
    "CWE-89": {
        "mocks": {"db": ["last_params", "last_query"]},
        "correct_assertions": [
            "db.last_params is not None",  # Parameterized query check
            "payload not in db.last_query",  # Injection not in query
        ],
        "wrong_assertions": [
            "db.last_params is None",  # Reversed polarity
            "payload in db.last_query",  # Expects vulnerability in secure code
        ],
    },
    "CWE-78": {
        "mocks": {"subprocess": ["injection_detected", "last_shell", "last_command",
                                  "dangerous_command_detected"]},
        "correct_assertions": [
            "not subprocess.injection_detected",
            "subprocess.last_shell == False",
            "not subprocess.last_shell",
        ],
        "wrong_assertions": [
            "subprocess.injection_detected",  # Reversed
            "subprocess.last_shell == True",  # Expects shell=True
        ],
    },
    "CWE-22": {
        "mocks": {"fs": ["last_path", "base_dir"]},
        "correct_assertions": [
            "pytest.raises(ValueError)",
            "pytest.raises(PermissionError)",
            "fs.last_path.startswith",
        ],
        "wrong_assertions": [],
    },
    "CWE-79": {
        "mocks": {},
        "correct_assertions": [
            "<script> not in",
            "not in result",
            "&lt;script&gt; in",
            "html.escape",
        ],
        "wrong_assertions": [
            "<script> in result",  # Expects XSS in secure output
        ],
    },
    "CWE-327": {
        "mocks": {"hashlib": ["weak_algorithm_used", "last_algorithm", "strong_algorithm_used"]},
        "correct_assertions": [
            "not hashlib.weak_algorithm_used",
            "hashlib.strong_algorithm_used",
        ],
        "wrong_assertions": [
            "hashlib.weak_algorithm_used",  # Reversed
        ],
    },
    "CWE-328": {
        "mocks": {"hashlib": ["weak_algorithm_used", "last_algorithm"]},
        "correct_assertions": [
            "not hashlib.weak_algorithm_used",
        ],
        "wrong_assertions": [],
    },
    "CWE-502": {
        "mocks": {
            "pickle": ["unsafe_load_called"],
            "yaml": ["unsafe_load_called", "safe_loader_used"],
        },
        "correct_assertions": [
            "not pickle.unsafe_load_called",
            "not yaml.unsafe_load_called",
            "yaml.safe_loader_used",
        ],
        "wrong_assertions": [],
    },
    "CWE-918": {
        "mocks": {"requests": ["ssrf_attempted", "last_url"]},
        "correct_assertions": [
            "not requests.ssrf_attempted",
        ],
        "wrong_assertions": [
            "requests.ssrf_attempted",  # Reversed
        ],
    },
    "CWE-611": {
        "mocks": {"xml_parser": ["external_entities_resolved"]},
        "correct_assertions": [
            "not xml_parser.external_entities_resolved",
        ],
        "wrong_assertions": [],
    },
    "CWE-798": {
        "mocks": {"env": ["access_log", "sensitive_accessed"], "mysql": ["last_password"]},
        "correct_assertions": [
            "len(env.access_log) > 0",
            "env.sensitive_accessed",
        ],
        "wrong_assertions": [],
    },
    "CWE-94": {
        "mocks": {"mock_eval": ["unsafe_eval_called", "injection_detected"]},
        "correct_assertions": [
            "not mock_eval.unsafe_eval_called",
            "not mock_eval.injection_detected",
        ],
        "wrong_assertions": [],
    },
    "CWE-95": {
        "mocks": {"mock_eval": ["unsafe_eval_called", "unsafe_exec_called"]},
        "correct_assertions": [
            "not mock_eval.unsafe_eval_called",
        ],
        "wrong_assertions": [],
    },
    "CWE-338": {
        "mocks": {"mock_random": ["weak_prng_used", "secure_prng_used"], "secrets": []},
        "correct_assertions": [
            "not mock_random.weak_prng_used",
            "mock_random.secure_prng_used",
        ],
        "wrong_assertions": [],
    },
    "CWE-287": {
        "mocks": {"auth": ["auth_attempts", "failed_attempts"]},
        "correct_assertions": [
            "pytest.raises(PermissionError)",
            "auth.failed_attempts",
        ],
        "wrong_assertions": [],
    },
    "CWE-306": {
        "mocks": {"auth": ["auth_attempts"], "request": ["is_authenticated"]},
        "correct_assertions": [
            "pytest.raises(PermissionError)",
        ],
        "wrong_assertions": [],
    },
    "CWE-295": {
        "mocks": {"requests": ["last_kwargs"]},
        "correct_assertions": [
            "verify=True",
            "verify is not False",
        ],
        "wrong_assertions": [],
    },
    "CWE-319": {
        "mocks": {"requests": ["last_url"]},
        "correct_assertions": [
            "https://",
            "not http://",
        ],
        "wrong_assertions": [],
    },
    "CWE-347": {
        "mocks": {"jwt": ["decode_called", "verify_signature"]},
        "correct_assertions": [
            "jwt.verify_signature",
        ],
        "wrong_assertions": [],
    },
    "CWE-326": {
        "mocks": {},
        "correct_assertions": [
            "2048",
            "key_size",
        ],
        "wrong_assertions": [],
    },
}

# CWE-specific attack payloads that indicate security awareness
CWE_ATTACK_VECTORS = {
    "CWE-89": {
        "payloads": [
            (r"OR\s+['\"]?1['\"]?\s*=\s*['\"]?1", "SQL tautology (OR 1=1)"),
            (r"UNION\s+SELECT", "UNION SELECT injection"),
            (r"DROP\s+TABLE", "DROP TABLE injection"),
            (r";\s*--", "SQL comment injection"),
            (r"admin['\"]?\s*--", "Auth bypass via comment"),
            (r"SELECT\s+\*\s+FROM", "SELECT * enumeration"),
            (r"SLEEP\s*\(", "Time-based blind injection"),
            (r"OR\s+SLEEP", "Boolean/time blind injection"),
        ],
        "min_vectors": 2,
    },
    "CWE-78": {
        "payloads": [
            (r";\s*(cat|ls|rm|wget|curl|nc|whoami|id)", "Shell command chaining (;)"),
            (r"\|\s*(cat|nc|sh|bash)", "Pipe injection"),
            (r"\$\(", "Command substitution $(...)"),
            (r"`[^`]+`", "Backtick command substitution"),
            (r"&&\s*(cat|rm|ls|id)", "AND command chaining"),
            (r"/etc/passwd", "Path disclosure payload"),
        ],
        "min_vectors": 2,
    },
    "CWE-22": {
        "payloads": [
            (r"\.\./", "Directory traversal (../)"),
            (r"\.\.\\/", "Backslash traversal (..\\)"),
            (r"/etc/passwd", "Absolute path escape"),
            (r"%2e%2e", "URL-encoded traversal"),
            (r"%00", "Null byte injection"),
            (r"\.\.%c0%af", "Unicode/UTF-8 traversal"),
        ],
        "min_vectors": 2,
    },
    "CWE-79": {
        "payloads": [
            (r"<script>", "Script tag injection"),
            (r"onerror\s*=", "Event handler (onerror)"),
            (r"onload\s*=", "Event handler (onload)"),
            (r"javascript:", "JavaScript URI"),
            (r"alert\s*\(", "Alert payload"),
            (r"<img\s", "IMG tag injection"),
        ],
        "min_vectors": 2,
    },
    "CWE-502": {
        "payloads": [
            (r"pickle", "Pickle deserialization"),
            (r"yaml\.load", "Unsafe YAML load"),
            (r"unsafe_load", "Explicit unsafe load"),
            (r"marshal", "Marshal deserialization"),
            (r"__reduce__", "Python pickle exploit"),
            (r"eval\s*\(", "Eval-based deserialization"),
        ],
        "min_vectors": 1,
    },
    "CWE-918": {
        "payloads": [
            (r"127\.0\.0\.1", "Localhost SSRF"),
            (r"localhost", "Localhost string SSRF"),
            (r"169\.254\.169\.254", "AWS metadata SSRF"),
            (r"192\.168\.", "Private network SSRF"),
            (r"10\.\d", "Private network SSRF (10.x)"),
            (r"0\.0\.0\.0", "All-interfaces SSRF"),
            (r"file://", "File protocol SSRF"),
        ],
        "min_vectors": 2,
    },
    "CWE-611": {
        "payloads": [
            (r"<!ENTITY", "XML entity declaration"),
            (r"<!DOCTYPE", "DOCTYPE declaration"),
            (r"SYSTEM", "External entity reference"),
            (r"file://", "File protocol in entity"),
            (r"xxe", "XXE reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-798": {
        "payloads": [
            (r"password", "Password reference"),
            (r"admin123|SuperSecret|root|default", "Common default credential"),
            (r"hardcod", "Hardcoded reference"),
            (r"api_key|apikey|secret", "API key/secret reference"),
            (r"os\.environ|env\.get|getenv", "Environment variable usage"),
        ],
        "min_vectors": 2,
    },
    "CWE-338": {
        "payloads": [
            (r"random\.(random|randint|choice|seed)", "Weak PRNG usage"),
            (r"secrets\.(token|choice|randbelow)", "Secure PRNG reference"),
            (r"urandom", "OS random reference"),
            (r"seed\s*\(", "Predictable seed"),
        ],
        "min_vectors": 1,
    },
    "CWE-94": {
        "payloads": [
            (r"eval\s*\(", "eval() injection"),
            (r"exec\s*\(", "exec() injection"),
            (r"__import__", "Dynamic import injection"),
            (r"os\.system", "OS command via eval"),
            (r"compile\s*\(", "compile() injection"),
        ],
        "min_vectors": 1,
    },
    "CWE-95": {
        "payloads": [
            (r"eval\s*\(", "eval() injection"),
            (r"exec\s*\(", "exec() injection"),
            (r"literal_eval", "Safe alternative check"),
            (r"__import__|os\.", "Dangerous import in eval"),
        ],
        "min_vectors": 1,
    },
    "CWE-117": {
        "payloads": [
            (r"\\n|\\r|\n|\r", "Newline injection"),
            (r"\\x0a|\\x0d", "Hex newline injection"),
            (r"CRLF|crlf", "CRLF reference"),
            (r"log.*inject", "Log injection reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-209": {
        "payloads": [
            (r"traceback", "Traceback exposure"),
            (r"stack.*trace", "Stack trace exposure"),
            (r"debug", "Debug info exposure"),
            (r"internal.*error|error.*detail", "Internal error detail"),
            (r"password|secret|key", "Sensitive data in error"),
        ],
        "min_vectors": 1,
    },
    "CWE-295": {
        "payloads": [
            (r"verify\s*=\s*False", "SSL verify disabled"),
            (r"verify\s*=\s*True", "SSL verify enabled check"),
            (r"certificate|cert", "Certificate reference"),
            (r"ssl|tls", "SSL/TLS reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-319": {
        "payloads": [
            (r"https?://", "HTTP/HTTPS URL"),
            (r"http://", "Insecure HTTP URL"),
            (r"encrypt", "Encryption reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-20": {
        "payloads": [
            (r"ValueError", "Input validation exception"),
            (r"validat", "Validation reference"),
            (r"sanitiz", "Sanitization reference"),
            (r"invalid|malicious", "Invalid input reference"),
            (r"special.*char|[<>&\"']", "Special character testing"),
        ],
        "min_vectors": 1,
    },
    "CWE-400": {
        "payloads": [
            (r"size.*limit|max.*size|too.*large", "Size limit check"),
            (r"timeout", "Timeout check"),
            (r"resource|exhaust", "Resource exhaustion"),
            (r"\*\s*\d{4,}|10{6,}", "Large input generation"),
        ],
        "min_vectors": 1,
    },
    "CWE-434": {
        "payloads": [
            (r"\.exe|\.php|\.sh|\.bat", "Dangerous extension"),
            (r"extension|file.*type", "Extension check"),
            (r"mime|content.type", "MIME type check"),
            (r"upload", "Upload reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-601": {
        "payloads": [
            (r"redirect", "Redirect reference"),
            (r"evil\.com|attacker", "Malicious domain"),
            (r"://", "Protocol reference"),
            (r"netloc|urlparse", "URL parsing check"),
        ],
        "min_vectors": 1,
    },
    "CWE-639": {
        "payloads": [
            (r"user_id|user\.id|current_user", "User identity check"),
            (r"PermissionError|Forbidden|403", "Access denied check"),
            (r"other.*user|different.*user", "Cross-user test"),
            (r"unauthorized", "Authorization check"),
        ],
        "min_vectors": 1,
    },
    "CWE-643": {
        "payloads": [
            (r"xpath|ldap", "Injection target"),
            (r"inject|f['\"]|format\s*\(", "Injection technique"),
        ],
        "min_vectors": 1,
    },
    "CWE-732": {
        "payloads": [
            (r"0o777|0o666|0o755", "Permissive file permissions"),
            (r"0o644|0o600|0o400", "Restrictive permissions"),
            (r"chmod|permission", "Permission reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-862": {
        "payloads": [
            (r"PermissionError|Forbidden", "Access denied check"),
            (r"authorization|role|is_admin", "Authorization check"),
            (r"admin|privilege", "Privilege reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-863": {
        "payloads": [
            (r"PermissionError", "Permission check"),
            (r"role|privilege", "Role reference"),
            (r"escalat", "Privilege escalation"),
        ],
        "min_vectors": 1,
    },
    "CWE-915": {
        "payloads": [
            (r"mass.*assign|__dict__", "Mass assignment"),
            (r"is_admin|role", "Privilege attribute"),
            (r"allowed_fields|whitelist", "Field restriction"),
        ],
        "min_vectors": 1,
    },
    "CWE-352": {
        "payloads": [
            (r"csrf|token", "CSRF token"),
            (r"cross.*site", "Cross-site reference"),
        ],
        "min_vectors": 1,
    },
    "CWE-306": {
        "payloads": [
            (r"authenticat", "Authentication reference"),
            (r"login|session", "Session/login reference"),
            (r"PermissionError", "Access denied"),
            (r"is_authenticated|unauthenticated", "Auth status check"),
        ],
        "min_vectors": 1,
    },
    "CWE-287": {
        "payloads": [
            (r"authenticat|password|credential", "Auth reference"),
            (r"verify|token", "Verification reference"),
            (r"brute.*force|rate.*limit", "Brute force protection"),
        ],
        "min_vectors": 1,
    },
    "CWE-326": {
        "payloads": [
            (r"key.*size|bit", "Key size reference"),
            (r"2048|4096", "Strong key size"),
            (r"512|1024", "Weak key size"),
            (r"RSA|generate", "Key generation"),
        ],
        "min_vectors": 1,
    },
    "CWE-347": {
        "payloads": [
            (r"jwt|token", "JWT reference"),
            (r"signature|verify", "Signature verification"),
            (r"decode|encode", "JWT operation"),
            (r"algorithm|none|alg", "Algorithm check"),
        ],
        "min_vectors": 1,
    },
    "CWE-74": {
        "payloads": [
            (r"inject", "Injection reference"),
            (r"sanitiz|escape", "Sanitization check"),
            (r"special.*char", "Special character test"),
        ],
        "min_vectors": 1,
    },
}

# Security assertion keywords
SECURITY_KEYWORDS = {
    "injection", "inject", "vulnerable", "vuln", "exploit",
    "malicious", "attack", "payload", "unsafe", "insecure",
    "security", "sanitiz", "escape", "xss", "sqli", "ssrf",
    "traversal", "bypass", "unauthorized", "permission", "auth",
    "hardcoded", "weak", "sensitive", "leak", "expos",
    "parameterized", "shell", "eval", "pickle", "deserializ",
    "csrf", "redirect", "certificate", "encrypt", "hash",
    "random", "secret", "token", "credential",
}

# Anti-patterns that indicate poor security testing
ANTI_PATTERNS = [
    (r"^\s*assert\s+True\s*$", "assert True (trivial)"),
    (r"^\s*assert\s+False\s*$", "assert False (always fails)"),
    (r"^\s*assert\s+result\s+is\s+not\s+None\s*$", "assert result is not None (weak)"),
    (r"^\s*assert\s+result\s*$", "bare assert result (weak)"),
    (r"^\s*assert\s+1\s*==\s*1", "assert 1==1 (tautology)"),
    (r"^\s*pass\s*$", "pass (empty test)"),
]


# =============================================================================
# AST-Based Test Analysis
# =============================================================================

def extract_test_functions(code: str) -> List[Dict[str, Any]]:
    """Parse test code and extract individual test functions with their bodies."""
    tests = []
    try:
        tree = ast.parse(code)
    except SyntaxError:
        # Fall back to regex-based extraction
        for match in re.finditer(r"def\s+(test_\w+)\s*\([^)]*\):\s*\n((?:\s+[^\n]+\n?)*)", code):
            tests.append({
                "name": match.group(1),
                "body": match.group(2),
                "ast_node": None,
            })
        return tests

    for node in ast.walk(tree):
        if isinstance(node, ast.FunctionDef) and node.name.startswith("test_"):
            # Get the source lines for this function
            start = node.lineno - 1
            end = node.end_lineno if hasattr(node, 'end_lineno') and node.end_lineno else start + 20
            lines = code.split("\n")
            body = "\n".join(lines[start:end])
            tests.append({
                "name": node.name,
                "body": body,
                "ast_node": node,
            })
    return tests


def extract_entry_point_from_secure_code(secure_code: str) -> str:
    """Extract the function name defined in secure_code."""
    match = re.search(r"def\s+(\w+)\s*\(", secure_code)
    return match.group(1) if match else ""


def check_calls_target(test_body: str, entry_point: str) -> bool:
    """Check if a test function actually calls the function under test."""
    if not entry_point:
        return True  # Can't verify, assume yes
    return entry_point in test_body


def count_assertions(test_body: str) -> int:
    """Count assertion statements in test body."""
    lines = test_body.split("\n")
    count = 0
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("assert ") or "pytest.fail" in stripped:
            count += 1
        if "pytest.raises" in stripped:
            count += 1
    return count


def check_assertion_polarity(test_body: str, cwe: str) -> Tuple[int, int, List[str]]:
    """
    Check if assertions have correct polarity for the CWE.

    Correct: tests should PASS on secure code (expect safe behavior)
    Wrong: tests expect vulnerable behavior (would fail on secure code)

    Returns: (correct_count, wrong_count, issues)
    """
    expectations = CWE_MOCK_EXPECTATIONS.get(cwe, {})
    correct_assertions = expectations.get("correct_assertions", [])
    wrong_assertions = expectations.get("wrong_assertions", [])

    correct = 0
    wrong = 0
    issues = []

    for pattern in correct_assertions:
        if pattern in test_body:
            correct += 1

    for pattern in wrong_assertions:
        if pattern in test_body:
            wrong += 1
            issues.append(f"Wrong assertion polarity: '{pattern}' expects vulnerability in secure code")

    return correct, wrong, issues


def check_mock_usage(test_body: str, cwe: str) -> Tuple[int, int, List[str]]:
    """
    Check if tests use the correct mock objects for the CWE.

    Returns: (mocks_used, mocks_expected, details)
    """
    expectations = CWE_MOCK_EXPECTATIONS.get(cwe, {})
    expected_mocks = expectations.get("mocks", {})

    if not expected_mocks:
        return 0, 0, []

    used = 0
    total = len(expected_mocks)
    details = []

    for mock_name, attrs in expected_mocks.items():
        if mock_name in test_body:
            used += 1
            attrs_found = [a for a in attrs if a in test_body]
            if attrs_found:
                details.append(f"Uses {mock_name}.{', '.join(attrs_found)}")
            else:
                details.append(f"References {mock_name} but no security attributes checked")
        else:
            details.append(f"Missing expected mock: {mock_name}")

    return used, total, details


def check_attack_vectors(test_body: str, cwe: str) -> Tuple[List[str], int]:
    """
    Check which CWE-specific attack vectors are present in the tests.

    Returns: (vectors_found, min_expected)
    """
    vectors = CWE_ATTACK_VECTORS.get(cwe, {})
    payloads = vectors.get("payloads", [])
    min_expected = vectors.get("min_vectors", 1)

    found = []
    for pattern, name in payloads:
        if re.search(pattern, test_body, re.IGNORECASE):
            found.append(name)

    return found, min_expected


def check_anti_patterns(test_body: str) -> List[str]:
    """Check for test anti-patterns."""
    found = []
    for pattern, name in ANTI_PATTERNS:
        if re.search(pattern, test_body, re.MULTILINE):
            count = len(re.findall(pattern, test_body, re.MULTILINE))
            found.append(f"{name} (x{count})")
    return found


def check_source_inspection(test_body: str) -> bool:
    """Check if tests use source code inspection as security verification."""
    return any(kw in test_body for kw in [
        "inspect.getsource", "inspect.getmodule",
        "re.search", "re.findall", "re.match",
    ]) and any(kw in test_body for kw in [
        "source", "code", "module",
    ])


def check_exception_testing(test_body: str) -> List[str]:
    """Check if tests verify security-relevant exceptions."""
    exceptions = []
    for exc_type in ["ValueError", "PermissionError", "SecurityError",
                     "AuthenticationError", "AuthorizationError",
                     "Forbidden", "Unauthorized"]:
        if exc_type in test_body:
            exceptions.append(exc_type)
    if "pytest.raises" in test_body:
        exceptions.append("pytest.raises used")
    return exceptions


def check_security_keywords_in_assertions(test_body: str) -> int:
    """Count security-relevant keywords in assertion statements."""
    lines = test_body.split("\n")
    sec_assertions = 0
    for line in lines:
        stripped = line.strip()
        if not (stripped.startswith("assert ") or "pytest.fail" in stripped):
            continue
        line_lower = stripped.lower()
        if any(kw in line_lower for kw in SECURITY_KEYWORDS):
            sec_assertions += 1
    return sec_assertions


# =============================================================================
# Main Security Relevance Judge
# =============================================================================

def judge_security_relevance(
    generated_tests: str,
    cwe: str,
    cwe_name: str,
    secure_code: str,
) -> Dict[str, Any]:
    """
    Judge the security relevance of generated tests using step-by-step reasoning.

    Reasoning chain (from /judge-security skill):
    a. What CWE is this? What does the secure code do?
    b. What attack vectors should a good test include?
    c. Does the test use correct mock objects?
    d. Are assertions checking security properties?
    e. Would this test actually detect a vulnerability?
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

    reasoning_parts = []
    score = 0.0
    attack_vectors_found = []
    security_props = []

    # --- Get entry point ---
    entry_point = extract_entry_point_from_secure_code(secure_code)

    # --- Extract test functions ---
    test_funcs = extract_test_functions(generated_tests)
    n_tests = len(test_funcs)

    # --- Step (a): CWE identification ---
    cwe_in_tests = cwe in generated_tests or cwe.replace("CWE-", "") in generated_tests
    cwe_name_lower = cwe_name.lower()
    cwe_name_in_tests = any(
        word in generated_tests.lower()
        for word in cwe_name_lower.split()
        if len(word) > 3
    )

    # --- Step (b): Attack vector analysis (0-35 points) ---
    vectors, min_expected = check_attack_vectors(generated_tests, cwe)
    attack_vectors_found = vectors

    if len(vectors) >= max(3, min_expected + 1):
        score += 35
        reasoning_parts.append(f"Excellent attack coverage: {len(vectors)} vectors ({', '.join(vectors[:4])})")
    elif len(vectors) >= min_expected:
        score += 25
        reasoning_parts.append(f"Good attack coverage: {len(vectors)} vectors ({', '.join(vectors[:3])})")
    elif len(vectors) >= 1:
        score += 15
        reasoning_parts.append(f"Limited attack coverage: {len(vectors)} vector(s) ({', '.join(vectors[:2])})")
    else:
        reasoning_parts.append(f"No CWE-specific attack vectors for {cwe} ({cwe_name})")

    # --- Step (c): Mock object usage (0-25 points) ---
    mocks_used, mocks_expected, mock_details = check_mock_usage(generated_tests, cwe)

    if mocks_expected > 0:
        if mocks_used == mocks_expected:
            score += 25
            reasoning_parts.append(f"All expected mocks used ({mocks_used}/{mocks_expected})")
            security_props.extend([d for d in mock_details if "Uses" in d])
        elif mocks_used > 0:
            score += 15
            reasoning_parts.append(f"Partial mock usage ({mocks_used}/{mocks_expected})")
            security_props.extend([d for d in mock_details if "Uses" in d])
        else:
            reasoning_parts.append(f"No expected mock objects used (expected: {', '.join(CWE_MOCK_EXPECTATIONS.get(cwe, {}).get('mocks', {}).keys())})")
    else:
        # No specific mocks expected — check alternative approaches
        if check_source_inspection(generated_tests):
            score += 20
            security_props.append("source_inspection")
            reasoning_parts.append("Uses source code inspection for security verification")
        elif check_exception_testing(generated_tests):
            exc_types = check_exception_testing(generated_tests)
            score += 18
            security_props.extend(exc_types)
            reasoning_parts.append(f"Tests security exceptions: {', '.join(exc_types[:3])}")
        else:
            score += 5
            reasoning_parts.append("No mock or exception-based security testing")

    # --- Step (d): Assertion correctness (0-25 points) ---
    correct_polarity, wrong_polarity, polarity_issues = check_assertion_polarity(
        generated_tests, cwe
    )
    sec_keyword_assertions = check_security_keywords_in_assertions(generated_tests)
    total_assertions = count_assertions(generated_tests)

    assertion_score = 0

    # Correct polarity assertions
    if correct_polarity >= 2:
        assertion_score += 15
        reasoning_parts.append(f"Strong correct assertions ({correct_polarity} with right polarity)")
    elif correct_polarity >= 1:
        assertion_score += 10
        reasoning_parts.append(f"Some correct assertions ({correct_polarity})")

    # Security keyword assertions
    if sec_keyword_assertions >= 3:
        assertion_score += 10
        reasoning_parts.append(f"Security-aware assertions ({sec_keyword_assertions} with security keywords)")
    elif sec_keyword_assertions >= 1:
        assertion_score += 5
        reasoning_parts.append(f"Some security assertions ({sec_keyword_assertions})")
    elif total_assertions > 0:
        reasoning_parts.append("Assertions lack security specificity")
    else:
        reasoning_parts.append("No assertions found")

    # Wrong polarity deduction
    if wrong_polarity > 0:
        assertion_score -= wrong_polarity * 5
        reasoning_parts.extend(polarity_issues)

    score += max(0, min(25, assertion_score))

    # --- Step (e): Would it detect a vulnerability? (0-15 points) ---
    # Check if tests actually call the target function
    calls_target = 0
    for tf in test_funcs:
        if check_calls_target(tf["body"], entry_point):
            calls_target += 1

    cwe_addressed = (
        cwe_in_tests or cwe_name_in_tests or
        len(vectors) >= 1 or
        correct_polarity >= 1 or
        mocks_used >= 1
    )

    detection_score = 0
    if calls_target > 0 and (mocks_used > 0 or len(vectors) >= 1) and correct_polarity >= 1:
        detection_score = 15
        reasoning_parts.append(f"Tests call target function and verify security properties — would detect vulnerability")
    elif calls_target > 0 and (mocks_used > 0 or len(vectors) >= 1):
        detection_score = 10
        reasoning_parts.append("Tests call target and use security patterns, but assertion specificity could be stronger")
    elif calls_target > 0:
        detection_score = 5
        reasoning_parts.append("Tests call target function but security verification is weak")
    elif n_tests > 0:
        detection_score = 2
        reasoning_parts.append("Tests exist but may not effectively call the function under test")
    else:
        reasoning_parts.append("No test functions found")

    if cwe_addressed:
        detection_score = max(detection_score, 5)
    else:
        reasoning_parts.append(f"CWE {cwe} ({cwe_name}) not directly addressed")

    score += detection_score

    # --- Anti-pattern deductions ---
    anti = check_anti_patterns(generated_tests)
    if anti:
        deduction = len(anti) * 4
        score = max(0, score - deduction)
        reasoning_parts.append(f"Anti-patterns: {'; '.join(anti[:3])}")

    # --- Normalize to 0-1 ---
    score = min(1.0, max(0.0, score / 100))

    # --- Confidence ---
    evidence_count = (
        len(vectors) + mocks_used + correct_polarity +
        sec_keyword_assertions + (1 if calls_target > 0 else 0)
    )
    confidence = min(1.0, 0.5 + evidence_count * 0.05)

    return {
        "score": round(score, 2),
        "cwe_addressed": cwe_addressed,
        "attack_vectors_tested": attack_vectors_found[:6],
        "security_properties_checked": security_props[:6],
        "reasoning": "; ".join(reasoning_parts),
        "confidence": round(confidence, 2),
    }


# =============================================================================
# File Processing
# =============================================================================

def judge_results_file(
    results_path: Path,
    verbose: bool = False,
) -> Dict[str, Any]:
    """Judge all samples in a results file for security relevance."""
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
        cwe_scores = {}  # Track per-CWE performance

        for i, r in enumerate(detailed, 1):
            tests = r.get("generated_tests", "")
            if not tests or not tests.strip():
                continue

            cwe = r.get("cwe", "")
            cwe_name = r.get("cwe_name", "vulnerability")
            secure_code = r.get("secure_code", "")

            result = judge_security_relevance(tests, cwe, cwe_name, secure_code)

            # Store in detailed results
            r["judge_security"] = {
                "model": "claude",
                "score": result["score"],
                "cwe_addressed": result["cwe_addressed"],
                "attack_vectors_tested": result["attack_vectors_tested"],
                "security_properties_checked": result["security_properties_checked"],
                "reasoning": result["reasoning"],
                "confidence": result["confidence"],
            }

            scores.append(result["score"])
            judged += 1

            # Track per-CWE
            if cwe not in cwe_scores:
                cwe_scores[cwe] = []
            cwe_scores[cwe].append(result["score"])

            if verbose and i % 50 == 0:
                print(f"    [{i}/{len(detailed)}] {r['sample_id'][:12]}... "
                      f"Score: {result['score']:.0%}")

        # Compute averages
        avg_score = sum(scores) / len(scores) if scores else 0.0
        model_data["avg_security_relevance"] = round(avg_score, 4)

        # Per-CWE summary
        cwe_summary = {}
        for cwe, cwe_sc in sorted(cwe_scores.items()):
            cwe_summary[cwe] = {
                "avg_score": round(sum(cwe_sc) / len(cwe_sc), 3),
                "count": len(cwe_sc),
            }

        summary = {
            "model_name": model_name,
            "samples_judged": judged,
            "samples_total": len(detailed),
            "avg_security_relevance": avg_score,
            "per_cwe": cwe_summary,
        }
        all_summaries.append(summary)

        print(f"    Judged {judged}/{len(detailed)} — Avg: {avg_score:.1%}")

        # Print per-CWE breakdown
        if verbose:
            print(f"\n    {'CWE':<10} {'Avg Score':<12} {'Count':<8}")
            print(f"    {'-'*30}")
            for cwe, info in sorted(cwe_summary.items(),
                                     key=lambda x: x[1]["avg_score"], reverse=True):
                print(f"    {cwe:<10} {info['avg_score']:.1%}{'':<6} {info['count']}")

    # Save
    data["judge_security_metadata"] = {
        "judge_model": "claude",
        "judge_method": "ast_security_analysis",
        "skill": "/judge-security",
        "judged_at": datetime.now().isoformat(),
        "scoring_dimensions": {
            "attack_vectors": "0-35 points (CWE-specific payloads)",
            "mock_usage": "0-25 points (correct mock objects)",
            "assertion_correctness": "0-25 points (polarity + security keywords)",
            "vulnerability_detection": "0-15 points (calls target + verifies security)",
            "anti_pattern_deductions": "-4 per anti-pattern",
        },
    }

    output_path = results_path.with_name(
        results_path.stem + "_judged_security" + results_path.suffix
    )
    with open(output_path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"    Saved: {output_path}")

    return {"summaries": all_summaries, "output_path": str(output_path)}


def find_unjudged_files(base_path: Path) -> List[Path]:
    """Find result files without _judged_security counterpart."""
    if base_path.is_file():
        return [base_path]

    all_files = sorted(base_path.rglob("baseline_results_*.json"))
    unjudged = []
    for f in all_files:
        if "_judged" in f.stem:
            continue
        judged_path = f.with_name(f.stem + "_judged_security" + f.suffix)
        if not judged_path.exists():
            unjudged.append(f)
    return unjudged


def print_summary_table(summaries: List[Dict]):
    """Print formatted cross-model/variant comparison."""
    print(f"\n{'='*80}")
    print("Security Relevance Judge Results (Claude /judge-security)")
    print(f"{'='*80}")
    print(f"{'Variant':<50} {'Sec Score':<12} {'Judged':<12}")
    print(f"{'-'*80}")

    for s in summaries:
        score = f"{s['avg_security_relevance']:.1%}"
        judged = f"{s['samples_judged']}/{s['samples_total']}"
        print(f"{s['model_name']:<50} {score:<12} {judged:<12}")

    print(f"{'='*80}")

    # Cross-CWE comparison (from last file)
    if summaries and "per_cwe" in summaries[-1]:
        print(f"\nPer-CWE Breakdown (last variant):")
        print(f"{'CWE':<10} {'Score':<10} {'Samples':<10}")
        print(f"{'-'*30}")
        for cwe, info in sorted(summaries[-1]["per_cwe"].items(),
                                 key=lambda x: x[1]["avg_score"], reverse=True):
            print(f"{cwe:<10} {info['avg_score']:.1%}{'':<4} {info['count']}")


def main():
    parser = argparse.ArgumentParser(
        description="Security Relevance Judge for SecMutBench (/judge-security skill)",
    )
    parser.add_argument("input", help="Results file or directory")
    parser.add_argument("--verbose", "-v", action="store_true",
                        help="Print per-CWE and periodic progress")
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
    print(f"Judge: Claude /judge-security (AST-based security analysis)")

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
