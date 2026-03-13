#!/usr/bin/env python3
"""
Comprehensive audit script for the SecMutBench dataset.
Checks secure_code, insecure_code, tests, mutants, entry points,
and cross-sample quality across all samples.
"""

import json
import re
import ast
import sys
import os
from collections import defaultdict, Counter
from difflib import SequenceMatcher

DATASET_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "dataset.json")

# ============================================================
# Severity levels
# ============================================================
CRITICAL = "CRITICAL"
WARNING = "WARNING"
INFO = "INFO"

issues = []  # (severity, sample_id, cwe, source, entry_point, category, message)

def add_issue(severity, sample, category, message):
    issues.append((
        severity,
        sample.get("id", "?"),
        sample.get("cwe", "?"),
        sample.get("source", "?"),
        sample.get("entry_point", "?"),
        category,
        message,
    ))

# ============================================================
# Valid CWEs and difficulties
# ============================================================
VALID_CWES = {
    "CWE-20", "CWE-22", "CWE-74", "CWE-77", "CWE-78", "CWE-79",
    "CWE-89", "CWE-94", "CWE-95", "CWE-117", "CWE-200", "CWE-209",
    "CWE-250", "CWE-269", "CWE-276", "CWE-285", "CWE-287", "CWE-295",
    "CWE-306", "CWE-307", "CWE-311", "CWE-312", "CWE-319", "CWE-320",
    "CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-347",
    "CWE-352", "CWE-367", "CWE-377", "CWE-384", "CWE-400", "CWE-434",
    "CWE-502", "CWE-522", "CWE-532", "CWE-538", "CWE-539", "CWE-601",
    "CWE-611", "CWE-614", "CWE-639", "CWE-640", "CWE-643", "CWE-693",
    "CWE-706", "CWE-732", "CWE-759", "CWE-760", "CWE-776", "CWE-798",
    "CWE-862", "CWE-863", "CWE-915", "CWE-918", "CWE-943", "CWE-1004",
    "CWE-1333",
}

VALID_DIFFICULTIES = {"easy", "medium", "hard"}

# ============================================================
# CWE-to-operator mapping (expected alignments)
# ============================================================
CWE_OPERATOR_MAP = {
    "CWE-89":  {"PSQLI", "RVALID"},
    "CWE-78":  {"CMDINJECT", "RVALID"},
    "CWE-77":  {"CMDINJECT", "RVALID", "EVALINJECT"},
    "CWE-79":  {"RVALID", "SUBDOMAIN_SPOOF"},
    "CWE-22":  {"PATHCONCAT", "RVALID"},
    "CWE-20":  {"RVALID", "INPUTVAL"},
    "CWE-74":  {"RVALID", "LOGINJECT", "EVALINJECT"},
    "CWE-94":  {"EVALINJECT", "RVALID"},
    "CWE-95":  {"EVALINJECT", "RVALID"},
    "CWE-502": {"DESERIAL", "RVALID"},
    "CWE-327": {"WEAKCRYPTO", "WEAKKEY"},
    "CWE-328": {"WEAKCRYPTO"},
    "CWE-326": {"WEAKKEY", "WEAKCRYPTO"},
    "CWE-798": {"HARDCODE"},
    "CWE-306": {"RMAUTH", "MISSINGAUTH"},
    "CWE-862": {"RMAUTH", "MISSINGAUTH", "IDOR"},
    "CWE-863": {"RMAUTH", "MISSINGAUTH"},
    "CWE-611": {"XXE"},
    "CWE-918": {"SSRF", "RVALID"},
    "CWE-338": {"WEAKRANDOM"},
    "CWE-601": {"OPENREDIRECT", "RVALID"},
    "CWE-434": {"FILEUPLOAD", "RVALID"},
    "CWE-639": {"IDOR", "MISSINGAUTH"},
    "CWE-352": {"CSRF_REMOVE"},
    "CWE-319": {"RENCRYPT"},
    "CWE-117": {"LOGINJECT", "RVALID"},
    "CWE-209": {"INFOEXPOSE"},
    "CWE-400": {"REGEXDOS", "RVALID"},
    "CWE-732": {"RVALID", "MISSINGAUTH"},
    "CWE-915": {"RVALID"},
    "CWE-1333": {"REGEXDOS"},
    "CWE-643": {"LDAPINJECT", "RVALID"},
}

# ============================================================
# 1. Secure Code Audit
# ============================================================
def audit_secure_code(sample):
    code = sample.get("secure_code", "")
    cwe = sample.get("cwe", "")

    if not code.strip():
        add_issue(CRITICAL, sample, "secure_code", "Empty secure_code")
        return

    # CWE-89: SQL injection patterns in secure code
    if cwe == "CWE-89":
        # Check for f-string SQL
        if re.search(r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|DROP|WHERE|FROM).*\{', code, re.IGNORECASE):
            add_issue(CRITICAL, sample, "secure_code", "Contains f-string SQL formatting (SQL injection risk)")
        # Check for % formatting in SQL
        if re.search(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE|FROM).*%s.*["\']\s*%', code, re.IGNORECASE):
            # This could be legitimate % param style if using proper DB API, check if it's string formatting
            if re.search(r'%\s*\(', code) or re.search(r'%\s*[a-zA-Z_]', code):
                add_issue(WARNING, sample, "secure_code", "Uses % string formatting with SQL keywords (potential SQL injection)")
        # Check for string concatenation in SQL
        if re.search(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*["\']\s*\+', code, re.IGNORECASE):
            add_issue(WARNING, sample, "secure_code", "Uses string concatenation with SQL keywords")
        # Check for .format() in SQL
        if re.search(r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*["\']\.format\(', code, re.IGNORECASE):
            add_issue(CRITICAL, sample, "secure_code", "Uses .format() with SQL keywords (SQL injection)")

    # CWE-78: Command injection
    if cwe in ("CWE-78", "CWE-77"):
        if re.search(r'os\.system\s*\(', code):
            add_issue(CRITICAL, sample, "secure_code", "Contains os.system() call (command injection risk)")
        if re.search(r'os\.popen\s*\(', code):
            add_issue(CRITICAL, sample, "secure_code", "Contains os.popen() call (command injection risk)")
        if re.search(r'shell\s*=\s*True', code):
            add_issue(CRITICAL, sample, "secure_code", "Contains shell=True (command injection risk)")
        if re.search(r'subprocess\.call\s*\([^)]*shell\s*=\s*True', code, re.DOTALL):
            add_issue(CRITICAL, sample, "secure_code", "Contains subprocess with shell=True")

    # CWE-79: XSS - should have escaping
    if cwe == "CWE-79":
        has_escape = bool(re.search(r'html\.escape|escape\(|bleach|markupsafe|sanitize|cgi\.escape', code, re.IGNORECASE))
        has_user_input_in_output = bool(re.search(r'f["\'].*<.*\{.*\}.*>', code))
        if has_user_input_in_output and not has_escape:
            add_issue(WARNING, sample, "secure_code", "Has user input in HTML output but no html.escape or sanitization visible")

    # CWE-22: Path traversal
    if cwe == "CWE-22":
        has_path_validation = bool(re.search(
            r'os\.path\.commonpath|os\.path\.abspath|os\.path\.realpath|'
            r'os\.path\.commonprefix|\.startswith\(|resolve\(\)|'
            r'pathlib|normpath|\.\..*in.*path|sanitize.*path',
            code, re.IGNORECASE
        ))
        if not has_path_validation:
            add_issue(WARNING, sample, "secure_code", "No visible path validation for CWE-22 (path traversal)")

    # CWE-502: Deserialization
    if cwe == "CWE-502":
        if re.search(r'pickle\.loads?\s*\(', code) and not re.search(r'RestrictedUnpickler|_safe|allowed_classes', code):
            add_issue(CRITICAL, sample, "secure_code", "Contains pickle.load(s) without restriction (unsafe deserialization)")
        if re.search(r'yaml\.unsafe_load\s*\(', code):
            add_issue(CRITICAL, sample, "secure_code", "Contains yaml.unsafe_load (unsafe deserialization)")
        if re.search(r'yaml\.load\s*\(', code) and not re.search(r'Loader\s*=\s*yaml\.SafeLoader|safe_load', code):
            add_issue(WARNING, sample, "secure_code", "Contains yaml.load without SafeLoader")
        if re.search(r'marshal\.loads?\s*\(', code):
            add_issue(WARNING, sample, "secure_code", "Contains marshal.load(s) (unsafe deserialization)")

    # CWE-327/328: Weak cryptography
    if cwe in ("CWE-327", "CWE-328"):
        if re.search(r'hashlib\.(md5|sha1)\s*\(', code):
            # Check if it's used for passwords
            if re.search(r'password|passwd|pass_hash|hash_pass', code, re.IGNORECASE):
                add_issue(CRITICAL, sample, "secure_code", "Uses MD5/SHA1 for password hashing")
            else:
                add_issue(INFO, sample, "secure_code", "Uses MD5/SHA1 (may not be for passwords)")
        if re.search(r'DES|Blowfish|RC4|RC2', code) and not re.search(r'3DES|TripleDES', code):
            add_issue(WARNING, sample, "secure_code", "Uses weak encryption algorithm (DES/RC4/RC2)")

    # CWE-798: Hardcoded credentials
    if cwe == "CWE-798":
        # Look for hardcoded passwords/keys as string literals
        if re.search(r'password\s*=\s*["\'][^"\']+["\']', code, re.IGNORECASE):
            # But not if it's getting from environment or config
            if not re.search(r'os\.environ|os\.getenv|config\[|settings\.|\.get\(', code):
                add_issue(CRITICAL, sample, "secure_code", "Contains hardcoded password literal")
        if re.search(r'(?:api_key|secret_key|auth_token|secret)\s*=\s*["\'][a-zA-Z0-9]{8,}["\']', code, re.IGNORECASE):
            if not re.search(r'os\.environ|os\.getenv|config\[|settings\.|\.get\(', code):
                add_issue(CRITICAL, sample, "secure_code", "Contains hardcoded secret/API key")

    # CWE-611: XXE
    if cwe == "CWE-611":
        has_defusedxml = bool(re.search(r'defusedxml|defused', code))
        has_resolve_entities = bool(re.search(r'resolve_entities\s*=\s*False', code))
        has_external_entities_disabled = bool(re.search(r'XMLParser.*resolve_entities|no_network|forbid_dtd|forbid_entities', code))
        if not (has_defusedxml or has_resolve_entities or has_external_entities_disabled):
            # May still be safe if it doesn't parse XML at all
            if re.search(r'\.parse|\.fromstring|etree|ElementTree|minidom|sax|lxml', code):
                add_issue(WARNING, sample, "secure_code", "Parses XML without visible XXE protection (no defusedxml or resolve_entities=False)")

    # CWE-918: SSRF
    if cwe == "CWE-918":
        has_url_validation = bool(re.search(
            r'urlparse|hostname|scheme|netloc|blocklist|allowlist|whitelist|blacklist|'
            r'is_valid_url|validate_url|check_url|private|internal|127\.0\.0\.1|localhost|'
            r'ipaddress|is_private',
            code, re.IGNORECASE
        ))
        if not has_url_validation:
            add_issue(WARNING, sample, "secure_code", "No visible URL validation for SSRF prevention")

    # CWE-94/95: Code injection
    if cwe in ("CWE-94", "CWE-95"):
        if re.search(r'\beval\s*\(', code):
            # Check if eval is on user-controlled input
            add_issue(WARNING, sample, "secure_code", "Contains eval() call - check if input is sanitized")
        if re.search(r'\bexec\s*\(', code):
            add_issue(WARNING, sample, "secure_code", "Contains exec() call - check if input is sanitized")

    # CWE-306/862: Missing auth
    if cwe in ("CWE-306", "CWE-862"):
        has_auth = bool(re.search(
            r'authenticate|authorization|is_authenticated|is_authorized|check_auth|'
            r'require_auth|login_required|permission|role|token|session|current_user|'
            r'request\.user|@login|verify_token|check_permission',
            code, re.IGNORECASE
        ))
        if not has_auth:
            add_issue(WARNING, sample, "secure_code", "No visible authentication/authorization check")

    # CWE-338: Weak random
    if cwe == "CWE-338":
        if re.search(r'\brandom\.(randint|random|choice|randrange|sample)\b', code):
            if not re.search(r'secrets|os\.urandom|SystemRandom', code):
                add_issue(CRITICAL, sample, "secure_code", "Uses random module instead of secrets/os.urandom for security-sensitive operation")

    # CWE-601: Open redirect
    if cwe == "CWE-601":
        has_redirect_validation = bool(re.search(
            r'allowed_domains|allowed_urls|whitelist|is_safe_url|url_has_allowed_host|'
            r'startswith\s*\(\s*["\']/["\']|urlparse.*netloc|validate.*redirect|'
            r'safe.*url|is_valid.*redirect',
            code, re.IGNORECASE
        ))
        if not has_redirect_validation:
            add_issue(WARNING, sample, "secure_code", "No visible redirect URL validation for CWE-601")

    # CWE-319: Cleartext transmission
    if cwe == "CWE-319":
        if re.search(r'http://', code) and not re.search(r'https://', code):
            add_issue(WARNING, sample, "secure_code", "Uses http:// instead of https:// (cleartext transmission)")

    # CWE-117: Log injection
    if cwe == "CWE-117":
        has_sanitization = bool(re.search(
            r'replace\s*\(\s*["\']\\n|replace\s*\(\s*["\']\\r|sanitize|escape|strip|'
            r'encode\(|re\.sub',
            code
        ))
        if not has_sanitization:
            if re.search(r'log\w*\.\w+\(|logging\.\w+\(|print\(', code):
                add_issue(INFO, sample, "secure_code", "Logs user input without visible sanitization (CWE-117)")

    # CWE-732: Incorrect permission assignment
    if cwe == "CWE-732":
        if re.search(r'0o777|0o666|0o776|0o767|chmod.*777|chmod.*666', code):
            add_issue(CRITICAL, sample, "secure_code", "Uses overly permissive file permissions (777/666)")

    # CWE-400/1333: ReDoS
    if cwe in ("CWE-400", "CWE-1333"):
        # Check for dangerous regex patterns (nested quantifiers)
        regex_matches = re.findall(r're\.compile\s*\(\s*[rf]?["\'](.+?)["\']', code)
        for pattern in regex_matches:
            if re.search(r'\(.+\+\)\+|\(.+\*\)\+|\(.+\+\)\*|\(.+\*\)\*', pattern):
                add_issue(CRITICAL, sample, "secure_code", f"Contains potentially catastrophic regex: {pattern[:50]}")

    # CWE-434: File upload
    if cwe == "CWE-434":
        has_validation = bool(re.search(
            r'allowed_extensions|ALLOWED_EXTENSIONS|content_type|mime|file_type|'
            r'\.endswith\(|\.lower\(\).*in|secure_filename|validate_file',
            code, re.IGNORECASE
        ))
        if not has_validation:
            add_issue(WARNING, sample, "secure_code", "No visible file extension/type validation for upload")


# ============================================================
# 2. Insecure Code Audit
# ============================================================
def audit_insecure_code(sample):
    code = sample.get("insecure_code", "")
    cwe = sample.get("cwe", "")

    if not code.strip():
        add_issue(CRITICAL, sample, "insecure_code", "Empty insecure_code")
        return

    # Check that insecure code actually has the vulnerability
    if cwe == "CWE-89":
        has_sqli = bool(re.search(
            r'f["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*\{|'
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*["\']\s*\+|'
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*["\']\.format\(|'
            r'["\'].*(?:SELECT|INSERT|UPDATE|DELETE|WHERE).*%s.*["\'].*%\s',
            code, re.IGNORECASE
        ))
        if not has_sqli:
            add_issue(CRITICAL, sample, "insecure_code", "CWE-89 insecure_code does not contain SQL string formatting")

    if cwe in ("CWE-78", "CWE-77"):
        has_cmdinj = bool(re.search(
            r'os\.system\s*\(|os\.popen\s*\(|shell\s*=\s*True|'
            r'subprocess\.\w+\s*\([^)]*shell\s*=\s*True|'
            r'eval\s*\(|exec\s*\(',
            code, re.DOTALL
        ))
        if not has_cmdinj:
            add_issue(WARNING, sample, "insecure_code", "CWE-78/77 insecure_code may not contain command injection pattern")

    if cwe == "CWE-79":
        has_xss = bool(re.search(r'f["\'].*<.*\{|\.format\(|%\s*[({]|<.*\+.*>|\+.*</', code))
        has_escape = bool(re.search(r'html\.escape|escape\(|bleach|markupsafe|cgi\.escape', code, re.IGNORECASE))
        if has_escape:
            add_issue(WARNING, sample, "insecure_code", "CWE-79 insecure_code has html.escape (should be missing)")

    if cwe == "CWE-22":
        has_path_validation = bool(re.search(
            r'os\.path\.commonpath|os\.path\.abspath.*startswith|os\.path\.realpath.*startswith|'
            r'resolve\(\).*is_relative_to|normpath.*startswith',
            code, re.DOTALL
        ))
        if has_path_validation:
            add_issue(WARNING, sample, "insecure_code", "CWE-22 insecure_code appears to have path validation (should be missing)")

    if cwe == "CWE-502":
        has_unsafe_deser = bool(re.search(
            r'pickle\.loads?\s*\(|yaml\.unsafe_load|yaml\.load\s*\([^)]*\)|'
            r'jsonpickle\.decode|marshal\.loads?\s*\(|shelve\.open',
            code
        ))
        if not has_unsafe_deser:
            add_issue(WARNING, sample, "insecure_code", "CWE-502 insecure_code may not contain unsafe deserialization")

    if cwe in ("CWE-327", "CWE-328"):
        has_weak_crypto = bool(re.search(
            r'hashlib\.(md5|sha1)\s*\(|DES\b|RC4|Blowfish|MD5|SHA1',
            code
        ))
        if not has_weak_crypto:
            # Also check for missing crypto entirely
            pass

    if cwe == "CWE-798":
        has_hardcoded = bool(re.search(
            r'(?:password|secret|key|token|api_key)\s*=\s*["\'][^"\']+["\']',
            code, re.IGNORECASE
        ))
        if not has_hardcoded:
            add_issue(INFO, sample, "insecure_code", "CWE-798 insecure_code may not have obviously hardcoded credential")

    if cwe == "CWE-611":
        has_xxe_vuln = bool(re.search(
            r'etree\.parse|etree\.fromstring|minidom\.parse|ElementTree|sax\.parse|lxml',
            code
        ))
        has_protection = bool(re.search(r'defusedxml|resolve_entities\s*=\s*False', code))
        if has_protection:
            add_issue(WARNING, sample, "insecure_code", "CWE-611 insecure_code has XXE protection (should be vulnerable)")

    if cwe == "CWE-918":
        has_ssrf_protection = bool(re.search(
            r'is_private|blocklist|blacklist|private|internal|validate_url|is_safe_url|'
            r'hostname.*not.*in|scheme.*not.*in',
            code, re.IGNORECASE
        ))
        if has_ssrf_protection:
            add_issue(WARNING, sample, "insecure_code", "CWE-918 insecure_code has SSRF protection (should be vulnerable)")

    if cwe in ("CWE-94", "CWE-95"):
        has_code_injection = bool(re.search(r'\beval\s*\(|\bexec\s*\(|compile\s*\(', code))
        has_protection = bool(re.search(r'ast\.literal_eval|sanitize|whitelist|allowed|restrict', code, re.IGNORECASE))
        # Insecure should have eval/exec or lack sanitization
        if has_protection and has_code_injection:
            add_issue(INFO, sample, "insecure_code", "CWE-94/95 insecure_code has both eval and sanitization (check logic)")

    if cwe in ("CWE-306", "CWE-862"):
        has_auth = bool(re.search(
            r'authenticate|is_authenticated|check_auth|require_auth|login_required|'
            r'verify_token|check_permission|@login|is_authorized',
            code, re.IGNORECASE
        ))
        if has_auth:
            add_issue(INFO, sample, "insecure_code", "CWE-306/862 insecure_code has auth check (should be missing)")

    if cwe == "CWE-338":
        uses_secure = bool(re.search(r'secrets\.|os\.urandom|SystemRandom', code))
        if uses_secure:
            add_issue(CRITICAL, sample, "insecure_code", "CWE-338 insecure_code uses secure random (should use random module)")


# ============================================================
# 3. Diff Quality
# ============================================================
def audit_diff_quality(sample):
    secure = sample.get("secure_code", "").strip()
    insecure = sample.get("insecure_code", "").strip()

    if not secure or not insecure:
        return

    # Check if they are identical
    if secure == insecure:
        add_issue(CRITICAL, sample, "diff_quality", "secure_code and insecure_code are IDENTICAL")
        return

    # Check similarity ratio
    ratio = SequenceMatcher(None, secure, insecure).ratio()
    if ratio > 0.99:
        add_issue(WARNING, sample, "diff_quality", f"secure_code and insecure_code are nearly identical (similarity={ratio:.4f})")

    # Check if diff is only whitespace
    secure_nows = re.sub(r'\s+', '', secure)
    insecure_nows = re.sub(r'\s+', '', insecure)
    if secure_nows == insecure_nows:
        add_issue(CRITICAL, sample, "diff_quality", "Difference is only whitespace (not a security-relevant change)")

    # Check if diff is only comments
    secure_nocomments = re.sub(r'#.*$', '', secure, flags=re.MULTILINE).strip()
    insecure_nocomments = re.sub(r'#.*$', '', insecure, flags=re.MULTILINE).strip()
    secure_nocomments = re.sub(r'""".*?"""', '', secure_nocomments, flags=re.DOTALL).strip()
    insecure_nocomments = re.sub(r'""".*?"""', '', insecure_nocomments, flags=re.DOTALL).strip()
    if secure_nocomments == insecure_nocomments:
        add_issue(CRITICAL, sample, "diff_quality", "Difference is only in comments/docstrings (not a security-relevant change)")


# ============================================================
# 4. Test Quality
# ============================================================
def audit_test_quality(sample):
    tests = sample.get("security_tests", "")
    entry_point = sample.get("entry_point", "")

    if not tests.strip():
        add_issue(CRITICAL, sample, "test_quality", "Empty security_tests")
        return

    # Check compilation
    try:
        ast.parse(tests)
    except SyntaxError as e:
        add_issue(CRITICAL, sample, "test_quality", f"security_tests have SyntaxError: {e}")
        return

    # Check for real assertions
    has_assert = bool(re.search(r'\bassert\b', tests))
    if not has_assert:
        add_issue(CRITICAL, sample, "test_quality", "security_tests contain no assert statements")

    # Check for trivial assertions
    trivial_asserts = re.findall(r'assert\s+True\b', tests)
    all_asserts = re.findall(r'\bassert\b', tests)
    if trivial_asserts and len(trivial_asserts) == len(all_asserts):
        add_issue(CRITICAL, sample, "test_quality", "All assertions are trivial 'assert True'")
    elif trivial_asserts:
        add_issue(WARNING, sample, "test_quality", f"Contains {len(trivial_asserts)} trivial 'assert True' out of {len(all_asserts)} assertions")

    # Check for `assert False` (always-fail tests)
    assert_false_count = len(re.findall(r'assert\s+False\b', tests))
    if assert_false_count > 0:
        add_issue(WARNING, sample, "test_quality", f"Contains {assert_false_count} 'assert False' statements (always-fail)")

    # Check for entry_point reference
    if entry_point and entry_point not in tests:
        add_issue(CRITICAL, sample, "test_quality", f"security_tests do not reference entry_point '{entry_point}'")

    # Check for test functions
    test_funcs = re.findall(r'def\s+(test_\w+)', tests)
    if not test_funcs:
        add_issue(CRITICAL, sample, "test_quality", "No test functions (def test_*) found in security_tests")

    # Check assertion messages reference security concepts
    cwe = sample.get("cwe", "")
    assertion_messages = re.findall(r'assert\s+.*?,\s*["\'](.+?)["\']', tests, re.DOTALL)
    assertion_messages += re.findall(r'assert\s+.*?,\s*f["\'](.+?)["\']', tests, re.DOTALL)
    if assertion_messages:
        security_terms = {
            "CWE-89": ["sql", "injection", "parameterized", "query"],
            "CWE-78": ["command", "injection", "shell", "subprocess"],
            "CWE-77": ["command", "injection", "shell"],
            "CWE-79": ["xss", "cross-site", "escape", "sanitiz"],
            "CWE-22": ["path", "traversal", "directory"],
            "CWE-502": ["deserializ", "pickle", "yaml", "marshal", "unsafe"],
            "CWE-327": ["crypto", "hash", "weak", "algorithm", "md5", "sha1"],
            "CWE-328": ["crypto", "hash", "weak", "algorithm"],
            "CWE-798": ["hardcod", "credential", "password", "secret"],
            "CWE-611": ["xxe", "xml", "entity", "external"],
            "CWE-918": ["ssrf", "url", "request", "internal", "server-side"],
            "CWE-94":  ["eval", "exec", "code", "injection"],
            "CWE-95":  ["eval", "exec", "code", "injection"],
            "CWE-306": ["auth", "permission", "access"],
            "CWE-862": ["auth", "permission", "access", "authorization"],
            "CWE-338": ["random", "secure", "predictab"],
            "CWE-601": ["redirect", "url", "open redirect"],
            "CWE-352": ["csrf", "token", "cross-site"],
        }
        terms = security_terms.get(cwe, [])
        if terms:
            all_messages = " ".join(assertion_messages).lower()
            has_security_term = any(t in all_messages for t in terms)
            if not has_security_term:
                add_issue(INFO, sample, "test_quality",
                          f"Assertion messages don't reference CWE-specific security terms: {terms[:3]}")


# ============================================================
# 5. Mutant Quality
# ============================================================
def audit_mutant_quality(sample):
    mutants = sample.get("mutants", [])
    secure_code = sample.get("secure_code", "")
    cwe = sample.get("cwe", "")
    mutation_operators = set(sample.get("mutation_operators", []))

    if not mutants:
        add_issue(CRITICAL, sample, "mutant_quality", "No mutants present")
        return

    for i, mutant in enumerate(mutants):
        mid = mutant.get("id", f"mutant_{i}")
        mcode = mutant.get("mutated_code", "")
        mop = mutant.get("operator", "")

        # Check compilation
        if not mcode.strip():
            add_issue(CRITICAL, sample, "mutant_quality", f"Mutant {mid}: empty mutated_code")
            continue

        try:
            ast.parse(mcode)
        except SyntaxError as e:
            add_issue(CRITICAL, sample, "mutant_quality", f"Mutant {mid} ({mop}): SyntaxError: {e}")
            continue

        # Check differs from secure code
        if mcode.strip() == secure_code.strip():
            add_issue(CRITICAL, sample, "mutant_quality", f"Mutant {mid} ({mop}): identical to secure_code (equivalent mutant)")

        # Check operator is in sample's mutation_operators
        if mop and mop not in mutation_operators:
            add_issue(WARNING, sample, "mutant_quality",
                      f"Mutant {mid}: operator '{mop}' not in sample's mutation_operators {mutation_operators}")

        # Check operator aligns with CWE
        expected_ops = CWE_OPERATOR_MAP.get(cwe, set())
        if mop and expected_ops and mop not in expected_ops:
            add_issue(WARNING, sample, "mutant_quality",
                      f"Mutant {mid}: operator '{mop}' not expected for {cwe} (expected: {expected_ops})")


# ============================================================
# 6. Entry Point Existence
# ============================================================
def audit_entry_point(sample):
    entry_point = sample.get("entry_point", "")
    if not entry_point:
        add_issue(CRITICAL, sample, "entry_point", "No entry_point defined")
        return

    secure = sample.get("secure_code", "")
    insecure = sample.get("insecure_code", "")

    # Check entry_point is defined as a function or class in secure_code
    ep_pattern = rf'def\s+{re.escape(entry_point)}\s*\(|class\s+{re.escape(entry_point)}\b'
    if not re.search(ep_pattern, secure):
        add_issue(CRITICAL, sample, "entry_point", f"entry_point '{entry_point}' not found in secure_code")

    if not re.search(ep_pattern, insecure):
        add_issue(CRITICAL, sample, "entry_point", f"entry_point '{entry_point}' not found in insecure_code")


# ============================================================
# 7. Cross-Sample Checks
# ============================================================
def audit_cross_sample(samples):
    """Check for near-duplicates and other cross-sample issues."""
    # Check CWE validity
    for s in samples:
        cwe = s.get("cwe", "")
        if cwe not in VALID_CWES:
            add_issue(WARNING, s, "cross_sample", f"CWE '{cwe}' not in common CWE list (may still be valid)")

        diff = s.get("difficulty", "")
        if diff not in VALID_DIFFICULTIES:
            add_issue(CRITICAL, s, "cross_sample", f"Invalid difficulty: '{diff}'")

        # Check required fields
        for field in ["id", "cwe", "cwe_name", "difficulty", "entry_point",
                       "secure_code", "insecure_code", "security_tests", "mutants"]:
            if not s.get(field):
                add_issue(CRITICAL, s, "cross_sample", f"Missing required field: '{field}'")

    # Near-duplicate detection on secure_code
    print("  Checking for near-duplicate secure_code (this may take a moment)...")
    n = len(samples)
    duplicates_found = 0
    for i in range(n):
        for j in range(i + 1, n):
            code_i = samples[i].get("secure_code", "")
            code_j = samples[j].get("secure_code", "")
            if not code_i or not code_j:
                continue
            # Quick length check to skip obviously different
            len_ratio = min(len(code_i), len(code_j)) / max(len(code_i), len(code_j))
            if len_ratio < 0.7:
                continue
            ratio = SequenceMatcher(None, code_i, code_j).ratio()
            if ratio > 0.90:
                add_issue(WARNING, samples[i], "cross_sample",
                          f"Near-duplicate secure_code with sample {samples[j]['id']} "
                          f"({samples[j]['cwe']}/{samples[j]['entry_point']}) - similarity={ratio:.3f}")
                duplicates_found += 1
    print(f"  Found {duplicates_found} near-duplicate pairs.")

    # Check for duplicate IDs
    ids = [s.get("id", "") for s in samples]
    id_counts = Counter(ids)
    for id_val, count in id_counts.items():
        if count > 1:
            add_issue(CRITICAL, {"id": id_val, "cwe": "?", "source": "?", "entry_point": "?"},
                      "cross_sample", f"Duplicate sample ID '{id_val}' appears {count} times")

    # Check for duplicate entry_points within same CWE
    cwe_entry_points = defaultdict(list)
    for s in samples:
        cwe_entry_points[s.get("cwe", "")].append((s.get("entry_point", ""), s.get("id", "")))
    for cwe, eps in cwe_entry_points.items():
        ep_names = [ep[0] for ep in eps]
        ep_counts = Counter(ep_names)
        for ep, count in ep_counts.items():
            if count > 1:
                dup_ids = [eid for ename, eid in eps if ename == ep]
                add_issue(INFO, {"id": dup_ids[0], "cwe": cwe, "source": "?", "entry_point": ep},
                          "cross_sample", f"Duplicate entry_point '{ep}' in {cwe} ({count} samples: {dup_ids})")


# ============================================================
# 8. Additional: Check functional_tests quality
# ============================================================
def audit_functional_tests(sample):
    tests = sample.get("functional_tests", "")
    if not tests.strip():
        add_issue(INFO, sample, "functional_tests", "Empty functional_tests")
        return
    try:
        ast.parse(tests)
    except SyntaxError as e:
        add_issue(WARNING, sample, "functional_tests", f"functional_tests have SyntaxError: {e}")


# ============================================================
# Main
# ============================================================
def main():
    print("=" * 80)
    print("SecMutBench Dataset Comprehensive Audit")
    print("=" * 80)

    # Load dataset
    with open(DATASET_PATH, "r") as f:
        data = json.load(f)

    samples = data.get("samples", [])
    metadata = data.get("metadata", {})

    print(f"\nDataset: {metadata.get('name', '?')} v{metadata.get('version', '?')}")
    print(f"Total samples: {len(samples)}")
    print(f"Created: {metadata.get('created', '?')}")
    print()

    # Run all audits
    print("[1/8] Auditing secure_code...")
    for s in samples:
        audit_secure_code(s)

    print("[2/8] Auditing insecure_code...")
    for s in samples:
        audit_insecure_code(s)

    print("[3/8] Auditing diff quality...")
    for s in samples:
        audit_diff_quality(s)

    print("[4/8] Auditing test quality...")
    for s in samples:
        audit_test_quality(s)

    print("[5/8] Auditing mutant quality...")
    for s in samples:
        audit_mutant_quality(s)

    print("[6/8] Auditing entry points...")
    for s in samples:
        audit_entry_point(s)

    print("[7/8] Auditing cross-sample quality...")
    audit_cross_sample(samples)

    print("[8/8] Auditing functional tests...")
    for s in samples:
        audit_functional_tests(s)

    print()

    # ============================================================
    # Report
    # ============================================================
    print("=" * 80)
    print("AUDIT REPORT")
    print("=" * 80)

    # Group by severity
    by_severity = defaultdict(list)
    for issue in issues:
        by_severity[issue[0]].append(issue)

    for severity in [CRITICAL, WARNING, INFO]:
        severity_issues = by_severity.get(severity, [])
        print(f"\n{'=' * 60}")
        print(f"  {severity} ({len(severity_issues)} issues)")
        print(f"{'=' * 60}")

        if not severity_issues:
            print("  None found.")
            continue

        # Group by category
        by_category = defaultdict(list)
        for issue in severity_issues:
            by_category[issue[5]].append(issue)

        for category, cat_issues in sorted(by_category.items()):
            print(f"\n  --- {category} ({len(cat_issues)}) ---")
            for issue in cat_issues:
                _, sid, cwe, source, ep, cat, msg = issue
                print(f"    [{sid[:12]}] {cwe} | {source} | {ep}")
                print(f"      -> {msg}")

    # ============================================================
    # Summary Statistics
    # ============================================================
    print()
    print("=" * 80)
    print("SUMMARY STATISTICS")
    print("=" * 80)

    total_issues = len(issues)
    print(f"\nTotal issues found: {total_issues}")
    print(f"  CRITICAL: {len(by_severity.get(CRITICAL, []))}")
    print(f"  WARNING:  {len(by_severity.get(WARNING, []))}")
    print(f"  INFO:     {len(by_severity.get(INFO, []))}")

    # Issues by category
    cat_counts = Counter(i[5] for i in issues)
    print(f"\nIssues by category:")
    for cat, count in cat_counts.most_common():
        print(f"  {cat}: {count}")

    # Issues by CWE
    cwe_counts = Counter(i[2] for i in issues)
    print(f"\nIssues by CWE (top 15):")
    for cwe, count in cwe_counts.most_common(15):
        print(f"  {cwe}: {count}")

    # Issues by source
    source_counts = Counter(i[3] for i in issues)
    print(f"\nIssues by source:")
    for source, count in source_counts.most_common():
        print(f"  {source}: {count}")

    # Samples with zero issues
    sample_ids_with_issues = set(i[1] for i in issues)
    clean_samples = [s for s in samples if s["id"] not in sample_ids_with_issues]
    print(f"\nClean samples (zero issues): {len(clean_samples)} / {len(samples)}")

    # Samples with CRITICAL issues
    critical_sample_ids = set(i[1] for i in by_severity.get(CRITICAL, []))
    print(f"Samples with CRITICAL issues: {len(critical_sample_ids)} / {len(samples)}")

    # Dataset health score
    critical_count = len(by_severity.get(CRITICAL, []))
    warning_count = len(by_severity.get(WARNING, []))
    # Weighted score: each critical = -2 points, each warning = -0.5
    max_score = len(samples) * 10  # 10 points per sample
    score = max_score - (critical_count * 2) - (warning_count * 0.5)
    health_pct = max(0, score / max_score * 100)
    print(f"\nDataset health score: {health_pct:.1f}% ({score:.0f}/{max_score})")

    # Mutant stats
    total_mutants = sum(len(s.get("mutants", [])) for s in samples)
    compilable_mutants = 0
    non_equivalent = 0
    for s in samples:
        for m in s.get("mutants", []):
            mcode = m.get("mutated_code", "")
            try:
                ast.parse(mcode)
                compilable_mutants += 1
            except:
                pass
            if mcode.strip() != s.get("secure_code", "").strip():
                non_equivalent += 1

    print(f"\nMutant statistics:")
    print(f"  Total mutants: {total_mutants}")
    print(f"  Compilable: {compilable_mutants} ({compilable_mutants/max(1,total_mutants)*100:.1f}%)")
    print(f"  Non-equivalent: {non_equivalent} ({non_equivalent/max(1,total_mutants)*100:.1f}%)")
    print(f"  Avg mutants/sample: {total_mutants/max(1,len(samples)):.1f}")

    # CWE coverage
    cwes_in_dataset = set(s.get("cwe", "") for s in samples)
    print(f"\nCWE coverage: {len(cwes_in_dataset)} CWEs")
    for cwe in sorted(cwes_in_dataset, key=lambda x: int(x.split("-")[1]) if "-" in x else 0):
        count = sum(1 for s in samples if s.get("cwe") == cwe)
        print(f"  {cwe}: {count} samples")

    # Difficulty distribution
    print(f"\nDifficulty distribution:")
    for diff in ["easy", "medium", "hard"]:
        count = sum(1 for s in samples if s.get("difficulty") == diff)
        print(f"  {diff}: {count}")

    # Source distribution
    print(f"\nSource distribution:")
    source_counter = Counter(s.get("source", "?") for s in samples)
    for source, count in source_counter.most_common():
        print(f"  {source}: {count}")

    print()
    print("=" * 80)
    print("AUDIT COMPLETE")
    print("=" * 80)


if __name__ == "__main__":
    main()
