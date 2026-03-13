#!/usr/bin/env python3
"""
CWEval Validation Script for SecMutBench

Loads data/validation.json (CWEval expert-verified pairs) and runs three
validation checks against the main data/dataset.json:

  Check 1: Mutation Operator Sanity
    - Do our mutation operators produce mutants in the same vulnerability class
      as CWEval's known insecure code?

  Check 2: Vulnerability Detection Ground Truth
    - Phase A: CWEval expert tests detect their own vulnerability (baseline)
    - Phase B: SecMutBench pipeline tests detect the same vulnerability

  Check 3: Attack Vector Coverage
    - What fraction of CWEval's attack categories does SecMutBench cover?

Usage:
    python evaluation/validate_with_cweval.py
    python evaluation/validate_with_cweval.py --checks mutation
    python evaluation/validate_with_cweval.py --checks detection
    python evaluation/validate_with_cweval.py --checks coverage
    python evaluation/validate_with_cweval.py --cwe CWE-78 --verbose
"""

import argparse
import difflib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Tuple

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

# Import test runner for SecMutBench pipeline tests (mock-based)
try:
    from evaluation.test_runner import TestRunner, TestSuiteResult
    TEST_RUNNER_AVAILABLE = True
except ImportError:
    TEST_RUNNER_AVAILABLE = False

# Import source_ingestion for normalize_cwe
scripts_dir = str(PROJECT_ROOT / "scripts")
if scripts_dir not in sys.path:
    sys.path.insert(0, scripts_dir)
try:
    from source_ingestion import normalize_cwe
except ImportError:
    def normalize_cwe(cwe):
        import re as _re
        m = _re.match(r'CWE-0*(\d+)', cwe)
        return f"CWE-{m.group(1)}" if m else cwe


# =============================================================================
# Minimal Conftest for CWEval (no mocks)
# =============================================================================

MINIMAL_CONFTEST = '''
import json
import os as _real_os


# Register custom markers so pytest doesn't warn
def pytest_configure(config):
    config.addinivalue_line("markers", "functionality: functionality test")
    config.addinivalue_line("markers", "security: security test")


class ResultCollector:
    """Pytest plugin that collects test results and writes to JSON."""

    def __init__(self):
        self.results = []

    def pytest_runtest_makereport(self, item, call):
        if call.when == "call":
            error = None
            error_type = None
            if call.excinfo is not None:
                error_type = call.excinfo.typename
                error = f"{error_type}: {str(call.excinfo.value)}"

            self.results.append({
                "name": item.name,
                "passed": call.excinfo is None,
                "error": error,
                "error_type": error_type,
            })

    def pytest_sessionfinish(self, session, exitstatus):
        results_path = _real_os.environ.get(
            "CWEVAL_RESULTS_PATH",
            _real_os.path.join(_real_os.getcwd(), "results.json"),
        )
        with open(results_path, "w") as f:
            json.dump(self.results, f, indent=2)


_collector = ResultCollector()


def pytest_configure(config):
    config.addinivalue_line("markers", "functionality: functionality test")
    config.addinivalue_line("markers", "security: security test")
    config.pluginmanager.register(_collector, "cweval_collector")
'''


# =============================================================================
# CWEval Test Runner (clean subprocess, no mocks)
# =============================================================================

class CWEvalTestRunner:
    """
    Test runner for CWEval expert tests.

    Unlike TestRunner, this runs in a clean subprocess with NO mock injection.
    CWEval code uses real subprocess, hashlib, os, etc.
    """

    def __init__(self, timeout: float = 30.0):
        self.timeout = timeout

    def run_test(
        self,
        test_code: str,
        target_code: str,
    ) -> TestSuiteResult:
        """
        Run CWEval expert tests against target code.

        Args:
            test_code: Reconstructed CWEval test code (imports from target_module)
            target_code: Secure or insecure implementation

        Returns:
            TestSuiteResult with outcomes
        """
        result = TestSuiteResult()

        with tempfile.TemporaryDirectory(prefix="cweval_") as tmp_dir:
            # Write target module
            target_path = os.path.join(tmp_dir, "target_module.py")
            with open(target_path, "w") as f:
                f.write(target_code)

            # Write test file
            test_path = os.path.join(tmp_dir, "test_cweval.py")
            with open(test_path, "w") as f:
                f.write(test_code)

            # Write minimal conftest (ResultCollector only, no mocks)
            conftest_path = os.path.join(tmp_dir, "conftest.py")
            with open(conftest_path, "w") as f:
                f.write(MINIMAL_CONFTEST)

            # Environment
            results_json_path = os.path.join(tmp_dir, "results.json")
            env = os.environ.copy()
            env["CWEVAL_RESULTS_PATH"] = results_json_path
            # Add project root for any project-level imports
            existing = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = str(PROJECT_ROOT) + (
                os.pathsep + existing if existing else ""
            )

            # Run pytest
            try:
                proc = subprocess.run(
                    [sys.executable, "-m", "pytest", "test_cweval.py",
                     "--tb=short", "-q", "--no-header"],
                    cwd=tmp_dir,
                    timeout=self.timeout,
                    capture_output=True,
                    text=True,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                result.errors = 1
                result.total = 1
                result.tests.append(type('TestResult', (), {
                    'name': 'timeout', 'passed': False,
                    'error': f'Timeout after {self.timeout}s', 'output': ''
                })())
                return result

            # Parse results
            if os.path.exists(results_json_path):
                try:
                    with open(results_json_path) as f:
                        data = json.load(f)
                    for td in data:
                        tr = type('TestResult', (), {
                            'name': td.get('name', 'unknown'),
                            'passed': td.get('passed', False),
                            'error': td.get('error'),
                            'output': '',
                        })()
                        result.tests.append(tr)
                        if tr.passed:
                            result.passed += 1
                        else:
                            result.failed += 1
                    result.total = len(result.tests)
                except (json.JSONDecodeError, IOError):
                    pass

            # Fallback: parse pytest output
            if result.total == 0 and proc.returncode != 0:
                combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
                result.errors = 1
                result.total = 1
                result.tests.append(type('TestResult', (), {
                    'name': 'pytest_error', 'passed': False,
                    'error': combined[:500], 'output': ''
                })())

        return result


# =============================================================================
# Vulnerability Fingerprints (for Check 1)
# =============================================================================

VULN_FINGERPRINTS = {
    "CWE-78": {
        "patterns": [r'shell\s*=\s*True', r'os\.system', r'os\.popen',
                     r'f["\'].*\{.*\}', r'f".*\{.*}"', r'subprocess\.call.*shell',
                     r'subprocess\.run.*shell', r'Popen.*shell'],
        "description": "Command injection via shell=True or string interpolation",
    },
    "CWE-22": {
        "patterns": [r'\.\./', r'\.\.\\\\', r'(?<!os\.path\.abs)join\(',
                     r'f["\'].*\{.*\}.*/', r'\+\s*["\']/', r'/\s*\+'],
        "description": "Path traversal via missing path validation",
    },
    "CWE-79": {
        "patterns": [r'(?<!html\.escape\()(?<!escape\(){.*}',
                     r'(?<!html\.escape)f["\'].*\{.*\}',
                     r'autoescape\s*=\s*False'],
        "description": "XSS via missing HTML escaping",
    },
    "CWE-327": {
        "patterns": [r'\bmd5\b', r'\bsha1\b', r'hashlib\.md5', r'hashlib\.sha1',
                     r'iterations\s*=\s*1\b', r'DES'],
        "description": "Weak hash algorithm (MD5/SHA1)",
    },
    "CWE-502": {
        "patterns": [r'yaml\.load\b(?!\s*\(.*safe)', r'pickle\.loads?\b',
                     r'Loader\s*=\s*Loader', r'yaml\.unsafe_load', r'\beval\(',
                     r'UnsafeLoader', r'FullLoader', r'marshal\.loads?\b',
                     r'!!python/object', r'!!python/apply', r'object_hook'],
        "description": "Insecure deserialization",
    },
    "CWE-918": {
        "patterns": [r'(?<!not\s)(?<!\.is)alnum', r'urlparse.*netloc',
                     r'requests\.get\(.*url', r'urllib.*urlopen',
                     r'127\.0\.0\.1', r'169\.254', r'localhost'],
        "description": "Missing URL/input validation for SSRF",
    },
    "CWE-20": {
        "patterns": [r'\.endswith\(', r'\.startswith\(', r'in\s+target_url\.netloc',
                     r'netloc\s+not\s+in', r'allowed_domains', r'valid_domains',
                     r'isinstance\s*\(', r'type\s*\(\s*\w+\s*\)\s*[!=]=',
                     r'\.isdigit\(\)', r'\.isnumeric\(\)', r'len\s*\(.*\)\s*[<>=]',
                     r'urlparse', r'\.netloc', r'\.scheme'],
        "description": "Incomplete input validation",
    },
    "CWE-89": {
        "patterns": [r'f["\'].*SELECT', r'f["\'].*INSERT', r'\.format\(.*SELECT',
                     r'%s.*SELECT', r'\+\s*["\'].*WHERE', r'execute\(.*\+'],
        "description": "SQL injection via string formatting",
    },
    "CWE-611": {
        "patterns": [r'resolve_entities\s*=\s*True', r'load_dtd\s*=\s*True',
                     r'no_network\s*=\s*False', r'xml\.etree', r'XMLParser\(\)'],
        "description": "XXE via enabled external entity processing",
    },
    "CWE-287": {
        "patterns": [r'is_authenticated.*True', r'check_auth.*True',
                     r'@login_required', r'bypass', r'skip.*auth'],
        "description": "Authentication bypass",
    },
    "CWE-798": {
        "patterns": [r'password\s*=\s*["\']', r'secret\s*=\s*["\']',
                     r'api_key\s*=\s*["\']', r'SuperSecret', r'admin123'],
        "description": "Hardcoded credentials",
    },
    "CWE-338": {
        "patterns": [r'random\.random', r'random\.randint', r'random\.choice',
                     r'random\.randbytes', r'(?<!System)Random\(\)'],
        "description": "Weak random number generation",
    },
    # New CWEs added in v2.5.0
    "CWE-95": {
        "patterns": [r'\beval\s*\(', r'\bexec\s*\(', r'compile\s*\(',
                     r'__import__', r'importlib\.import_module'],
        "description": "Code injection via eval/exec",
    },
    "CWE-601": {
        "patterns": [r'redirect\s*\(', r'302', r'301', r'Location:',
                     r'url_for.*_external', r'next=', r'return_url='],
        "description": "Open redirect via unvalidated URL",
    },
    "CWE-295": {
        "patterns": [r'verify\s*=\s*False', r'CERT_NONE', r'check_hostname\s*=\s*False',
                     r'ssl\._create_unverified_context', r'InsecureRequestWarning'],
        "description": "Disabled SSL/TLS certificate validation",
    },
    "CWE-209": {
        "patterns": [r'traceback', r'\.stack', r'exc_info', r'print\s*\(.*exception',
                     r'str\s*\(\s*e\s*\)', r'repr\s*\(\s*e\s*\)', r'debug\s*=\s*True'],
        "description": "Sensitive information in error messages",
    },
    "CWE-400": {
        "patterns": [r'\(\.\*\)\+', r'\(\.\+\)\+', r'\(\[.*\]\+\)\+', r'\(\w\+\)\+',
                     r'a\{1,100\}\{1,100\}', r'\(\?:.*\)\{.*\}\{'],
        "description": "ReDoS via catastrophic backtracking regex",
    },
    "CWE-1333": {
        "patterns": [r'\(\.\*\)\+', r'\(\.\+\)\+', r'\(\[.*\]\+\)\+', r'\(\w\+\)\+',
                     r'a\{1,100\}\{1,100\}', r'\(\?:.*\)\{.*\}\{'],
        "description": "ReDoS via inefficient regex (alias of CWE-400)",
    },
    "CWE-862": {
        "patterns": [r'@login_required', r'check_permission', r'has_permission',
                     r'is_authorized', r'require_auth', r'@permission_required'],
        "description": "Missing authorization check",
    },
    "CWE-352": {
        "patterns": [r'csrf_exempt', r'csrf_token', r'X-CSRF-Token',
                     r'@csrf_protect', r'validate_csrf', r'WTF_CSRF'],
        "description": "Missing CSRF protection",
    },
    "CWE-117": {
        "patterns": [r'logging\.\w+\(.*\+', r'logger\.\w+\(.*f["\']',
                     r'log\.\w+\(.*format', r'\\n', r'\\r',
                     r'print\(.*user', r'logging\.info\(.*request'],
        "description": "Log injection via unsanitized user input in logs",
    },
    "CWE-306": {
        "patterns": [r'@login_required', r'is_authenticated', r'check_auth',
                     r'require_auth', r'@auth_required', r'PermissionError',
                     r'session\[.*user', r'request\.user'],
        "description": "Missing authentication for critical function",
    },
    "CWE-319": {
        "patterns": [r'http://', r'https://', r'verify\s*=\s*False',
                     r'CERT_NONE', r'ssl', r'tls', r'ftp://'],
        "description": "Cleartext transmission of sensitive information",
    },
    "CWE-328": {
        "patterns": [r'\bmd5\b', r'\bsha1\b', r'hashlib\.md5', r'hashlib\.sha1',
                     r'sha256', r'sha512', r'bcrypt', r'pbkdf2'],
        "description": "Weak hash without salt (reversible)",
    },
    "CWE-434": {
        "patterns": [r'\.filename', r'allowed_extensions', r'file\.save',
                     r'\.endswith', r'content_type', r'mimetype',
                     r'upload', r'multipart'],
        "description": "Unrestricted file upload",
    },
    "CWE-639": {
        "patterns": [r'user_id', r'current_user', r'request\.user',
                     r'object_id', r'pk=', r'get_object_or_404'],
        "description": "Authorization bypass through user-controlled key (IDOR)",
    },
    "CWE-732": {
        "patterns": [r'chmod', r'0o777', r'0o666', r'0o755', r'os\.chmod',
                     r'stat\.S_', r'permission', r'umask', r'world.readable',
                     r'mode\s*='],
        "description": "Incorrect permission assignment for critical resource",
    },
    "CWE-74": {
        "patterns": [r'os\.system', r'subprocess', r'eval\(', r'exec\(',
                     r'\.format\(', r'f["\'].*\{.*\}', r'\+\s*user'],
        "description": "Injection (general)",
    },
    "CWE-863": {
        "patterns": [r'is_admin', r'is_superuser', r'has_permission',
                     r'role', r'authorize', r'access_control',
                     r'@permission_required', r'check_permission'],
        "description": "Incorrect authorization",
    },
    "CWE-915": {
        "patterns": [r'setattr', r'__dict__', r'update\(', r'mass_assignment',
                     r'\*\*kwargs', r'\*\*request', r'__class__'],
        "description": "Mass assignment vulnerability",
    },
    "CWE-94": {
        "patterns": [r'\beval\s*\(', r'\bexec\s*\(', r'compile\s*\(',
                     r'__import__', r'importlib', r'subprocess\.call',
                     r'os\.system'],
        "description": "Code injection",
    },
}


# =============================================================================
# Attack Vector Categories (for Check 3)
# =============================================================================

ATTACK_CATEGORIES = {
    "CWE-78": {
        "command_chaining": [r'&&', r'\|\|', r';', r';rm', r';cat', r'&& cat'],
        "pipe": [r'\|', r'\|cat', r'\|ls', r'\| grep'],
        "subshell": [r'\$\(', r'\$\(whoami\)', r'\$\(id\)'],
        "backtick": [r'`', r'`whoami`', r'`id`'],
        "shell_check": [r'shell=true', r'shell=false', r'last_shell', r'subprocess'],
    },
    "CWE-22": {
        "parent_traversal": [r'\.\./', r'\.\./'],
        "encoded_traversal": [r'%2e%2e', r'%252e', r'%2f', r'%00'],
        "absolute_path": [r'^/', r'/etc/passwd', r'/etc/shadow'],
        "null_byte": [r'\\x00', r'\\0', r'%00'],
        "base_dir_check": [r'base_dir', r'startswith', r'realpath', r'abspath'],
    },
    "CWE-79": {
        "script_injection": [r'<script', r'javascript:', r'alert\('],
        "event_handler": [r'onerror', r'onload', r'onclick', r'onmouseover'],
        "attribute_injection": [r'style\s*=', r'"onclick', r"'onclick"],
        "escape_check": [r'escape', r'&lt;', r'&gt;', r'html\.escape'],
    },
    "CWE-918": {
        "internal_ip": [r'127\.0\.0\.1', r'localhost', r'169\.254', r'0\.0\.0\.0'],
        "cloud_metadata": [r'169\.254\.169\.254', r'metadata', r'computeMetadata'],
        "domain_spoofing": [r'@', r'#', r'\\\\'],
        "url_scheme": [r'file://', r'gopher://', r'dict://', r'ftp://'],
        "dns_rebinding": [r'rebind', r'dns', r'ttl', r'resolve', r'toctou'],
        "allowlist": [r'allowlist', r'whitelist', r'allowed_hosts', r'ssrf_attempted'],
    },
    "CWE-327": {
        "weak_md5": [r'\bmd5\b', r'\bMD5\b', r'hashlib\.md5'],
        "weak_sha1": [r'\bsha1\b', r'\bSHA1\b', r'hashlib\.sha1'],
        "secure_check": [r'sha256', r'sha512', r'bcrypt', r'argon2', r'pbkdf2'],
    },
    "CWE-502": {
        "yaml_gadget": [r'!!python', r'!!python/object', r'apply:', r'tag:yaml\.org'],
        "pickle_gadget": [r'pickle', r'__reduce__', r'cPickle'],
        "safe_check": [r'safe_load', r'SafeLoader', r'json\.loads', r'literal_eval'],
        "object_instantiation": [r'__class__', r'__init__', r'__new__'],
    },
    "CWE-20": {
        "subdomain_spoofing": [r'attack-', r'\.attacker\.', r'evil\.'],
        "url_embedding": [r'/example\.com', r'@example\.com'],
        "boundary_values": [r'negative', r'-1', r'\b0\b', r'max', r'min'],
        "type_validation": [r'isinstance', r'typeerror', r'type\('],
        "length_validation": [r'len\(', r'maxlength', r'minlength'],
    },
    "CWE-89": {
        "tautology": [r"or\s*'1'\s*=\s*'1'", r'or\s*1\s*=\s*1', r"'\s*or\s*''"],
        "union_injection": [r'union', r'union\s+select', r'union\s+all'],
        "stacked_queries": [r';\s*select', r';\s*drop', r';\s*delete'],
        "comment_truncation": [r'--', r"admin'--", r'/\*'],
        "time_based": [r'sleep\(', r'waitfor', r'benchmark\(', r'pg_sleep'],
        "parameterization": [r'last_params', r'parameterized', r'\?', r'%s'],
    },
    "CWE-611": {
        "external_entity": [r'<!entity', r'<!doctype', r'system', r'xxe'],
        "dtd_processing": [r'dtd', r'doctype', r'entity', r'resolve_entities'],
        "safe_parser": [r'defusedxml', r'XMLParser', r'resolve_entities=False'],
    },
    # New CWEs added in v2.5.0
    "CWE-95": {
        "code_execution": [r'eval\(', r'exec\(', r'compile\(', r'__import__'],
        "ast_bypass": [r'ast\.literal_eval', r'json\.loads', r'safe_eval'],
        "injection_payload": [r'__class__', r'__mro__', r'__subclasses__', r'__builtins__'],
        "safe_check": [r'literal_eval', r'ast\.parse', r'safe_eval', r'sandbox'],
    },
    "CWE-601": {
        "redirect_function": [r'redirect\(', r'HttpResponseRedirect', r'send_redirect'],
        "url_parameter": [r'next=', r'return_url=', r'redirect_uri=', r'continue='],
        "domain_validation": [r'urlparse', r'netloc', r'allowed_hosts', r'same_origin'],
        "open_redirect_payload": [r'//evil\.com', r'//attacker\.', r'@evil\.com'],
    },
    "CWE-295": {
        "disable_verification": [r'verify=False', r'CERT_NONE', r'check_hostname=False'],
        "insecure_context": [r'_create_unverified_context', r'PROTOCOL_TLS'],
        "warning_suppression": [r'InsecureRequestWarning', r'disable_warnings'],
        "secure_check": [r'verify=True', r'CERT_REQUIRED', r'load_verify_locations'],
    },
    "CWE-209": {
        "stack_trace": [r'traceback', r'print_exc', r'format_exc', r'exc_info'],
        "error_detail": [r'str\(e\)', r'repr\(e\)', r'exception\.args'],
        "debug_mode": [r'debug=True', r'DEBUG\s*=\s*True', r'\.debug\('],
        "safe_error": [r'generic error', r'something went wrong', r'log\.error'],
    },
    "CWE-400": {
        "nested_quantifier": [r'\(\.\*\)\+', r'\(\.\+\)\+', r'\(\w\+\)\+'],
        "backtracking": [r'\(\[.*\]\)\{', r'a\{.*\}\{', r'\(\?:.*\)\+\+'],
        "timeout_protection": [r'timeout', r're2', r'regex\.match.*timeout'],
    },
    "CWE-862": {
        "missing_decorator": [r'@login_required', r'@permission_required', r'@auth_required'],
        "permission_check": [r'has_permission', r'is_authorized', r'check_access'],
        "role_check": [r'is_admin', r'is_superuser', r'user\.role', r'request\.user'],
        "bypass_indicator": [r'# TODO.*auth', r'# FIXME.*permission', r'pass  # auth'],
    },
    "CWE-352": {
        "csrf_exempt": [r'@csrf_exempt', r'csrf_exempt', r'disable_csrf'],
        "token_validation": [r'csrf_token', r'X-CSRF-Token', r'_csrf'],
        "method_check": [r'request\.method', r'POST', r'PUT', r'DELETE'],
        "protection": [r'@csrf_protect', r'validate_csrf', r'CSRFProtect'],
    },
    "CWE-117": {
        "newline_injection": [r'\\n', r'\\r', r'%0a', r'%0d'],
        "log_format": [r'logging\.', r'logger\.', r'log\.info', r'log\.error'],
        "sanitization": [r'replace.*\\n', r'strip', r'sanitize', r'escape'],
    },
    "CWE-1333": {
        "nested_quantifier": [r'\(\.\*\)\+', r'\(\.\+\)\+', r'\(\w\+\)\+'],
        "backtracking": [r'\(\[.*\]\)\{', r'a\{.*\}\{', r'\(\?:.*\)\+\+'],
        "timeout_protection": [r'timeout', r're2', r'regex\.match.*timeout'],
    },
    "CWE-732": {
        "permission_value": [r'0o777', r'0o666', r'0o755', r'0o644'],
        "chmod_call": [r'os\.chmod', r'chmod', r'fchmod'],
        "permission_check": [r'stat\.S_', r'os\.stat', r'permission'],
        "safe_permission": [r'0o600', r'0o400', r'0o700'],
    },
    "CWE-94": {
        "code_execution": [r'eval\(', r'exec\(', r'compile\(', r'__import__'],
        "sandbox_check": [r'ast\.literal_eval', r'restricted', r'sandbox', r'safe_eval'],
        "injection_payload": [r'__class__', r'__mro__', r'__subclasses__', r'__builtins__'],
        "safe_check": [r'literal_eval', r'ast\.parse', r'whitelist'],
    },
    "CWE-306": {
        "auth_decorator": [r'@login_required', r'@auth_required', r'@require_auth'],
        "auth_check": [r'is_authenticated', r'check_auth', r'verify_auth'],
        "session_check": [r'session\[', r'request\.user', r'current_user'],
        "error_response": [r'PermissionError', r'unauthorized', r'forbidden', r'401'],
    },
    "CWE-798": {
        "hardcoded_password": [r'password\s*=\s*["\']', r'passwd\s*=\s*["\']'],
        "hardcoded_key": [r'api_key\s*=\s*["\']', r'secret\s*=\s*["\']', r'token\s*=\s*["\']'],
        "environment_var": [r'os\.environ', r'getenv', r'config\[', r'\.env'],
        "known_defaults": [r'admin123', r'password123', r'SuperSecret', r'changeme'],
    },
    "CWE-338": {
        "weak_random": [r'random\.random', r'random\.randint', r'random\.choice'],
        "secure_random": [r'secrets\.', r'os\.urandom', r'SystemRandom'],
        "crypto_context": [r'token', r'key', r'password', r'nonce', r'salt'],
    },
}


# =============================================================================
# Check 1: Mutation Operator Sanity
# =============================================================================

def check_mutation_sanity(
    validation_samples: List[Dict],
    main_samples: List[Dict],
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    For each overlapping validation sample, check if at least one mutant
    introduces the same vulnerability class as the known insecure code.
    """
    results = {
        "samples_checked": 0,
        "samples_with_class_match": 0,
        "avg_similarity": 0.0,
        "per_sample": {},
    }

    similarities = []

    for vsample in validation_samples:
        cwe = vsample["cwe"]
        fingerprints = VULN_FINGERPRINTS.get(cwe, {}).get("patterns", [])
        mutants = vsample.get("mutants", [])

        if not mutants:
            if verbose:
                print(f"  [{vsample['id']}] No mutants, skipping")
            continue

        results["samples_checked"] += 1

        # Compute diff: secure -> insecure (the known vulnerability)
        secure_code = vsample["secure_code"]
        insecure_code = vsample["insecure_code"]

        insecure_diff = _compute_diff(secure_code, insecure_code)

        # Check each mutant
        best_similarity = 0.0
        has_class_match = False

        for mutant in mutants:
            mutant_diff = _compute_diff(secure_code, mutant["mutated_code"])

            # Fingerprint matching
            if fingerprints:
                insecure_matches = sum(
                    1 for p in fingerprints
                    if re.search(p, insecure_diff, re.IGNORECASE)
                )
                mutant_matches = sum(
                    1 for p in fingerprints
                    if re.search(p, mutant_diff, re.IGNORECASE)
                )
                if insecure_matches > 0 and mutant_matches > 0:
                    has_class_match = True

            # Diff similarity
            sim = difflib.SequenceMatcher(
                None, insecure_diff, mutant_diff
            ).ratio()
            best_similarity = max(best_similarity, sim)

        if has_class_match:
            results["samples_with_class_match"] += 1

        similarities.append(best_similarity)

        sample_result = {
            "cwe": cwe,
            "mutant_count": len(mutants),
            "class_match": has_class_match,
            "best_similarity": round(best_similarity, 3),
        }
        results["per_sample"][vsample["id"]] = sample_result

        if verbose:
            match_str = "MATCH" if has_class_match else "NO MATCH"
            print(f"  [{vsample['id']}] {cwe} - {match_str} "
                  f"(sim={best_similarity:.3f}, {len(mutants)} mutants)")

    if similarities:
        results["avg_similarity"] = round(
            sum(similarities) / len(similarities), 3
        )

    return results


def _compute_diff(code_a: str, code_b: str) -> str:
    """Compute unified diff between two code strings."""
    diff = difflib.unified_diff(
        code_a.splitlines(), code_b.splitlines(), lineterm=""
    )
    return "\n".join(
        line for line in diff if line.startswith("+") and not line.startswith("+++")
    )


# =============================================================================
# Check 2: Vulnerability Detection Ground Truth
# =============================================================================

def check_vulnerability_detection(
    validation_samples: List[Dict],
    main_samples: List[Dict],
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Phase A: CWEval expert tests detect their own vulnerability (baseline).
    Phase B: SecMutBench pipeline tests detect the same vulnerability.
    """
    cweval_runner = CWEvalTestRunner(timeout=30.0)
    mock_runner = TestRunner(timeout=10.0) if TEST_RUNNER_AVAILABLE else None

    results = {
        "ground_truth_established": 0,
        "ground_truth_failed": 0,
        "secmutbench_matches": 0,
        "secmutbench_tested": 0,
        "per_sample": {},
    }

    # Index main samples by CWE
    main_by_cwe = defaultdict(list)
    for ms in main_samples:
        main_by_cwe[ms["cwe"]].append(ms)

    for vsample in validation_samples:
        cwe = vsample["cwe"]
        sample_id = vsample["id"]
        expert_tests = vsample["security_tests"]
        secure_code = vsample["secure_code"]
        insecure_code = vsample["insecure_code"]

        if verbose:
            print(f"\n  [{sample_id}] {cwe}")

        # Phase A: Expert test baseline
        if verbose:
            print(f"    Phase A: Running expert tests...")

        secure_result = cweval_runner.run_test(expert_tests, secure_code)
        insecure_result = cweval_runner.run_test(expert_tests, insecure_code)

        secure_passes = secure_result.all_passed
        insecure_fails = not insecure_result.all_passed
        ground_truth = secure_passes and insecure_fails

        if ground_truth:
            results["ground_truth_established"] += 1
        else:
            results["ground_truth_failed"] += 1

        sample_result = {
            "cwe": cwe,
            "expert_secure_passes": secure_passes,
            "expert_secure_total": secure_result.total,
            "expert_secure_passed": secure_result.passed,
            "expert_insecure_fails": insecure_fails,
            "expert_insecure_total": insecure_result.total,
            "expert_insecure_failed": insecure_result.failed,
            "ground_truth_established": ground_truth,
            "secmutbench_detection": None,
        }

        if verbose:
            gt_str = "ESTABLISHED" if ground_truth else "FAILED"
            print(f"    Expert tests: secure={secure_result.passed}/{secure_result.total}, "
                  f"insecure_fails={insecure_result.failed}/{insecure_result.total} -> {gt_str}")

        # Phase B: SecMutBench pipeline comparison
        if mock_runner and cwe in main_by_cwe:
            matching_samples = main_by_cwe[cwe]
            any_detection = False

            for ms in matching_samples[:3]:  # Check up to 3 matching samples
                ms_tests = ms.get("security_tests", "")
                if not ms_tests:
                    continue

                results["secmutbench_tested"] += 1

                try:
                    ms_secure = mock_runner.run_tests(ms_tests, secure_code)
                    ms_insecure = mock_runner.run_tests(ms_tests, insecure_code)

                    detected = ms_secure.all_passed and not ms_insecure.all_passed
                    if detected:
                        any_detection = True

                    if verbose:
                        det_str = "DETECTED" if detected else "MISSED"
                        print(f"    Pipeline [{ms['id'][:12]}]: "
                              f"secure={ms_secure.passed}/{ms_secure.total}, "
                              f"insecure_fails={ms_insecure.failed}/{ms_insecure.total} -> {det_str}")
                except Exception as e:
                    if verbose:
                        print(f"    Pipeline [{ms['id'][:12]}]: ERROR - {e}")

            if any_detection:
                results["secmutbench_matches"] += 1
            sample_result["secmutbench_detection"] = any_detection

        results["per_sample"][sample_id] = sample_result

    return results


# =============================================================================
# Check 3: Attack Vector Coverage
# =============================================================================

def check_attack_coverage(
    validation_samples: List[Dict],
    main_samples: List[Dict],
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Compare attack categories between CWEval expert tests and SecMutBench.
    """
    results = {
        "avg_coverage": 0.0,
        "per_cwe": {},
    }

    coverages = []

    # Group by CWE
    val_by_cwe = defaultdict(list)
    main_by_cwe = defaultdict(list)
    for vs in validation_samples:
        val_by_cwe[vs["cwe"]].append(vs)
    for ms in main_samples:
        main_by_cwe[ms["cwe"]].append(ms)

    for cwe, categories in ATTACK_CATEGORIES.items():
        val_samples = val_by_cwe.get(cwe, [])
        main_samps = main_by_cwe.get(cwe, [])

        if not val_samples or not main_samps:
            continue

        # Extract attack payloads from CWEval raw test source
        cweval_categories = set()
        for vs in val_samples:
            raw = vs.get("metadata", {}).get("test_raw_source", "")
            for cat_name, patterns in categories.items():
                for p in patterns:
                    if re.search(p, raw, re.IGNORECASE):
                        cweval_categories.add(cat_name)
                        break

        # Extract from SecMutBench security tests
        secmutbench_categories = set()
        for ms in main_samps:
            tests = ms.get("security_tests", "")
            for cat_name, patterns in categories.items():
                for p in patterns:
                    if re.search(p, tests, re.IGNORECASE):
                        secmutbench_categories.add(cat_name)
                        break

        # Jaccard overlap
        if cweval_categories:
            intersection = cweval_categories & secmutbench_categories
            union = cweval_categories | secmutbench_categories
            coverage = len(intersection) / len(union) if union else 0.0
        else:
            coverage = 0.0

        coverages.append(coverage)

        cwe_result = {
            "cweval_categories": sorted(list(cweval_categories)),
            "secmutbench_categories": sorted(list(secmutbench_categories)),
            "intersection": sorted(list(cweval_categories & secmutbench_categories)),
            "coverage": round(coverage, 3),
        }
        results["per_cwe"][cwe] = cwe_result

        if verbose:
            print(f"  {cwe}: coverage={coverage:.3f}")
            print(f"    CWEval: {sorted(cweval_categories)}")
            print(f"    SecMutBench: {sorted(secmutbench_categories)}")
            print(f"    Overlap: {sorted(cweval_categories & secmutbench_categories)}")

    if coverages:
        results["avg_coverage"] = round(sum(coverages) / len(coverages), 3)

    return results


# =============================================================================
# Report Formatting
# =============================================================================

def print_report(report: Dict[str, Any]):
    """Print a formatted summary of the validation report."""
    print(f"\n{'='*60}")
    print("CWEval Validation Report")
    print(f"{'='*60}")

    meta = report.get("metadata", {})
    print(f"\nValidation dataset: {meta.get('validation_dataset', 'N/A')}")
    print(f"Main dataset: {meta.get('main_dataset', 'N/A')}")
    print(f"Validation samples: {meta.get('total_validation_samples', 0)}")
    print(f"Overlapping CWEs: {meta.get('overlapping_cwes', 0)}")

    # Check 1: Mutation Sanity
    if "mutation_operator_sanity" in report:
        ms = report["mutation_operator_sanity"]
        print(f"\n--- Check 1: Mutation Operator Sanity ---")
        print(f"  Samples checked: {ms.get('samples_checked', 0)}")
        print(f"  Vulnerability class match: {ms.get('samples_with_class_match', 0)}/{ms.get('samples_checked', 0)}")
        print(f"  Avg diff similarity: {ms.get('avg_similarity', 0):.3f}")

    # Check 2: Vulnerability Detection
    if "vulnerability_detection" in report:
        vd = report["vulnerability_detection"]
        print(f"\n--- Check 2: Vulnerability Detection Ground Truth ---")
        gt_total = vd.get("ground_truth_established", 0) + vd.get("ground_truth_failed", 0)
        print(f"  Ground truth established: {vd.get('ground_truth_established', 0)}/{gt_total}")
        print(f"  SecMutBench matches: {vd.get('secmutbench_matches', 0)}/{vd.get('secmutbench_tested', 0)}")

    # Check 3: Attack Coverage
    if "attack_vector_coverage" in report:
        ac = report["attack_vector_coverage"]
        print(f"\n--- Check 3: Attack Vector Coverage ---")
        print(f"  Avg coverage (Jaccard): {ac.get('avg_coverage', 0):.3f}")
        for cwe, info in ac.get("per_cwe", {}).items():
            print(f"  {cwe}: {info['coverage']:.3f} "
                  f"({len(info['intersection'])}/{len(info['cweval_categories'])} categories)")


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Validate SecMutBench pipeline against CWEval expert-verified tests",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    default_validation = PROJECT_ROOT / "data" / "validation.json"
    default_dataset = PROJECT_ROOT / "data" / "dataset.json"
    default_output = PROJECT_ROOT / "results" / "cweval_validation.json"

    parser.add_argument(
        "--validation-dataset", type=str, default=str(default_validation),
        help="Path to validation.json",
    )
    parser.add_argument(
        "--main-dataset", type=str, default=str(default_dataset),
        help="Path to main dataset.json",
    )
    parser.add_argument(
        "--output", type=str, default=str(default_output),
        help="Output JSON report path",
    )
    parser.add_argument(
        "--checks", nargs="+",
        choices=["mutation", "detection", "coverage"],
        default=["mutation", "detection", "coverage"],
        help="Which checks to run",
    )
    parser.add_argument("--cwe", type=str, default=None, help="Filter to a single CWE")
    parser.add_argument("--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    # Load datasets
    val_path = Path(args.validation_dataset)
    main_path = Path(args.main_dataset)

    if not val_path.exists():
        print(f"Error: Validation dataset not found: {val_path}")
        print("Run: python scripts/build_validation_dataset.py")
        sys.exit(1)

    if not main_path.exists():
        print(f"Error: Main dataset not found: {main_path}")
        sys.exit(1)

    with open(val_path) as f:
        val_data = json.load(f)
    with open(main_path) as f:
        main_data = json.load(f)

    val_samples = val_data.get("samples", [])
    main_samples = main_data.get("samples", main_data)
    if isinstance(main_samples, dict):
        main_samples = main_samples.get("samples", [])

    # Find overlapping CWEs
    val_cwes = set(s["cwe"] for s in val_samples)
    main_cwes = set(s["cwe"] for s in main_samples)
    overlapping = val_cwes & main_cwes

    # Filter to overlapping CWEs (and optional CWE filter)
    if args.cwe:
        target_cwe = normalize_cwe(args.cwe)
        val_samples = [s for s in val_samples if s["cwe"] == target_cwe]
        main_samples = [s for s in main_samples if s["cwe"] == target_cwe]
    else:
        val_samples = [s for s in val_samples if s["cwe"] in overlapping]

    print(f"\n{'='*60}")
    print("CWEval Validation")
    print(f"{'='*60}")
    print(f"Validation samples: {len(val_samples)}")
    print(f"Main dataset samples: {len(main_samples)}")
    print(f"Overlapping CWEs: {sorted(overlapping)}")
    if args.cwe:
        print(f"CWE filter: {args.cwe}")

    # Build report
    report = {
        "timestamp": datetime.now().isoformat(),
        "metadata": {
            "validation_dataset": str(val_path),
            "main_dataset": str(main_path),
            "total_validation_samples": len(val_samples),
            "total_main_samples": len(main_samples),
            "overlapping_cwes": len(overlapping),
            "overlapping_cwe_list": sorted(list(overlapping)),
        },
    }

    # Run checks
    if "mutation" in args.checks:
        print(f"\n--- Running Check 1: Mutation Operator Sanity ---")
        report["mutation_operator_sanity"] = check_mutation_sanity(
            val_samples, main_samples, verbose=args.verbose
        )

    if "detection" in args.checks:
        print(f"\n--- Running Check 2: Vulnerability Detection Ground Truth ---")
        if not TEST_RUNNER_AVAILABLE:
            print("  Warning: TestRunner not available, Phase B will be skipped")
        report["vulnerability_detection"] = check_vulnerability_detection(
            val_samples, main_samples, verbose=args.verbose
        )

    if "coverage" in args.checks:
        print(f"\n--- Running Check 3: Attack Vector Coverage ---")
        report["attack_vector_coverage"] = check_attack_coverage(
            val_samples, main_samples, verbose=args.verbose
        )

    # Print summary
    print_report(report)

    # Save report
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nReport saved to {output_path}")


if __name__ == "__main__":
    main()
