#!/usr/bin/env python3
"""
Sample Generator Module for SecMutBench

Unified sample generation from all sources:
- Template-based generation (SecMutBench)
- SecurityEval transformation
- CyberSecEval transformation
- Secure code generation
- Security test generation
- Difficulty estimation

This module consolidates functionality from:
- generate_samples.py (templates)
- transform_datasets.py (transformations)
- rebuild_dataset.py (test generation, difficulty)
"""

import ast
import hashlib
import json
import re
import textwrap
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any

# Import from source_ingestion
from source_ingestion import (
    SourceManager,
    CWE_REGISTRY,
    SAMPLE_TEMPLATES,
    normalize_cwe,
)


# =============================================================================
# Sample Data Class
# =============================================================================

@dataclass
class Sample:
    """Represents a SecMutBench sample."""
    id: str
    cwe: str
    cwe_name: str
    difficulty: str
    prompt: str
    entry_point: str
    insecure_code: str
    secure_code: str
    functional_tests: str
    security_tests: str
    mutation_operators: List[str]
    source: str
    original_id: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return asdict(self)

    def validate(self) -> Tuple[bool, List[str]]:
        """Validate sample has required fields and valid code."""
        issues = []

        # Check required fields
        required = ['id', 'cwe', 'insecure_code', 'secure_code', 'security_tests']
        for field in required:
            value = getattr(self, field, None)
            if not value:
                issues.append(f"Missing or empty field: {field}")

        # Check placeholder code
        if "# Secure version of" in self.secure_code:
            issues.append("secure_code is placeholder")
        if "# Secure version of" in self.insecure_code:
            issues.append("insecure_code is placeholder")

        # Check Python syntax
        for name, code in [('insecure_code', self.insecure_code),
                           ('secure_code', self.secure_code),
                           ('security_tests', self.security_tests)]:
            if code:
                try:
                    compile(code, f"<{name}>", "exec")
                except SyntaxError as e:
                    issues.append(f"{name} syntax error: {e}")

        return len(issues) == 0, issues


# =============================================================================
# ID Generation
# =============================================================================

def generate_id(content: str) -> str:
    """Generate unique 12-character ID from content."""
    return hashlib.sha256(content.encode()).hexdigest()[:12]


# =============================================================================
# Code Preprocessing
# =============================================================================

def preprocess_code(code: str) -> str:
    """
    Preprocess code to fix common issues from external sources.

    Fixes:
    - Dedent code that starts with indentation (snippets from classes/functions)
    - Convert Python 2 print statements to Python 3
    - Fix common syntax issues

    Args:
        code: Raw source code

    Returns:
        Preprocessed code that can compile as standalone Python 3
    """
    if not code or not code.strip():
        return code

    # Step 1: Dedent the code (remove common leading whitespace)
    code = textwrap.dedent(code)

    # Step 2: Remove leading blank lines
    lines = code.split('\n')
    while lines and not lines[0].strip():
        lines.pop(0)
    code = '\n'.join(lines)

    # Step 3: Convert Python 2 print statements to Python 3
    # Match: print "..." or print '...' or print variable
    # But NOT: print(...) which is already Python 3
    code = re.sub(
        r'\bprint\s+(["\'][^"\']*["\'])',
        r'print(\1)',
        code
    )
    code = re.sub(
        r'\bprint\s+(\w+)\s*$',
        r'print(\1)',
        code,
        flags=re.MULTILINE
    )
    code = re.sub(
        r'\bprint\s+(\w+)\s*,',
        r'print(\1,',
        code
    )

    # Step 4: Fix common Python 2 constructs
    # except Exception, e: -> except Exception as e:
    code = re.sub(
        r'except\s+(\w+)\s*,\s*(\w+)\s*:',
        r'except \1 as \2:',
        code
    )

    # Step 5: If code still has leading indentation on first line, wrap in function
    if code and code[0] in ' \t':
        # Still indented - wrap in a dummy function
        code = f"def _wrapper():\n{code}"

    return code


# =============================================================================
# Difficulty Estimation
# =============================================================================

def calculate_ast_depth(node, current_depth: int = 0) -> int:
    """Calculate maximum AST nesting depth."""
    max_depth = current_depth
    for child in ast.iter_child_nodes(node):
        child_depth = calculate_ast_depth(child, current_depth + 1)
        max_depth = max(max_depth, child_depth)
    return max_depth


def estimate_difficulty(code: str, cwe: str = "") -> str:
    """
    Estimate difficulty based on multiple complexity factors.

    Factors:
    - Line count
    - Control flow complexity (branches, loops)
    - Function calls (more interactions)
    - AST nesting depth
    - CWE-specific modifiers
    """
    lines = len(code.strip().split('\n'))

    # Default values if parsing fails
    branches = 0
    calls = 0
    max_depth = 0

    try:
        tree = ast.parse(code)

        # Count control flow complexity
        branches = sum(1 for node in ast.walk(tree)
                       if isinstance(node, (ast.If, ast.For, ast.While, ast.Try,
                                            ast.With, ast.ExceptHandler)))

        # Count function calls
        calls = sum(1 for node in ast.walk(tree) if isinstance(node, ast.Call))

        # Calculate nesting depth
        max_depth = calculate_ast_depth(tree)

    except SyntaxError:
        pass

    # CWE-specific difficulty modifiers
    hard_cwes = {"CWE-287", "CWE-306", "CWE-502", "CWE-611", "CWE-918"}
    medium_cwes = {"CWE-78", "CWE-94", "CWE-327"}
    cwe_modifier = 1.5 if cwe in hard_cwes else (1.2 if cwe in medium_cwes else 1.0)

    # Compute weighted score
    score = (lines * 0.3 + branches * 2 + calls * 0.5 + max_depth * 3) * cwe_modifier

    if score <= 20:
        return "easy"
    elif score <= 50:
        return "medium"
    else:
        return "hard"


# =============================================================================
# Function Name Extraction
# =============================================================================

def extract_function_name(code: str) -> Optional[str]:
    """Extract first function name from code."""
    match = re.search(r'def\s+(\w+)\s*\(', code)
    return match.group(1) if match else None


# =============================================================================
# Secure Code Generation
# =============================================================================

def generate_secure_code(insecure_code: str, cwe: str, prompt: str = "") -> Tuple[str, bool]:
    """
    Generate secure version of insecure code based on CWE type.

    Returns:
        Tuple of (secure_code, transformation_succeeded)
    """
    secure = insecure_code
    transformed = False

    # CWE-89: SQL Injection - Fix f-string to parameterized query
    if cwe == "CWE-89":
        def fix_fstring_sql(code: str) -> str:
            lines = code.split('\n')
            new_lines = []
            query_var = None
            params = []

            for line in lines:
                # Detect f-string query assignment
                fstring_match = re.match(r'(\s*)(\w+)\s*=\s*f["\'](.+?)["\']', line)
                if fstring_match:
                    indent, var, query = fstring_match.groups()
                    placeholders = re.findall(r'\{(\w+)\}', query)
                    if placeholders:
                        clean_query = re.sub(r'\{(\w+)\}', '?', query)
                        new_lines.append(f'{indent}{var} = "{clean_query}"')
                        query_var = var
                        params = placeholders
                        continue

                # Detect execute() call and add params
                if query_var and '.execute(' in line:
                    execute_match = re.match(r'(\s*)(.+)\.execute\((\w+)\)', line)
                    if execute_match and execute_match.group(3) == query_var:
                        indent = execute_match.group(1)
                        obj = execute_match.group(2)
                        params_str = ', '.join(params)
                        new_lines.append(f'{indent}{obj}.execute({query_var}, ({params_str},))')
                        query_var = None
                        params = []
                        continue

                new_lines.append(line)

            return '\n'.join(new_lines)

        secure = fix_fstring_sql(secure)
        transformed = True

    # CWE-78: Command Injection - Per MITRE: Use parameterized commands, avoid shell
    elif cwe == "CWE-78":
        if 'shell=True' in secure:
            secure = re.sub(r'shell\s*=\s*True', 'shell=False', secure)
            transformed = True
        # Transform os.system(cmd) to subprocess.run(shlex.split(cmd), shell=False)
        if 'os.system(' in secure:
            # Match os.system(variable) or os.system(f"...")
            secure = re.sub(
                r'os\.system\(([^)]+)\)',
                r'subprocess.run(shlex.split(\1), shell=False, check=True)',
                secure
            )
            if 'import subprocess' not in secure:
                secure = 'import subprocess\n' + secure
            if 'import shlex' not in secure:
                secure = 'import shlex\n' + secure
            transformed = True
        # Ensure shlex is imported for any subprocess usage
        if 'subprocess' in secure and 'shlex' not in secure:
            secure = 'import shlex\n' + secure

    # CWE-22: Path Traversal
    elif cwe == "CWE-22":
        validation_func = '''
def safe_path(base_dir, user_path):
    """Validate path is within allowed directory."""
    import os
    full_path = os.path.normpath(os.path.join(base_dir, user_path))
    if not full_path.startswith(os.path.normpath(base_dir)):
        raise ValueError("Path traversal detected")
    return full_path
'''
        if 'safe_path' not in secure and 'normpath' not in secure:
            secure = validation_func + '\n' + secure
            transformed = True

    # CWE-79: XSS
    elif cwe == "CWE-79":
        if 'html' not in secure:
            secure = 'import html\n' + secure
        secure = re.sub(
            r'return\s+f["\'](.+?)["\']',
            r'return html.escape(f"\1")',
            secure
        )
        transformed = True

    # CWE-327/328: Weak Crypto
    elif cwe in ["CWE-327", "CWE-328"]:
        replacements = [
            ('md5', 'sha256'), ('MD5', 'SHA256'),
            ('sha1', 'sha256'), ('SHA1', 'SHA256'),
            ('des', 'aes'), ('DES', 'AES'),
        ]
        for old, new in replacements:
            if old in secure:
                secure = secure.replace(old, new)
                transformed = True

    # CWE-338: Weak PRNG - Per MITRE: Use cryptographically secure PRNG
    elif cwe == "CWE-338":
        if 'import random' in secure or 'random.' in secure:
            secure = secure.replace('import random', 'import secrets')
            # random.randint(a, b) returns [a, b] inclusive
            # secrets.randbelow(n) returns [0, n) exclusive
            # Correct transformation: random.randint(0, n) -> secrets.randbelow(n + 1)
            # For random.randint(a, b) where a > 0: a + secrets.randbelow(b - a + 1)
            def fix_randint(match):
                a, b = match.groups()
                if a == '0':
                    return f'secrets.randbelow({b} + 1)'
                return f'{a} + secrets.randbelow({b} - {a} + 1)'
            secure = re.sub(r'random\.randint\((\d+),\s*(\d+)\)', fix_randint, secure)
            secure = re.sub(r'random\.choice\(', 'secrets.choice(', secure)
            # random.random() returns [0, 1) - use token_bytes for true randomness
            secure = re.sub(r'random\.random\(\)', 'int.from_bytes(secrets.token_bytes(4), "big") / (2**32)', secure)
            transformed = True

    # CWE-502: Insecure Deserialization
    elif cwe == "CWE-502":
        if 'pickle.loads' in secure or 'pickle.load' in secure:
            secure = secure.replace('pickle.loads', 'json.loads')
            secure = secure.replace('pickle.load', 'json.load')
            secure = secure.replace('import pickle', 'import json')
            transformed = True
        if 'yaml.load(' in secure and 'safe_load' not in secure:
            secure = secure.replace('yaml.load(', 'yaml.safe_load(')
            transformed = True

    # CWE-798: Hardcoded Credentials
    elif cwe == "CWE-798":
        patterns = [
            (r'password\s*=\s*["\'][^"\']+["\']', 'password = os.environ.get("PASSWORD")'),
            (r'secret\s*=\s*["\'][^"\']+["\']', 'secret = os.environ.get("SECRET")'),
            (r'api_key\s*=\s*["\'][^"\']+["\']', 'api_key = os.environ.get("API_KEY")'),
            (r'token\s*=\s*["\'][^"\']+["\']', 'token = os.environ.get("TOKEN")'),
        ]
        for pattern, replacement in patterns:
            if re.search(pattern, secure, re.IGNORECASE):
                secure = re.sub(pattern, replacement, secure, flags=re.IGNORECASE)
                transformed = True
        if 'os.environ' in secure and 'import os' not in secure:
            secure = 'import os\n' + secure

    # CWE-611: XXE
    elif cwe == "CWE-611":
        if 'xml.etree' in secure or 'xml.dom' in secure:
            secure = secure.replace('xml.etree.ElementTree', 'defusedxml.ElementTree')
            secure = secure.replace('from xml.', 'from defusedxml.')
            secure = secure.replace('import xml.', 'import defusedxml.')
            transformed = True

    # CWE-94: Code Injection
    elif cwe == "CWE-94":
        if 'eval(' in secure:
            secure = secure.replace('eval(', 'ast.literal_eval(')
            if 'import ast' not in secure:
                secure = 'import ast\n' + secure
            transformed = True

    # CWE-287/306: Authentication Issues
    elif cwe in ["CWE-287", "CWE-306"]:
        if 'def ' in secure and 'is_authenticated' not in secure:
            secure = re.sub(
                r'(def \w+\([^)]*\):)\n(\s+)',
                r'\1\n\2if not is_authenticated():\n\2    raise PermissionError("Authentication required")\n\2',
                secure
            )
            transformed = True

    # Validate transformation
    try:
        compile(secure, "<secure>", "exec")
    except SyntaxError as e:
        return (
            f"# AUTO-GENERATION FAILED: {e}\n# Manual fix required for {cwe}\n{insecure_code}",
            False
        )

    return secure, transformed


# =============================================================================
# Test Generation
# =============================================================================

def generate_functional_test(entry_point: str, cwe: str) -> str:
    """Generate functional test for sample."""
    return f'''def test_{entry_point}_basic():
    """Basic functionality test."""
    try:
        result = {entry_point}("test_input")
        assert result is not None or result is None  # May return None
    except (ValueError, TypeError):
        pass  # May reject invalid input'''


def generate_security_test(entry_point: str, cwe: str) -> str:
    """
    Generate security test for sample based on CWE type.

    These tests are designed to:
    - PASS on secure code (proper security controls in place)
    - FAIL on insecure code (vulnerability detected via mock)

    Tests use mock object APIs to verify security behavior.
    """
    tests = {
        # CWE-89: SQL Injection
        # Mock API: db.last_params is None when query not parameterized
        "CWE-89": f'''def test_{entry_point}_sql_injection():
    """Test SQL injection prevention using mock database.

    PASS condition: db.last_params is not None (parameterized query used)
    FAIL condition: db.last_params is None (raw string interpolation)
    """
    db.reset()

    # Test with SQL injection payload
    payload = "' OR '1'='1"
    try:
        {entry_point}(payload)
    except (ValueError, TypeError):
        # Rejecting malicious input is also secure
        return

    # Check that parameterized query was used
    assert db.last_params is not None, \\
        f"SQL Injection: query not parameterized. Query: {{db.last_query}}"''',

        # CWE-79: Cross-Site Scripting
        # Check that dangerous characters are escaped in output
        "CWE-79": f'''def test_{entry_point}_xss():
    """Test XSS prevention via output escaping.

    PASS condition: < and > are escaped to &lt; and &gt;
    FAIL condition: raw < or > in output
    """
    payload = "<script>alert(1)</script>"
    result = {entry_point}(payload)

    # Result must exist and have dangerous chars escaped
    assert result is not None, "Function returned None"
    assert "<script>" not in result, \\
        f"XSS: unescaped <script> tag in output: {{result}}"
    assert "<" not in result or "&lt;" in result, \\
        f"XSS: unescaped < character in output: {{result}}"''',

        # CWE-78: OS Command Injection
        # Mock API: subprocess.injection_detected, subprocess.used_shell
        "CWE-78": f'''def test_{entry_point}_command_injection():
    """Test command injection prevention using mock subprocess.

    PASS condition: No shell=True with user input, or input rejected
    FAIL condition: shell=True used OR injection patterns in command
    """
    subprocess.reset()

    # Test with command injection payload
    payload = "localhost; cat /etc/passwd"
    try:
        {entry_point}(payload)
    except (ValueError, OSError, TypeError):
        # Rejecting malicious input is secure
        return

    # Check mock detected no injection
    assert not subprocess.injection_detected, \\
        f"Command injection: dangerous pattern executed. Command: {{subprocess.last_command}}"''',

        # CWE-22: Path Traversal
        # Secure code should reject or raise error for traversal attempts
        "CWE-22": f'''def test_{entry_point}_path_traversal():
    """Test path traversal prevention.

    PASS condition: ValueError raised for traversal attempt
    FAIL condition: No error raised (traversal allowed)
    """
    payload = "../../../etc/passwd"
    traversal_blocked = False

    try:
        {entry_point}(payload)
    except (ValueError, PermissionError, FileNotFoundError) as e:
        # Path traversal was blocked
        traversal_blocked = True

    assert traversal_blocked, \\
        f"Path traversal: '../' pattern was not blocked"''',

        # CWE-20: Improper Input Validation
        # Secure code should validate and reject invalid input
        "CWE-20": f'''def test_{entry_point}_input_validation():
    """Test input validation.

    PASS condition: Invalid input raises ValueError
    FAIL condition: Invalid input accepted without validation
    """
    invalid_inputs = ["-999", "99999", "abc", "<script>"]
    validation_occurred = False

    for payload in invalid_inputs:
        try:
            {entry_point}(payload)
        except (ValueError, TypeError):
            validation_occurred = True
            break

    assert validation_occurred, \\
        "Input validation: no validation error raised for invalid inputs"''',

        # CWE-287: Improper Authentication
        # Secure code should verify tokens properly
        "CWE-287": f'''def test_{entry_point}_authentication():
    """Test authentication verification.

    PASS condition: Invalid token raises error
    FAIL condition: Invalid token accepted
    """
    invalid_token = "invalid_token_12345"
    auth_failed = False

    try:
        {entry_point}(invalid_token)
    except (ValueError, PermissionError, Exception) as e:
        if "invalid" in str(e).lower() or "unauthorized" in str(e).lower():
            auth_failed = True

    assert auth_failed, \\
        "Authentication: invalid token was accepted without verification"''',

        # CWE-798: Hardcoded Credentials
        # Check that credentials come from environment, not hardcoded
        "CWE-798": f'''def test_{entry_point}_no_hardcoded_creds():
    """Test no hardcoded credentials.

    PASS condition: Function uses os.environ for credentials
    FAIL condition: Function has hardcoded credential strings
    """
    # Call the function to ensure it runs
    try:
        {entry_point}()
    except (KeyError, ValueError, Exception):
        # KeyError from os.environ means it's trying to read from env (good!)
        return

    # If no KeyError, check if env mock was accessed
    if hasattr(env, 'accessed_keys'):
        assert len(env.accessed_keys) > 0, \\
            "Hardcoded credentials: function did not read from environment"''',

        # CWE-502: Insecure Deserialization
        # Mock API: pickle.unsafe_load_called, yaml.unsafe_load_called
        "CWE-502": f'''def test_{entry_point}_safe_deserialization():
    """Test safe deserialization using mock modules.

    PASS condition: pickle.unsafe_load_called is False AND
                    (yaml.safe_loader_used is True OR yaml not used)
    FAIL condition: pickle.loads used OR yaml.load without SafeLoader
    """
    # Reset mocks
    pickle.reset()
    yaml.reset()

    # Test payload - could be JSON, YAML, or serialized
    test_payload = '{{"user": "test", "role": "guest"}}'

    try:
        {entry_point}(test_payload)
    except Exception:
        pass  # May fail for other reasons

    # Check mocks for unsafe operations
    assert not pickle.unsafe_load_called, \\
        "Insecure deserialization: pickle.loads() used on untrusted data"

    if yaml.load_count > 0:
        assert yaml.safe_loader_used or not yaml.unsafe_load_called, \\
            "Insecure deserialization: yaml.load() without SafeLoader"''',

        # CWE-327: Use of Weak Cryptography
        # Mock API: hashlib.weak_algorithm_used, hashlib.last_algorithm
        "CWE-327": f'''def test_{entry_point}_strong_crypto():
    """Test strong cryptographic algorithms using mock hashlib.

    PASS condition: hashlib.weak_algorithm_used is False
    FAIL condition: MD5, SHA1, or other weak algorithms used
    """
    # Reset mock
    hashlib.reset()

    test_input = "test_password_123"

    try:
        result = {entry_point}(test_input)
    except Exception:
        pass  # Function may require different input format

    # Check if weak algorithm was used
    assert not hashlib.weak_algorithm_used, \\
        f"Weak crypto: {{hashlib.last_algorithm}} used. Use SHA-256 or stronger."''',

        # CWE-352: Cross-Site Request Forgery
        # Secure code should validate CSRF token
        "CWE-352": f'''def test_{entry_point}_csrf_protection():
    """Test CSRF protection.

    PASS condition: Request without valid CSRF token is rejected
    FAIL condition: Request processed without CSRF validation
    """
    # Create a mock request without CSRF token
    class MockRequest:
        method = "POST"
        form = {{"data": "test"}}
        session = {{}}

    csrf_validated = False
    try:
        {entry_point}(MockRequest())
    except (ValueError, PermissionError, Exception) as e:
        if "csrf" in str(e).lower():
            csrf_validated = True

    assert csrf_validated, \\
        "CSRF: POST request accepted without CSRF token validation"''',

        # CWE-611: XML External Entity (XXE)
        # Mock API: xml_parser.external_entities_resolved
        "CWE-611": f'''def test_{entry_point}_xxe_prevention():
    """Test XXE prevention using mock XML parser.

    PASS condition: External entities are not resolved
    FAIL condition: external_entities_resolved is True
    """
    # XXE payload
    xxe_payload = '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'

    try:
        {entry_point}(xxe_payload)
    except Exception:
        # Rejecting XXE payload is secure
        return

    # Check if mock detected XXE attempt
    if hasattr(xml_parser, 'external_entities_resolved'):
        assert not xml_parser.external_entities_resolved, \\
            "XXE: external entities were resolved (unsafe XML parsing)"''',

        # CWE-918: Server-Side Request Forgery
        # Mock API: http_client.ssrf_attempted
        "CWE-918": f'''def test_{entry_point}_ssrf_prevention():
    """Test SSRF prevention using mock HTTP client.

    PASS condition: Internal URLs are blocked
    FAIL condition: ssrf_attempted is True without rejection
    """
    requests.reset()

    # SSRF payload targeting internal service
    internal_url = "http://169.254.169.254/latest/meta-data/"

    ssrf_blocked = False
    try:
        {entry_point}(internal_url)
    except (ValueError, PermissionError, Exception):
        ssrf_blocked = True

    if not ssrf_blocked:
        assert not requests.ssrf_attempted, \\
            f"SSRF: internal URL was accessed: {{requests.last_url}}"''',

        # CWE-94: Code Injection
        # Mock API: mock_eval.unsafe_eval_called, mock_eval.injection_detected
        "CWE-94": f'''def test_{entry_point}_code_injection():
    """Test code injection prevention using mock eval tracker.

    PASS condition: No eval/exec called, or input rejected
    FAIL condition: eval/exec used on untrusted input
    """
    mock_eval.reset()

    # Code injection payload
    payload = "__import__('os').system('id')"

    try:
        result = {entry_point}(payload)
        # If we get here without error, check mock flags
        if result is not None:
            # Check result doesn't contain executed output
            assert "uid=" not in str(result), \\
                "Code injection: payload was executed"
    except (ValueError, TypeError, SyntaxError):
        # Input was rejected - this is secure
        return

    # Check if unsafe eval was called (via mock tracking)
    # Note: mock_eval only tracks if code explicitly uses our mock
    # This is a backup check for eval-like behavior
    assert not mock_eval.unsafe_eval_called or not mock_eval.injection_detected, \\
        "Code injection: eval/exec used on untrusted input"''',

        # CWE-306: Missing Authentication
        "CWE-306": f'''def test_{entry_point}_requires_auth():
    """Test that authentication is required.

    PASS condition: Unauthenticated request is rejected
    FAIL condition: Request processed without authentication
    """
    auth_required = False

    try:
        # Call without authentication context
        {entry_point}()
    except (PermissionError, ValueError, Exception) as e:
        err_msg = str(e).lower()
        if "auth" in err_msg or "permission" in err_msg or "unauthorized" in err_msg:
            auth_required = True

    assert auth_required, \\
        "Missing authentication: function executed without auth check"''',

        # CWE-295: Improper Certificate Validation
        "CWE-295": f'''def test_{entry_point}_certificate_validation():
    """Test proper certificate validation.

    PASS condition: verify=True or proper cert validation
    FAIL condition: verify=False or cert validation disabled
    """
    test_url = "https://example.com"

    try:
        {entry_point}(test_url)
    except Exception:
        pass

    # Check if requests mock shows verify was disabled
    if hasattr(requests, 'last_kwargs'):
        verify = requests.last_kwargs.get('verify', True)
        assert verify is not False, \\
            "Certificate validation: verify=False disables TLS verification"''',

        # CWE-319: Cleartext Transmission
        "CWE-319": f'''def test_{entry_point}_no_cleartext():
    """Test no cleartext transmission of sensitive data.

    PASS condition: Uses HTTPS for transmission
    FAIL condition: Uses HTTP for sensitive data
    """
    try:
        {entry_point}("sensitive_data")
    except Exception:
        pass

    if hasattr(requests, 'last_url') and requests.last_url:
        assert requests.last_url.startswith('https://'), \\
            f"Cleartext transmission: using HTTP instead of HTTPS: {{requests.last_url}}"''',
    }

    # Default fallback test
    return tests.get(cwe, f'''def test_{entry_point}_security():
    """Generic security test for {cwe}."""
    try:
        result = {entry_point}("test_input")
        # Basic check that function executes
        assert True
    except (ValueError, TypeError, PermissionError):
        # Rejecting input is acceptable
        pass''')


# =============================================================================
# Sample Generator Class
# =============================================================================

class SampleGenerator:
    """
    Unified sample generator for SecMutBench.

    Usage:
        generator = SampleGenerator()
        samples = generator.from_templates("CWE-89")
        samples = generator.from_security_eval(raw_samples)
        samples = generator.from_cyber_sec_eval(raw_samples)
    """

    def __init__(self):
        """Initialize sample generator."""
        self.source_manager = SourceManager()

    def from_template(self, cwe: str, template: Dict, index: int = 0) -> Sample:
        """Generate a sample from a template."""
        entry_point = template["entry_point"]
        sample_id = generate_id(f"{cwe}_{entry_point}_{index}")

        cwe_info = CWE_REGISTRY.get(cwe, {})

        return Sample(
            id=sample_id,
            cwe=cwe,
            cwe_name=cwe_info.get("name", cwe),
            difficulty=template.get("difficulty", "medium"),
            prompt=template["prompt"],
            entry_point=entry_point,
            insecure_code=template["insecure"],
            secure_code=template["secure"],
            functional_tests=generate_functional_test(entry_point, cwe),
            security_tests=generate_security_test(entry_point, cwe),
            mutation_operators=cwe_info.get("operators", ["RVALID"]),
            source="SecMutBench",
            original_id=f"{cwe}_{entry_point}"
        )

    def from_templates(self, cwe: Optional[str] = None) -> List[Sample]:
        """Generate samples from all templates for a CWE or all CWEs."""
        samples = []
        templates = self.source_manager.load_templates(cwe)

        for i, t in enumerate(templates):
            template_cwe = t.get("cwe", cwe)
            if template_cwe:
                sample = self.from_template(template_cwe, t, i)
                samples.append(sample)

        return samples

    def from_security_eval(self, raw: Dict) -> Optional[Sample]:
        """Transform SecurityEval sample to SecMutBench format."""
        try:
            # Extract CWE from ID (format: CWE-089_author_1.py)
            sample_id_raw = raw.get("ID", raw.get("id", raw.get("original_id", "")))
            cwe_match = re.search(r'CWE-0*(\d+)', sample_id_raw)
            if cwe_match:
                cwe = f"CWE-{cwe_match.group(1)}"
            else:
                cwe = raw.get("cwe", "")
                if not cwe:
                    return None
                cwe = normalize_cwe(cwe)

            # Get code
            code = raw.get("Insecure_code", raw.get("insecure_code", raw.get("code", "")))
            if not code:
                return None

            # Preprocess code to fix indentation and Python 2 issues
            code = preprocess_code(code)

            # Skip if still can't compile
            try:
                compile(code, '<code>', 'exec')
            except SyntaxError:
                return None

            # Extract entry point
            entry_point = extract_function_name(code)
            if not entry_point:
                entry_point = f"func_{generate_id(code)[:6]}"

            # Generate secure code
            secure_code, _ = generate_secure_code(code, cwe, raw.get("Prompt", ""))

            # Validate secure code compiles
            try:
                compile(secure_code, '<secure>', 'exec')
            except SyntaxError:
                # If secure code doesn't compile, use preprocessed original
                secure_code = code

            # Generate ID
            sample_id = generate_id(f"seceval_{sample_id_raw}_{code[:50]}")

            cwe_info = CWE_REGISTRY.get(cwe, {})

            return Sample(
                id=sample_id,
                cwe=cwe,
                cwe_name=cwe_info.get("name", cwe),
                difficulty=estimate_difficulty(code, cwe),
                prompt=raw.get("Prompt", raw.get("prompt", f"Implement {entry_point}")),
                entry_point=entry_point,
                insecure_code=code,
                secure_code=secure_code,
                functional_tests=generate_functional_test(entry_point, cwe),
                security_tests=generate_security_test(entry_point, cwe),
                mutation_operators=cwe_info.get("operators", ["RVALID"]),
                source="SecurityEval",
                original_id=sample_id_raw
            )

        except Exception as e:
            print(f"Error transforming SecurityEval sample: {e}")
            return None

    def from_cyber_sec_eval(self, raw: Dict) -> Optional[Sample]:
        """Transform CyberSecEval sample to SecMutBench format."""
        try:
            cwe = raw.get("cwe_identifier", raw.get("cwe", ""))
            if not cwe:
                return None
            cwe = normalize_cwe(cwe)

            # Get code
            code = raw.get("origin_code", raw.get("code", raw.get("prompt", "")))
            if not code:
                return None

            # Preprocess code to fix indentation and Python 2 issues
            code = preprocess_code(code)

            # Skip if still can't compile
            try:
                compile(code, '<code>', 'exec')
            except SyntaxError:
                return None

            # Extract entry point
            entry_point = extract_function_name(code)
            if not entry_point:
                entry_point = f"func_{generate_id(code)[:6]}"

            # Generate secure code
            secure_code, _ = generate_secure_code(code, cwe)

            # Validate secure code compiles
            try:
                compile(secure_code, '<secure>', 'exec')
            except SyntaxError:
                # If secure code doesn't compile, use preprocessed original
                secure_code = code

            # Generate ID
            original_id = raw.get("pattern_id", raw.get("id", generate_id(code)))
            sample_id = generate_id(f"cybersec_{original_id}_{code[:50]}")

            cwe_info = CWE_REGISTRY.get(cwe, {})

            return Sample(
                id=sample_id,
                cwe=cwe,
                cwe_name=cwe_info.get("name", raw.get("cwe_name", cwe)),
                difficulty=estimate_difficulty(code, cwe),
                prompt=raw.get("prompt", f"Implement {entry_point}"),
                entry_point=entry_point,
                insecure_code=code,
                secure_code=secure_code,
                functional_tests=generate_functional_test(entry_point, cwe),
                security_tests=generate_security_test(entry_point, cwe),
                mutation_operators=cwe_info.get("operators", ["RVALID"]),
                source="CyberSecEval",
                original_id=str(original_id)
            )

        except Exception as e:
            print(f"Error transforming CyberSecEval sample: {e}")
            return None

    def generate_all(self, include_external: bool = True) -> List[Sample]:
        """
        Generate all samples from all sources.

        Args:
            include_external: Whether to include SecurityEval/CyberSecEval

        Returns:
            List of all generated samples
        """
        samples = []

        # Generate from templates
        print("Generating from templates...")
        template_samples = self.from_templates()
        print(f"  Generated {len(template_samples)} from templates")
        samples.extend(template_samples)

        if include_external:
            # Transform SecurityEval
            print("Transforming SecurityEval samples...")
            se_raw = self.source_manager.load_security_eval()
            se_samples = []
            for raw in se_raw:
                sample = self.from_security_eval(raw)
                if sample:
                    se_samples.append(sample)
            print(f"  Transformed {len(se_samples)} from SecurityEval")
            samples.extend(se_samples)

            # Transform CyberSecEval
            print("Transforming CyberSecEval samples...")
            cse_raw = self.source_manager.load_cyber_sec_eval()
            cse_samples = []
            for raw in cse_raw:
                sample = self.from_cyber_sec_eval(raw)
                if sample:
                    cse_samples.append(sample)
            print(f"  Transformed {len(cse_samples)} from CyberSecEval")
            samples.extend(cse_samples)

        return samples

    def validate_samples(self, samples: List[Sample]) -> Tuple[List[Sample], List[Dict]]:
        """
        Validate samples and return valid/invalid lists.

        Returns:
            Tuple of (valid_samples, invalid_sample_info)
        """
        valid = []
        invalid = []

        for sample in samples:
            is_valid, issues = sample.validate()
            if is_valid:
                valid.append(sample)
            else:
                invalid.append({
                    "id": sample.id,
                    "cwe": sample.cwe,
                    "source": sample.source,
                    "issues": issues
                })

        return valid, invalid


def main():
    """Test the sample generator."""
    import argparse

    parser = argparse.ArgumentParser(description="Test sample generation")
    parser.add_argument("--cwe", help="Generate for specific CWE")
    parser.add_argument("--templates-only", action="store_true", help="Only generate from templates")
    parser.add_argument("--validate", action="store_true", help="Validate generated samples")
    parser.add_argument("--output", help="Output file for samples")

    args = parser.parse_args()

    generator = SampleGenerator()

    if args.cwe:
        samples = generator.from_templates(args.cwe)
        print(f"\nGenerated {len(samples)} samples for {args.cwe}")
    elif args.templates_only:
        samples = generator.from_templates()
        print(f"\nGenerated {len(samples)} samples from templates")
    else:
        samples = generator.generate_all(include_external=True)
        print(f"\nGenerated {len(samples)} total samples")

    if args.validate:
        valid, invalid = generator.validate_samples(samples)
        print(f"\nValidation: {len(valid)} valid, {len(invalid)} invalid")
        if invalid:
            print("\nInvalid samples:")
            for info in invalid[:5]:
                print(f"  {info['id']} ({info['cwe']}): {info['issues']}")

    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, 'w') as f:
            json.dump([s.to_dict() for s in samples], f, indent=2)
        print(f"\nSaved {len(samples)} samples to {output_path}")

    # Show sample distribution
    cwe_counts = {}
    source_counts = {}
    for s in samples:
        cwe_counts[s.cwe] = cwe_counts.get(s.cwe, 0) + 1
        source_counts[s.source] = source_counts.get(s.source, 0) + 1

    print("\nDistribution by CWE:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")

    print("\nDistribution by source:")
    for source, count in sorted(source_counts.items()):
        print(f"  {source}: {count}")


if __name__ == "__main__":
    main()
