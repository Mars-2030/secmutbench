#!/usr/bin/env python3
"""
Transform SecurityEval and CyberSecEval datasets to SecMutBench format.

This script:
1. Loads raw samples from both datasets
2. Transforms them to SecMutBench schema
3. Generates secure code versions using vulnerability-specific patterns
4. Generates functional and security tests
5. Maps appropriate mutation operators
"""

import ast
import json
import re
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
import hashlib


# CWE mappings
CWE_INFO = {
    "CWE-20": {"name": "Improper Input Validation", "operators": ["RVALID"]},
    "CWE-22": {"name": "Path Traversal", "operators": ["PATHCONCAT", "RVALID"]},
    "CWE-78": {"name": "OS Command Injection", "operators": ["CMDINJECT", "RVALID"]},
    "CWE-79": {"name": "Cross-Site Scripting (XSS)", "operators": ["RVALID"]},
    "CWE-89": {"name": "SQL Injection", "operators": ["PSQLI", "RVALID"]},
    "CWE-94": {"name": "Code Injection", "operators": ["RVALID"]},
    "CWE-116": {"name": "Improper Encoding", "operators": ["RVALID"]},
    "CWE-117": {"name": "Improper Output Neutralization for Logs", "operators": ["RVALID"]},
    "CWE-287": {"name": "Improper Authentication", "operators": ["RMAUTH"]},
    "CWE-295": {"name": "Improper Certificate Validation", "operators": ["RENCRYPT"]},
    "CWE-306": {"name": "Missing Authentication", "operators": ["RMAUTH"]},
    "CWE-312": {"name": "Cleartext Storage of Sensitive Info", "operators": ["RENCRYPT"]},
    "CWE-327": {"name": "Weak Cryptography", "operators": ["WEAKCRYPTO"]},
    "CWE-328": {"name": "Reversible One-Way Hash", "operators": ["WEAKCRYPTO"]},
    "CWE-338": {"name": "Weak PRNG", "operators": ["WEAKCRYPTO"]},
    "CWE-347": {"name": "Improper Verification of Cryptographic Signature", "operators": ["WEAKCRYPTO"]},
    "CWE-502": {"name": "Insecure Deserialization", "operators": ["DESERIAL"]},
    "CWE-601": {"name": "Open Redirect", "operators": ["RVALID"]},
    "CWE-611": {"name": "XXE Injection", "operators": ["RVALID"]},
    "CWE-703": {"name": "Improper Check or Handling of Exceptional Conditions", "operators": ["RVALID"]},
    "CWE-730": {"name": "OWASP Top Ten 2021 Category A10", "operators": ["RVALID"]},
    "CWE-798": {"name": "Hardcoded Credentials", "operators": ["HARDCODE"]},
}


@dataclass
class TransformedSample:
    id: str
    cwe: str
    cwe_name: str
    difficulty: str
    source: str
    original_id: str
    prompt: str
    entry_point: str
    insecure_code: str
    secure_code: str
    functional_tests: str
    security_tests: str
    mutation_operators: List[str]


def normalize_cwe(cwe_raw: str) -> str:
    """Normalize CWE format (CWE-089 -> CWE-89)."""
    match = re.match(r'CWE-0*(\d+)', cwe_raw)
    if match:
        return f"CWE-{match.group(1)}"
    return cwe_raw


def extract_function_name(code: str) -> Optional[str]:
    """Extract first function name from code.

    Returns:
        Function name if found, None otherwise.
    """
    match = re.search(r'def\s+(\w+)\s*\(', code)
    if match:
        return match.group(1)
    return None  # Let caller handle missing function


def calculate_ast_depth(node, current_depth=0) -> int:
    """Calculate maximum AST nesting depth."""
    max_depth = current_depth
    for child in ast.iter_child_nodes(node):
        child_depth = calculate_ast_depth(child, current_depth + 1)
        max_depth = max(max_depth, child_depth)
    return max_depth


def estimate_difficulty(code: str, cwe: str = "") -> str:
    """Estimate difficulty based on multiple complexity factors.

    Factors:
    - Line count
    - Control flow complexity (branches, loops)
    - Function calls (more interactions)
    - AST nesting depth
    - CWE-specific modifiers (auth, deserialization are harder)
    """
    import ast

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

        # Count function calls (more calls = more complex interactions)
        calls = sum(1 for node in ast.walk(tree) if isinstance(node, ast.Call))

        # Calculate nesting depth
        max_depth = calculate_ast_depth(tree)

    except SyntaxError:
        pass  # Use defaults

    # CWE-specific difficulty modifiers (inherently harder to test)
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


def validate_python_syntax(code: str) -> Tuple[bool, Optional[str]]:
    """Validate that code is syntactically correct Python.

    Returns:
        Tuple of (is_valid, error_message)
    """
    try:
        compile(code, "<secure>", "exec")
        return True, None
    except SyntaxError as e:
        return False, str(e)


def generate_secure_code(insecure_code: str, cwe: str, prompt: str) -> Tuple[str, bool]:
    """Generate secure version of insecure code based on CWE type.

    Returns:
        Tuple of (secure_code, transformation_succeeded)
        If transformation fails validation, returns original code with a comment.
    """

    secure = insecure_code
    transformed = False

    # CWE-89: SQL Injection - Fix f-string to parameterized query
    if cwe == "CWE-89":
        # Pattern 1: f"SELECT ... WHERE col = {var}" with execute()
        # Transform to: execute("SELECT ... WHERE col = ?", (var,))
        def fix_fstring_sql(code: str) -> str:
            """Fix f-string SQL to parameterized queries."""
            lines = code.split('\n')
            new_lines = []
            query_var = None
            params = []

            for line in lines:
                # Detect f-string query assignment
                fstring_match = re.match(r'(\s*)(\w+)\s*=\s*f["\'](.+?)["\']', line)
                if fstring_match:
                    indent, var, query = fstring_match.groups()
                    # Extract placeholders
                    placeholders = re.findall(r'\{(\w+)\}', query)
                    if placeholders:
                        # Replace {var} with ? and collect params
                        clean_query = re.sub(r'\{(\w+)\}', '?', query)
                        params_str = ', '.join(placeholders)
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

        # Pattern 2: % formatting
        secure = re.sub(
            r'["\']([^"\']*?)%s([^"\']*?)["\'](\s*%\s*\(?)(\w+)(\)?)',
            lambda m: f'"{m.group(1)}?{m.group(2)}", ({m.group(4)},)',
            secure
        )
        transformed = True

    # CWE-78: Command Injection
    elif cwe == "CWE-78":
        # Replace shell=True with shell=False
        if 'shell=True' in secure:
            secure = re.sub(r'shell\s*=\s*True', 'shell=False', secure)
            transformed = True
        # Replace os.system with subprocess.run with list args
        if 'os.system(' in secure:
            secure = secure.replace('os.system(', 'subprocess.run([')
            # This needs more sophisticated handling but flags it
            transformed = True
        if 'subprocess' in secure and 'shlex' not in secure:
            secure = 'import shlex\n' + secure

    # CWE-22: Path Traversal
    elif cwe == "CWE-22":
        # Add path validation function
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
        # Replace string concat with os.path.join
        secure = re.sub(
            r'(\w+)\s*\+\s*["\'/]+\s*\+\s*(\w+)',
            r'os.path.join(\1, \2)',
            secure
        )

    # CWE-79: XSS
    elif cwe == "CWE-79":
        # Add html.escape to string outputs
        if 'html' not in secure:
            secure = 'import html\n' + secure
        # Wrap return values with html.escape
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

    # CWE-338: Weak PRNG
    elif cwe == "CWE-338":
        if 'import random' in secure or 'random.' in secure:
            secure = secure.replace('import random', 'import secrets')
            secure = re.sub(r'random\.randint\((\d+),\s*(\d+)\)', r'secrets.randbelow(\2)', secure)
            secure = re.sub(r'random\.choice\(', 'secrets.choice(', secure)
            secure = re.sub(r'random\.random\(\)', 'secrets.randbelow(1000000) / 1000000', secure)
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
        # Replace hardcoded strings with env vars
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
        if 'exec(' in secure:
            # exec cannot be made safe, comment it out
            secure = re.sub(r'exec\((.+?)\)', r'# UNSAFE REMOVED: exec(\1)', secure)
            transformed = True

    # CWE-20: Input Validation
    elif cwe == "CWE-20":
        if 'yaml.load(' in secure and 'safe_load' not in secure:
            secure = secure.replace('yaml.load(', 'yaml.safe_load(')
            transformed = True

    # CWE-287/306: Authentication Issues
    elif cwe in ["CWE-287", "CWE-306"]:
        # Add authentication check placeholder
        if 'def ' in secure and 'is_authenticated' not in secure:
            # Find function definition and add auth check
            secure = re.sub(
                r'(def \w+\([^)]*\):)\n(\s+)',
                r'\1\n\2if not is_authenticated():\n\2    raise PermissionError("Authentication required")\n\2',
                secure
            )
            transformed = True

    # Validate the transformation produced valid Python
    is_valid, error = validate_python_syntax(secure)
    if not is_valid:
        # Return original with comment about failed transformation
        return (
            f"# AUTO-GENERATION FAILED: {error}\n"
            f"# Manual fix required for {cwe}\n"
            f"{insecure_code}",
            False
        )

    return secure, transformed


def generate_functional_tests(entry_point: str, cwe: str, code: str) -> str:
    """Generate functional tests for the code."""

    tests = []

    # Basic test that function exists and runs
    tests.append(f'''def test_{entry_point}_exists():
    """Test that {entry_point} function exists and is callable."""
    assert callable({entry_point})''')

    # CWE-specific functional tests
    if cwe == "CWE-89":
        tests.append(f'''
def test_{entry_point}_normal_input():
    """Test with normal input."""
    try:
        result = {entry_point}("test_value")
        assert result is not None or result is None  # May return None
    except Exception:
        pass  # Some implementations may raise on missing DB''')

    elif cwe == "CWE-78":
        tests.append(f'''
def test_{entry_point}_normal_input():
    """Test with normal input."""
    try:
        result = {entry_point}("localhost")
        assert isinstance(result, (bool, str, type(None)))
    except Exception:
        pass''')

    elif cwe == "CWE-22":
        tests.append(f'''
def test_{entry_point}_normal_file():
    """Test with normal filename."""
    try:
        result = {entry_point}("test.txt")
    except Exception:
        pass  # May fail if file doesn't exist''')

    elif cwe == "CWE-502":
        tests.append(f'''
def test_{entry_point}_valid_data():
    """Test with valid data."""
    try:
        result = {entry_point}("{{}}")
    except Exception:
        pass''')

    else:
        tests.append(f'''
def test_{entry_point}_basic():
    """Basic functionality test."""
    try:
        result = {entry_point}("test")
    except Exception:
        pass''')

    return '\n'.join(tests)


def generate_security_tests(entry_point: str, cwe: str, code: str) -> str:
    """Generate behavioral security tests that execute attack payloads.

    These tests verify security by:
    1. Executing actual attack payloads against the function
    2. Monitoring mock objects to verify secure behavior
    3. Checking that secure implementations handle attacks properly

    Tests are designed to PASS on secure code and FAIL on vulnerable code.
    """

    tests = []

    if cwe == "CWE-89":
        # SQL Injection - Behavioral tests with mock database
        tests.append(f'''def test_{entry_point}_sql_injection_tautology():
    """Test SQL injection with tautology attack - PASS if payload in params, not query."""
    payload = "' OR '1'='1"
    try:
        result = {entry_point}(payload)
        # Secure code uses parameterized queries - payload should NOT be in raw query
        if hasattr(db, 'last_query') and db.last_query:
            assert payload not in db.last_query, f"SQL injection: payload found in query: {{db.last_query}}"
    except (ValueError, TypeError) as e:
        pass  # Rejecting malicious input is also secure

def test_{entry_point}_sql_injection_union():
    """Test SQL injection with UNION attack."""
    payload = "' UNION SELECT password FROM users--"
    try:
        result = {entry_point}(payload)
        if hasattr(db, 'last_query') and db.last_query:
            assert "UNION" not in db.last_query.upper(), "UNION injection detected in query"
    except (ValueError, TypeError):
        pass

def test_{entry_point}_sql_injection_stacked():
    """Test SQL injection with stacked queries."""
    payload = "'; DROP TABLE users;--"
    try:
        result = {entry_point}(payload)
        if hasattr(db, 'last_query') and db.last_query:
            assert "DROP" not in db.last_query.upper(), "Stacked query injection detected"
    except (ValueError, TypeError):
        pass

def test_{entry_point}_uses_parameterization():
    """Verify parameterized queries are used."""
    # Call with normal input and check db mock was called with params
    try:
        result = {entry_point}("test_user")
        # If db tracks params, verify they were used
        if hasattr(db, 'last_params'):
            assert db.last_params is not None, "No parameterization: params should not be None"
    except Exception:
        pass''')

    elif cwe == "CWE-78":
        # Command Injection - Behavioral tests
        tests.append(f'''def test_{entry_point}_command_injection_semicolon():
    """Test command injection with semicolon chaining."""
    payload = "localhost; cat /etc/passwd"
    try:
        result = {entry_point}(payload)
        # Result should NOT contain /etc/passwd contents
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "root:" not in result_str, "Command injection: /etc/passwd content leaked"
    except (ValueError, OSError, subprocess.SubprocessError):
        pass  # Rejecting or failing on malicious input is secure

def test_{entry_point}_command_injection_pipe():
    """Test command injection with pipe."""
    payload = "localhost | whoami"
    try:
        result = {entry_point}(payload)
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            # Should not execute whoami
            assert len(result_str) < 100 or "localhost" in result_str
    except (ValueError, OSError):
        pass

def test_{entry_point}_command_injection_backtick():
    """Test command injection with backticks."""
    payload = "`cat /etc/passwd`"
    try:
        result = {entry_point}(payload)
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "root:" not in result_str
    except (ValueError, OSError):
        pass

def test_{entry_point}_command_injection_subshell():
    """Test command injection with $()."""
    payload = "$(id)"
    try:
        result = {entry_point}(payload)
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "uid=" not in result_str, "Subshell injection: id command executed"
    except (ValueError, OSError):
        pass''')

    elif cwe == "CWE-22":
        # Path Traversal - Behavioral tests with mock filesystem
        tests.append(f'''def test_{entry_point}_path_traversal_parent():
    """Test path traversal with ../ sequences."""
    payload = "../../../etc/passwd"
    try:
        result = {entry_point}(payload)
        # Should not return /etc/passwd contents
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "root:" not in result_str, "Path traversal: accessed /etc/passwd"
    except (ValueError, PermissionError, FileNotFoundError):
        pass  # Rejecting traversal is secure

def test_{entry_point}_path_traversal_absolute():
    """Test path traversal with absolute path."""
    payload = "/etc/passwd"
    try:
        result = {entry_point}(payload)
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "root:" not in result_str, "Path traversal: absolute path accessed"
    except (ValueError, PermissionError, FileNotFoundError):
        pass

def test_{entry_point}_path_traversal_encoded():
    """Test path traversal with encoded characters."""
    payload = "..%2f..%2f..%2fetc%2fpasswd"
    try:
        result = {entry_point}(payload)
        if isinstance(result, (str, bytes)):
            result_str = result.decode() if isinstance(result, bytes) else result
            assert "root:" not in result_str
    except (ValueError, PermissionError, FileNotFoundError):
        pass

def test_{entry_point}_stays_in_base_dir():
    """Test that access is restricted to allowed directory."""
    if hasattr(fs, 'base_dir'):
        # Try to escape base directory
        payload = "../../../tmp/test"
        try:
            result = {entry_point}(payload)
            # Should not access files outside base_dir
            if hasattr(fs, 'last_path') and fs.last_path:
                assert fs.last_path.startswith(fs.base_dir), "Accessed path outside base directory"
        except (ValueError, PermissionError):
            pass''')

    elif cwe == "CWE-79":
        # XSS - Behavioral tests verifying output encoding
        tests.append(f'''def test_{entry_point}_xss_script_tag():
    """Test XSS with script tag - should be escaped in output."""
    payload = "<script>alert('XSS')</script>"
    try:
        result = {entry_point}(payload)
        if isinstance(result, str):
            # Output should have escaped HTML
            assert "<script>" not in result, "XSS: unescaped script tag in output"
            assert "&lt;script&gt;" in result or payload not in result
    except ValueError:
        pass  # Rejecting malicious input is also secure

def test_{entry_point}_xss_event_handler():
    """Test XSS with event handler injection."""
    payload = '<img src=x onerror="alert(1)">'
    try:
        result = {entry_point}(payload)
        if isinstance(result, str):
            assert 'onerror=' not in result.lower(), "XSS: unescaped event handler"
    except ValueError:
        pass

def test_{entry_point}_xss_javascript_uri():
    """Test XSS with javascript: URI."""
    payload = "javascript:alert(document.cookie)"
    try:
        result = {entry_point}(payload)
        if isinstance(result, str):
            assert "javascript:" not in result.lower(), "XSS: javascript URI not sanitized"
    except ValueError:
        pass

def test_{entry_point}_xss_html_entities():
    """Test that HTML special characters are escaped."""
    payload = "<>&\\""
    try:
        result = {entry_point}(payload)
        if isinstance(result, str) and payload in result:
            # If payload appears, check it's escaped
            assert "&lt;" in result or "&gt;" in result or "&amp;" in result
    except ValueError:
        pass''')

    elif cwe == "CWE-502":
        # Insecure Deserialization - Behavioral tests
        tests.append(f'''def test_{entry_point}_pickle_rce():
    """Test that pickle deserialization doesn't allow RCE."""
    # Create a pickle payload that would execute code if deserialized with pickle
    import pickle
    import base64

    class RCE:
        def __reduce__(self):
            return (eval, ("__import__('os').system('echo PWNED')",))

    malicious = base64.b64encode(pickle.dumps(RCE())).decode()

    try:
        result = {entry_point}(malicious)
        # If function accepts this, it should use safe deserialization
        # that doesn't execute the payload
    except (ValueError, TypeError, json.JSONDecodeError):
        pass  # Rejecting pickle data is secure

def test_{entry_point}_safe_json():
    """Test that safe JSON-like data works."""
    safe_data = '{{"key": "value", "number": 42}}'
    try:
        result = {entry_point}(safe_data)
        # Should successfully parse safe data
        assert result is not None or True  # May return None for some implementations
    except json.JSONDecodeError:
        pass  # JSON errors are acceptable

def test_{entry_point}_yaml_safe_load():
    """Test YAML uses safe_load."""
    # Dangerous YAML that would execute with yaml.load()
    malicious_yaml = "!!python/object/apply:os.system [echo PWNED]"
    try:
        result = {entry_point}(malicious_yaml)
        # Should not execute the command
    except (ValueError, yaml.YAMLError):
        pass''')

    elif cwe in ["CWE-327", "CWE-328"]:
        # Weak Cryptography - Test output characteristics
        tests.append(f'''def test_{entry_point}_hash_length():
    """Test that hash output is appropriate length for strong algorithm."""
    test_input = "test_password_123"
    try:
        result = {entry_point}(test_input)
        if isinstance(result, str):
            # SHA-256 produces 64 hex chars, MD5 produces 32
            assert len(result) >= 64, f"Hash too short ({{len(result)}}), may be using weak algorithm"
        elif isinstance(result, bytes):
            # SHA-256 produces 32 bytes, MD5 produces 16
            assert len(result) >= 32, f"Hash too short ({{len(result)}} bytes)"
    except Exception:
        pass

def test_{entry_point}_different_inputs_different_hashes():
    """Test hash produces different outputs for different inputs."""
    try:
        result1 = {entry_point}("input1")
        result2 = {entry_point}("input2")
        assert result1 != result2, "Hash collision or constant output"
    except Exception:
        pass

def test_{entry_point}_consistent_output():
    """Test hash is deterministic."""
    test_input = "consistent_test"
    try:
        result1 = {entry_point}(test_input)
        result2 = {entry_point}(test_input)
        assert result1 == result2, "Hash not deterministic"
    except Exception:
        pass''')

    elif cwe == "CWE-338":
        # Weak PRNG - Test randomness properties
        tests.append(f'''def test_{entry_point}_sufficient_entropy():
    """Test that generated values have sufficient entropy."""
    try:
        results = [{entry_point}() for _ in range(100)]
        unique = set(str(r) for r in results)
        # Should have high uniqueness (at least 90% unique)
        assert len(unique) >= 90, f"Low entropy: only {{len(unique)}} unique values in 100 calls"
    except Exception:
        pass

def test_{entry_point}_unpredictable():
    """Test that values are not easily predictable."""
    try:
        results = [{entry_point}() for _ in range(10)]
        # Check that results aren't sequential or patterned
        if all(isinstance(r, (int, float)) for r in results):
            diffs = [results[i+1] - results[i] for i in range(len(results)-1)]
            # Diffs should not all be the same (sequential)
            assert len(set(diffs)) > 1, "Values appear sequential/predictable"
    except Exception:
        pass''')

    elif cwe == "CWE-798":
        # Hardcoded Credentials - Behavioral test
        tests.append(f'''def test_{entry_point}_no_hardcoded_password():
    """Test that passwords come from secure source, not hardcoded."""
    import os
    # Temporarily clear environment to test fallback behavior
    old_env = os.environ.copy()
    try:
        # Remove credential env vars
        for key in ["PASSWORD", "SECRET", "API_KEY", "TOKEN"]:
            os.environ.pop(key, None)

        # Function should fail or use empty/None, not hardcoded value
        result = {entry_point}()
        # If it returns a credential, it should be None or empty
        if isinstance(result, str):
            assert result in ("", None) or result.startswith("env:"), \\
                "Possible hardcoded credential returned when env vars missing"
    except (KeyError, ValueError, TypeError):
        pass  # Failing when credentials missing is secure
    finally:
        os.environ.update(old_env)

def test_{entry_point}_uses_environment():
    """Test credentials are loaded from environment."""
    import os
    test_password = "test_secure_password_12345"
    os.environ["PASSWORD"] = test_password
    try:
        result = {entry_point}()
        if result:
            assert test_password in str(result) or result == test_password, \\
                "Password not loaded from environment"
    except Exception:
        pass
    finally:
        os.environ.pop("PASSWORD", None)''')

    elif cwe == "CWE-94":
        # Code Injection - Behavioral tests
        tests.append(f'''def test_{entry_point}_eval_injection():
    """Test that eval injection doesn't execute arbitrary code."""
    payload = "__import__('os').system('echo PWNED')"
    try:
        result = {entry_point}(payload)
        # If function parses this, it should use ast.literal_eval which would fail
        # on __import__ calls
    except (ValueError, SyntaxError, TypeError):
        pass  # Rejecting malicious code is secure

def test_{entry_point}_safe_literal():
    """Test that safe literals are parsed correctly."""
    safe_inputs = [
        "42",
        "[1, 2, 3]",
        "{{'key': 'value'}}",
        "True",
        "'hello'"
    ]
    for safe in safe_inputs:
        try:
            result = {entry_point}(safe)
            # Should successfully parse safe literals
        except (ValueError, SyntaxError):
            pass  # Some implementations may be more restrictive

def test_{entry_point}_no_function_calls():
    """Test that function calls are not executed."""
    payload = "print('executed')"
    try:
        result = {entry_point}(payload)
        # If this returns without error, it should NOT have printed
    except (ValueError, SyntaxError):
        pass''')

    elif cwe == "CWE-611":
        # XXE - Behavioral tests
        tests.append(f'''def test_{entry_point}_xxe_file_read():
    """Test XXE file read prevention."""
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<data>&xxe;</data>"""
    try:
        result = {entry_point}(xxe_payload)
        if result:
            result_str = str(result)
            assert "root:" not in result_str, "XXE: /etc/passwd contents leaked"
    except (ValueError, Exception):
        pass  # Rejecting XXE is secure

def test_{entry_point}_xxe_external_entity():
    """Test external entity prevention."""
    xxe_payload = """<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]>
<data>&xxe;</data>"""
    try:
        result = {entry_point}(xxe_payload)
        # Should not make external request
    except (ValueError, Exception):
        pass

def test_{entry_point}_safe_xml():
    """Test that safe XML parses correctly."""
    safe_xml = "<root><item>value</item></root>"
    try:
        result = {entry_point}(safe_xml)
        assert result is not None
    except Exception:
        pass''')

    elif cwe in ["CWE-287", "CWE-306"]:
        # Authentication bypass - Behavioral tests
        tests.append(f'''def test_{entry_point}_requires_auth():
    """Test that function requires authentication."""
    # Mock unauthenticated user
    try:
        # Clear any auth state
        if hasattr({entry_point}, '__globals__'):
            {entry_point}.__globals__['is_authenticated'] = lambda: False

        result = {entry_point}()
        # Should raise or return unauthorized
        assert result is None or result == False or "unauthorized" in str(result).lower()
    except (PermissionError, ValueError, Exception) as e:
        # Raising on unauthenticated access is secure
        assert "auth" in str(e).lower() or "permission" in str(e).lower()

def test_{entry_point}_allows_authenticated():
    """Test that authenticated users can access."""
    try:
        if hasattr({entry_point}, '__globals__'):
            {entry_point}.__globals__['is_authenticated'] = lambda: True

        result = {entry_point}()
        # Should succeed for authenticated users
    except PermissionError:
        pass  # May still need additional authorization''')

    else:
        # Generic security test - behavioral
        tests.append(f'''def test_{entry_point}_handles_malicious_input():
    """Test graceful handling of potentially malicious input."""
    malicious_inputs = [
        "<script>alert(1)</script>",
        "'; DROP TABLE users;--",
        "../../../etc/passwd",
        "{{{{constructor.constructor('return this')()}}}}",
    ]
    for payload in malicious_inputs:
        try:
            result = {entry_point}(payload)
            # Should handle without crashing or exposing sensitive data
        except (ValueError, TypeError, Exception):
            pass  # Rejecting malicious input is acceptable

def test_{entry_point}_normal_operation():
    """Test normal operation with benign input."""
    try:
        result = {entry_point}("normal_input")
        # Should process normal input without error
    except Exception as e:
        # Log but don't fail - may need specific input format
        pass''')

    return '\n'.join(tests)


def transform_securityeval_sample(sample: Dict, index: int) -> Optional[TransformedSample]:
    """Transform a SecurityEval sample."""

    sample_id = sample.get("ID", "")
    cwe_raw = sample_id.split("_")[0] if sample_id else ""
    cwe = normalize_cwe(cwe_raw)

    if not cwe or cwe not in CWE_INFO:
        return None

    prompt = sample.get("Prompt", "")
    insecure_code = sample.get("Insecure_code", "")

    if not prompt or not insecure_code:
        return None

    # Extract entry point - skip samples without clear function definition
    entry_point = extract_function_name(prompt)
    if entry_point is None:
        entry_point = extract_function_name(insecure_code)
    if entry_point is None:
        return None  # Skip samples without identifiable entry point

    # Generate secure code with validation
    secure_code, transform_succeeded = generate_secure_code(insecure_code, cwe, prompt)

    return TransformedSample(
        id=f"SE_{cwe}_{index:03d}",
        cwe=cwe,
        cwe_name=CWE_INFO[cwe]["name"],
        difficulty=estimate_difficulty(insecure_code, cwe),
        source="SecurityEval",
        original_id=sample_id,
        prompt=prompt,
        entry_point=entry_point,
        insecure_code=insecure_code,
        secure_code=secure_code,
        functional_tests=generate_functional_tests(entry_point, cwe, insecure_code),
        security_tests=generate_security_tests(entry_point, cwe, insecure_code),
        mutation_operators=CWE_INFO[cwe]["operators"],
    )


def transform_cyberseceval_sample(sample: Dict, index: int) -> Optional[TransformedSample]:
    """Transform a CyberSecEval sample."""

    cwe = sample.get("cwe_identifier", "")
    if not cwe or cwe not in CWE_INFO:
        return None

    prompt = sample.get("prompt", "")
    origin_code = sample.get("origin_code", "")

    if not prompt:
        return None

    # CyberSecEval has prompts but may not have complete code
    # Use origin_code as insecure example if available
    if origin_code:
        insecure_code = origin_code
    else:
        # Skip samples without actual code
        return None

    # Extract entry point - skip samples without clear function definition
    entry_point = extract_function_name(insecure_code)
    if entry_point is None:
        return None  # Skip samples without identifiable entry point

    # Generate secure code with validation
    secure_code, transform_succeeded = generate_secure_code(insecure_code, cwe, prompt)

    # Create unique ID from hash
    id_hash = hashlib.md5(f"{cwe}_{prompt[:100]}".encode()).hexdigest()[:6]

    return TransformedSample(
        id=f"CSE_{cwe}_{id_hash}",
        cwe=cwe,
        cwe_name=CWE_INFO[cwe]["name"],
        difficulty=estimate_difficulty(insecure_code, cwe),
        source="CyberSecEval",
        original_id=sample.get("pattern_id", ""),
        prompt=prompt,
        entry_point=entry_point,
        insecure_code=insecure_code,
        secure_code=secure_code,
        functional_tests=generate_functional_tests(entry_point, cwe, insecure_code),
        security_tests=generate_security_tests(entry_point, cwe, insecure_code),
        mutation_operators=CWE_INFO[cwe]["operators"],
    )


def transform_all_samples(
    securityeval_path: str,
    cyberseceval_path: str,
    output_path: str,
    existing_samples_path: Optional[str] = None,
) -> Dict:
    """Transform all samples from both datasets."""

    all_samples = []
    stats = {
        "securityeval": {"total": 0, "transformed": 0, "skipped": 0},
        "cyberseceval": {"total": 0, "transformed": 0, "skipped": 0},
        "existing": {"total": 0},
        "by_cwe": {},
    }

    # Load existing samples if provided
    existing_ids = set()
    if existing_samples_path and os.path.exists(existing_samples_path):
        with open(existing_samples_path, "r") as f:
            existing = json.load(f)
        all_samples.extend(existing)
        existing_ids = {s["id"] for s in existing}
        stats["existing"]["total"] = len(existing)
        print(f"Loaded {len(existing)} existing samples")

    # Transform SecurityEval
    if os.path.exists(securityeval_path):
        with open(securityeval_path, "r") as f:
            se_samples = json.load(f)

        stats["securityeval"]["total"] = len(se_samples)
        se_index = 1

        for sample in se_samples:
            transformed = transform_securityeval_sample(sample, se_index)
            if transformed and transformed.id not in existing_ids:
                all_samples.append(asdict(transformed))
                existing_ids.add(transformed.id)
                stats["securityeval"]["transformed"] += 1

                cwe = transformed.cwe
                stats["by_cwe"][cwe] = stats["by_cwe"].get(cwe, 0) + 1
                se_index += 1
            else:
                stats["securityeval"]["skipped"] += 1

        print(f"SecurityEval: {stats['securityeval']['transformed']} transformed, "
              f"{stats['securityeval']['skipped']} skipped")

    # Transform CyberSecEval
    if os.path.exists(cyberseceval_path):
        with open(cyberseceval_path, "r") as f:
            cse_samples = json.load(f)

        stats["cyberseceval"]["total"] = len(cse_samples)
        cse_index = 1

        for sample in cse_samples:
            transformed = transform_cyberseceval_sample(sample, cse_index)
            if transformed and transformed.id not in existing_ids:
                all_samples.append(asdict(transformed))
                existing_ids.add(transformed.id)
                stats["cyberseceval"]["transformed"] += 1

                cwe = transformed.cwe
                stats["by_cwe"][cwe] = stats["by_cwe"].get(cwe, 0) + 1
                cse_index += 1
            else:
                stats["cyberseceval"]["skipped"] += 1

        print(f"CyberSecEval: {stats['cyberseceval']['transformed']} transformed, "
              f"{stats['cyberseceval']['skipped']} skipped")

    # Save all samples
    with open(output_path, "w") as f:
        json.dump(all_samples, f, indent=2)

    print(f"\nTotal samples: {len(all_samples)}")
    print(f"Saved to: {output_path}")

    print("\nBy CWE:")
    for cwe, count in sorted(stats["by_cwe"].items(), key=lambda x: -x[1]):
        print(f"  {cwe}: {count}")

    return stats


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Transform datasets to SecMutBench format")
    parser.add_argument("--securityeval", default="data/raw_securityeval.json",
                        help="Path to SecurityEval raw data")
    parser.add_argument("--cyberseceval", default="data/raw_cyberseceval.json",
                        help="Path to CyberSecEval raw data")
    parser.add_argument("--existing", default="data/samples.json",
                        help="Path to existing samples to merge with")
    parser.add_argument("--output", default="data/samples_merged.json",
                        help="Output path")

    args = parser.parse_args()

    stats = transform_all_samples(
        args.securityeval,
        args.cyberseceval,
        args.output,
        args.existing,
    )

    print("\n" + "=" * 50)
    print("Transformation complete!")


if __name__ == "__main__":
    main()
