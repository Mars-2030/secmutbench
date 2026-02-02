"""
CWE Attack Vector Patterns for SecMutBench

Provides predefined attack patterns per CWE for coverage checking
without requiring LLM calls.
"""

from typing import Dict, List, Tuple


# Attack vectors by CWE with detection patterns
CWE_ATTACK_VECTORS: Dict[str, List[Dict[str, any]]] = {
    "CWE-89": [
        {
            "name": "SQL Tautology",
            "patterns": ["or '1'='1", "or 1=1", "' or ''='", "1=1", "tautology"],
            "importance": "critical",
            "description": "Tests should verify tautology attacks don't return unauthorized data"
        },
        {
            "name": "UNION Injection",
            "patterns": ["union", "union select", "union all"],
            "importance": "critical",
            "description": "Tests should verify UNION attacks fail"
        },
        {
            "name": "Stacked Queries",
            "patterns": ["drop table", "delete from", "; select", ";select", "insert into"],
            "importance": "high",
            "description": "Tests should verify additional queries aren't executed"
        },
        {
            "name": "Comment Truncation",
            "patterns": ["--", "admin'--", "#", "/*"],
            "importance": "high",
            "description": "Tests should verify comments don't bypass authentication"
        },
        {
            "name": "Parameterization Check",
            "patterns": ["last_params", "parameterized", "execute(", "?", "%s"],
            "importance": "critical",
            "description": "Tests should verify parameterized queries are used"
        },
    ],
    "CWE-78": [
        {
            "name": "Command Chaining",
            "patterns": ["; ", " && ", " || ", ";rm", ";cat", "&& cat"],
            "importance": "critical",
            "description": "Tests should verify chained commands don't execute"
        },
        {
            "name": "Pipe Injection",
            "patterns": [" | ", "|cat", "|ls", "| grep"],
            "importance": "critical",
            "description": "Tests should verify piped commands fail"
        },
        {
            "name": "Backtick Execution",
            "patterns": ["`", "backtick", "`whoami`", "`id`"],
            "importance": "high",
            "description": "Tests should verify backticks aren't interpreted"
        },
        {
            "name": "Subshell Execution",
            "patterns": ["$(", "subshell", "$(whoami)", "$(id)"],
            "importance": "high",
            "description": "Tests should verify subshells don't execute"
        },
        {
            "name": "shell=True Check",
            "patterns": ["shell=true", "shell=false", "last_shell", "subprocess"],
            "importance": "critical",
            "description": "Tests should verify shell=False is used"
        },
    ],
    "CWE-22": [
        {
            "name": "Parent Traversal",
            "patterns": ["../", "..\\", "..", "traversal", "parent"],
            "importance": "critical",
            "description": "Tests should verify parent directory traversal fails"
        },
        {
            "name": "Encoded Traversal",
            "patterns": ["%2e", "%252e", "%2f", "encoded", "url"],
            "importance": "high",
            "description": "Tests should verify encoded traversal attempts fail"
        },
        {
            "name": "Absolute Path",
            "patterns": ["/etc/passwd", "/etc/shadow", "c:\\", "absolute"],
            "importance": "high",
            "description": "Tests should verify absolute paths are blocked"
        },
        {
            "name": "Null Byte Injection",
            "patterns": ["\\x00", "\\0", "null", "%00"],
            "importance": "medium",
            "description": "Tests should verify null bytes don't truncate paths"
        },
        {
            "name": "Base Directory Check",
            "patterns": ["base_dir", "startswith", "realpath", "abspath", "normpath"],
            "importance": "critical",
            "description": "Tests should verify path stays within allowed directory"
        },
    ],
    "CWE-79": [
        {
            "name": "Script Tag Injection",
            "patterns": ["<script>", "<script", "script>", "alert(", "javascript:"],
            "importance": "critical",
            "description": "Tests should verify script tags are escaped"
        },
        {
            "name": "Event Handler Injection",
            "patterns": ["onerror", "onclick", "onload", "onmouseover", "onfocus"],
            "importance": "critical",
            "description": "Tests should verify event handlers are escaped"
        },
        {
            "name": "Attribute Injection",
            "patterns": ["\"onclick", "'onclick", "\" onfocus", "' onfocus"],
            "importance": "high",
            "description": "Tests should verify attribute injection fails"
        },
        {
            "name": "HTML Escape Verification",
            "patterns": ["escape", "&lt;", "&gt;", "&amp;", "html.escape", "markupsafe"],
            "importance": "critical",
            "description": "Tests should verify proper HTML escaping"
        },
    ],
    "CWE-20": [
        {
            "name": "Boundary Value Testing",
            "patterns": ["negative", "-1", "0", "max", "min", "boundary", "2147483647"],
            "importance": "high",
            "description": "Tests should check boundary values"
        },
        {
            "name": "Type Confusion",
            "patterns": ["type", "isinstance", "string", "int", "float", "typeerror"],
            "importance": "high",
            "description": "Tests should verify type validation"
        },
        {
            "name": "Null/Empty Input",
            "patterns": ["none", "null", '""', "''", "empty", "[]", "{}"],
            "importance": "critical",
            "description": "Tests should handle null/empty inputs"
        },
        {
            "name": "Length Validation",
            "patterns": ["len(", "length", "maxlength", "minlength", "too long", "too short"],
            "importance": "medium",
            "description": "Tests should verify length constraints"
        },
        {
            "name": "Format Validation",
            "patterns": ["regex", "pattern", "format", "validate", "match"],
            "importance": "medium",
            "description": "Tests should verify format validation"
        },
    ],
    "CWE-798": [
        {
            "name": "Hardcoded Password Detection",
            "patterns": ["hardcoded", "password123", "secret", "admin123", "password ="],
            "importance": "critical",
            "description": "Tests should detect hardcoded passwords"
        },
        {
            "name": "Environment Variable Check",
            "patterns": ["os.environ", "os.getenv", "env.get", "was_accessed", "environ["],
            "importance": "critical",
            "description": "Tests should verify credentials come from environment"
        },
        {
            "name": "Config File Check",
            "patterns": ["config", ".env", "settings", "credentials"],
            "importance": "high",
            "description": "Tests should verify credentials come from config"
        },
    ],
    "CWE-327": [
        {
            "name": "MD5 Detection",
            "patterns": ["md5", "hashlib.md5", "md5("],
            "importance": "critical",
            "description": "Tests should detect weak MD5 usage"
        },
        {
            "name": "SHA1 Detection",
            "patterns": ["sha1", "hashlib.sha1", "sha1("],
            "importance": "critical",
            "description": "Tests should detect weak SHA1 usage"
        },
        {
            "name": "Weak Random Detection",
            "patterns": ["random.random", "random.randint", "time.time", "seed"],
            "importance": "high",
            "description": "Tests should verify secure random is used"
        },
        {
            "name": "Secure Algorithm Verification",
            "patterns": ["sha256", "sha512", "bcrypt", "argon2", "pbkdf2", "scrypt"],
            "importance": "critical",
            "description": "Tests should verify secure algorithms are used"
        },
    ],
    "CWE-502": [
        {
            "name": "Pickle Detection",
            "patterns": ["pickle.load", "pickle.loads", "unpickle", "cPickle"],
            "importance": "critical",
            "description": "Tests should detect unsafe pickle usage"
        },
        {
            "name": "YAML Detection",
            "patterns": ["yaml.load", "yaml.unsafe_load", "Loader=Loader"],
            "importance": "critical",
            "description": "Tests should detect unsafe YAML loading"
        },
        {
            "name": "Safe Deserialize Check",
            "patterns": ["safe_load", "SafeLoader", "json.loads", "literal_eval"],
            "importance": "critical",
            "description": "Tests should verify safe deserialization"
        },
    ],
    "CWE-287": [
        {
            "name": "Authentication Bypass",
            "patterns": ["bypass", "skip", "admin", "is_authenticated", "login"],
            "importance": "critical",
            "description": "Tests should verify authentication cannot be bypassed"
        },
        {
            "name": "Session Validation",
            "patterns": ["session", "token", "jwt", "cookie", "valid"],
            "importance": "high",
            "description": "Tests should verify session validation"
        },
        {
            "name": "Role Check",
            "patterns": ["role", "permission", "authorize", "access", "privilege"],
            "importance": "high",
            "description": "Tests should verify role-based access"
        },
    ],
    "CWE-306": [
        {
            "name": "Missing Auth Check",
            "patterns": ["@login_required", "@authenticate", "require_auth", "check_auth"],
            "importance": "critical",
            "description": "Tests should verify authentication decorators exist"
        },
        {
            "name": "Direct Access",
            "patterns": ["direct", "unauthenticated", "anonymous", "public"],
            "importance": "high",
            "description": "Tests should verify endpoints require authentication"
        },
    ],
    "CWE-352": [
        {
            "name": "CSRF Token Check",
            "patterns": ["csrf", "token", "csrftoken", "csrf_token", "_token"],
            "importance": "critical",
            "description": "Tests should verify CSRF token validation"
        },
        {
            "name": "Origin Check",
            "patterns": ["origin", "referer", "referrer", "same-origin"],
            "importance": "high",
            "description": "Tests should verify origin validation"
        },
    ],
}


def check_attack_coverage(test_code: str, cwe: str) -> Tuple[float, List[Dict], List[Dict]]:
    """
    Check which attack vectors are covered in the test code.

    Args:
        test_code: The test code to analyze
        cwe: The CWE identifier (e.g., "CWE-89")

    Returns:
        Tuple of (coverage_score, covered_attacks, missing_attacks)
    """
    # Normalize CWE format
    cwe = cwe.upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"

    expected_attacks = CWE_ATTACK_VECTORS.get(cwe, [])
    if not expected_attacks:
        return 1.0, [], []  # Unknown CWE, can't check

    test_lower = test_code.lower()
    covered = []
    missing = []

    for attack in expected_attacks:
        patterns = attack["patterns"]
        if any(p.lower() in test_lower for p in patterns):
            covered.append({
                "name": attack["name"],
                "importance": attack["importance"],
                "description": attack["description"],
            })
        else:
            missing.append({
                "name": attack["name"],
                "importance": attack["importance"],
                "description": attack["description"],
                "suggestion": f"Add test checking: {attack['description']}"
            })

    # Calculate weighted coverage (critical attacks worth more)
    weight_map = {"critical": 3, "high": 2, "medium": 1, "low": 0.5}

    total_weight = sum(weight_map.get(a["importance"], 1) for a in expected_attacks)
    covered_weight = sum(weight_map.get(a["importance"], 1) for a in covered)

    coverage_score = covered_weight / total_weight if total_weight > 0 else 0

    return coverage_score, covered, missing


def get_attack_vectors_for_cwe(cwe: str) -> List[Dict]:
    """Get all attack vectors for a specific CWE."""
    cwe = cwe.upper()
    if not cwe.startswith("CWE-"):
        cwe = f"CWE-{cwe}"
    return CWE_ATTACK_VECTORS.get(cwe, [])


def get_critical_attacks(cwe: str) -> List[str]:
    """Get only critical attack vector names for a CWE."""
    attacks = get_attack_vectors_for_cwe(cwe)
    return [a["name"] for a in attacks if a["importance"] == "critical"]


def format_coverage_report(
    cwe: str,
    coverage_score: float,
    covered: List[Dict],
    missing: List[Dict]
) -> str:
    """Format a human-readable coverage report."""
    lines = [
        f"Attack Vector Coverage for {cwe}",
        "=" * 40,
        f"Coverage Score: {coverage_score:.1%}",
        "",
        f"Covered ({len(covered)}):",
    ]

    for attack in covered:
        lines.append(f"  [+] {attack['name']} ({attack['importance']})")

    lines.append("")
    lines.append(f"Missing ({len(missing)}):")

    for attack in missing:
        lines.append(f"  [-] {attack['name']} ({attack['importance']})")
        lines.append(f"      Suggestion: {attack['suggestion']}")

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo
    sample_test = """
def test_sql_injection():
    result = get_user("1 OR 1=1")
    assert result is None

def test_union():
    result = get_user("1 UNION SELECT * FROM passwords")
    assert 'password' not in str(result)

def test_parameterized():
    get_user(1)
    assert db.last_params is not None
"""

    coverage, covered, missing = check_attack_coverage(sample_test, "CWE-89")
    print(format_coverage_report("CWE-89", coverage, covered, missing))
