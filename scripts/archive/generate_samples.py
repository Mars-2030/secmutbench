#!/usr/bin/env python3
"""
Research-Driven Sample Generator for SecMutBench

Generates validated security benchmark samples based on:
1. CWE research documents
2. OWASP attack payloads
3. Mock object contracts

Each sample is validated before output.

Contamination Prevention:
- PerturbationPipeline: Renames identifiers, removes comments, varies string literals
- TemporalFilter: Filters CVE-based samples by disclosure year (default: 2024+)
- ContaminationAuditor: N-gram overlap analysis with configurable threshold
- NovelSampleTracker: Tracks novel vs adapted samples, reports 30% requirement
"""

import json
import hashlib
import sys
import os

# Add parent directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict, field

# Import contamination prevention components
from contamination_prevention import (
    PerturbationPipeline,
    TemporalFilter,
    ContaminationAuditor,
    NovelSampleTracker,
    PerturbationResult,
    ContaminationAuditResult,
)


@dataclass
class ContaminationPreventionConfig:
    """Configuration for contamination prevention during sample generation."""

    # Enable/disable contamination prevention
    enabled: bool = True

    # PerturbationPipeline settings
    apply_perturbation: bool = True
    perturbation_seed: int = 42

    # TemporalFilter settings
    apply_temporal_filter: bool = True
    cutoff_year: int = 2024

    # ContaminationAuditor settings
    run_audit: bool = True
    ngram_size: int = 5
    contamination_threshold: float = 0.3

    # NovelSampleTracker settings
    track_novelty: bool = True
    require_30_percent_novel: bool = True

    # Output settings
    output_audit_report: bool = True
    output_fingerprint: bool = True


@dataclass
class ContaminationPreventionResult:
    """Results from contamination prevention processing."""

    original_count: int = 0
    final_count: int = 0

    # Temporal filtering results
    temporal_passed: int = 0
    temporal_filtered: int = 0

    # Perturbation results
    perturbation_success: int = 0
    perturbation_failed: int = 0

    # Audit results
    potentially_contaminated: int = 0
    contamination_rate: float = 0.0

    # Novelty tracking
    novel_count: int = 0
    adapted_count: int = 0
    novel_ratio: float = 0.0
    meets_30_percent_novel: bool = False

    # Details
    audit_details: Dict[str, Any] = field(default_factory=dict)
    novelty_by_source: Dict[str, int] = field(default_factory=dict)


@dataclass
class Sample:
    """A benchmark sample."""
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
    source: str = "SecMutBench"
    generation_method: str = "research-driven"
    generation_quality: str = "validated"


# ============================================================================
# CWE-89: SQL Injection Samples
# ============================================================================

CWE89_SAMPLES = [
    {
        "variant": "get_user",
        "prompt": "Write a function that retrieves a user from the database by username.",
        "entry_point": "get_user",
        "insecure_code": '''
def get_user(username):
    """Get user by username from database."""
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)
''',
        "secure_code": '''
def get_user(username):
    """Get user by username from database using parameterized query."""
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))
''',
        "functional_tests": '''
def test_get_user_existing():
    """Test retrieving an existing user."""
    db.reset()
    result = get_user("alice")
    assert result is not None

def test_get_user_returns_list():
    """Test that function returns a list."""
    db.reset()
    result = get_user("alice")
    assert isinstance(result, list)
''',
        "security_tests": '''
def test_sql_injection_tautology():
    """Test SQL injection with tautology payload."""
    db.reset()
    result = get_user("' OR '1'='1")
    # Secure code should use parameterized query
    assert db.last_params is not None, "SQL injection risk: query not parameterized"
    # With parameterization, injection payload is treated as literal username
    # No user named "' OR '1'='1" exists, so result should be empty
    assert len(result) == 0, f"SQL injection: got {len(result)} rows, expected 0"

def test_sql_injection_comment():
    """Test SQL injection with comment payload."""
    db.reset()
    result = get_user("admin'--")
    assert db.last_params is not None, "SQL injection risk: query not parameterized"
''',
        "mutation_operators": ["PSQLI", "RPS"],
    },
    {
        "variant": "search_products",
        "prompt": "Write a function that searches for products by name pattern.",
        "entry_point": "search_products",
        "insecure_code": '''
def search_products(search_term):
    """Search products by name."""
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    return db.execute(query)
''',
        "secure_code": '''
def search_products(search_term):
    """Search products by name using parameterized query."""
    query = "SELECT * FROM products WHERE name LIKE ?"
    return db.execute(query, (f"%{search_term}%",))
''',
        "functional_tests": '''
def test_search_products_basic():
    """Test basic product search."""
    db.reset()
    db.add_row("products", {"id": 1, "name": "Test Product"})
    result = search_products("Test")
    assert result is not None

def test_search_products_empty():
    """Test search with no results."""
    db.reset()
    result = search_products("nonexistent_xyz")
    assert result is not None
    assert len(result) == 0
''',
        "security_tests": '''
def test_search_sql_injection():
    """Test SQL injection in search."""
    db.reset()
    result = search_products("'; DROP TABLE products;--")
    assert db.last_params is not None, "SQL injection risk: query not parameterized"

def test_search_union_injection():
    """Test UNION-based SQL injection."""
    db.reset()
    result = search_products("' UNION SELECT * FROM users--")
    assert db.last_params is not None, "SQL injection risk: query not parameterized"
''',
        "mutation_operators": ["PSQLI", "RPS"],
    },
]


# ============================================================================
# CWE-78: Command Injection Samples
# ============================================================================

CWE78_SAMPLES = [
    {
        "variant": "ping_host",
        "prompt": "Write a function that pings a hostname and returns the result.",
        "entry_point": "ping_host",
        "insecure_code": '''
def ping_host(hostname):
    """Ping a host and return output."""
    command = f"ping -c 1 {hostname}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
''',
        "secure_code": '''
import re

def ping_host(hostname):
    """Ping a host safely using argument list."""
    # Validate hostname format
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname format")
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
    return result.stdout
''',
        "functional_tests": '''
def test_ping_valid_host():
    """Test pinging a valid hostname."""
    subprocess.reset()
    result = ping_host("localhost")
    assert result is not None
    assert len(result) > 0

def test_ping_ip_address():
    """Test pinging an IP address."""
    subprocess.reset()
    result = ping_host("127.0.0.1")
    assert result is not None
''',
        "security_tests": '''
def test_command_injection_semicolon():
    """Test command injection with semicolon."""
    subprocess.reset()
    try:
        result = ping_host("localhost; cat /etc/passwd")
    except ValueError:
        pass  # Secure code raises ValueError - this is correct
    else:
        # If no exception, check that shell=False was used
        assert subprocess.last_shell == False, "Command injection: shell=True used"
        assert ";" not in str(subprocess.last_command), "Command injection: payload in command"

def test_command_injection_pipe():
    """Test command injection with pipe."""
    subprocess.reset()
    try:
        result = ping_host("localhost | whoami")
    except ValueError:
        pass  # Secure code raises ValueError
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True used"
''',
        "mutation_operators": ["RCMDI", "SHELLT"],
    },
    {
        "variant": "lookup_dns",
        "prompt": "Write a function that performs DNS lookup for a domain.",
        "entry_point": "lookup_dns",
        "insecure_code": '''
def lookup_dns(domain):
    """Perform DNS lookup."""
    command = f"nslookup {domain}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
''',
        "secure_code": '''
import re

def lookup_dns(domain):
    """Perform DNS lookup safely."""
    # Validate domain format
    if not re.match(r'^[a-zA-Z0-9.-]+$', domain):
        raise ValueError("Invalid domain format")
    result = subprocess.run(["nslookup", domain], capture_output=True, text=True)
    return result.stdout
''',
        "functional_tests": '''
def test_lookup_valid_domain():
    """Test DNS lookup for valid domain."""
    subprocess.reset()
    result = lookup_dns("example.com")
    assert result is not None

def test_lookup_localhost():
    """Test DNS lookup for localhost."""
    subprocess.reset()
    result = lookup_dns("localhost")
    assert result is not None
''',
        "security_tests": '''
def test_dns_command_injection():
    """Test command injection in DNS lookup."""
    subprocess.reset()
    try:
        result = lookup_dns("example.com; cat /etc/passwd")
    except ValueError:
        pass  # Expected for secure code
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True used"
''',
        "mutation_operators": ["RCMDI", "SHELLT"],
    },
]


# ============================================================================
# CWE-22: Path Traversal Samples
# ============================================================================

CWE22_SAMPLES = [
    {
        "variant": "read_config",
        "prompt": "Write a function that reads a configuration file from the config directory.",
        "entry_point": "read_config",
        "insecure_code": '''
import os

def read_config(filename):
    """Read a configuration file."""
    path = os.path.join("/var/data", filename)
    return fs.read_file(path)
''',
        "secure_code": '''
import os

def read_config(filename):
    """Read a configuration file safely with path validation."""
    base_dir = "/var/data"
    # Normalize path to resolve ../ sequences
    path = os.path.normpath(os.path.join(base_dir, filename))
    # Verify path stays within base directory
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Path traversal detected")
    return fs.read_file(path)
''',
        "functional_tests": '''
def test_read_valid_config():
    """Test reading a valid config file."""
    fs.reset()
    fs.write_file("/var/data/config.txt", "config_value")
    result = read_config("config.txt")
    assert result == "config_value"

def test_read_subdirectory():
    """Test reading from subdirectory."""
    fs.reset()
    fs.write_file("/var/data/sub/settings.txt", "settings")
    result = read_config("sub/settings.txt")
    assert result == "settings"
''',
        "security_tests": '''
def test_path_traversal_etc_passwd():
    """Test path traversal to /etc/passwd."""
    fs.reset()
    try:
        result = read_config("../../../etc/passwd")
    except ValueError:
        pass  # Secure code raises ValueError
    else:
        # If no exception, verify we didn't escape base dir
        assert fs.last_path is None or fs.last_path.startswith("/var/data"), \
            f"Path traversal: accessed {fs.last_path}"
        assert result is None or "root:" not in str(result), \
            "Path traversal: accessed /etc/passwd content"

def test_path_traversal_absolute():
    """Test absolute path traversal."""
    fs.reset()
    try:
        result = read_config("/etc/passwd")
    except ValueError:
        pass  # Secure code raises ValueError
    else:
        assert fs.last_path is None or fs.last_path.startswith("/var/data")
''',
        "mutation_operators": ["RPTV", "APTV"],
    },
]


# ============================================================================
# CWE-79: XSS Samples
# ============================================================================

CWE79_SAMPLES = [
    {
        "variant": "render_greeting",
        "prompt": "Write a function that renders a greeting message with a username.",
        "entry_point": "render_greeting",
        "insecure_code": '''
def render_greeting(username):
    """Render greeting message (INSECURE - no escaping)."""
    return f"<div>Hello, {username}!</div>"
''',
        "secure_code": '''
import html

def render_greeting(username):
    """Render greeting message with HTML escaping."""
    safe_username = html.escape(username)
    return f"<div>Hello, {safe_username}!</div>"
''',
        "functional_tests": '''
def test_render_basic_greeting():
    """Test basic greeting rendering."""
    result = render_greeting("Alice")
    assert "Alice" in result
    assert "Hello" in result

def test_render_returns_html():
    """Test that output is HTML."""
    result = render_greeting("Bob")
    assert "<div>" in result
    assert "</div>" in result
''',
        "security_tests": '''
def test_xss_script_tag():
    """Test XSS with script tag."""
    result = render_greeting("<script>alert('XSS')</script>")
    # Secure version escapes < and >
    assert "<script>" not in result, "XSS: unescaped script tag"
    # Should contain escaped version
    assert "&lt;script&gt;" in result or "script" not in result.lower()

def test_xss_event_handler():
    """Test XSS with event handler."""
    result = render_greeting('<img onerror="alert(1)" src=x>')
    assert 'onerror="alert' not in result, "XSS: unescaped event handler"
''',
        "mutation_operators": ["RXSS", "HTMLESC"],
    },
]


# ============================================================================
# CWE-327: Weak Cryptography Samples (Already working - include as reference)
# ============================================================================

CWE327_SAMPLES = [
    {
        "variant": "hash_password",
        "prompt": "Write a function that hashes a password for secure storage.",
        "entry_point": "hash_password",
        "insecure_code": '''
import hashlib

def hash_password(password):
    """Hash a password using MD5 (INSECURE)."""
    return hashlib.md5(password.encode()).hexdigest()
''',
        "secure_code": '''
import hashlib

def hash_password(password):
    """Hash a password using SHA-256."""
    return hashlib.sha256(password.encode()).hexdigest()
''',
        "functional_tests": '''
def test_hash_returns_string():
    """Test that hash function returns a string."""
    result = hash_password("test_password")
    assert isinstance(result, str)
    assert len(result) > 0

def test_hash_deterministic():
    """Test that same input produces same hash."""
    result1 = hash_password("test")
    result2 = hash_password("test")
    assert result1 == result2

def test_hash_different_inputs():
    """Test that different inputs produce different hashes."""
    result1 = hash_password("password1")
    result2 = hash_password("password2")
    assert result1 != result2
''',
        "security_tests": '''
def test_hash_length():
    """Test hash length indicates strong algorithm."""
    result = hash_password("test")
    # MD5 = 32 chars, SHA-256 = 64 chars
    assert len(result) >= 64, f"Weak hash: length {len(result)} < 64 (SHA-256)"

def test_not_md5():
    """Test that hash is not MD5."""
    result = hash_password("test")
    md5_hash = hashlib.md5("test".encode()).hexdigest()
    assert result != md5_hash, "Weak cryptography: MD5 hash detected"
''',
        "mutation_operators": ["WCRYPTO", "WHASH"],
    },
    {
        "variant": "generate_token",
        "prompt": "Write a function that generates a secure random token.",
        "entry_point": "generate_token",
        "insecure_code": '''
import hashlib
import time

def generate_token():
    """Generate a token using weak randomness (INSECURE)."""
    return hashlib.md5(str(time.time()).encode()).hexdigest()
''',
        "secure_code": '''
import secrets

def generate_token():
    """Generate a cryptographically secure token."""
    return secrets.token_hex(32)
''',
        "functional_tests": '''
def test_token_returns_string():
    """Test that token function returns a string."""
    result = generate_token()
    assert isinstance(result, str)
    assert len(result) > 0

def test_token_unique():
    """Test that tokens are unique."""
    tokens = [generate_token() for _ in range(10)]
    assert len(set(tokens)) == 10, "Tokens should be unique"
''',
        "security_tests": '''
def test_token_length():
    """Test token has sufficient length for security."""
    result = generate_token()
    # Secure tokens should be at least 32 bytes (64 hex chars)
    assert len(result) >= 64, f"Token too short: {len(result)} < 64"

def test_token_randomness():
    """Test tokens appear random."""
    tokens = [generate_token() for _ in range(5)]
    # Check tokens don't share common prefix (would indicate weak randomness)
    prefixes = [t[:8] for t in tokens]
    assert len(set(prefixes)) == 5, "Tokens have predictable pattern"
''',
        "mutation_operators": ["WCRYPTO", "WRNG"],
    },
]


# ============================================================================
# CWE-798: Hardcoded Credentials Samples
# ============================================================================

CWE798_SAMPLES = [
    {
        "variant": "get_db_password",
        "prompt": "Write a function that returns the database password.",
        "entry_point": "get_db_password",
        "insecure_code": '''
def get_db_password():
    """Get database password (INSECURE - hardcoded)."""
    return "supersecret123"
''',
        "secure_code": '''
def get_db_password():
    """Get database password from environment variable."""
    password = env.get("DB_PASSWORD")
    if password is None:
        raise ValueError("DB_PASSWORD environment variable not set")
    return password
''',
        "functional_tests": '''
def test_get_password_returns_string():
    """Test that function returns a string."""
    env.reset()
    env.set("DB_PASSWORD", "test_password")
    result = get_db_password()
    assert isinstance(result, str)
    assert len(result) > 0
''',
        "security_tests": '''
def test_password_from_environment():
    """Test that password comes from environment, not hardcoded."""
    env.reset()
    # Set a unique test value
    test_value = "unique_env_password_xyz789"
    env.set("DB_PASSWORD", test_value)
    result = get_db_password()
    # If secure, result should match our test value
    assert result == test_value, f"Hardcoded password: got '{result}' instead of env value"
    # Verify environment was actually accessed
    assert env.was_accessed("DB_PASSWORD"), "Environment variable not accessed"

def test_password_not_hardcoded():
    """Test that password changes with environment."""
    env.reset()
    env.set("DB_PASSWORD", "value_one")
    result1 = get_db_password()
    env.set("DB_PASSWORD", "value_two")
    result2 = get_db_password()
    assert result1 != result2, "Password appears hardcoded (doesn't change with env)"
''',
        "mutation_operators": ["RHCRED", "HCPWD"],
    },
    {
        "variant": "get_api_key",
        "prompt": "Write a function that returns the API key for external service.",
        "entry_point": "get_api_key",
        "insecure_code": '''
def get_api_key():
    """Get API key (INSECURE - hardcoded)."""
    return "sk-hardcoded-api-key-12345"
''',
        "secure_code": '''
def get_api_key():
    """Get API key from environment variable."""
    api_key = env.get("API_KEY")
    if api_key is None:
        raise ValueError("API_KEY environment variable not set")
    return api_key
''',
        "functional_tests": '''
def test_get_api_key_returns_string():
    """Test that function returns a string."""
    env.reset()
    env.set("API_KEY", "test_api_key")
    result = get_api_key()
    assert isinstance(result, str)
    assert len(result) > 0
''',
        "security_tests": '''
def test_api_key_from_environment():
    """Test that API key comes from environment, not hardcoded."""
    env.reset()
    test_value = "unique_api_key_test_abc123"
    env.set("API_KEY", test_value)
    result = get_api_key()
    assert result == test_value, f"Hardcoded API key: got '{result}' instead of env value"
    assert env.was_accessed("API_KEY"), "Environment variable not accessed"
''',
        "mutation_operators": ["RHCRED", "HCPWD"],
    },
]


# ============================================================================
# CWE-502: Insecure Deserialization Samples
# ============================================================================

CWE502_SAMPLES = [
    {
        "variant": "load_user_data",
        "prompt": "Write a function that loads user data from a serialized string.",
        "entry_point": "load_user_data",
        "insecure_code": '''
import pickle
import base64

def load_user_data(data_string):
    """Load user data from serialized string (INSECURE - uses pickle)."""
    decoded = base64.b64decode(data_string)
    return pickle.loads(decoded)
''',
        "secure_code": '''
import json
import base64

def load_user_data(data_string):
    """Load user data from JSON string (secure)."""
    decoded = base64.b64decode(data_string)
    return json.loads(decoded.decode('utf-8'))
''',
        "functional_tests": '''
def test_load_valid_data():
    """Test loading valid user data."""
    import base64
    import json
    data = {"name": "alice", "role": "user"}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = load_user_data(encoded)
    assert result["name"] == "alice"

def test_load_returns_dict():
    """Test that result is a dictionary."""
    import base64
    import json
    data = {"id": 1}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = load_user_data(encoded)
    assert isinstance(result, dict)
''',
        "security_tests": '''
def test_no_pickle_deserialization():
    """Test that pickle is not used for deserialization."""
    import base64
    import json
    # Create valid JSON data
    data = {"safe": "data"}
    encoded = base64.b64encode(json.dumps(data).encode()).decode()
    result = load_user_data(encoded)
    # If using JSON, this should work fine
    assert result["safe"] == "data"

def test_rejects_non_json():
    """Test that non-JSON data is rejected."""
    import base64
    # Send data that's valid pickle but not JSON
    bad_data = base64.b64encode(b"not valid json").decode()
    try:
        result = load_user_data(bad_data)
        # If it succeeds, verify it didn't execute arbitrary code
        assert True  # JSON would fail to parse this
    except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
        pass  # Expected for secure JSON-based implementation
''',
        "mutation_operators": ["DESERIAL", "RPICKLE"],
    },
    {
        "variant": "load_config",
        "prompt": "Write a function that loads configuration from a file.",
        "entry_point": "load_config_file",
        "insecure_code": '''
import pickle

def load_config_file(filepath):
    """Load config from file (INSECURE - uses pickle)."""
    content = fs.read_file(filepath)
    if content:
        return pickle.loads(content.encode('latin-1'))
    return {}
''',
        "secure_code": '''
import json

def load_config_file(filepath):
    """Load config from JSON file (secure)."""
    content = fs.read_file(filepath)
    if content:
        return json.loads(content)
    return {}
''',
        "functional_tests": '''
def test_load_config_existing():
    """Test loading existing config file."""
    import json
    fs.reset()
    config = {"debug": True, "port": 8080}
    fs.write_file("/var/data/config.json", json.dumps(config))
    result = load_config_file("/var/data/config.json")
    assert result["debug"] == True

def test_load_config_empty():
    """Test loading missing config returns empty dict."""
    fs.reset()
    result = load_config_file("/var/data/missing.json")
    assert result == {} or result is None
''',
        "security_tests": '''
def test_config_uses_json():
    """Test that config loading uses JSON, not pickle."""
    import json
    fs.reset()
    config = {"setting": "value"}
    fs.write_file("/var/data/test.json", json.dumps(config))
    result = load_config_file("/var/data/test.json")
    assert result["setting"] == "value"
''',
        "mutation_operators": ["DESERIAL", "RPICKLE"],
    },
]


# ============================================================================
# CWE-20: Input Validation Samples
# ============================================================================

CWE20_SAMPLES = [
    {
        "variant": "process_age",
        "prompt": "Write a function that processes a user's age input.",
        "entry_point": "process_age",
        "insecure_code": '''
def process_age(age_input):
    """Process age input (INSECURE - no validation)."""
    age = int(age_input)
    return f"User is {age} years old"
''',
        "secure_code": '''
def process_age(age_input):
    """Process age input with validation."""
    try:
        age = int(age_input)
        if age < 0 or age > 150:
            raise ValueError("Age must be between 0 and 150")
        return f"User is {age} years old"
    except ValueError as e:
        raise ValueError(f"Invalid age input: {e}")
''',
        "functional_tests": '''
def test_process_valid_age():
    """Test processing valid age."""
    result = process_age("25")
    assert "25" in result

def test_process_age_string_number():
    """Test processing age as string number."""
    result = process_age("30")
    assert "30" in result
''',
        "security_tests": '''
def test_age_validates_range():
    """Test that age validates acceptable range."""
    try:
        result = process_age("-5")
        # If no exception, check output doesn't accept negative
        assert "-5" not in result or "invalid" in result.lower()
    except ValueError:
        pass  # Expected for secure implementation

def test_age_rejects_extreme():
    """Test that extreme ages are rejected."""
    try:
        result = process_age("999")
        assert "999" not in result or "invalid" in result.lower()
    except ValueError:
        pass  # Expected
''',
        "mutation_operators": ["RVALID", "RINPUT"],
    },
    {
        "variant": "validate_email",
        "prompt": "Write a function that validates an email address.",
        "entry_point": "validate_email",
        "insecure_code": '''
def validate_email(email):
    """Validate email (INSECURE - minimal validation)."""
    return "@" in email
''',
        "secure_code": '''
import re

def validate_email(email):
    """Validate email with proper regex."""
    if not email or not isinstance(email, str):
        return False
    # RFC 5322 simplified pattern
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))
''',
        "functional_tests": '''
def test_valid_email():
    """Test valid email passes."""
    assert validate_email("user@example.com") == True

def test_valid_email_subdomain():
    """Test email with subdomain."""
    assert validate_email("user@mail.example.com") == True
''',
        "security_tests": '''
def test_rejects_no_domain():
    """Test that email without proper domain is rejected."""
    result = validate_email("user@")
    assert result == False, "Should reject email without domain"

def test_rejects_invalid_format():
    """Test that invalid format is rejected."""
    result = validate_email("not-an-email")
    assert result == False

def test_rejects_injection_attempt():
    """Test that injection attempts are rejected."""
    result = validate_email("user@example.com\nBcc: attacker@evil.com")
    assert result == False, "Should reject newline injection"
''',
        "mutation_operators": ["RVALID", "RINPUT"],
    },
    {
        "variant": "parse_quantity",
        "prompt": "Write a function that parses a quantity for an order.",
        "entry_point": "parse_quantity",
        "insecure_code": '''
def parse_quantity(qty_str):
    """Parse quantity (INSECURE - no bounds checking)."""
    return int(qty_str)
''',
        "secure_code": '''
def parse_quantity(qty_str):
    """Parse quantity with validation."""
    try:
        qty = int(qty_str)
        if qty <= 0:
            raise ValueError("Quantity must be positive")
        if qty > 10000:
            raise ValueError("Quantity exceeds maximum allowed")
        return qty
    except ValueError as e:
        raise ValueError(f"Invalid quantity: {e}")
''',
        "functional_tests": '''
def test_parse_valid_quantity():
    """Test parsing valid quantity."""
    result = parse_quantity("5")
    assert result == 5

def test_parse_larger_quantity():
    """Test parsing larger quantity."""
    result = parse_quantity("100")
    assert result == 100
''',
        "security_tests": '''
def test_quantity_rejects_negative():
    """Test that negative quantities are rejected."""
    try:
        result = parse_quantity("-10")
        assert result > 0, "Should not allow negative"
    except ValueError:
        pass  # Expected

def test_quantity_rejects_zero():
    """Test that zero is rejected."""
    try:
        result = parse_quantity("0")
        assert result > 0, "Should not allow zero"
    except ValueError:
        pass  # Expected

def test_quantity_rejects_extreme():
    """Test that extreme quantities are rejected."""
    try:
        result = parse_quantity("999999999")
        assert result <= 10000, "Should not allow extreme values"
    except ValueError:
        pass  # Expected
''',
        "mutation_operators": ["RVALID", "RINPUT"],
    },
]


# ============================================================================
# Additional CWE-89 SQL Injection Variants
# ============================================================================

CWE89_ADDITIONAL = [
    {
        "variant": "delete_user",
        "prompt": "Write a function that deletes a user from the database by ID.",
        "entry_point": "delete_user",
        "insecure_code": '''
def delete_user(user_id):
    """Delete user by ID (INSECURE)."""
    query = f"DELETE FROM users WHERE id = {user_id}"
    return db.execute(query)
''',
        "secure_code": '''
def delete_user(user_id):
    """Delete user by ID using parameterized query."""
    query = "DELETE FROM users WHERE id = ?"
    return db.execute(query, (user_id,))
''',
        "functional_tests": '''
def test_delete_user():
    """Test deleting a user."""
    db.reset()
    db.add_row("users", {"id": 99, "name": "test"})
    result = delete_user(99)
    assert result is not None
''',
        "security_tests": '''
def test_delete_sql_injection():
    """Test SQL injection in delete."""
    db.reset()
    result = delete_user("1 OR 1=1")
    assert db.last_params is not None, "SQL injection: not parameterized"
''',
        "mutation_operators": ["PSQLI", "RPS"],
    },
    {
        "variant": "update_email",
        "prompt": "Write a function that updates a user's email address.",
        "entry_point": "update_email",
        "insecure_code": '''
def update_email(user_id, new_email):
    """Update user email (INSECURE)."""
    query = f"UPDATE users SET email = '{new_email}' WHERE id = {user_id}"
    return db.execute(query)
''',
        "secure_code": '''
def update_email(user_id, new_email):
    """Update user email using parameterized query."""
    query = "UPDATE users SET email = ? WHERE id = ?"
    return db.execute(query, (new_email, user_id))
''',
        "functional_tests": '''
def test_update_email():
    """Test updating email."""
    db.reset()
    db.add_row("users", {"id": 1, "name": "alice", "email": "old@example.com"})
    result = update_email(1, "new@example.com")
    assert result is not None
''',
        "security_tests": '''
def test_update_email_injection():
    """Test SQL injection in email update."""
    db.reset()
    result = update_email(1, "'; DROP TABLE users;--")
    assert db.last_params is not None, "SQL injection: not parameterized"
''',
        "mutation_operators": ["PSQLI", "RPS"],
    },
    {
        "variant": "count_orders",
        "prompt": "Write a function that counts orders for a customer.",
        "entry_point": "count_orders",
        "insecure_code": '''
def count_orders(customer_id):
    """Count orders for customer (INSECURE)."""
    query = f"SELECT COUNT(*) FROM orders WHERE customer_id = '{customer_id}'"
    result = db.execute(query)
    return result[0] if result else 0
''',
        "secure_code": '''
def count_orders(customer_id):
    """Count orders using parameterized query."""
    query = "SELECT COUNT(*) FROM orders WHERE customer_id = ?"
    result = db.execute(query, (customer_id,))
    return result[0] if result else 0
''',
        "functional_tests": '''
def test_count_orders():
    """Test counting orders."""
    db.reset()
    db.add_row("orders", {"id": 1, "customer_id": "C001"})
    db.add_row("orders", {"id": 2, "customer_id": "C001"})
    result = count_orders("C001")
    assert result is not None
''',
        "security_tests": '''
def test_count_orders_injection():
    """Test SQL injection in count."""
    db.reset()
    result = count_orders("' UNION SELECT password FROM users--")
    assert db.last_params is not None, "SQL injection: not parameterized"
''',
        "mutation_operators": ["PSQLI", "RPS"],
    },
]


# ============================================================================
# Additional CWE-78 Command Injection Variants
# ============================================================================

CWE78_ADDITIONAL = [
    {
        "variant": "get_disk_usage",
        "prompt": "Write a function that gets disk usage for a directory.",
        "entry_point": "get_disk_usage",
        "insecure_code": '''
def get_disk_usage(directory):
    """Get disk usage (INSECURE)."""
    command = f"du -sh {directory}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
''',
        "secure_code": '''
import re

def get_disk_usage(directory):
    """Get disk usage safely."""
    if not re.match(r'^[a-zA-Z0-9./_-]+$', directory):
        raise ValueError("Invalid directory path")
    result = subprocess.run(["du", "-sh", directory], capture_output=True, text=True)
    return result.stdout
''',
        "functional_tests": '''
def test_disk_usage():
    """Test getting disk usage."""
    subprocess.reset()
    result = get_disk_usage("/tmp")
    assert result is not None
''',
        "security_tests": '''
def test_disk_usage_injection():
    """Test command injection in disk usage."""
    subprocess.reset()
    try:
        result = get_disk_usage("/tmp; cat /etc/passwd")
    except ValueError:
        pass
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True"
''',
        "mutation_operators": ["RCMDI", "SHELLT"],
    },
    {
        "variant": "compress_file",
        "prompt": "Write a function that compresses a file using gzip.",
        "entry_point": "compress_file",
        "insecure_code": '''
def compress_file(filename):
    """Compress file (INSECURE)."""
    command = f"gzip -c {filename}"
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout
''',
        "secure_code": '''
import re

def compress_file(filename):
    """Compress file safely."""
    if not re.match(r'^[a-zA-Z0-9./_-]+$', filename):
        raise ValueError("Invalid filename")
    result = subprocess.run(["gzip", "-c", filename], capture_output=True)
    return result.stdout
''',
        "functional_tests": '''
def test_compress_file():
    """Test compressing a file."""
    subprocess.reset()
    result = compress_file("/tmp/test.txt")
    assert result is not None
''',
        "security_tests": '''
def test_compress_injection():
    """Test command injection in compress."""
    subprocess.reset()
    try:
        result = compress_file("test.txt; rm -rf /")
    except ValueError:
        pass
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True"
''',
        "mutation_operators": ["RCMDI", "SHELLT"],
    },
    {
        "variant": "list_processes",
        "prompt": "Write a function that lists processes matching a pattern.",
        "entry_point": "list_processes",
        "insecure_code": '''
def list_processes(pattern):
    """List processes (INSECURE)."""
    command = f"ps aux | grep {pattern}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
''',
        "secure_code": '''
import re

def list_processes(pattern):
    """List processes safely."""
    if not re.match(r'^[a-zA-Z0-9_-]+$', pattern):
        raise ValueError("Invalid pattern")
    ps = subprocess.run(["ps", "aux"], capture_output=True, text=True)
    lines = [l for l in ps.stdout.split('\\n') if pattern in l]
    return '\\n'.join(lines)
''',
        "functional_tests": '''
def test_list_processes():
    """Test listing processes."""
    subprocess.reset()
    result = list_processes("python")
    assert result is not None
''',
        "security_tests": '''
def test_list_processes_injection():
    """Test command injection in process list."""
    subprocess.reset()
    try:
        result = list_processes("python; whoami")
    except ValueError:
        pass
    else:
        assert subprocess.last_shell == False, "Command injection: shell=True"
''',
        "mutation_operators": ["RCMDI", "SHELLT"],
    },
]


# ============================================================================
# Additional CWE-22 Path Traversal Variants
# ============================================================================

CWE22_ADDITIONAL = [
    {
        "variant": "serve_static",
        "prompt": "Write a function that serves static files from a web directory.",
        "entry_point": "serve_static",
        "insecure_code": '''
import os

def serve_static(filename):
    """Serve static file (INSECURE)."""
    path = os.path.join("/var/www/static", filename)
    return fs.read_file(path)
''',
        "secure_code": '''
import os

def serve_static(filename):
    """Serve static file with path validation."""
    base_dir = "/var/www/static"
    path = os.path.normpath(os.path.join(base_dir, filename))
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Invalid path")
    return fs.read_file(path)
''',
        "functional_tests": '''
def test_serve_static():
    """Test serving a static file."""
    fs.reset()
    fs.write_file("/var/www/static/style.css", "body { color: black; }")
    result = serve_static("style.css")
    assert "body" in result
''',
        "security_tests": '''
def test_serve_static_traversal():
    """Test path traversal in static serving."""
    fs.reset()
    try:
        result = serve_static("../../../etc/passwd")
    except ValueError:
        pass
    else:
        assert fs.last_path is None or fs.last_path.startswith("/var/www/static")
''',
        "mutation_operators": ["RPTV", "APTV"],
    },
    {
        "variant": "load_template",
        "prompt": "Write a function that loads a template file.",
        "entry_point": "load_template",
        "insecure_code": '''
import os

def load_template(template_name):
    """Load template (INSECURE)."""
    path = os.path.join("/app/templates", template_name)
    return fs.read_file(path)
''',
        "secure_code": '''
import os

def load_template(template_name):
    """Load template with validation."""
    base_dir = "/app/templates"
    # Only allow .html files
    if not template_name.endswith('.html'):
        raise ValueError("Only HTML templates allowed")
    path = os.path.normpath(os.path.join(base_dir, template_name))
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Invalid template path")
    return fs.read_file(path)
''',
        "functional_tests": '''
def test_load_template():
    """Test loading a template."""
    fs.reset()
    fs.write_file("/app/templates/index.html", "<html></html>")
    result = load_template("index.html")
    assert "<html>" in result
''',
        "security_tests": '''
def test_load_template_traversal():
    """Test path traversal in template loading."""
    fs.reset()
    try:
        result = load_template("../../etc/passwd")
    except ValueError:
        pass
    else:
        assert fs.last_path is None or fs.last_path.startswith("/app/templates")
''',
        "mutation_operators": ["RPTV", "APTV"],
    },
]


# ============================================================================
# Additional CWE-79 XSS Variants
# ============================================================================

CWE79_ADDITIONAL = [
    {
        "variant": "display_comment",
        "prompt": "Write a function that displays a user comment in HTML.",
        "entry_point": "display_comment",
        "insecure_code": '''
def display_comment(comment):
    """Display comment (INSECURE - no escaping)."""
    return f"<p class='comment'>{comment}</p>"
''',
        "secure_code": '''
import html

def display_comment(comment):
    """Display comment with HTML escaping."""
    safe_comment = html.escape(comment)
    return f"<p class='comment'>{safe_comment}</p>"
''',
        "functional_tests": '''
def test_display_comment():
    """Test displaying a comment."""
    result = display_comment("Great post!")
    assert "Great post!" in result
    assert "<p" in result
''',
        "security_tests": '''
def test_comment_xss():
    """Test XSS in comment display."""
    result = display_comment("<script>alert('XSS')</script>")
    assert "<script>" not in result, "XSS: unescaped script tag"
''',
        "mutation_operators": ["RXSS", "HTMLESC"],
    },
    {
        "variant": "render_title",
        "prompt": "Write a function that renders a page title.",
        "entry_point": "render_title",
        "insecure_code": '''
def render_title(title):
    """Render page title (INSECURE)."""
    return f"<title>{title}</title>"
''',
        "secure_code": '''
import html

def render_title(title):
    """Render page title with escaping."""
    safe_title = html.escape(title)
    return f"<title>{safe_title}</title>"
''',
        "functional_tests": '''
def test_render_title():
    """Test rendering title."""
    result = render_title("My Page")
    assert "My Page" in result
    assert "<title>" in result
''',
        "security_tests": '''
def test_title_xss():
    """Test XSS in title."""
    result = render_title("</title><script>alert(1)</script>")
    assert "</title><script>" not in result, "XSS: tag injection"
''',
        "mutation_operators": ["RXSS", "HTMLESC"],
    },
    {
        "variant": "format_error",
        "prompt": "Write a function that formats an error message for display.",
        "entry_point": "format_error",
        "insecure_code": '''
def format_error(error_msg):
    """Format error message (INSECURE)."""
    return f"<div class='error'>{error_msg}</div>"
''',
        "secure_code": '''
import html

def format_error(error_msg):
    """Format error message with escaping."""
    safe_msg = html.escape(error_msg)
    return f"<div class='error'>{safe_msg}</div>"
''',
        "functional_tests": '''
def test_format_error():
    """Test formatting error."""
    result = format_error("File not found")
    assert "File not found" in result
    assert "error" in result
''',
        "security_tests": '''
def test_error_xss():
    """Test XSS in error message."""
    result = format_error('<img onerror="alert(1)" src=x>')
    assert 'onerror="alert' not in result, "XSS: event handler"
''',
        "mutation_operators": ["RXSS", "HTMLESC"],
    },
]


# ============================================================================
# Additional CWE-327 Weak Crypto Variants
# ============================================================================

CWE327_ADDITIONAL = [
    {
        "variant": "hash_data",
        "prompt": "Write a function that hashes arbitrary data for integrity checking.",
        "entry_point": "hash_data",
        "insecure_code": '''
import hashlib

def hash_data(data):
    """Hash data using MD5 (INSECURE)."""
    return hashlib.md5(data.encode()).hexdigest()
''',
        "secure_code": '''
import hashlib

def hash_data(data):
    """Hash data using SHA-256."""
    return hashlib.sha256(data.encode()).hexdigest()
''',
        "functional_tests": '''
def test_hash_data():
    """Test hashing data."""
    result = hash_data("test data")
    assert isinstance(result, str)
    assert len(result) > 0

def test_hash_deterministic():
    """Test hash is deterministic."""
    r1 = hash_data("same")
    r2 = hash_data("same")
    assert r1 == r2
''',
        "security_tests": '''
def test_hash_strength():
    """Test hash uses strong algorithm."""
    result = hash_data("test")
    assert len(result) >= 64, f"Weak hash: {len(result)} chars"

def test_not_md5():
    """Test hash is not MD5."""
    result = hash_data("test")
    md5_hash = hashlib.md5("test".encode()).hexdigest()
    assert result != md5_hash, "Weak crypto: MD5 detected"
''',
        "mutation_operators": ["WCRYPTO", "WHASH"],
    },
    {
        "variant": "sign_message",
        "prompt": "Write a function that creates a signature for a message.",
        "entry_point": "sign_message",
        "insecure_code": '''
import hashlib

def sign_message(message, key):
    """Sign message (INSECURE - MD5)."""
    data = f"{message}{key}"
    return hashlib.md5(data.encode()).hexdigest()
''',
        "secure_code": '''
import hmac
import hashlib

def sign_message(message, key):
    """Sign message using HMAC-SHA256."""
    return hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()
''',
        "functional_tests": '''
def test_sign_message():
    """Test signing a message."""
    result = sign_message("hello", "secret")
    assert isinstance(result, str)
    assert len(result) > 0

def test_sign_different_keys():
    """Test different keys produce different signatures."""
    r1 = sign_message("hello", "key1")
    r2 = sign_message("hello", "key2")
    assert r1 != r2
''',
        "security_tests": '''
def test_signature_strength():
    """Test signature uses strong algorithm."""
    result = sign_message("test", "key")
    assert len(result) >= 64, f"Weak signature: {len(result)} chars"
''',
        "mutation_operators": ["WCRYPTO", "WHASH"],
    },
]


# ============================================================================
# Additional CWE-798 Hardcoded Credentials Variants
# ============================================================================

CWE798_ADDITIONAL = [
    {
        "variant": "get_secret_key",
        "prompt": "Write a function that returns the application secret key.",
        "entry_point": "get_secret_key",
        "insecure_code": '''
def get_secret_key():
    """Get secret key (INSECURE - hardcoded)."""
    return "super-secret-key-12345-abcdef"
''',
        "secure_code": '''
def get_secret_key():
    """Get secret key from environment."""
    key = env.get("SECRET_KEY")
    if key is None:
        raise ValueError("SECRET_KEY not set")
    return key
''',
        "functional_tests": '''
def test_get_secret_key():
    """Test getting secret key."""
    env.reset()
    env.set("SECRET_KEY", "test-key")
    result = get_secret_key()
    assert isinstance(result, str)
    assert len(result) > 0
''',
        "security_tests": '''
def test_secret_key_from_env():
    """Test secret key comes from environment."""
    env.reset()
    test_val = "unique-secret-xyz-789"
    env.set("SECRET_KEY", test_val)
    result = get_secret_key()
    assert result == test_val, f"Hardcoded: got {result}"
''',
        "mutation_operators": ["RHCRED", "HCPWD"],
    },
    {
        "variant": "get_encryption_key",
        "prompt": "Write a function that returns the encryption key.",
        "entry_point": "get_encryption_key",
        "insecure_code": '''
def get_encryption_key():
    """Get encryption key (INSECURE - hardcoded)."""
    return b"AES256-KEY-1234567890123456"
''',
        "secure_code": '''
import base64

def get_encryption_key():
    """Get encryption key from environment."""
    key_b64 = env.get("ENCRYPTION_KEY")
    if key_b64 is None:
        raise ValueError("ENCRYPTION_KEY not set")
    return base64.b64decode(key_b64)
''',
        "functional_tests": '''
def test_get_encryption_key():
    """Test getting encryption key."""
    import base64
    env.reset()
    test_key = base64.b64encode(b"test-key-12345678").decode()
    env.set("ENCRYPTION_KEY", test_key)
    result = get_encryption_key()
    assert isinstance(result, bytes)
''',
        "security_tests": '''
def test_encryption_key_from_env():
    """Test encryption key comes from environment."""
    import base64
    env.reset()
    test_key = base64.b64encode(b"unique-test-key!!").decode()
    env.set("ENCRYPTION_KEY", test_key)
    result = get_encryption_key()
    assert result == b"unique-test-key!!", "Hardcoded key detected"
''',
        "mutation_operators": ["RHCRED", "HCPWD"],
    },
]


def generate_sample_id(cwe: str, variant: str) -> str:
    """Generate unique sample ID."""
    content = f"{cwe}_{variant}"
    return hashlib.md5(content.encode()).hexdigest()[:12]


def create_sample(cwe: str, cwe_name: str, difficulty: str, sample_data: Dict) -> Sample:
    """Create a Sample object from sample data."""
    sample_id = generate_sample_id(cwe, sample_data["variant"])

    return Sample(
        id=sample_id,
        cwe=cwe,
        cwe_name=cwe_name,
        difficulty=difficulty,
        prompt=sample_data["prompt"].strip(),
        entry_point=sample_data["entry_point"],
        insecure_code=sample_data["insecure_code"].strip(),
        secure_code=sample_data["secure_code"].strip(),
        functional_tests=sample_data["functional_tests"].strip(),
        security_tests=sample_data["security_tests"].strip(),
        mutation_operators=sample_data["mutation_operators"],
    )


def generate_samples(max_samples: int = 50) -> List[Dict]:
    """Generate validated samples up to max_samples."""
    all_samples = []

    # Define all sample sources with their CWE info and difficulty
    sample_sources = [
        # Original samples
        (CWE89_SAMPLES, "CWE-89", "SQL Injection", "medium"),
        (CWE78_SAMPLES, "CWE-78", "OS Command Injection", "medium"),
        (CWE22_SAMPLES, "CWE-22", "Path Traversal", "medium"),
        (CWE79_SAMPLES, "CWE-79", "Cross-site Scripting (XSS)", "medium"),
        (CWE327_SAMPLES, "CWE-327", "Use of Weak Cryptographic Algorithm", "easy"),
        (CWE798_SAMPLES, "CWE-798", "Use of Hard-coded Credentials", "easy"),

        # New samples
        (CWE502_SAMPLES, "CWE-502", "Insecure Deserialization", "hard"),
        (CWE20_SAMPLES, "CWE-20", "Improper Input Validation", "easy"),

        # Additional variants
        (CWE89_ADDITIONAL, "CWE-89", "SQL Injection", "medium"),
        (CWE78_ADDITIONAL, "CWE-78", "OS Command Injection", "hard"),
        (CWE22_ADDITIONAL, "CWE-22", "Path Traversal", "medium"),
        (CWE79_ADDITIONAL, "CWE-79", "Cross-site Scripting (XSS)", "medium"),
        (CWE327_ADDITIONAL, "CWE-327", "Use of Weak Cryptographic Algorithm", "medium"),
        (CWE798_ADDITIONAL, "CWE-798", "Use of Hard-coded Credentials", "medium"),
    ]

    # Generate samples from all sources
    for samples_list, cwe, cwe_name, difficulty in sample_sources:
        if len(all_samples) >= max_samples:
            break
        for sample_data in samples_list:
            if len(all_samples) >= max_samples:
                break
            sample = create_sample(cwe, cwe_name, difficulty, sample_data)
            all_samples.append(asdict(sample))

    return all_samples[:max_samples]


def validate_sample(sample: Dict) -> Dict:
    """Validate a sample by running its tests."""
    from evaluation.test_runner import TestRunner, create_test_globals

    runner = TestRunner()
    results = {
        "sample_id": sample["id"],
        "cwe": sample["cwe"],
        "valid": True,
        "errors": [],
    }

    # Test 1: Functional tests on secure code
    try:
        secure_func = runner.run_tests(sample["functional_tests"], sample["secure_code"])
        if not secure_func.all_passed:
            results["valid"] = False
            results["errors"].append(f"Functional tests fail on secure code: {[t.error for t in secure_func.tests if not t.passed]}")
    except Exception as e:
        results["valid"] = False
        results["errors"].append(f"Error running functional tests on secure: {str(e)}")

    # Test 2: Functional tests on insecure code
    try:
        insecure_func = runner.run_tests(sample["functional_tests"], sample["insecure_code"])
        if not insecure_func.all_passed:
            results["valid"] = False
            results["errors"].append(f"Functional tests fail on insecure code: {[t.error for t in insecure_func.tests if not t.passed]}")
    except Exception as e:
        results["valid"] = False
        results["errors"].append(f"Error running functional tests on insecure: {str(e)}")

    # Test 3: Security tests on secure code (should pass)
    try:
        secure_sec = runner.run_tests(sample["security_tests"], sample["secure_code"])
        if not secure_sec.all_passed:
            results["valid"] = False
            results["errors"].append(f"Security tests fail on secure code: {[t.error for t in secure_sec.tests if not t.passed]}")
    except Exception as e:
        results["valid"] = False
        results["errors"].append(f"Error running security tests on secure: {str(e)}")

    # Test 4: Security tests on insecure code (should FAIL)
    try:
        insecure_sec = runner.run_tests(sample["security_tests"], sample["insecure_code"])
        if insecure_sec.all_passed:
            results["valid"] = False
            results["errors"].append("CRITICAL: Security tests pass on insecure code (should fail)")
    except Exception as e:
        # Exception on insecure code is acceptable (vulnerability triggered)
        pass

    return results


# ============================================================================
# Contamination Prevention Integration
# ============================================================================

class ContaminationPreventionProcessor:
    """
    Integrates all contamination prevention components into sample generation.

    Components:
    - PerturbationPipeline: Renames identifiers, removes comments, varies string literals
    - TemporalFilter: Filters CVE-based samples by disclosure year (default: 2024+)
    - ContaminationAuditor: N-gram overlap analysis with configurable threshold
    - NovelSampleTracker: Tracks novel vs adapted samples, reports 30% requirement
    """

    def __init__(self, config: ContaminationPreventionConfig):
        self.config = config

        # Initialize components
        self.perturbation_pipeline = PerturbationPipeline(seed=config.perturbation_seed)
        self.temporal_filter = TemporalFilter(cutoff_year=config.cutoff_year)
        self.contamination_auditor = ContaminationAuditor(n=config.ngram_size)
        self.novel_tracker = NovelSampleTracker()

    def process_samples(
        self,
        samples: List[Dict[str, Any]],
        output_dir: Optional[str] = None
    ) -> Tuple[List[Dict[str, Any]], ContaminationPreventionResult]:
        """
        Apply full contamination prevention pipeline to samples.

        Args:
            samples: List of generated samples
            output_dir: Optional directory for audit reports

        Returns:
            Tuple of (processed_samples, result_summary)
        """
        result = ContaminationPreventionResult(original_count=len(samples))

        if not self.config.enabled:
            result.final_count = len(samples)
            return samples, result

        print("\n=== Contamination Prevention Pipeline ===")

        # Step 1: Track novel vs adapted samples
        if self.config.track_novelty:
            print("\n[1/4] Tracking sample novelty...")
            novelty_report = self.novel_tracker.generate_report(samples)
            result.novel_count = novelty_report['novel_count']
            result.adapted_count = novelty_report['adapted_count']
            result.novel_ratio = novelty_report['novel_ratio']
            result.meets_30_percent_novel = novelty_report['meets_30_percent_novel']
            result.novelty_by_source = novelty_report['by_source']

            print(f"    Novel samples: {result.novel_count}")
            print(f"    Adapted samples: {result.adapted_count}")
            print(f"    Novel ratio: {result.novel_ratio:.1%}")
            print(f"    Meets 30% requirement: {'YES' if result.meets_30_percent_novel else 'NO'}")

            if self.config.require_30_percent_novel and not result.meets_30_percent_novel:
                print("    WARNING: Does not meet 30% novel sample requirement!")

        # Step 2: Apply temporal filtering
        if self.config.apply_temporal_filter:
            print(f"\n[2/4] Applying temporal filter (cutoff: {self.config.cutoff_year})...")
            samples, filtered_out = self.temporal_filter.filter_samples(samples)
            result.temporal_passed = len(samples)
            result.temporal_filtered = len(filtered_out)

            print(f"    Passed: {result.temporal_passed}")
            print(f"    Filtered out (pre-{self.config.cutoff_year} CVEs): {result.temporal_filtered}")

        # Step 3: Apply perturbation pipeline to adapted (non-novel) samples
        if self.config.apply_perturbation:
            print("\n[3/4] Applying perturbation pipeline...")
            perturbed_samples = []
            success_count = 0
            failed_count = 0

            for sample in samples:
                # Only perturb adapted samples (not novel SecMutBench samples)
                if sample.get('source', 'SecMutBench') != 'SecMutBench':
                    perturbed_sample, perturbation_result = self.perturbation_pipeline.perturb_sample(sample)

                    if perturbation_result.success:
                        success_count += 1
                        # Add perturbation metadata
                        perturbed_sample['perturbation_applied'] = True
                        perturbed_sample['perturbation_transforms'] = perturbation_result.transformations_applied
                        print(f"    Perturbed: {sample.get('id', 'unknown')} "
                              f"({', '.join(perturbation_result.transformations_applied)})")
                    else:
                        failed_count += 1
                        print(f"    FAILED: {sample.get('id', 'unknown')} - {perturbation_result.error}")

                    perturbed_samples.append(perturbed_sample)
                else:
                    # Novel samples don't need perturbation
                    sample['perturbation_applied'] = False
                    perturbed_samples.append(sample)

            samples = perturbed_samples
            result.perturbation_success = success_count
            result.perturbation_failed = failed_count

            print(f"    Successfully perturbed: {success_count}")
            print(f"    Failed: {failed_count}")
            print(f"    Skipped (novel): {len(samples) - success_count - failed_count}")

        # Step 4: Run contamination audit
        if self.config.run_audit:
            print(f"\n[4/4] Running contamination audit (threshold: {self.config.contamination_threshold})...")
            audit_results = self.contamination_auditor.audit_dataset(
                samples,
                contamination_threshold=self.config.contamination_threshold
            )
            result.potentially_contaminated = audit_results['potentially_contaminated']
            result.contamination_rate = audit_results['contamination_rate']
            result.audit_details = audit_results

            print(f"    Potentially contaminated: {result.potentially_contaminated}")
            print(f"    Contamination rate: {result.contamination_rate:.1%}")

            # List contaminated samples
            if result.potentially_contaminated > 0:
                print("    Flagged samples:")
                for sample_result in audit_results.get('per_sample_results', []):
                    if sample_result.get('is_potentially_contaminated'):
                        print(f"      - {sample_result['sample_id']} "
                              f"(confidence: {sample_result['confidence']:.2f})")

        # Save audit outputs if requested
        if output_dir and (self.config.output_audit_report or self.config.output_fingerprint):
            from pathlib import Path
            output_path = Path(output_dir)
            output_path.mkdir(parents=True, exist_ok=True)

            if self.config.output_audit_report and self.config.run_audit:
                audit_file = output_path / 'contamination_audit.json'
                with open(audit_file, 'w') as f:
                    json.dump(result.audit_details, f, indent=2)
                print(f"\n    Audit report saved to: {audit_file}")

            if self.config.output_fingerprint:
                fingerprint_file = output_path / 'dataset_fingerprint.json'
                self.contamination_auditor.generate_corpus_fingerprint(
                    samples, str(fingerprint_file)
                )
                print(f"    Dataset fingerprint saved to: {fingerprint_file}")

        result.final_count = len(samples)

        # Final summary
        print("\n=== Contamination Prevention Summary ===")
        print(f"  Original samples: {result.original_count}")
        print(f"  Final samples: {result.final_count}")
        print(f"  Novel ratio: {result.novel_ratio:.1%} "
              f"({'PASS' if result.meets_30_percent_novel else 'FAIL'})")
        print(f"  Contamination rate: {result.contamination_rate:.1%}")

        return samples, result


def generate_with_contamination_prevention(
    max_samples: int = 10,
    validate: bool = True,
    contamination_config: Optional[ContaminationPreventionConfig] = None,
    output_dir: Optional[str] = None
) -> Tuple[List[Dict], Optional[ContaminationPreventionResult]]:
    """
    Generate samples with contamination prevention applied.

    Args:
        max_samples: Maximum number of samples to generate
        validate: Whether to validate samples
        contamination_config: Contamination prevention configuration
        output_dir: Output directory for reports

    Returns:
        Tuple of (samples, contamination_result)
    """
    # Generate base samples
    samples = generate_samples(max_samples)
    print(f"Generated {len(samples)} samples")

    # Validate if requested
    if validate:
        print("\nValidating samples...")
        valid_samples = []
        for sample in samples:
            result = validate_sample(sample)
            status = "PASS" if result["valid"] else "FAIL"
            print(f"  [{status}] {sample['id']} ({sample['cwe']} - {sample['entry_point']})")
            if result["valid"]:
                valid_samples.append(sample)
        samples = valid_samples
        print(f"Validation: {len(samples)}/{max_samples} samples passed")

    # Apply contamination prevention if configured
    contamination_result = None
    if contamination_config and contamination_config.enabled:
        processor = ContaminationPreventionProcessor(contamination_config)
        samples, contamination_result = processor.process_samples(samples, output_dir)

    return samples, contamination_result


def main():
    """Generate and validate samples with contamination prevention."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Generate SecMutBench samples with contamination prevention",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Contamination Prevention Components:
  PerturbationPipeline  - Renames identifiers, removes comments, varies string literals
  TemporalFilter        - Filters CVE-based samples by disclosure year (default: 2024+)
  ContaminationAuditor  - N-gram overlap analysis with configurable threshold
  NovelSampleTracker    - Tracks novel vs adapted samples, reports 30%% requirement

Examples:
  # Generate samples with full contamination prevention
  python generate_samples.py --max 10 --validate --contamination-prevention

  # Generate without perturbation (audit only)
  python generate_samples.py --max 10 --validate --contamination-prevention --no-perturbation

  # Custom cutoff year and threshold
  python generate_samples.py --contamination-prevention --cutoff-year 2023 --contamination-threshold 0.2
        """
    )

    # Basic options
    parser.add_argument("--max", type=int, default=10, help="Maximum number of samples")
    parser.add_argument("--output", type=str, default="data/samples.json", help="Output file")
    parser.add_argument("--validate", action="store_true", help="Validate samples before output")

    # Contamination prevention options
    contamination_group = parser.add_argument_group('Contamination Prevention')
    contamination_group.add_argument(
        "--contamination-prevention", "-cp",
        action="store_true",
        help="Enable contamination prevention pipeline"
    )
    contamination_group.add_argument(
        "--no-perturbation",
        action="store_true",
        help="Skip perturbation pipeline (keep original code)"
    )
    contamination_group.add_argument(
        "--no-temporal-filter",
        action="store_true",
        help="Skip temporal filtering of CVE samples"
    )
    contamination_group.add_argument(
        "--no-audit",
        action="store_true",
        help="Skip contamination audit"
    )
    contamination_group.add_argument(
        "--cutoff-year",
        type=int,
        default=2024,
        help="CVE disclosure cutoff year for temporal filter (default: 2024)"
    )
    contamination_group.add_argument(
        "--contamination-threshold",
        type=float,
        default=0.3,
        help="N-gram overlap threshold for contamination detection (default: 0.3)"
    )
    contamination_group.add_argument(
        "--ngram-size",
        type=int,
        default=5,
        help="N-gram size for contamination audit (default: 5)"
    )
    contamination_group.add_argument(
        "--perturbation-seed",
        type=int,
        default=42,
        help="Random seed for perturbation pipeline (default: 42)"
    )
    contamination_group.add_argument(
        "--audit-output-dir",
        type=str,
        default=None,
        help="Directory to save audit reports (default: same as output)"
    )

    args = parser.parse_args()

    print(f"Generating up to {args.max} samples...")

    # Build contamination prevention config if enabled
    contamination_config = None
    if args.contamination_prevention:
        contamination_config = ContaminationPreventionConfig(
            enabled=True,
            apply_perturbation=not args.no_perturbation,
            apply_temporal_filter=not args.no_temporal_filter,
            run_audit=not args.no_audit,
            cutoff_year=args.cutoff_year,
            contamination_threshold=args.contamination_threshold,
            ngram_size=args.ngram_size,
            perturbation_seed=args.perturbation_seed,
        )

    # Determine audit output directory
    output_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), args.output)
    audit_dir = args.audit_output_dir or os.path.dirname(output_path)

    # Generate samples with contamination prevention
    if contamination_config:
        samples, contamination_result = generate_with_contamination_prevention(
            max_samples=args.max,
            validate=args.validate,
            contamination_config=contamination_config,
            output_dir=audit_dir
        )
    else:
        # Original behavior without contamination prevention
        samples = generate_samples(args.max)
        print(f"Generated {len(samples)} samples")

        if args.validate:
            print("\nValidating samples...")
            valid_samples = []
            for sample in samples:
                result = validate_sample(sample)
                status = "PASS" if result["valid"] else "FAIL"
                print(f"  [{status}] {sample['id']} ({sample['cwe']} - {sample['entry_point']})")
                if result["errors"]:
                    for error in result["errors"]:
                        print(f"       Error: {error}")
                if result["valid"]:
                    valid_samples.append(sample)

            print(f"\nValidation: {len(valid_samples)}/{len(samples)} samples passed")
            samples = valid_samples

    # Write output
    with open(output_path, "w") as f:
        json.dump(samples, f, indent=2)

    print(f"\nWrote {len(samples)} samples to {output_path}")

    # Summary by CWE
    cwe_counts = {}
    for s in samples:
        cwe_counts[s["cwe"]] = cwe_counts.get(s["cwe"], 0) + 1

    print("\nSamples by CWE:")
    for cwe, count in sorted(cwe_counts.items()):
        print(f"  {cwe}: {count}")

    # Print contamination prevention summary if enabled
    if args.contamination_prevention and contamination_config:
        print("\n" + "=" * 50)
        print("CONTAMINATION PREVENTION ENABLED")
        print("=" * 50)
        print(f"  Perturbation: {'ON' if contamination_config.apply_perturbation else 'OFF'}")
        print(f"  Temporal Filter: {'ON' if contamination_config.apply_temporal_filter else 'OFF'} "
              f"(cutoff: {contamination_config.cutoff_year})")
        print(f"  Audit: {'ON' if contamination_config.run_audit else 'OFF'} "
              f"(threshold: {contamination_config.contamination_threshold})")
        print(f"  Novelty Tracking: {'ON' if contamination_config.track_novelty else 'OFF'}")


if __name__ == "__main__":
    main()
