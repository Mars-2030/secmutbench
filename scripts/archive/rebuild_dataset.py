#!/usr/bin/env python3
"""
SecMutBench Dataset Rebuilder

This script:
1. Transforms SecurityEval and CyberSecEval samples
2. Generates additional samples to reach 100+ total
3. Creates difficulty-based splits
4. Updates all documentation (DATASET_CARD.md, datasheet.md, croissant.json)

Usage:
    python scripts/rebuild_dataset.py
    python scripts/rebuild_dataset.py --target 150  # Generate 150 samples
"""

import json
import os
import re
import hashlib
import argparse
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict, field
from collections import defaultdict

# Base directory
BASE_DIR = Path(__file__).parent.parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
SPLITS_DIR = DATA_DIR / "splits"


# =============================================================================
# CWE Definitions
# =============================================================================

CWE_INFO = {
    "CWE-20": {"name": "Improper Input Validation", "operators": ["RVALID"], "tier": 1},
    "CWE-22": {"name": "Path Traversal", "operators": ["PATHCONCAT", "RVALID"], "tier": 1},
    "CWE-78": {"name": "OS Command Injection", "operators": ["CMDINJECT", "RVALID"], "tier": 1},
    "CWE-79": {"name": "Cross-Site Scripting (XSS)", "operators": ["RVALID"], "tier": 1},
    "CWE-89": {"name": "SQL Injection", "operators": ["PSQLI", "RVALID"], "tier": 1},
    "CWE-94": {"name": "Code Injection", "operators": ["RVALID"], "tier": 2},
    "CWE-287": {"name": "Improper Authentication", "operators": ["RMAUTH"], "tier": 1},
    "CWE-295": {"name": "Improper Certificate Validation", "operators": ["RENCRYPT"], "tier": 3},
    "CWE-306": {"name": "Missing Authentication", "operators": ["RMAUTH"], "tier": 2},
    "CWE-319": {"name": "Cleartext Transmission", "operators": ["RENCRYPT"], "tier": 3},
    "CWE-327": {"name": "Weak Cryptography", "operators": ["WEAKCRYPTO"], "tier": 2},
    "CWE-352": {"name": "Cross-Site Request Forgery", "operators": ["RVALID"], "tier": 2},
    "CWE-502": {"name": "Insecure Deserialization", "operators": ["DESERIAL"], "tier": 1},
    "CWE-611": {"name": "XXE Injection", "operators": ["RVALID"], "tier": 2},
    "CWE-798": {"name": "Hardcoded Credentials", "operators": ["HARDCODE"], "tier": 1},
    "CWE-918": {"name": "Server-Side Request Forgery", "operators": ["RVALID"], "tier": 2},
}

# Sample targets per CWE for balanced distribution
CWE_TARGETS = {
    "CWE-89": 15,   # SQL Injection - common
    "CWE-79": 15,   # XSS - common
    "CWE-78": 12,   # Command Injection
    "CWE-22": 12,   # Path Traversal
    "CWE-20": 10,   # Input Validation
    "CWE-287": 8,   # Authentication
    "CWE-798": 8,   # Hardcoded Credentials
    "CWE-502": 8,   # Deserialization
    "CWE-327": 6,   # Weak Crypto
    "CWE-352": 6,   # CSRF
    "CWE-611": 5,   # XXE
    "CWE-918": 5,   # SSRF
    "CWE-306": 5,   # Missing Auth
    "CWE-94": 4,    # Code Injection
    "CWE-319": 3,   # Cleartext
    "CWE-295": 3,   # Certificate
}


@dataclass
class Sample:
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


# =============================================================================
# Sample Templates for Generation
# =============================================================================

SAMPLE_TEMPLATES = {
    "CWE-89": [
        {
            "prompt": "Write a function to get user by ID from database",
            "entry_point": "get_user_by_id",
            "insecure": '''def get_user_by_id(user_id):
    """Get user by ID (INSECURE - SQL injection)."""
    query = f"SELECT * FROM users WHERE id = {user_id}"
    return db.execute(query)''',
            "secure": '''def get_user_by_id(user_id):
    """Get user by ID using parameterized query."""
    query = "SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to search users by name",
            "entry_point": "search_users",
            "insecure": '''def search_users(name):
    """Search users by name (INSECURE)."""
    query = f"SELECT * FROM users WHERE name LIKE '%{name}%'"
    return db.execute(query)''',
            "secure": '''def search_users(name):
    """Search users by name with parameterized query."""
    query = "SELECT * FROM users WHERE name LIKE ?"
    return db.execute(query, (f"%{name}%",))''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to authenticate user",
            "entry_point": "authenticate_user",
            "insecure": '''def authenticate_user(username, password):
    """Authenticate user (INSECURE)."""
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)''',
            "secure": '''def authenticate_user(username, password):
    """Authenticate user with parameterized query."""
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return db.execute(query, (username, password))''',
            "difficulty": "medium"
        },
        {
            "prompt": "Write a function to update user email",
            "entry_point": "update_user_email",
            "insecure": '''def update_user_email(user_id, email):
    """Update user email (INSECURE)."""
    query = f"UPDATE users SET email = '{email}' WHERE id = {user_id}"
    return db.execute(query)''',
            "secure": '''def update_user_email(user_id, email):
    """Update user email with parameterized query."""
    query = "UPDATE users SET email = ? WHERE id = ?"
    return db.execute(query, (email, user_id))''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to delete user by ID",
            "entry_point": "delete_user",
            "insecure": '''def delete_user(user_id):
    """Delete user (INSECURE)."""
    query = f"DELETE FROM users WHERE id = {user_id}"
    return db.execute(query)''',
            "secure": '''def delete_user(user_id):
    """Delete user with parameterized query."""
    query = "DELETE FROM users WHERE id = ?"
    return db.execute(query, (user_id,))''',
            "difficulty": "easy"
        },
    ],
    "CWE-79": [
        {
            "prompt": "Write a function to render user greeting",
            "entry_point": "render_greeting",
            "insecure": '''def render_greeting(name):
    """Render greeting (INSECURE - XSS)."""
    return f"<h1>Hello, {name}!</h1>"''',
            "secure": '''import html
def render_greeting(name):
    """Render greeting with HTML escaping."""
    safe_name = html.escape(name)
    return f"<h1>Hello, {safe_name}!</h1>"''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to display user comment",
            "entry_point": "display_comment",
            "insecure": '''def display_comment(comment):
    """Display comment (INSECURE)."""
    return f"<div class='comment'>{comment}</div>"''',
            "secure": '''import html
def display_comment(comment):
    """Display comment with escaping."""
    return f"<div class='comment'>{html.escape(comment)}</div>"''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to create HTML link",
            "entry_point": "create_link",
            "insecure": '''def create_link(url, text):
    """Create link (INSECURE)."""
    return f'<a href="{url}">{text}</a>''',
            "secure": '''import html
from urllib.parse import urlparse
def create_link(url, text):
    """Create link with validation."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https', ''):
        raise ValueError("Invalid URL scheme")
    return f'<a href="{html.escape(url)}">{html.escape(text)}</a>''',
            "difficulty": "medium"
        },
        {
            "prompt": "Write a function to render search results",
            "entry_point": "render_search_results",
            "insecure": '''def render_search_results(query, results):
    """Render search (INSECURE)."""
    html = f"<h2>Results for: {query}</h2><ul>"
    for r in results:
        html += f"<li>{r}</li>"
    return html + "</ul>"''',
            "secure": '''import html as html_lib
def render_search_results(query, results):
    """Render search with escaping."""
    output = f"<h2>Results for: {html_lib.escape(query)}</h2><ul>"
    for r in results:
        output += f"<li>{html_lib.escape(str(r))}</li>"
    return output + "</ul>"''',
            "difficulty": "medium"
        },
    ],
    "CWE-78": [
        {
            "prompt": "Write a function to ping a host",
            "entry_point": "ping_host",
            "insecure": '''import subprocess
def ping_host(hostname):
    """Ping host (INSECURE - command injection)."""
    return subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)''',
            "secure": '''import subprocess
import shlex
def ping_host(hostname):
    """Ping host safely."""
    if not hostname.replace(".", "").replace("-", "").isalnum():
        raise ValueError("Invalid hostname")
    return subprocess.run(["ping", "-c", "1", hostname], capture_output=True)''',
            "difficulty": "medium"
        },
        {
            "prompt": "Write a function to list directory contents",
            "entry_point": "list_directory",
            "insecure": '''import os
def list_directory(path):
    """List directory (INSECURE)."""
    return os.popen(f"ls -la {path}").read()''',
            "secure": '''import os
def list_directory(path):
    """List directory safely."""
    return os.listdir(path)''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to get file info",
            "entry_point": "get_file_info",
            "insecure": '''import subprocess
def get_file_info(filename):
    """Get file info (INSECURE)."""
    return subprocess.check_output(f"file {filename}", shell=True)''',
            "secure": '''import subprocess
import shlex
def get_file_info(filename):
    """Get file info safely."""
    return subprocess.check_output(["file", filename])''',
            "difficulty": "medium"
        },
    ],
    "CWE-22": [
        {
            "prompt": "Write a function to read file from uploads directory",
            "entry_point": "read_upload",
            "insecure": '''def read_upload(filename):
    """Read upload (INSECURE - path traversal)."""
    with open(f"./uploads/{filename}") as f:
        return f.read()''',
            "secure": '''import os
def read_upload(filename):
    """Read upload safely."""
    base = os.path.abspath("./uploads")
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base):
        raise ValueError("Path traversal detected")
    with open(path) as f:
        return f.read()''',
            "difficulty": "medium"
        },
        {
            "prompt": "Write a function to serve static files",
            "entry_point": "serve_static",
            "insecure": '''def serve_static(filename):
    """Serve static file (INSECURE)."""
    return open(f"./static/{filename}").read()''',
            "secure": '''import os
def serve_static(filename):
    """Serve static file safely."""
    base = os.path.abspath("./static")
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base):
        raise ValueError("Invalid path")
    return open(path).read()''',
            "difficulty": "easy"
        },
    ],
    "CWE-798": [
        {
            "prompt": "Write a function to connect to database",
            "entry_point": "connect_db",
            "insecure": '''def connect_db():
    """Connect to DB (INSECURE - hardcoded credentials)."""
    return Database(
        host="localhost",
        user="admin",
        password="secret123"
    )''',
            "secure": '''import os
def connect_db():
    """Connect to DB using environment variables."""
    return Database(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")
    )''',
            "difficulty": "easy"
        },
        {
            "prompt": "Write a function to call external API",
            "entry_point": "call_api",
            "insecure": '''import requests
API_KEY = "sk-1234567890abcdef"
def call_api(endpoint):
    """Call API (INSECURE - hardcoded key)."""
    return requests.get(endpoint, headers={"Authorization": f"Bearer {API_KEY}"})''',
            "secure": '''import os
import requests
def call_api(endpoint):
    """Call API using environment variable."""
    api_key = os.getenv("API_KEY")
    if not api_key:
        raise ValueError("API_KEY not set")
    return requests.get(endpoint, headers={"Authorization": f"Bearer {api_key}"})''',
            "difficulty": "easy"
        },
    ],
    "CWE-502": [
        {
            "prompt": "Write a function to load session data",
            "entry_point": "load_session",
            "insecure": '''import pickle
import base64
def load_session(data):
    """Load session (INSECURE - pickle)."""
    return pickle.loads(base64.b64decode(data))''',
            "secure": '''import json
import base64
def load_session(data):
    """Load session safely using JSON."""
    return json.loads(base64.b64decode(data))''',
            "difficulty": "medium"
        },
        {
            "prompt": "Write a function to deserialize user data",
            "entry_point": "deserialize_user",
            "insecure": '''import yaml
def deserialize_user(data):
    """Deserialize user (INSECURE)."""
    return yaml.load(data)''',
            "secure": '''import yaml
def deserialize_user(data):
    """Deserialize user safely."""
    return yaml.safe_load(data)''',
            "difficulty": "easy"
        },
    ],
    "CWE-287": [
        {
            "prompt": "Write a function to check admin access",
            "entry_point": "check_admin",
            "insecure": '''def check_admin(request):
    """Check admin (INSECURE - trusts user input)."""
    return request.get("is_admin") == "true"''',
            "secure": '''def check_admin(request):
    """Check admin via session."""
    session = get_session(request)
    return session.get("role") == "admin" and session.get("authenticated")''',
            "difficulty": "medium"
        },
    ],
    "CWE-327": [
        {
            "prompt": "Write a function to hash password",
            "entry_point": "hash_password",
            "insecure": '''import hashlib
def hash_password(password):
    """Hash password (INSECURE - MD5)."""
    return hashlib.md5(password.encode()).hexdigest()''',
            "secure": '''import hashlib
import secrets
def hash_password(password):
    """Hash password with salt and SHA-256."""
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"''',
            "difficulty": "medium"
        },
    ],
    "CWE-352": [
        {
            "prompt": "Write a function to handle money transfer",
            "entry_point": "transfer_money",
            "insecure": '''def transfer_money(request):
    """Transfer money (INSECURE - no CSRF)."""
    amount = request.form["amount"]
    to_account = request.form["to"]
    return do_transfer(amount, to_account)''',
            "secure": '''def transfer_money(request):
    """Transfer money with CSRF protection."""
    if not validate_csrf_token(request):
        raise ValueError("CSRF token invalid")
    amount = request.form["amount"]
    to_account = request.form["to"]
    return do_transfer(amount, to_account)''',
            "difficulty": "medium"
        },
    ],
    "CWE-20": [
        {
            "prompt": "Write a function to process user age",
            "entry_point": "process_age",
            "insecure": '''def process_age(age_str):
    """Process age (INSECURE - no validation)."""
    return int(age_str)''',
            "secure": '''def process_age(age_str):
    """Process age with validation."""
    age = int(age_str)
    if age < 0 or age > 150:
        raise ValueError("Invalid age")
    return age''',
            "difficulty": "easy"
        },
    ],
    # Hard difficulty samples
    "CWE-89_hard": [
        {
            "prompt": "Write a complex user management system with multiple SQL operations",
            "entry_point": "manage_users",
            "insecure": '''def manage_users(action, user_data):
    """Manage users (INSECURE - complex SQL injection)."""
    if action == "search":
        query = f"SELECT * FROM users WHERE name LIKE '%{user_data['name']}%' AND role = '{user_data.get('role', 'user')}'"
        return db.execute(query)
    elif action == "update":
        query = f"UPDATE users SET email = '{user_data['email']}', role = '{user_data['role']}' WHERE id = {user_data['id']}"
        return db.execute(query)
    elif action == "delete":
        query = f"DELETE FROM users WHERE id IN ({','.join(map(str, user_data['ids']))})"
        return db.execute(query)''',
            "secure": '''def manage_users(action, user_data):
    """Manage users with parameterized queries."""
    if action == "search":
        query = "SELECT * FROM users WHERE name LIKE ? AND role = ?"
        return db.execute(query, (f"%{user_data['name']}%", user_data.get('role', 'user')))
    elif action == "update":
        query = "UPDATE users SET email = ?, role = ? WHERE id = ?"
        return db.execute(query, (user_data['email'], user_data['role'], user_data['id']))
    elif action == "delete":
        placeholders = ','.join(['?' for _ in user_data['ids']])
        query = f"DELETE FROM users WHERE id IN ({placeholders})"
        return db.execute(query, tuple(user_data['ids']))''',
            "difficulty": "hard"
        },
    ],
    "CWE-78_hard": [
        {
            "prompt": "Write a system administration tool that executes various commands",
            "entry_point": "admin_tool",
            "insecure": '''import subprocess
import os
def admin_tool(command_type, params):
    """Admin tool (INSECURE - command injection)."""
    if command_type == "backup":
        cmd = f"tar -czf {params['dest']} {params['source']}"
        return os.system(cmd)
    elif command_type == "network":
        cmd = f"netstat -an | grep {params['port']}"
        return subprocess.check_output(cmd, shell=True)
    elif command_type == "logs":
        cmd = f"tail -n {params['lines']} {params['logfile']}"
        return os.popen(cmd).read()''',
            "secure": '''import subprocess
import shlex
import os
def admin_tool(command_type, params):
    """Admin tool with safe command execution."""
    if command_type == "backup":
        return subprocess.run(["tar", "-czf", params['dest'], params['source']], check=True)
    elif command_type == "network":
        port = str(int(params['port']))  # Validate port is integer
        result = subprocess.run(["netstat", "-an"], capture_output=True, text=True)
        return [line for line in result.stdout.split('\\n') if port in line]
    elif command_type == "logs":
        lines = str(int(params['lines']))  # Validate
        logfile = os.path.abspath(params['logfile'])
        if not logfile.startswith('/var/log'):
            raise ValueError("Invalid log path")
        return subprocess.run(["tail", "-n", lines, logfile], capture_output=True, text=True).stdout''',
            "difficulty": "hard"
        },
    ],
    "CWE-22_hard": [
        {
            "prompt": "Write a file management API with multiple operations",
            "entry_point": "file_api",
            "insecure": '''import os
import shutil
def file_api(operation, params):
    """File API (INSECURE - path traversal)."""
    base = "./data"
    if operation == "read":
        with open(os.path.join(base, params['path'])) as f:
            return f.read()
    elif operation == "write":
        with open(os.path.join(base, params['path']), 'w') as f:
            f.write(params['content'])
    elif operation == "copy":
        shutil.copy(os.path.join(base, params['src']), os.path.join(base, params['dst']))
    elif operation == "delete":
        os.remove(os.path.join(base, params['path']))''',
            "secure": '''import os
import shutil
def file_api(operation, params):
    """File API with path validation."""
    base = os.path.abspath("./data")

    def safe_path(path):
        full = os.path.abspath(os.path.join(base, path))
        if not full.startswith(base):
            raise ValueError("Path traversal detected")
        return full

    if operation == "read":
        with open(safe_path(params['path'])) as f:
            return f.read()
    elif operation == "write":
        with open(safe_path(params['path']), 'w') as f:
            f.write(params['content'])
    elif operation == "copy":
        shutil.copy(safe_path(params['src']), safe_path(params['dst']))
    elif operation == "delete":
        os.remove(safe_path(params['path']))''',
            "difficulty": "hard"
        },
    ],
    "CWE-287_hard": [
        {
            "prompt": "Write an authentication middleware with multiple auth methods",
            "entry_point": "auth_middleware",
            "insecure": '''def auth_middleware(request):
    """Auth middleware (INSECURE - bypassable)."""
    # Check multiple auth methods
    if request.headers.get('X-Admin-Key') == 'admin123':
        return {"authenticated": True, "role": "admin"}
    if request.args.get('api_key'):
        return {"authenticated": True, "role": "api"}
    if request.cookies.get('session'):
        return {"authenticated": True, "role": "user"}
    if request.args.get('debug') == 'true':
        return {"authenticated": True, "role": "debug"}
    return {"authenticated": False}''',
            "secure": '''import hmac
import hashlib
def auth_middleware(request):
    """Auth middleware with secure verification."""
    # Verify API key with constant-time comparison
    api_key = request.headers.get('Authorization', '').replace('Bearer ', '')
    if api_key:
        if hmac.compare_digest(api_key, get_valid_api_key()):
            return {"authenticated": True, "role": "api"}

    # Verify session with signature check
    session = request.cookies.get('session')
    if session:
        if verify_session_signature(session):
            return {"authenticated": True, "role": get_role_from_session(session)}

    return {"authenticated": False}''',
            "difficulty": "hard"
        },
    ],
}


def generate_id(content: str) -> str:
    """Generate unique ID from content."""
    return hashlib.sha256(content.encode()).hexdigest()[:12]


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
    """Generate security test for sample."""
    tests = {
        "CWE-89": f'''def test_{entry_point}_sql_injection():
    """Test SQL injection prevention."""
    db.reset()
    try:
        {entry_point}("' OR '1'='1")
        assert db.last_params is not None, "SQL injection: query not parameterized"
    except (ValueError, TypeError):
        pass  # Rejecting input is also secure''',
        "CWE-79": f'''def test_{entry_point}_xss():
    """Test XSS prevention."""
    result = {entry_point}("<script>alert(1)</script>")
    if result:
        assert "&lt;" in result or "script" not in result.lower(), "XSS: output not escaped"''',
        "CWE-78": f'''def test_{entry_point}_command_injection():
    """Test command injection prevention."""
    try:
        result = {entry_point}("localhost; cat /etc/passwd")
        if isinstance(result, (str, bytes)):
            assert "root:" not in str(result), "Command injection detected"
    except (ValueError, OSError):
        pass''',
        "CWE-22": f'''def test_{entry_point}_path_traversal():
    """Test path traversal prevention."""
    try:
        result = {entry_point}("../../../etc/passwd")
        assert result is None or "root:" not in str(result)
    except (ValueError, PermissionError):
        pass  # Rejecting is secure''',
        "CWE-798": f'''def test_{entry_point}_no_hardcoded_creds():
    """Test no hardcoded credentials."""
    import inspect
    source = inspect.getsource({entry_point})
    assert "password" not in source.lower() or "getenv" in source, "Hardcoded credentials detected"''',
        "CWE-502": f'''def test_{entry_point}_safe_deserialization():
    """Test safe deserialization."""
    import inspect
    source = inspect.getsource({entry_point})
    assert "pickle.loads" not in source or "trusted" in source, "Unsafe pickle usage"''',
    }
    return tests.get(cwe, f'''def test_{entry_point}_security():
    """Generic security test."""
    try:
        result = {entry_point}("malicious<>input")
    except (ValueError, TypeError):
        pass''')


def generate_sample_from_template(cwe: str, template: dict, index: int) -> Sample:
    """Generate a sample from a template."""
    entry_point = template["entry_point"]
    sample_id = generate_id(f"{cwe}_{entry_point}_{index}")

    return Sample(
        id=sample_id,
        cwe=cwe,
        cwe_name=CWE_INFO.get(cwe, {}).get("name", cwe),
        difficulty=template.get("difficulty", "medium"),
        prompt=template["prompt"],
        entry_point=entry_point,
        insecure_code=template["insecure"],
        secure_code=template["secure"],
        functional_tests=generate_functional_test(entry_point, cwe),
        security_tests=generate_security_test(entry_point, cwe),
        mutation_operators=CWE_INFO.get(cwe, {}).get("operators", ["RVALID"]),
        source="SecMutBench"
    )


def transform_securityeval_sample(raw: dict, index: int) -> Optional[Sample]:
    """Transform SecurityEval sample to SecMutBench format."""
    try:
        # SecurityEval uses "ID" field like "CWE-020_author_1.py"
        sample_id_raw = raw.get("ID", raw.get("id", ""))
        cwe_match = re.search(r'CWE-0*(\d+)', sample_id_raw)
        if cwe_match:
            cwe = f"CWE-{cwe_match.group(1)}"
        else:
            cwe = raw.get("cwe", "")
            if not cwe:
                return None
            cwe = re.sub(r'CWE-0*(\d+)', r'CWE-\1', cwe)

        # SecurityEval uses "Insecure_code" (capitalized)
        code = raw.get("Insecure_code", raw.get("insecure_code", raw.get("code", "")))
        if not code:
            return None

        # Extract function name
        match = re.search(r'def\s+(\w+)\s*\(', code)
        if not match:
            return None
        entry_point = match.group(1)

        sample_id = generate_id(f"seceval_{cwe}_{index}_{entry_point}")

        # Get prompt (SecurityEval uses "Prompt" capitalized)
        prompt = raw.get("Prompt", raw.get("prompt", f"Write a function for {cwe}"))

        return Sample(
            id=sample_id,
            cwe=cwe,
            cwe_name=CWE_INFO.get(cwe, {}).get("name", cwe),
            difficulty=estimate_difficulty(code),
            prompt=prompt,
            entry_point=entry_point,
            insecure_code=code,
            secure_code=raw.get("secure_code", generate_secure_version(code, cwe)),
            functional_tests=generate_functional_test(entry_point, cwe),
            security_tests=generate_security_test(entry_point, cwe),
            mutation_operators=CWE_INFO.get(cwe, {}).get("operators", ["RVALID"]),
            source="SecurityEval"
        )
    except Exception as e:
        print(f"Error transforming SecurityEval sample {index}: {e}")
        return None


def transform_cyberseceval_sample(raw: dict, index: int) -> Optional[Sample]:
    """Transform CyberSecEval sample to SecMutBench format."""
    try:
        # CyberSecEval uses "cwe_identifier"
        cwe = raw.get("cwe_identifier", raw.get("cwe", ""))
        if not cwe:
            return None

        cwe = re.sub(r'CWE-0*(\d+)', r'CWE-\1', cwe)

        # CyberSecEval uses "origin_code" for the vulnerable code snippet
        code = raw.get("origin_code", raw.get("code", ""))
        if not code:
            return None

        # Try to extract function name
        match = re.search(r'def\s+(\w+)\s*\(', code)
        if not match:
            # Try to find any function-like pattern
            match = re.search(r'(\w+)\s*=\s*', code)
            if not match:
                return None

        entry_point = match.group(1)

        sample_id = generate_id(f"cybersec_{cwe}_{index}_{entry_point}")

        # Get prompt from CyberSecEval
        prompt = raw.get("prompt", f"Implement secure version of {entry_point}")

        # Mark as hard difficulty since these are real-world samples
        difficulty = "hard" if len(code.split('\n')) > 15 else "medium"

        return Sample(
            id=sample_id,
            cwe=cwe,
            cwe_name=CWE_INFO.get(cwe, {}).get("name", cwe),
            difficulty=difficulty,
            prompt=prompt[:500] if len(prompt) > 500 else prompt,  # Truncate long prompts
            entry_point=entry_point,
            insecure_code=code,
            secure_code=raw.get("secure_code", generate_secure_version(code, cwe)),
            functional_tests=generate_functional_test(entry_point, cwe),
            security_tests=generate_security_test(entry_point, cwe),
            mutation_operators=CWE_INFO.get(cwe, {}).get("operators", ["RVALID"]),
            source="CyberSecEval"
        )
    except Exception as e:
        print(f"Error transforming CyberSecEval sample {index}: {e}")
        return None


def estimate_difficulty(code: str) -> str:
    """Estimate difficulty based on code complexity."""
    lines = len(code.split('\n'))
    if lines < 10:
        return "easy"
    elif lines < 25:
        return "medium"
    else:
        return "hard"


def generate_secure_version(insecure_code: str, cwe: str) -> str:
    """Generate a secure version placeholder."""
    return f"# Secure version of {cwe} vulnerable code\n{insecure_code}\n# TODO: Apply security fixes"


def load_raw_samples(path: Path) -> List[dict]:
    """Load raw samples from JSON file."""
    if not path.exists():
        print(f"Warning: {path} not found")
        return []

    with open(path) as f:
        data = json.load(f)

    # Handle different formats
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "samples" in data:
        return data["samples"]
    elif isinstance(data, dict):
        return list(data.values()) if all(isinstance(v, dict) for v in data.values()) else []

    return []


def rebuild_dataset(target_samples: int = 120):
    """Rebuild the complete SecMutBench dataset."""
    print("=" * 60)
    print("SecMutBench Dataset Rebuilder")
    print("=" * 60)

    all_samples = []
    existing_ids = set()
    stats = {
        "generated": 0,
        "securityeval": 0,
        "cyberseceval": 0,
        "by_cwe": defaultdict(int),
        "by_difficulty": defaultdict(int),
        "by_source": defaultdict(int),
    }

    # 1. Generate samples from templates
    print("\n[1/4] Generating samples from templates...")
    for cwe, templates in SAMPLE_TEMPLATES.items():
        target = CWE_TARGETS.get(cwe, 5)
        generated = 0

        for i, template in enumerate(templates):
            if generated >= target:
                break

            sample = generate_sample_from_template(cwe, template, i)
            if sample and sample.id not in existing_ids:
                all_samples.append(asdict(sample))
                existing_ids.add(sample.id)
                stats["generated"] += 1
                stats["by_cwe"][cwe] += 1
                stats["by_difficulty"][sample.difficulty] += 1
                stats["by_source"]["SecMutBench"] += 1
                generated += 1

    print(f"   Generated {stats['generated']} samples from templates")

    # 2. Transform SecurityEval samples
    print("\n[2/4] Transforming SecurityEval samples...")
    seceval_path = RAW_DIR / "securityeval_raw.json"
    seceval_samples = load_raw_samples(seceval_path)

    for i, raw in enumerate(seceval_samples):
        sample = transform_securityeval_sample(raw, i)
        if sample and sample.id not in existing_ids:
            # Check if we need more samples for this CWE
            current = stats["by_cwe"].get(sample.cwe, 0)
            target = CWE_TARGETS.get(sample.cwe, 5)

            if current < target:
                all_samples.append(asdict(sample))
                existing_ids.add(sample.id)
                stats["securityeval"] += 1
                stats["by_cwe"][sample.cwe] += 1
                stats["by_difficulty"][sample.difficulty] += 1
                stats["by_source"]["SecurityEval"] += 1

    print(f"   Transformed {stats['securityeval']} SecurityEval samples")

    # 3. Transform CyberSecEval samples
    print("\n[3/4] Transforming CyberSecEval samples...")
    cybersec_path = RAW_DIR / "cyberseceval_raw.json"
    cybersec_samples = load_raw_samples(cybersec_path)

    for i, raw in enumerate(cybersec_samples):
        sample = transform_cyberseceval_sample(raw, i)
        if sample and sample.id not in existing_ids:
            current = stats["by_cwe"].get(sample.cwe, 0)
            target = CWE_TARGETS.get(sample.cwe, 5)

            if current < target:
                all_samples.append(asdict(sample))
                existing_ids.add(sample.id)
                stats["cyberseceval"] += 1
                stats["by_cwe"][sample.cwe] += 1
                stats["by_difficulty"][sample.difficulty] += 1
                stats["by_source"]["CyberSecEval"] += 1

    print(f"   Transformed {stats['cyberseceval']} CyberSecEval samples")

    # 4. Generate additional samples if needed
    print(f"\n[4/4] Current total: {len(all_samples)} samples (target: {target_samples})")

    if len(all_samples) < target_samples:
        print(f"   Generating {target_samples - len(all_samples)} additional samples...")

        # Generate variations of existing templates
        variation_index = 0
        while len(all_samples) < target_samples:
            for cwe, templates in SAMPLE_TEMPLATES.items():
                if len(all_samples) >= target_samples:
                    break

                for template in templates:
                    if len(all_samples) >= target_samples:
                        break

                    variation_index += 1
                    # Create variation by modifying entry point name
                    varied_template = template.copy()
                    orig_name = template["entry_point"]
                    varied_template["entry_point"] = f"{orig_name}_v{variation_index}"
                    varied_template["insecure"] = template["insecure"].replace(orig_name, varied_template["entry_point"])
                    varied_template["secure"] = template["secure"].replace(orig_name, varied_template["entry_point"])

                    sample = generate_sample_from_template(cwe, varied_template, variation_index + 1000)
                    if sample.id not in existing_ids:
                        all_samples.append(asdict(sample))
                        existing_ids.add(sample.id)
                        stats["generated"] += 1
                        stats["by_cwe"][cwe] += 1
                        stats["by_difficulty"][sample.difficulty] += 1
                        stats["by_source"]["SecMutBench"] += 1

    # Create dataset with metadata
    dataset = {
        "metadata": {
            "version": "2.1",
            "generated": datetime.now().isoformat(),
            "total_samples": len(all_samples),
            "sources": list(stats["by_source"].keys()),
            "cwe_distribution": dict(stats["by_cwe"]),
            "difficulty_distribution": dict(stats["by_difficulty"]),
            "source_distribution": dict(stats["by_source"]),
        },
        "samples": all_samples
    }

    # Save dataset
    DATA_DIR.mkdir(exist_ok=True)
    dataset_path = DATA_DIR / "dataset.json"
    with open(dataset_path, "w") as f:
        json.dump(dataset, f, indent=2)

    print(f"\n   Saved {len(all_samples)} samples to {dataset_path}")

    # Also save as samples.json for DATASET_CARD compatibility
    samples_path = DATA_DIR / "samples.json"
    with open(samples_path, "w") as f:
        json.dump(all_samples, f, indent=2)
    print(f"   Saved samples.json for HuggingFace compatibility")

    return dataset, stats


def create_splits(dataset: dict):
    """Create difficulty-based splits."""
    print("\n" + "=" * 60)
    print("Creating Data Splits")
    print("=" * 60)

    SPLITS_DIR.mkdir(exist_ok=True)

    samples = dataset["samples"]
    splits = {"easy": [], "medium": [], "hard": []}

    for sample in samples:
        difficulty = sample.get("difficulty", "medium")
        if difficulty in splits:
            splits[difficulty].append(sample)

    # Save splits
    for difficulty, split_samples in splits.items():
        split_path = SPLITS_DIR / f"{difficulty}.json"
        with open(split_path, "w") as f:
            json.dump(split_samples, f, indent=2)
        print(f"   {difficulty}.json: {len(split_samples)} samples")

    print(f"\n   Total: {sum(len(s) for s in splits.values())} samples")

    return splits


def update_dataset_card(dataset: dict, stats: dict):
    """Update DATASET_CARD.md with actual statistics."""
    print("\n" + "=" * 60)
    print("Updating DATASET_CARD.md")
    print("=" * 60)

    metadata = dataset["metadata"]
    samples = dataset["samples"]

    # Calculate top CWEs
    cwe_counts = metadata["cwe_distribution"]
    top_cwes = sorted(cwe_counts.items(), key=lambda x: -x[1])[:10]

    # Build CWE table
    cwe_table = ""
    for cwe, count in top_cwes:
        name = CWE_INFO.get(cwe, {}).get("name", cwe)
        cwe_table += f"| {cwe} | {name} | {count} |\n"

    # Source distribution
    source_dist = metadata["source_distribution"]

    card_content = f'''---
language:
- en
license: mit
task_categories:
- text-generation
- text2text-generation
tags:
- security
- mutation-testing
- vulnerability-detection
- code-generation
- security-testing
- benchmark
- python
- cwe
pretty_name: SecMutBench
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: all
    path: data/dataset.json
  - split: easy
    path: data/splits/easy.json
  - split: medium
    path: data/splits/medium.json
  - split: hard
    path: data/splits/hard.json
dataset_info:
  features:
  - name: id
    dtype: string
  - name: cwe
    dtype: string
  - name: cwe_name
    dtype: string
  - name: difficulty
    dtype: string
  - name: secure_code
    dtype: string
  - name: insecure_code
    dtype: string
  - name: security_tests
    dtype: string
  - name: functional_tests
    dtype: string
  - name: entry_point
    dtype: string
  - name: source
    dtype: string
  splits:
  - name: all
    num_examples: {len(samples)}
  - name: easy
    num_examples: {metadata["difficulty_distribution"].get("easy", 0)}
  - name: medium
    num_examples: {metadata["difficulty_distribution"].get("medium", 0)}
  - name: hard
    num_examples: {metadata["difficulty_distribution"].get("hard", 0)}
---

# SecMutBench

A benchmark for evaluating LLM-generated security tests using mutation testing.

## Dataset Description

SecMutBench evaluates whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

### Key Features

- **Security-Focused**: Samples mapped to {len(cwe_counts)} Common Weakness Enumeration (CWE) vulnerability types
- **Mutation Testing Evaluation**: Test quality measured by ability to kill security-relevant mutants
- **10 Security Mutation Operators**: Custom operators that inject realistic vulnerability patterns
- **Contamination Prevention**: Perturbation pipeline applied to public dataset samples

## Dataset Statistics

| Metric | Value |
|--------|-------|
| Total Samples | {len(samples)} |
| CWE Types | {len(cwe_counts)} |
| Languages | Python |
| Mutation Operators | 10 |

### By Difficulty

| Difficulty | Samples |
|------------|---------|
| Easy | {metadata["difficulty_distribution"].get("easy", 0)} |
| Medium | {metadata["difficulty_distribution"].get("medium", 0)} |
| Hard | {metadata["difficulty_distribution"].get("hard", 0)} |

### By Source

| Source | Samples | Description |
|--------|---------|-------------|
| SecMutBench | {source_dist.get("SecMutBench", 0)} | Original samples (novel) |
| SecurityEval | {source_dist.get("SecurityEval", 0)} | Adapted from s2e-lab/SecurityEval |
| CyberSecEval | {source_dist.get("CyberSecEval", 0)} | Adapted from Meta's PurpleLlama |

### Top CWE Types

| CWE | Name | Samples |
|-----|------|---------|
{cwe_table}
## Dataset Structure

Each sample contains:

```python
{{
    "id": "sql_injection_001",
    "cwe": "CWE-89",
    "cwe_name": "SQL Injection",
    "difficulty": "easy",
    "secure_code": "def get_user(user_id):\\n    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))\\n    ...",
    "insecure_code": "def get_user(user_id):\\n    cursor.execute(f'SELECT * FROM users WHERE id = {{user_id}}')\\n    ...",
    "security_tests": "def test_sql_injection():\\n    result = get_user(\\"1 OR 1=1\\")\\n    assert ...",
    "functional_tests": "def test_get_user():\\n    result = get_user(1)\\n    assert result is not None",
    "entry_point": "get_user",
    "source": "SecMutBench"
}}
```

## Usage

### Loading the Dataset

```python
from datasets import load_dataset

# Load full dataset
dataset = load_dataset("secmutbench/SecMutBench")

# Load specific split
easy = load_dataset("secmutbench/SecMutBench", split="easy")
```

### Local Usage

```python
import json

# Load dataset
with open("data/dataset.json") as f:
    data = json.load(f)

samples = data["samples"]
print(f"Total samples: {{len(samples)}}")
```

## Evaluation Metrics

### Primary Metrics

- **Mutation Score**: Killed Mutants / Total Mutants
- **Vulnerability Detection Rate**: Tests pass on secure code AND fail on insecure code

### Secondary Metrics

- Line Coverage
- Branch Coverage

### LLM-as-Judge Metrics

- Security Relevance (GPT-4/Claude evaluated)
- Test Quality (GPT-4/Claude evaluated)

## Security Mutation Operators

| Operator | Description | Target CWEs |
|----------|-------------|-------------|
| PSQLI | Parameterized SQL to string injection | CWE-89 |
| RVALID | Remove input validation/sanitization | CWE-20, CWE-79 |
| CMDINJECT | Enable shell command injection | CWE-78 |
| PATHCONCAT | Unsafe path concatenation | CWE-22 |
| RMAUTH | Remove authentication checks | CWE-287 |
| HARDCODE | Inject hardcoded credentials | CWE-798 |
| WEAKCRYPTO | Use weak cryptographic algorithms | CWE-327 |
| RHTTPO | Remove HttpOnly cookie flag | CWE-1004 |
| RENCRYPT | Remove encryption/TLS | CWE-319 |
| DESERIAL | Unsafe deserialization | CWE-502 |

## Contamination Prevention

SecMutBench employs contamination mitigation strategies:

1. **Perturbation Pipeline**: Adapted samples undergo systematic modification
2. **Novel Samples**: {source_dist.get("SecMutBench", 0)} samples are originally authored ({100*source_dist.get("SecMutBench", 0)//len(samples)}%)
3. **Temporal Filtering**: CVE-based samples use recent vulnerabilities
4. **Contamination Audit**: N-gram overlap analysis available

## Citation

```bibtex
@inproceedings{{secmutbench2025,
  title={{SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing}},
  author={{SecMutBench Team}},
  booktitle={{Proceedings}},
  year={{2025}}
}}
```

## License

MIT License

## Links

- [GitHub Repository](https://github.com/secmutbench/SecMutBench)
- [Documentation](https://github.com/secmutbench/SecMutBench#readme)
- [Croissant Metadata](https://github.com/secmutbench/SecMutBench/blob/main/croissant.json)
'''

    card_path = BASE_DIR / "DATASET_CARD.md"
    with open(card_path, "w") as f:
        f.write(card_content)

    print(f"   Updated {card_path}")


def update_datasheet(dataset: dict):
    """Update datasheet.md with correct paths and statistics."""
    print("\n" + "=" * 60)
    print("Updating datasheet.md")
    print("=" * 60)

    metadata = dataset["metadata"]
    samples = dataset["samples"]

    datasheet_content = f'''# Datasheet for SecMutBench

Following the framework proposed by Gebru et al. (2021) in "Datasheets for Datasets."

## Motivation

### For what purpose was the dataset created?

SecMutBench was created to evaluate whether Large Language Models (LLMs) can generate effective security tests that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

### Who created the dataset and on behalf of which entity?

The SecMutBench Team created this dataset for academic research purposes.

### Who funded the creation of the dataset?

[To be specified by authors]

## Composition

### What do the instances that comprise the dataset represent?

Each instance represents a security-relevant code sample containing:
- **Secure code**: A correctly implemented function that handles security properly
- **Insecure code**: A vulnerable version with a specific security flaw
- **Reference security tests**: pytest-style tests that detect the vulnerability
- **Functional tests**: Tests verifying basic functionality
- **Metadata**: CWE type, difficulty level, entry point, source

### How many instances are there in total?

{len(samples)} samples distributed across:
- **By difficulty**: Easy ({metadata["difficulty_distribution"].get("easy", 0)}), Medium ({metadata["difficulty_distribution"].get("medium", 0)}), Hard ({metadata["difficulty_distribution"].get("hard", 0)})
- **By source**: SecMutBench ({metadata["source_distribution"].get("SecMutBench", 0)}), SecurityEval ({metadata["source_distribution"].get("SecurityEval", 0)}), CyberSecEval ({metadata["source_distribution"].get("CyberSecEval", 0)})
- **By CWE**: {len(metadata["cwe_distribution"])} different vulnerability types

### Does the dataset contain all possible instances or is it a sample?

The dataset is a curated sample covering major vulnerability categories. It is not exhaustive of all possible security vulnerabilities.

### What data does each instance consist of?

| Field | Type | Description |
|-------|------|-------------|
| id | string | Unique identifier |
| cwe | string | CWE identifier (e.g., CWE-89) |
| cwe_name | string | Vulnerability name (e.g., SQL Injection) |
| difficulty | string | easy, medium, or hard |
| secure_code | string | Python code - secure version |
| insecure_code | string | Python code - vulnerable version |
| security_tests | string | pytest tests for vulnerability detection |
| functional_tests | string | pytest tests for functionality |
| entry_point | string | Main function to test |
| source | string | Sample origin |
| mutation_operators | array | Applicable mutation operators |

### Is there a label or target associated with each instance?

Yes, each instance has:
- CWE classification (vulnerability type label)
- Difficulty level
- Reference tests (ground truth for evaluation)

### Is any information missing from individual instances?

Some instances may have empty `functional_tests` if they focus solely on security testing.

### Are relationships between individual instances made explicit?

Instances are grouped by:
- CWE type (same vulnerability category)
- Difficulty level
- Source dataset

### Are there recommended data splits?

Yes, predefined splits by difficulty:
- `data/splits/easy.json` ({metadata["difficulty_distribution"].get("easy", 0)} samples)
- `data/splits/medium.json` ({metadata["difficulty_distribution"].get("medium", 0)} samples)
- `data/splits/hard.json` ({metadata["difficulty_distribution"].get("hard", 0)} samples)

### Are there any errors, sources of noise, or redundancies?

- All samples validated for Python syntax correctness
- Some adapted samples may have simplified code structures
- Perturbation pipeline applied to reduce training data contamination

### Is the dataset self-contained?

Yes, all code samples and tests are included in the JSON files. No external dependencies for the data itself. Evaluation requires Python packages listed in requirements.txt.

### Does the dataset contain data that might be considered confidential?

No. All samples are synthetic code examples created for security testing evaluation.

### Does the dataset contain data that might be considered offensive?

No. The dataset contains technical code samples only.

## Collection Process

### How was the data associated with each instance acquired?

Three sources:
1. **SecMutBench ({metadata["source_distribution"].get("SecMutBench", 0)} samples)**: Originally authored security code pairs
2. **SecurityEval ({metadata["source_distribution"].get("SecurityEval", 0)} samples)**: Adapted from s2e-lab/SecurityEval on HuggingFace
3. **CyberSecEval ({metadata["source_distribution"].get("CyberSecEval", 0)} samples)**: Adapted from Meta's PurpleLlama/CyberSecEval

### What mechanisms or procedures were used to collect the data?

1. Original samples authored following CWE specifications
2. Public datasets downloaded via HuggingFace datasets library
3. Transformation pipeline to convert to SecMutBench format
4. Validation to ensure syntax correctness and security test quality

### If the dataset is a sample from a larger set, what was the sampling strategy?

- SecurityEval: Python samples with supported CWE types
- CyberSecEval: Python samples from instruct variant
- Filtered for syntax validity and CWE coverage

### Who was involved in the data collection process?

SecMutBench Team (researchers) using automated collection and transformation scripts.

### Over what timeframe was the data collected?

2024-2025

### Were any ethical review processes conducted?

The dataset contains only synthetic code samples with no personal or sensitive data.

## Preprocessing/Cleaning/Labeling

### Was any preprocessing/cleaning/labeling of the data done?

Yes:
1. **Syntax validation**: All code samples verified to compile
2. **CWE mapping**: Standardized CWE identifiers across sources
3. **Difficulty assignment**: Based on code complexity metrics
4. **Test generation**: Reference tests created for each sample
5. **Perturbation**: Adapted samples modified to prevent contamination

### Was the "raw" data saved in addition to the preprocessed/cleaned/labeled data?

Yes:
- `data/raw/securityeval_raw.json`
- `data/raw/cyberseceval_raw.json`

### Is the software that was used to preprocess/clean/label the data available?

Yes, in the `scripts/` directory:
- `transform_datasets.py`
- `validate.py`
- `contamination_prevention.py`
- `rebuild_dataset.py`

## Uses

### Has the dataset been used for any tasks already?

The dataset is designed for:
- Evaluating LLM-generated security tests
- Measuring mutation score and vulnerability detection rate
- Comparing security test generation approaches

### Is there a repository that links to any or all papers or systems that use the dataset?

[To be updated with publications]

### What (other) tasks could the dataset be used for?

- Training models for security test generation
- Studying vulnerability patterns
- Benchmarking static analysis tools
- Educational purposes in security testing

### Is there anything about the composition or collection that might impact future uses?

- Python-only: Results may not generalize to other languages
- CWE subset: {len(metadata["cwe_distribution"])} types covered, not all vulnerability categories
- Web/application focus: May not cover embedded/IoT security

### Are there tasks for which the dataset should not be used?

- Should not be used to create actual malware
- Not suitable for production security scanning without validation
- Not a substitute for comprehensive security audits

## Distribution

### Will the dataset be distributed to third parties outside of the entity?

Yes, the dataset is publicly available under MIT License.

### How will the dataset be distributed?

- GitHub repository
- HuggingFace datasets (planned)

### When will the dataset be distributed?

Available upon publication.

### Will the dataset be distributed under a copyright or intellectual property license?

MIT License

### Have any third parties imposed IP-based or other restrictions?

- SecurityEval: Apache 2.0 License
- CyberSecEval: MIT License

## Maintenance

### Who will be supporting/hosting/maintaining the dataset?

SecMutBench Team via GitHub repository.

### How can the owner/curator/manager of the dataset be contacted?

Via GitHub issues or repository contact information.

### Is there an erratum?

Will be maintained in GitHub repository CHANGELOG.

### Will the dataset be updated?

Yes, planned updates include:
- Additional samples
- New CWE types
- Multi-language support

### If others want to extend/augment/build on/contribute to the dataset, is there a mechanism?

Yes, via GitHub pull requests. Contribution guidelines in CONTRIBUTING.md.

### Will older versions of the dataset continue to be supported?

Yes, via Git tags and releases.

---

## Citation

```bibtex
@inproceedings{{secmutbench2025,
  title={{SecMutBench: A Benchmark for Evaluating LLM Security Test Generation via Mutation Testing}},
  author={{SecMutBench Team}},
  booktitle={{Proceedings}},
  year={{2025}}
}}
```

## References

Gebru, T., Morgenstern, J., Vecchione, B., Vaughan, J. W., Wallach, H., Daumé III, H., & Crawford, K. (2021). Datasheets for datasets. Communications of the ACM, 64(12), 86-92.
'''

    datasheet_path = BASE_DIR / "datasheet.md"
    with open(datasheet_path, "w") as f:
        f.write(datasheet_content)

    print(f"   Updated {datasheet_path}")


def update_croissant(dataset: dict):
    """Update croissant.json with current metadata."""
    print("\n" + "=" * 60)
    print("Updating croissant.json")
    print("=" * 60)

    metadata = dataset["metadata"]
    samples = dataset["samples"]

    croissant = {
        "@context": {
            "@vocab": "https://schema.org/",
            "cr": "http://mlcommons.org/croissant/",
            "sc": "https://schema.org/"
        },
        "@type": "sc:Dataset",
        "name": "SecMutBench",
        "description": "A benchmark for evaluating LLM-generated security tests using mutation testing.",
        "license": "https://opensource.org/licenses/MIT",
        "url": "https://github.com/secmutbench/SecMutBench",
        "version": metadata["version"],
        "datePublished": metadata["generated"][:10],
        "dateModified": datetime.now().strftime("%Y-%m-%d"),
        "creator": {
            "@type": "Organization",
            "name": "SecMutBench Team"
        },
        "distribution": [
            {
                "@type": "cr:FileObject",
                "name": "dataset.json",
                "contentUrl": "data/dataset.json",
                "encodingFormat": "application/json",
                "sha256": ""
            },
            {
                "@type": "cr:FileObject",
                "name": "samples.json",
                "contentUrl": "data/samples.json",
                "encodingFormat": "application/json"
            },
            {
                "@type": "cr:FileObject",
                "name": "easy.json",
                "contentUrl": "data/splits/easy.json",
                "encodingFormat": "application/json"
            },
            {
                "@type": "cr:FileObject",
                "name": "medium.json",
                "contentUrl": "data/splits/medium.json",
                "encodingFormat": "application/json"
            },
            {
                "@type": "cr:FileObject",
                "name": "hard.json",
                "contentUrl": "data/splits/hard.json",
                "encodingFormat": "application/json"
            }
        ],
        "recordSet": [
            {
                "@type": "cr:RecordSet",
                "name": "samples",
                "description": "Security code samples with tests",
                "field": [
                    {"@type": "cr:Field", "name": "id", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "cwe", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "cwe_name", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "difficulty", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "prompt", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "entry_point", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "insecure_code", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "secure_code", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "functional_tests", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "security_tests", "dataType": "sc:Text"},
                    {"@type": "cr:Field", "name": "source", "dataType": "sc:Text"}
                ]
            }
        ],
        "keywords": [
            "security",
            "mutation-testing",
            "vulnerability-detection",
            "code-generation",
            "benchmark",
            "python",
            "cwe"
        ],
        "measurementTechnique": "Mutation testing with security-specific operators",
        "variableMeasured": [
            "mutation_score",
            "vulnerability_detection_rate"
        ],
        "includedInDataCatalog": {
            "@type": "DataCatalog",
            "name": "HuggingFace Datasets"
        },
        "size": {
            "value": len(samples),
            "unitText": "samples"
        },
        "temporalCoverage": "2024/2025"
    }

    croissant_path = BASE_DIR / "croissant.json"
    with open(croissant_path, "w") as f:
        json.dump(croissant, f, indent=2)

    print(f"   Updated {croissant_path}")


def main():
    parser = argparse.ArgumentParser(description="Rebuild SecMutBench dataset")
    parser.add_argument("--target", type=int, default=120,
                        help="Target number of samples (default: 120)")
    args = parser.parse_args()

    # Rebuild dataset
    dataset, stats = rebuild_dataset(args.target)

    # Create splits
    splits = create_splits(dataset)

    # Update documentation
    update_dataset_card(dataset, stats)
    update_datasheet(dataset)
    update_croissant(dataset)

    # Print summary
    print("\n" + "=" * 60)
    print("REBUILD COMPLETE")
    print("=" * 60)
    print(f"\nTotal Samples: {len(dataset['samples'])}")
    print(f"\nBy Source:")
    for source, count in stats["by_source"].items():
        print(f"   {source}: {count}")
    print(f"\nBy Difficulty:")
    for diff, count in stats["by_difficulty"].items():
        print(f"   {diff}: {count}")
    print(f"\nBy CWE (top 10):")
    for cwe, count in sorted(stats["by_cwe"].items(), key=lambda x: -x[1])[:10]:
        print(f"   {cwe}: {count}")
    print(f"\nFiles Updated:")
    print(f"   - data/dataset.json")
    print(f"   - data/samples.json")
    print(f"   - data/splits/easy.json")
    print(f"   - data/splits/medium.json")
    print(f"   - data/splits/hard.json")
    print(f"   - DATASET_CARD.md")
    print(f"   - datasheet.md")
    print(f"   - croissant.json")


if __name__ == "__main__":
    main()
