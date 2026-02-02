# SecMutBench Documentation

**Date:** 2026-02-01
**Version:** 2.1
**Author:** SecMutBench Team

---

## Table of Contents

1. [Overview](#overview)
2. [How SecMutBench Works](#how-secmutbench-works)
3. [Dataset Generation](#dataset-generation)
4. [Templates Deep Dive](#templates-deep-dive)
5. [File Structure](#file-structure)

---

## Overview

SecMutBench is a benchmark for evaluating how well Large Language Models (LLMs) can generate **security tests** that detect vulnerabilities in code. Unlike existing benchmarks that assess secure code generation, SecMutBench focuses on **security test generation** evaluated through **mutation testing**.

```
┌─────────────────────────────────────────────────────────────────┐
│                      SecMutBench Flow                           │
├─────────────────────────────────────────────────────────────────┤
│  Dataset → Prompt LLM → Generate Test → Mutation Testing → Score │
└─────────────────────────────────────────────────────────────────┘
```

---

## How SecMutBench Works

### Step 1: Dataset Preparation

The dataset (`data/dataset.json`) contains 149 validated samples. Each sample has:

```json
{
  "id": "abc123",
  "cwe": "CWE-89",
  "cwe_name": "SQL Injection",
  "difficulty": "medium",
  "prompt": "Write a function to get user by ID",
  "entry_point": "get_user_by_id",
  "secure_code": "def get_user_by_id(id): ...",
  "insecure_code": "def get_user_by_id(id): ...",
  "security_tests": "def test_sql_injection(): ...",
  "functional_tests": "def test_basic(): ...",
  "mutation_operators": ["PSQLI", "RVALID"],
  "source": "SecMutBench"
}
```

---

### Step 2: Prompt the LLM

The model receives a prompt like:

```
You are a security testing expert. Generate pytest security tests
for the following code that may be vulnerable to CWE-89 (SQL Injection).

Code:
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = ?"
    return db.execute(query, (user_id,))

Entry point: get_user

Generate comprehensive security tests that would detect if this
code were vulnerable to SQL injection.
```

---

### Step 3: LLM Generates Tests

The model (e.g., qwen2.5-coder:7b) generates:

```python
def test_sql_injection_prevention():
    """Test that SQL injection payloads are handled safely."""
    malicious_inputs = [
        "' OR '1'='1",
        "'; DROP TABLE users;--",
        "1 UNION SELECT * FROM passwords"
    ]
    for payload in malicious_inputs:
        result = get_user(payload)
        assert "error" in str(result).lower() or result is None
```

---

### Step 4: Mutation Testing

This is the **core evaluation mechanism**.

#### 4a. Generate Mutants

The **MutationEngine** creates "mutants" - slightly modified versions of the secure code that introduce vulnerabilities:

```
Original (Secure):
    query = "SELECT * FROM users WHERE id = ?"
    db.execute(query, (user_id,))

Mutant 1 (Vulnerable - string concat):
    query = "SELECT * FROM users WHERE id = " + user_id
    db.execute(query)

Mutant 2 (Vulnerable - f-string):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    db.execute(query)

Mutant 3 (Vulnerable - no parameterization):
    query = "SELECT * FROM users WHERE id = '%s'" % user_id
    db.execute(query)
```

#### 4b. Run Tests Against Mutants

```
┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 1   │ --> │   FAIL ✓   │  (killed)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘

┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 2   │ --> │   PASS ✗   │  (survived)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘

┌────────────────┐     ┌─────────────┐     ┌────────────┐
│ Generated Test │ --> │  Mutant 3   │ --> │   FAIL ✓   │  (killed)
│                │     │ (vulnerable)│     │            │
└────────────────┘     └─────────────┘     └────────────┘
```

#### 4c. Calculate Mutation Score

```
Mutation Score = Killed Mutants / Total Mutants
               = 2 / 3
               = 66.7%
```

**Higher score = Better security tests**

---

### Step 5: Additional Checks

#### 5a. Vulnerability Detection Check

```
1. Run generated test on SECURE code   → Should PASS ✓
2. Run generated test on INSECURE code → Should FAIL ✓

If both conditions met → vuln_detected = True
```

#### 5b. Line Coverage

```
How much of the code did the tests execute?
Coverage = Lines Executed / Total Lines = 85%
```

#### 5c. Attack Vector Coverage

```
Check if tests cover known attack patterns:
✓ Tautology attacks ("' OR '1'='1")
✓ Union-based injection
✗ Time-based injection (missing)
✗ Error-based injection (missing)

Attack Coverage = 2/4 = 50%
```

---

### Step 6: LLM Judge Evaluation

An LLM judge (e.g., gpt-5) reviews the generated tests:

```
┌─────────────────────────────────────────────────────────┐
│                    LLM Judge Scores                     │
├─────────────────────────────────────────────────────────┤
│ Security Relevance: 0.88                                │
│   "Tests target correct vulnerability pattern"          │
│                                                         │
│ Test Quality: 0.35                                      │
│   "Tests are brittle, implementation-specific"          │
│                                                         │
│ Composite Score: 0.23                                   │
└─────────────────────────────────────────────────────────┘
```

---

### Step 7: Results Aggregation

All metrics combined:

```json
{
  "model": "qwen2.5-coder:7b",
  "sample_id": "abc123",
  "cwe": "CWE-89",
  "mutation_score": 0.67,
  "vuln_detected": true,
  "line_coverage": 0.85,
  "attack_coverage": 0.50,
  "judge_scores": {
    "security_relevance": 0.88,
    "test_quality": 0.35,
    "composite": 0.23
  }
}
```

---

### Step 8: Feedback Loop (Optional)

```
Results Analysis
      ↓
Identify weak CWEs (score < 50%)
      ↓
Flag problematic samples
      ↓
Add new samples / Fix issues
      ↓
Rebuild dataset
      ↓
Run again (iteration)
```

---

### Visual Summary

```
                    SecMutBench Pipeline

    ┌──────────────────────────────────────────────────┐
    │                   DATASET                        │
    │  149 samples (secure code, insecure code, CWE)   │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │                 PROMPT LLM                       │
    │  "Generate security tests for this CWE-89 code" │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │              LLM GENERATES TESTS                 │
    │  def test_sql_injection(): assert ...           │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │             MUTATION TESTING                     │
    │  Create mutants → Run tests → Count kills       │
    │  Score = killed / total = 67%                   │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │              LLM JUDGE REVIEW                    │
    │  Security: 88% | Quality: 35% | Composite: 23%  │
    └──────────────────────────────────────────────────┘
                           │
                           ▼
    ┌──────────────────────────────────────────────────┐
    │               FINAL RESULTS                      │
    │  Model X scored 45% avg mutation score          │
    │  Best on CWE-89, worst on CWE-79                │
    └──────────────────────────────────────────────────┘
```

---

### Key Insight

**Why mutation testing?**

Traditional metrics (coverage, assertions) don't measure if tests actually **detect vulnerabilities**.

Mutation testing answers: *"If someone introduced a security bug, would these tests catch it?"*

---

## Dataset Generation

### Overview

The dataset is built from **3 sources** and goes through a transformation + validation pipeline.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DATASET GENERATION PIPELINE                      │
├─────────────────────────────────────────────────────────────────────┤
│  Source 1: Templates  ──┐                                           │
│  Source 2: SecurityEval ─┼──→ Transform ──→ Validate ──→ dataset.json│
│  Source 3: CyberSecEval ─┘                                           │
└─────────────────────────────────────────────────────────────────────┘
```

---

### Step 1: Define CWE Types & Targets

```python
CWE_TARGETS = {
    "CWE-89": 15,   # SQL Injection - most samples
    "CWE-79": 15,   # XSS
    "CWE-78": 12,   # Command Injection
    "CWE-22": 12,   # Path Traversal
    "CWE-20": 10,   # Input Validation
    "CWE-287": 8,   # Authentication
    "CWE-798": 8,   # Hardcoded Credentials
    "CWE-502": 8,   # Deserialization
    ...
}
```

---

### Step 2: Source 1 - Generate from Templates (SecMutBench Original)

Hand-crafted templates for each CWE:

```python
SAMPLE_TEMPLATES = {
    "CWE-89": [
        {
            "prompt": "Write a function to get user by ID from database",
            "entry_point": "get_user_by_id",

            # INSECURE version (vulnerable)
            "insecure": '''def get_user_by_id(user_id):
                query = f"SELECT * FROM users WHERE id = {user_id}"  # SQL injection!
                return db.execute(query)''',

            # SECURE version (safe)
            "secure": '''def get_user_by_id(user_id):
                query = "SELECT * FROM users WHERE id = ?"
                return db.execute(query, (user_id,))''',  # Parameterized

            "difficulty": "easy"
        },
        # ... more templates
    ],
    "CWE-79": [...],  # XSS templates
    "CWE-78": [...],  # Command injection templates
    ...
}
```

**For each template, the script generates:**
- Unique ID (hash of content)
- Functional tests (basic)
- Security tests (CWE-specific)
- Mutation operators list

---

### Step 3: Source 2 - Transform SecurityEval

Download from HuggingFace (`s2e-lab/SecurityEval`):

```
data/raw/securityeval_raw.json
```

**Transformation:**
```python
def transform_securityeval_sample(raw, index):
    # Extract CWE from ID like "CWE-020_author_1.py"
    cwe = extract_cwe(raw["ID"])  # → "CWE-20"

    # Get vulnerable code
    code = raw["Insecure_code"]

    # Extract function name
    entry_point = extract_function_name(code)  # → "get_user"

    # Generate secure version (placeholder or transform)
    secure_code = generate_secure_version(code, cwe)

    # Generate tests
    security_tests = generate_security_test(entry_point, cwe)

    return Sample(...)
```

---

### Step 4: Source 3 - Transform CyberSecEval

Download from Meta's PurpleLlama:

```
data/raw/cyberseceval_raw.json
```

**Transformation:**
```python
def transform_cyberseceval_sample(raw, index):
    cwe = raw["cwe_identifier"]  # e.g., "CWE-89"
    code = raw["origin_code"]    # Vulnerable code

    # Similar process...
    return Sample(...)
```

---

### Step 5: Generate Security Tests

For each CWE, generate appropriate security tests:

```python
def generate_security_test(entry_point, cwe):
    tests = {
        "CWE-89": f'''def test_{entry_point}_sql_injection():
            """Test SQL injection prevention."""
            db.reset()
            try:
                {entry_point}("' OR '1'='1")
                assert db.last_params is not None, "SQL not parameterized"
            except (ValueError, TypeError):
                pass  # Rejecting input is also secure''',

        "CWE-79": f'''def test_{entry_point}_xss():
            """Test XSS prevention."""
            result = {entry_point}("<script>alert(1)</script>")
            assert "&lt;" in result, "XSS: output not escaped"''',

        "CWE-78": f'''def test_{entry_point}_command_injection():
            """Test command injection prevention."""
            result = {entry_point}("localhost; cat /etc/passwd")
            assert "root:" not in str(result)''',
        ...
    }
    return tests.get(cwe, generic_test)
```

---

### Step 6: Assign Mutation Operators

Each CWE has specific mutation operators:

```python
CWE_INFO = {
    "CWE-89": {"operators": ["PSQLI", "RVALID"]},      # SQL injection
    "CWE-79": {"operators": ["RVALID"]},               # XSS
    "CWE-78": {"operators": ["CMDINJECT", "RVALID"]},  # Command injection
    "CWE-22": {"operators": ["PATHCONCAT", "RVALID"]}, # Path traversal
    "CWE-798": {"operators": ["HARDCODE"]},            # Hardcoded creds
    "CWE-502": {"operators": ["DESERIAL"]},            # Deserialization
    ...
}
```

---

### Step 7: Validate & Clean

```python
# Check syntax validity
compile(secure_code, "<string>", "exec")
compile(insecure_code, "<string>", "exec")
compile(security_tests, "<string>", "exec")

# Check required fields
assert "assert" in security_tests  # Must have assertions
assert entry_point in secure_code   # Function must exist
```

---

### Step 8: Create Final Dataset Structure

```python
dataset = {
    "metadata": {
        "version": "2.1",
        "total_samples": 149,
        "cwe_distribution": {"CWE-89": 15, "CWE-79": 7, ...},
        "difficulty_distribution": {"easy": 45, "medium": 72, "hard": 32},
        "source_distribution": {"SecMutBench": 80, "SecurityEval": 40, "CyberSecEval": 29}
    },
    "samples": [
        {
            "id": "abc123",
            "cwe": "CWE-89",
            "cwe_name": "SQL Injection",
            "difficulty": "easy",
            "prompt": "Write a function to get user by ID",
            "entry_point": "get_user_by_id",
            "insecure_code": "def get_user_by_id(id): ...",
            "secure_code": "def get_user_by_id(id): ...",
            "functional_tests": "def test_basic(): ...",
            "security_tests": "def test_sql_injection(): ...",
            "mutation_operators": ["PSQLI", "RVALID"],
            "source": "SecMutBench"
        },
        ...
    ]
}
```

---

### Step 9: Create Difficulty Splits

```
splits/
├── easy.json    # 45 samples (short, simple vulnerabilities)
├── medium.json  # 72 samples (standard complexity)
└── hard.json    # 32 samples (complex, multi-function, real-world)
```

---

### Dataset Generation Visual Summary

```
                     DATASET GENERATION FLOW

    ┌──────────────────┐   ┌──────────────────┐   ┌──────────────────┐
    │   TEMPLATES      │   │   SECURITYEVAL   │   │   CYBERSECEVAL   │
    │   (Original)     │   │   (HuggingFace)  │   │   (Meta)         │
    │   ~80 samples    │   │   ~40 samples    │   │   ~29 samples    │
    └────────┬─────────┘   └────────┬─────────┘   └────────┬─────────┘
             │                      │                      │
             └──────────────────────┼──────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    TRANSFORMATION LAYER                         │
    │  • Extract CWE from raw data                                   │
    │  • Generate secure/insecure pairs                              │
    │  • Create security tests                                       │
    │  • Assign mutation operators                                   │
    │  • Generate unique IDs                                         │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    VALIDATION LAYER                            │
    │  • Check Python syntax                                         │
    │  • Verify assertions exist                                     │
    │  • Validate entry points                                       │
    │  • Remove duplicates                                           │
    └─────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
    ┌─────────────────────────────────────────────────────────────────┐
    │                    OUTPUT FILES                                 │
    │  • data/dataset.json (149 validated samples)                   │
    │  • data/samples.json (HuggingFace format)                      │
    │  • data/splits/easy.json                                       │
    │  • data/splits/medium.json                                     │
    │  • data/splits/hard.json                                       │
    │  • DATASET_CARD.md, datasheet.md, croissant.json              │
    └─────────────────────────────────────────────────────────────────┘
```

---

### Key Points

| Aspect | Details |
|--------|---------|
| **Sources** | 3: Templates (original), SecurityEval, CyberSecEval |
| **CWEs Covered** | 16 vulnerability types |
| **Difficulty Levels** | Easy, Medium, Hard |
| **Each Sample Has** | secure_code, insecure_code, security_tests, mutation_operators |
| **Validation** | Syntax check, assertion check, entry point verification |
| **Output** | JSON files + documentation (DATASET_CARD.md, datasheet.md) |

---

## Templates Deep Dive

Templates are the **core building blocks** for generating original SecMutBench samples. Each template defines a **vulnerable pattern** and its **secure fix**.

### Template Structure

```python
{
    "prompt": "Task description for the LLM",
    "entry_point": "function_name",
    "insecure": "Vulnerable code implementation",
    "secure": "Fixed/safe code implementation",
    "difficulty": "easy|medium|hard"
}
```

---

### CWE-89: SQL Injection (5 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `get_user_by_id` | f-string in query | Parameterized `?` |
| 2 | `search_users` | f-string LIKE | Parameterized LIKE |
| 3 | `authenticate_user` | String concat login | Parameterized auth |
| 4 | `update_user_email` | f-string UPDATE | Parameterized UPDATE |
| 5 | `delete_user` | f-string DELETE | Parameterized DELETE |

**Example - Template 1:**
```python
# INSECURE (vulnerable)
def get_user_by_id(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"  # ❌ Direct injection
    return db.execute(query)

# SECURE (fixed)
def get_user_by_id(user_id):
    query = "SELECT * FROM users WHERE id = ?"  # ✓ Placeholder
    return db.execute(query, (user_id,))        # ✓ Parameterized
```

**Example - Template 3 (Authentication):**
```python
# INSECURE
def authenticate_user(username, password):
    query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
    return db.execute(query)
    # Attack: username = "admin'--" bypasses password check

# SECURE
def authenticate_user(username, password):
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    return db.execute(query, (username, password))
```

---

### CWE-79: Cross-Site Scripting (4 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `render_greeting` | Unescaped name in HTML | `html.escape()` |
| 2 | `display_comment` | Unescaped comment | `html.escape()` |
| 3 | `create_link` | Unvalidated URL | URL validation + escape |
| 4 | `render_search_results` | Unescaped query + results | Escape all outputs |

**Example - Template 1:**
```python
# INSECURE
def render_greeting(name):
    return f"<h1>Hello, {name}!</h1>"  # ❌ XSS: <script>alert(1)</script>

# SECURE
import html
def render_greeting(name):
    safe_name = html.escape(name)      # ✓ Escapes < > & " '
    return f"<h1>Hello, {safe_name}!</h1>"
```

**Example - Template 3 (Link with URL validation):**
```python
# INSECURE
def create_link(url, text):
    return f'<a href="{url}">{text}</a>'
    # Attack: url = "javascript:alert(1)"

# SECURE
import html
from urllib.parse import urlparse
def create_link(url, text):
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https', ''):
        raise ValueError("Invalid URL scheme")
    return f'<a href="{html.escape(url)}">{html.escape(text)}</a>'
```

---

### CWE-78: Command Injection (3 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `ping_host` | `shell=True` with f-string | Array args, no shell |
| 2 | `list_directory` | `os.popen()` with user input | `os.listdir()` |
| 3 | `get_file_info` | `shell=True` in subprocess | Array args |

**Example - Template 1:**
```python
# INSECURE
import subprocess
def ping_host(hostname):
    return subprocess.run(f"ping -c 1 {hostname}", shell=True, capture_output=True)
    # Attack: hostname = "localhost; rm -rf /"

# SECURE
import subprocess
def ping_host(hostname):
    if not hostname.replace(".", "").replace("-", "").isalnum():
        raise ValueError("Invalid hostname")
    return subprocess.run(["ping", "-c", "1", hostname], capture_output=True)
    # ✓ Array args prevent injection
    # ✓ No shell=True
    # ✓ Input validation
```

**Example - Template 2:**
```python
# INSECURE
import os
def list_directory(path):
    return os.popen(f"ls -la {path}").read()  # ❌ Command injection

# SECURE
import os
def list_directory(path):
    return os.listdir(path)  # ✓ No shell execution
```

---

### CWE-22: Path Traversal (2 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `read_upload` | Direct path concat | `abspath` + prefix check |
| 2 | `serve_static` | Direct path concat | `abspath` + prefix check |

**Example:**
```python
# INSECURE
def read_upload(filename):
    with open(f"./uploads/{filename}") as f:
        return f.read()
    # Attack: filename = "../../../etc/passwd"

# SECURE
import os
def read_upload(filename):
    base = os.path.abspath("./uploads")
    path = os.path.abspath(os.path.join(base, filename))
    if not path.startswith(base):  # ✓ Check path stays in base
        raise ValueError("Path traversal detected")
    with open(path) as f:
        return f.read()
```

---

### CWE-798: Hardcoded Credentials (2 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `connect_db` | Password in code | Environment variables |
| 2 | `call_api` | API key in code | Environment variables |

**Example:**
```python
# INSECURE
def connect_db():
    return Database(
        host="localhost",
        user="admin",
        password="secret123"  # ❌ Hardcoded!
    )

# SECURE
import os
def connect_db():
    return Database(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD")  # ✓ From environment
    )
```

---

### CWE-502: Insecure Deserialization (2 Templates)

| Template | Entry Point | Vulnerability | Fix |
|----------|-------------|---------------|-----|
| 1 | `load_session` | `pickle.loads()` | `json.loads()` |
| 2 | `deserialize_user` | `yaml.load()` | `yaml.safe_load()` |

**Example:**
```python
# INSECURE
import pickle
import base64
def load_session(data):
    return pickle.loads(base64.b64decode(data))  # ❌ Arbitrary code execution

# SECURE
import json
import base64
def load_session(data):
    return json.loads(base64.b64decode(data))  # ✓ Safe parsing
```

---

### CWE-287: Improper Authentication (1 Template)

```python
# INSECURE
def check_admin(request):
    return request.get("is_admin") == "true"  # ❌ Trusts user input!

# SECURE
def check_admin(request):
    session = get_session(request)
    return session.get("role") == "admin" and session.get("authenticated")
    # ✓ Server-side session validation
```

---

### CWE-327: Weak Cryptography (1 Template)

```python
# INSECURE
import hashlib
def hash_password(password):
    return hashlib.md5(password.encode()).hexdigest()  # ❌ MD5 is weak

# SECURE
import hashlib
import secrets
def hash_password(password):
    salt = secrets.token_hex(16)
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${hashed.hex()}"
    # ✓ SHA-256
    # ✓ Salt
    # ✓ Key stretching (100k iterations)
```

---

### CWE-352: CSRF (1 Template)

```python
# INSECURE
def transfer_money(request):
    amount = request.form["amount"]
    to_account = request.form["to"]
    return do_transfer(amount, to_account)  # ❌ No CSRF check

# SECURE
def transfer_money(request):
    if not validate_csrf_token(request):  # ✓ CSRF validation
        raise ValueError("CSRF token invalid")
    amount = request.form["amount"]
    to_account = request.form["to"]
    return do_transfer(amount, to_account)
```

---

### CWE-20: Input Validation (1 Template)

```python
# INSECURE
def process_age(age_str):
    return int(age_str)  # ❌ No bounds checking

# SECURE
def process_age(age_str):
    age = int(age_str)
    if age < 0 or age > 150:  # ✓ Validate range
        raise ValueError("Invalid age")
    return age
```

---

### Hard Difficulty Templates

For complex, real-world scenarios:

**CWE-89_hard: Multi-operation User Management**
```python
# INSECURE - Multiple SQL operations
def manage_users(action, user_data):
    if action == "search":
        query = f"SELECT * FROM users WHERE name LIKE '%{user_data['name']}%'"
    elif action == "update":
        query = f"UPDATE users SET email = '{user_data['email']}' WHERE id = {user_data['id']}"
    elif action == "delete":
        query = f"DELETE FROM users WHERE id IN ({','.join(map(str, user_data['ids']))})"
    return db.execute(query)
```

**CWE-78_hard: System Admin Tool**
```python
# INSECURE - Multiple command types
def admin_tool(command_type, params):
    if command_type == "backup":
        cmd = f"tar -czf {params['dest']} {params['source']}"
        return os.system(cmd)
    elif command_type == "network":
        cmd = f"netstat -an | grep {params['port']}"
        return subprocess.check_output(cmd, shell=True)
```

**CWE-22_hard: File Management API**
```python
# INSECURE - Multiple file operations
def file_api(operation, params):
    base = "./data"
    if operation == "read":
        with open(os.path.join(base, params['path'])) as f:
            return f.read()
    elif operation == "write":
        with open(os.path.join(base, params['path']), 'w') as f:
            f.write(params['content'])
    elif operation == "copy":
        shutil.copy(os.path.join(base, params['src']), os.path.join(base, params['dst']))
```

---

### Template Summary

| CWE | Count | Difficulty Mix |
|-----|-------|----------------|
| CWE-89 (SQL Injection) | 5 + 1 hard | 4 easy, 1 medium, 1 hard |
| CWE-79 (XSS) | 4 | 2 easy, 2 medium |
| CWE-78 (Command Injection) | 3 + 1 hard | 1 easy, 2 medium, 1 hard |
| CWE-22 (Path Traversal) | 2 + 1 hard | 1 easy, 1 medium, 1 hard |
| CWE-798 (Hardcoded Creds) | 2 | 2 easy |
| CWE-502 (Deserialization) | 2 | 1 easy, 1 medium |
| CWE-287 (Auth) | 1 + 1 hard | 1 medium, 1 hard |
| CWE-327 (Weak Crypto) | 1 | 1 medium |
| CWE-352 (CSRF) | 1 | 1 medium |
| CWE-20 (Input Validation) | 1 | 1 easy |

**Total: ~25 base templates** → Expanded to ~80 SecMutBench original samples through variations.

---

## File Structure

```
SecMutBench/
│
├── 📄 README.md                    # Project documentation
├── 📄 DATASET_CARD.md              # HuggingFace dataset card
├── 📄 datasheet.md                 # Datasheet for datasets (Gebru et al.)
├── 📄 croissant.json               # ML Commons Croissant metadata
├── 📄 requirements.txt             # Python dependencies
│
├── 📁 data/                        # === DATASET FILES ===
│   ├── 📄 dataset.json             # Main dataset (149 samples, validated)
│   ├── 📄 samples.json             # HuggingFace-compatible format (180 raw)
│   ├── 📄 contamination_audit.json # N-gram overlap analysis
│   ├── 📄 dataset_fingerprint.json # Dataset integrity fingerprint
│   │
│   ├── 📁 splits/                  # Difficulty-based splits
│   │   ├── easy.json
│   │   ├── medium.json
│   │   └── hard.json
│   │
│   ├── 📁 raw/                     # Original source data
│   │   ├── securityeval_raw.json   # From HuggingFace
│   │   ├── cyberseceval_raw.json   # From Meta
│   │   └── 📁 cwe_cache/           # CWE definitions cache
│   │
│   ├── 📁 backups/                 # Auto-backups before modifications
│   │   ├── dataset_backup_*.json
│   │   └── removed_samples_*.json
│   │
│   ├── 📁 attack_payloads/         # Security test payloads
│   │   └── payloads.json
│   │
│   ├── 📁 codeql_cache/            # Static analysis cache
│   └── 📁 external_references/     # External data sources
│
├── 📁 evaluation/                  # === CORE EVALUATION ENGINE ===
│   ├── 📄 __init__.py
│   ├── 📄 evaluate.py              # Main evaluation orchestrator
│   ├── 📄 mutation_engine.py       # Mutation testing engine
│   ├── 📄 test_runner.py           # Test execution framework
│   ├── 📄 sample_validator.py      # Sample validation logic
│   ├── 📄 llm_judge.py             # LLM-as-judge evaluation
│   ├── 📄 attack_vectors.py        # Attack coverage checking
│   ├── 📄 metrics.py               # Metric calculations
│   ├── 📄 prompts.py               # Prompt templates
│   ├── 📄 version.py               # Version info
│   └── 📁 mocks/                   # Mock objects for testing
│       ├── db_mock.py
│       └── ...
│
├── 📁 operators/                   # === MUTATION OPERATORS ===
│   ├── 📄 __init__.py
│   ├── 📄 operator_registry.py     # Operator registration
│   └── 📄 security_operators.py    # 10 security mutation operators
│
├── 📁 scripts/                     # === DATASET GENERATION SCRIPTS ===
│   ├── 📄 rebuild_dataset.py       # Main dataset builder (templates + transforms)
│   ├── 📄 fix_dataset_issues.py    # Fix validation issues
│   ├── 📄 validate.py              # Dataset validation
│   ├── 📄 transform_datasets.py    # Transform external datasets
│   ├── 📄 generate_samples.py      # Sample generation
│   ├── 📄 generate_dataset.py      # Dataset generation
│   ├── 📄 generate_benchmark.py    # Benchmark generation
│   ├── 📄 template_generator.py    # Template-based generation
│   ├── 📄 contamination_prevention.py  # Prevent data leakage
│   ├── 📄 cwe_research.py          # CWE research utilities
│   ├── 📄 source_handlers.py       # External source handlers
│   ├── 📄 quality_manager.py       # Quality checks
│   ├── 📄 download_sources.py      # Download external data
│   ├── 📄 generate_splits.py       # Create train/test splits
│   ├── 📄 transform.py             # Data transformations
│   └── 📄 verify_samples.py        # Sample verification
│
├── 📁 agentic_pipeline/           # === MULTI-AGENT SYSTEM ===
│   ├── 📄 README.md                # Agent system documentation
│   ├── 📄 MULTI_AGENT_SYSTEM.md    # Architecture docs
│   ├── 📄 IMPROVEMENTS_LOG.md      # Change tracking
│   ├── 📄 run_agents.py            # Agent runner
│   │
│   ├── 📁 agents/                  # Agent implementations
│   │   ├── 📄 orchestrator.py      # Main coordinator (runs experiments)
│   │   ├── 📄 log_improvement.py   # Improvement logger CLI
│   │   │
│   │   └── 📁 sub_agents/          # Specialized agents
│   │       ├── 📄 __init__.py
│   │       ├── 📄 model_runner.py      # Run LLM evaluations
│   │       ├── 📄 judge_runner.py      # Run LLM judges
│   │       ├── 📄 data_generator.py    # Generate samples
│   │       ├── 📄 dataset_improver.py  # Improve dataset
│   │       ├── 📄 result_reviewer.py   # Review results
│   │       ├── 📄 stat_agent.py        # Statistical analysis
│   │       ├── 📄 chart_agent.py       # Generate visualizations
│   │       └── 📄 report_agent.py      # Generate reports
│   │
│   ├── 📁 outputs/                 # Agent outputs
│   │   ├── 📁 data_generation/     # Generated samples (staging)
│   │   │   ├── tier1_samples_*.json
│   │   │   └── tier2_samples_*.json
│   │   │
│   │   └── 📁 experiments/         # Experiment results
│   │       └── 📁 YYYY-MM-DD_HH-MM-SS/  # Timestamped runs
│   │           ├── experiment_metadata.json
│   │           ├── orchestrator_results.json
│   │           ├── review_results.json
│   │           ├── improvement_report.json
│   │           ├── 📁 <model_name>/
│   │           │   ├── summary.json
│   │           │   ├── judge_scores.json
│   │           │   └── 📁 results/
│   │           │       └── <sample_id>.json
│   │           ├── 📁 charts/
│   │           │   ├── mutation_score_heatmap.png
│   │           │   ├── model_comparison.png
│   │           │   └── cwe_distribution.png
│   │           └── 📁 reports/
│   │               ├── EVALUATION_REPORT.md
│   │               └── paper_tables.tex
│   │
│   └── 📁 scripts/                 # Agent helper scripts
│       ├── run_rewrite.py
│       └── test_templates.py
│
├── 📁 baselines/                   # Baseline implementations
│
├── 📁 results/                     # Historical evaluation results
│   ├── baseline_results_*.json
│   └── evaluation_report_*.md
│
├── 📁 docs/                        # === DOCUMENTATION ===
│   ├── 📄 PROJECT_SUMMARY_*.md
│   ├── 📄 EVALUATION_SUMMARY_*.md
│   ├── 📄 DATASET_GENERATION_PLAN_*.md
│   ├── 📄 mock_contracts.md
│   ├── 📄 REFLECTION_*.md
│   └── 📁 cwe_research/            # CWE-specific research
│       ├── CWE-22.md
│       ├── CWE-78.md
│       └── CWE-89.md
│
└── 📁 tests/                       # Test files
```

---

### Key File Descriptions

#### Core Dataset Files

| File | Purpose |
|------|---------|
| `data/dataset.json` | **Main dataset** - 149 validated samples used for evaluation |
| `data/samples.json` | HuggingFace-compatible format |
| `data/splits/*.json` | Difficulty-based splits (easy/medium/hard) |
| `data/raw/*.json` | Original source data from SecurityEval & CyberSecEval |

#### Evaluation Engine

| File | Purpose |
|------|---------|
| `evaluation/evaluate.py` | Main evaluation orchestrator |
| `evaluation/mutation_engine.py` | Creates and applies mutations |
| `evaluation/test_runner.py` | Executes tests against code |
| `evaluation/sample_validator.py` | Validates sample structure |
| `evaluation/llm_judge.py` | LLM-as-judge evaluation |
| `evaluation/attack_vectors.py` | Checks attack pattern coverage |

#### Dataset Generation

| File | Purpose |
|------|---------|
| `scripts/rebuild_dataset.py` | **Main builder** - templates + transforms |
| `scripts/fix_dataset_issues.py` | Fix validation issues |
| `scripts/validate.py` | Validate dataset integrity |
| `scripts/contamination_prevention.py` | Prevent training data leakage |

#### Multi-Agent System

| File | Purpose |
|------|---------|
| `agents/orchestrator.py` | **Main coordinator** - runs full pipeline |
| `agents/sub_agents/model_runner.py` | Runs LLM evaluations (Ollama/API) |
| `agents/sub_agents/judge_runner.py` | Runs LLM judges |
| `agents/sub_agents/data_generator.py` | Generates new samples |
| `agents/sub_agents/result_reviewer.py` | Analyzes results, finds issues |
| `agents/sub_agents/dataset_improver.py` | Implements improvements |

---

### Data Flow

```
scripts/rebuild_dataset.py
         │
         ▼
    ┌─────────┐     ┌─────────────┐     ┌─────────────┐
    │Templates│ +   │SecurityEval │ +   │CyberSecEval │
    └────┬────┘     └──────┬──────┘     └──────┬──────┘
         │                 │                   │
         └────────────────┬┬───────────────────┘
                          ││
                          ▼▼
                   data/dataset.json
                          │
                          ▼
              ┌───────────────────────┐
              │  agents/orchestrator  │
              └───────────┬───────────┘
                          │
         ┌────────────────┼────────────────┐
         ▼                ▼                ▼
   model_runner     judge_runner    result_reviewer
         │                │                │
         └────────────────┼────────────────┘
                          ▼
              outputs/experiments/<timestamp>/
```

---

## References

- [MITRE CWE](https://cwe.mitre.org/) - Common Weakness Enumeration
- [SecurityEval](https://huggingface.co/datasets/s2e-lab/SecurityEval) - HuggingFace Dataset
- [CyberSecEval](https://github.com/meta-llama/PurpleLlama) - Meta's PurpleLlama
- Gebru et al. (2021) - "Datasheets for Datasets"
