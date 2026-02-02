# Mock Object Contracts

This document defines the API contracts for all mock objects used in SecMutBench test execution.

## Overview

Mock objects simulate external dependencies during test execution. Templates and tests MUST use these mock APIs, not real libraries.

---

## MockDatabase

**Purpose:** Simulate SQL database operations for SQL injection testing (CWE-89).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Clear all tables and state |
| `add_row()` | `add_row(table: str, row: dict)` | `None` | Add row to table |
| `execute()` | `execute(query: str, params: tuple = None)` | `List[Dict]` | Execute SQL query |
| `get_row()` | `get_row(table: str, col: str, val: Any)` | `Dict or None` | Get single row |
| `get_table()` | `get_table(table: str)` | `List[Dict]` | Get all rows from table |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_query` | `str` | Last executed SQL query string |
| `last_params` | `tuple or None` | Parameters from last query (None if not parameterized) |
| `query_count` | `int` | Number of queries executed |

### Behavior Contract

```python
# SECURE code uses parameterized queries:
db.execute("SELECT * FROM users WHERE name = ?", (username,))
# Result: db.last_params = (username,)  # NOT None

# INSECURE code uses string interpolation:
db.execute(f"SELECT * FROM users WHERE name = '{username}'")
# Result: db.last_params = None

# Security tests should check:
assert db.last_params is not None, "Query not parameterized - SQL injection risk"
```

### Default Tables

```python
{
    "users": [
        {"id": 1, "name": "alice", "email": "alice@example.com"},
        {"id": 2, "name": "bob", "email": "bob@example.com"},
        {"id": 3, "name": "charlie", "email": "charlie@example.com"},
    ]
}
```

### Usage Example

```python
# In functional test:
db.reset()
db.add_row("users", {"id": 99, "name": "testuser"})
result = get_user("testuser")
assert len(result) == 1

# In security test:
db.reset()
db.add_row("users", {"id": 1, "name": "alice"})
db.add_row("users", {"id": 2, "name": "bob"})
result = get_user("' OR '1'='1")
# Check parameterization was used
assert db.last_params is not None, "SQL injection: query not parameterized"
# If parameterized, injection payload is treated as literal - no match
assert len(result) == 0, f"SQL injection: got {len(result)} rows instead of 0"
```

---

## MockFileSystem

**Purpose:** Simulate file operations for path traversal testing (CWE-22).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset to initial state |
| `read_file()` | `read_file(path: str)` | `str or None` | Read file contents |
| `write_file()` | `write_file(path: str, content: str)` | `None` | Write to file |
| `file_exists()` | `file_exists(path: str)` | `bool` | Check if file exists |
| `list_files()` | `list_files(directory: str)` | `List[str]` | List files in directory |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_path` | `str` | Last accessed file path |
| `base_dir` | `str` | Allowed base directory (default: `/var/data`) |

### Behavior Contract

```python
# SECURE code validates path stays within base_dir:
def read_config(filename):
    path = os.path.join(fs.base_dir, filename)
    normalized = os.path.normpath(path)
    if not normalized.startswith(fs.base_dir):
        raise ValueError("Path traversal detected")
    return fs.read_file(normalized)

# INSECURE code doesn't validate:
def read_config(filename):
    return fs.read_file(os.path.join(fs.base_dir, filename))

# Security tests should check:
result = read_config("../../../etc/passwd")
assert fs.last_path.startswith(fs.base_dir), "Path traversal: accessed outside base_dir"
```

### Default Files

```python
{
    "/var/data/file1.txt": "content1",
    "/var/data/test.txt": "test content",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",  # Sensitive!
}
```

### Usage Example

```python
# In functional test:
fs.reset()
fs.write_file("/var/data/config.txt", "config_value")
result = read_config("config.txt")
assert result == "config_value"

# In security test:
fs.reset()
result = read_config("../../../etc/passwd")
# Secure code should reject or return None
assert result is None or "root:" not in str(result)
# Check path didn't escape base_dir
assert fs.last_path.startswith("/var/data")
```

---

## MockSubprocess

**Purpose:** Simulate command execution for command injection testing (CWE-78).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset state |
| `run()` | `run(command, shell=False, **kwargs)` | `MockCompletedProcess` | Execute command |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_command` | `str or List[str]` | Last executed command |
| `last_shell` | `bool` | Whether shell=True was used |
| `commands_executed` | `List` | History of all commands |

### Behavior Contract

```python
# SECURE code uses shell=False with list:
subprocess.run(["ping", "-c", "1", hostname], shell=False)
# Result: last_shell = False, no injection possible

# INSECURE code uses shell=True with string:
subprocess.run(f"ping -c 1 {hostname}", shell=True)
# Result: last_shell = True, injection possible

# Security tests should check:
ping_host("localhost; cat /etc/passwd")
assert subprocess.last_shell == False, "Command injection: shell=True used"
assert ";" not in str(subprocess.last_command), "Command injection: payload in command"
```

### Usage Example

```python
# In functional test:
subprocess.reset()
result = ping_host("localhost")
assert result.returncode == 0

# In security test:
subprocess.reset()
result = ping_host("localhost; rm -rf /")
# Check shell=False was used (secure)
assert subprocess.last_shell == False, "Insecure: shell=True"
# Check injection payload not in command
assert ";" not in " ".join(subprocess.last_command)
```

---

## MockEnvironment

**Purpose:** Simulate environment variables for hardcoded credentials testing (CWE-798).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset to defaults |
| `get()` | `get(key: str, default: str = None)` | `str or None` | Get env variable |
| `set()` | `set(key: str, value: str)` | `None` | Set env variable |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_key` | `str` | Last accessed key |
| `access_log` | `List[str]` | All keys accessed |

### Behavior Contract

```python
# SECURE code reads from environment:
def get_db_password():
    return env.get("DB_PASSWORD")

# INSECURE code has hardcoded password:
def get_db_password():
    return "hardcoded_secret_123"

# Security tests should check:
# Set up environment with test value
env.set("DB_PASSWORD", "test_password_from_env")
result = get_db_password()
# Secure code returns env value
assert result == "test_password_from_env", "Hardcoded credentials detected"
```

### Usage Example

```python
# In functional test:
env.reset()
env.set("API_KEY", "test_key")
result = get_api_key()
assert result == "test_key"

# In security test:
env.reset()
env.set("DB_PASSWORD", "unique_test_value_12345")
result = get_db_password()
# If result != our test value, password is hardcoded
assert result == "unique_test_value_12345", f"Hardcoded password: {result}"
```

---

## MockHTTPClient

**Purpose:** Simulate HTTP requests for SSRF testing (CWE-918).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset state |
| `get()` | `get(url: str, **kwargs)` | `MockHTTPResponse` | HTTP GET |
| `post()` | `post(url: str, **kwargs)` | `MockHTTPResponse` | HTTP POST |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_url` | `str` | Last requested URL |
| `last_method` | `str` | Last HTTP method |
| `ssrf_attempted` | `bool` | True if internal URL was requested |

### Internal Hosts (SSRF targets)

```python
["localhost", "127.0.0.1", "192.168.", "10.", "172.16.", "169.254."]
```

### Behavior Contract

```python
# SECURE code validates URL:
def fetch_url(url):
    if is_internal_url(url):
        raise ValueError("Internal URLs not allowed")
    return requests.get(url)

# INSECURE code doesn't validate:
def fetch_url(url):
    return requests.get(url)

# Security tests should check:
fetch_url("http://169.254.169.254/latest/meta-data/")
assert not requests.ssrf_attempted, "SSRF: internal URL was accessed"
```

---

## MockXMLParser

**Purpose:** Simulate XML parsing for XXE testing (CWE-611).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset state |
| `parse_safe()` | `parse_safe(xml: str)` | `Dict` | Parse with XXE protection |
| `parse_unsafe()` | `parse_unsafe(xml: str)` | `Dict` | Parse without protection |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_xml` | `str` | Last parsed XML |
| `external_entities_resolved` | `bool` | True if external entities processed |
| `dtd_processed` | `bool` | True if DTD was processed |

### Behavior Contract

```python
# SECURE code uses safe parser:
def parse_xml(xml_string):
    return xml_parser.parse_safe(xml_string)

# INSECURE code uses unsafe parser:
def parse_xml(xml_string):
    return xml_parser.parse_unsafe(xml_string)

# Security tests should check:
xxe_payload = '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'
result = parse_xml(xxe_payload)
assert not xml_parser.external_entities_resolved, "XXE: external entities resolved"
```

---

## MockAuthenticator

**Purpose:** Simulate authentication for auth bypass testing (CWE-287).

### Methods

| Method | Signature | Returns | Description |
|--------|-----------|---------|-------------|
| `reset()` | `reset()` | `None` | Reset state |
| `verify_password()` | `verify_password(user: str, pwd: str)` | `bool` | Verify credentials |
| `verify_session()` | `verify_session(token: str)` | `Dict or None` | Verify session |
| `create_session()` | `create_session(user: str)` | `str` | Create session token |

### State Tracking

| Property | Type | Description |
|----------|------|-------------|
| `last_username` | `str` | Last checked username |
| `last_password` | `str` | Last checked password |
| `auth_attempts` | `int` | Number of auth attempts |
| `failed_attempts` | `int` | Number of failed attempts |

### Valid Test Credentials

```python
{
    "admin": {"password": "password"},  # MD5: 5f4dcc3b5aa765d61d8327deb882cf99
    "user1": {"password": "user"},      # MD5: ee11cbb19052e40b07aac0ca060c23ee
}
```

---

## Global Mock Injection

All mocks are injected into the test execution environment:

```python
globals_dict = {
    "db": MockDatabase(),
    "fs": MockFileSystem(),
    "subprocess": MockSubprocess(),
    "env": MockEnvironment(),
    "requests": MockHTTPClient(),
    "xml_parser": MockXMLParser(),
    "auth": MockAuthenticator(),
}
```

**Important:** Templates MUST use these names. Do NOT import real modules.
