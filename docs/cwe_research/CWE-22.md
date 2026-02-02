# CWE-22: Path Traversal

**Source:** https://cwe.mitre.org/data/definitions/22.html

## Description

The product constructs pathnames using external input intended for restricted directories but fails to neutralize special elements like ".." and "/" that allow resolution outside the restricted area.

## Vulnerable Pattern

```python
# INSECURE - No path validation
def read_file(filename):
    path = os.path.join("/var/data", filename)
    with open(path, 'r') as f:
        return f.read()
```

## Secure Pattern (Mitigation)

```python
# SECURE - Path validation with normpath and startswith
def read_file(filename):
    base_dir = "/var/data"
    # Normalize to resolve ../ sequences
    path = os.path.normpath(os.path.join(base_dir, filename))
    # Verify path is still within base directory
    if not path.startswith(os.path.normpath(base_dir) + os.sep):
        raise ValueError("Path traversal detected")
    return fs.read_file(path)
```

## Attack Payloads (from OWASP)

### Relative path traversal
- `../../../etc/passwd`
- `..\..\..\..\windows\system32\config\sam`
- `....//....//....//etc/passwd`

### Absolute path
- `/etc/passwd`
- `C:\Windows\System32\config\SAM`

### URL encoding
- `%2e%2e%2f` (../)
- `%2e%2e/`
- `..%2f`

### Double encoding
- `%252e%252e%252f`

### Null byte (legacy)
- `../../../etc/passwd%00.jpg`

## Detection in Tests

```python
# Security test should verify:
# 1. Accessed path stays within base_dir
assert fs.last_path.startswith("/var/data"), "Path traversal: escaped base directory"

# 2. Sensitive files not accessed
assert "/etc/passwd" not in fs.last_path, "Path traversal: accessed sensitive file"
```

## Bandit Detection

- B310: urllib_urlopen (partial coverage)
