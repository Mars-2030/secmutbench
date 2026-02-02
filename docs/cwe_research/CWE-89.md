# CWE-89: SQL Injection

**Source:** https://cwe.mitre.org/data/definitions/89.html

## Description

The product constructs all or part of an SQL command using externally-influenced input from an upstream component, but it does not neutralize or incorrectly neutralizes special elements that could modify the intended SQL command.

## Vulnerable Pattern

```python
# INSECURE - String interpolation
def get_user(username):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    return db.execute(query)
```

## Secure Pattern (Mitigation)

```python
# SECURE - Parameterized query
def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))
```

## Attack Payloads (from OWASP)

### Tautology-based
- `' OR '1'='1`
- `' OR '1'='1'--`
- `' OR 1=1--`
- `admin'--`

### Union-based
- `' UNION SELECT * FROM users--`
- `' UNION SELECT username, password FROM users--`

### Stacked queries
- `'; DROP TABLE users;--`
- `'; DELETE FROM users;--`

### Comment-based
- `admin'/*`
- `*/OR/**/1=1/*`

## Detection in Tests

```python
# Security test should verify:
# 1. Parameterization was used
assert db.last_params is not None, "SQL injection: query not parameterized"

# 2. Payload not in query string (if parameterized, payload is in params)
assert "' OR '" not in db.last_query, "SQL injection: payload in query"
```

## Bandit Detection

- B608: Hardcoded SQL expressions
- B309: SQL injection via format string
