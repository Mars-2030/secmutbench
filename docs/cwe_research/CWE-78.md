# CWE-78: OS Command Injection

**Source:** https://cwe.mitre.org/data/definitions/78.html

## Description

The product constructs OS commands using externally-influenced input without properly neutralizing special elements that could modify the intended command.

## Vulnerable Pattern

```python
# INSECURE - shell=True with string interpolation
def ping_host(hostname):
    command = f"ping -c 1 {hostname}"
    result = subprocess.run(command, shell=True, capture_output=True, text=True)
    return result.stdout
```

## Secure Pattern (Mitigation)

```python
# SECURE - shell=False with argument list
def ping_host(hostname):
    # Validate hostname first
    if not re.match(r'^[a-zA-Z0-9.-]+$', hostname):
        raise ValueError("Invalid hostname")
    result = subprocess.run(["ping", "-c", "1", hostname], capture_output=True, text=True)
    return result.stdout
```

## Attack Payloads (from OWASP)

### Command chaining
- `; cat /etc/passwd`
- `&& cat /etc/passwd`
- `|| cat /etc/passwd`
- `| cat /etc/passwd`

### Command substitution
- `` `cat /etc/passwd` ``
- `$(cat /etc/passwd)`

### Newline injection
- `%0acat /etc/passwd`
- `\ncat /etc/passwd`

## Detection in Tests

```python
# Security test should verify:
# 1. shell=False was used
assert subprocess.last_shell == False, "Command injection: shell=True used"

# 2. Command is list, not string with injection
assert ";" not in str(subprocess.last_command), "Command injection: separator in command"
```

## Bandit Detection

- B602: subprocess_popen_with_shell_equals_true
- B603: subprocess_without_shell_equals_true
- B604: any_other_function_with_shell_equals_true
- B605: start_process_with_a_shell
- B607: start_process_with_partial_path
