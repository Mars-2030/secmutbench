"""
MockEnvironment - Mock for environment variable operations

Used for testing hardcoded credentials vulnerabilities (CWE-798).
Tracks environment variable access to detect hardcoded secrets.
"""

from typing import Optional, List, Dict, Any


class MockEnvironment:
    """
    Mock environment variable access for hardcoded credentials testing.

    Tracks all environment variable accesses to allow security tests
    to verify that credentials are read from environment, not hardcoded.

    Security Contract:
    - SECURE: Reads sensitive values from environment variables
    - INSECURE: Returns hardcoded values without checking environment

    Usage in tests:
        env.reset()
        env.set("DB_PASSWORD", "unique_test_value_12345")
        result = get_db_password()
        # If secure, result should be our test value
        assert result == "unique_test_value_12345", "Hardcoded password detected"
        # Check that env was actually accessed
        assert "DB_PASSWORD" in env.access_log, "Environment not checked"
    """

    # Common sensitive environment variable names
    SENSITIVE_KEYS = [
        "PASSWORD", "SECRET", "KEY", "TOKEN", "CREDENTIAL",
        "API_KEY", "APIKEY", "AUTH", "PRIVATE",
        "DB_PASSWORD", "DATABASE_PASSWORD",
        "AWS_SECRET", "AZURE_KEY", "GCP_KEY",
    ]

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"last_key", "sensitive_accessed", "access_log"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockEnvironment.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset all state to defaults."""
        self._variables: Dict[str, str] = {
            # Default environment variables for testing
            "PATH": "/usr/bin:/bin",
            "HOME": "/home/testuser",
            "USER": "testuser",
            "SHELL": "/bin/bash",
            # Sensitive defaults that SHOULD be overridden by code reading env
            "DB_PASSWORD": "default_db_password",
            "API_KEY": "default_api_key",
            "SECRET_KEY": "default_secret_key",
            "AUTH_TOKEN": "default_auth_token",
        }
        self.last_key: Optional[str] = None
        self.last_default: Optional[str] = None
        self.access_log: List[str] = []
        self.sensitive_accessed: List[str] = []

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def get(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """
        Get environment variable (like os.environ.get).

        Args:
            key: Environment variable name
            default: Default value if not set

        Returns:
            Variable value or default
        """
        self.last_key = key
        self.last_default = default
        self.access_log.append(key)

        # Track access to sensitive variables
        for sensitive in self.SENSITIVE_KEYS:
            if sensitive.upper() in key.upper():
                self.sensitive_accessed.append(key)
                break

        return self._variables.get(key, default)

    def set(self, key: str, value: str):
        """
        Set environment variable (like os.environ[key] = value).

        Args:
            key: Environment variable name
            value: Value to set
        """
        self._variables[key] = value

    def __getitem__(self, key: str) -> str:
        """Get environment variable (like os.environ[key])."""
        self.access_log.append(key)
        self.last_key = key

        for sensitive in self.SENSITIVE_KEYS:
            if sensitive.upper() in key.upper():
                self.sensitive_accessed.append(key)
                break

        if key not in self._variables:
            raise KeyError(f"Environment variable '{key}' not set")
        return self._variables[key]

    def __setitem__(self, key: str, value: str):
        """Set environment variable (like os.environ[key] = value)."""
        self._variables[key] = value

    def __contains__(self, key: str) -> bool:
        """Check if variable exists (like 'key in os.environ')."""
        return key in self._variables

    def __delitem__(self, key: str):
        """Delete environment variable."""
        if key in self._variables:
            del self._variables[key]

    def keys(self):
        """Return all variable names."""
        return self._variables.keys()

    def values(self):
        """Return all variable values."""
        return self._variables.values()

    def items(self):
        """Return all variable name-value pairs."""
        return self._variables.items()

    def pop(self, key: str, *args) -> Optional[str]:
        """Remove and return variable."""
        return self._variables.pop(key, *args)

    def getenv(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Alias for get() - like os.getenv()."""
        return self.get(key, default)

    def was_accessed(self, key: str) -> bool:
        """Check if a specific key was accessed."""
        return key in self.access_log

    def was_sensitive_accessed(self) -> bool:
        """Check if any sensitive variable was accessed."""
        return len(self.sensitive_accessed) > 0

    def get_access_count(self, key: str) -> int:
        """Get number of times a key was accessed."""
        return self.access_log.count(key)


class MockOS:
    """
    Mock os module with environment support.

    Provides os.environ and os.getenv() with tracking.
    """

    def __init__(self):
        self.environ = MockEnvironment()
        self.path = MockOSPath()
        self.sep = "/"
        self.linesep = "\n"
        self.name = "posix"

    def getenv(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Mock os.getenv()."""
        return self.environ.get(key, default)

    def reset(self):
        """Reset environment state."""
        self.environ.reset()


class MockOSPath:
    """Mock os.path module."""

    def join(self, *args) -> str:
        """Mock os.path.join() — M10 fix: handle absolute paths like real os.path.join."""
        result = ""
        for a in args:
            s = str(a)
            if s.startswith("/"):
                # Absolute path resets — matches real os.path.join behavior
                result = s
            elif result:
                result = result.rstrip("/") + "/" + s
            else:
                result = s
        return result

    def exists(self, path: str) -> bool:
        """Mock os.path.exists() - always returns True for testing."""
        return True

    def isfile(self, path: str) -> bool:
        """Mock os.path.isfile()."""
        return "." in path.split("/")[-1]

    def isdir(self, path: str) -> bool:
        """Mock os.path.isdir()."""
        return not self.isfile(path)

    def dirname(self, path: str) -> str:
        """Mock os.path.dirname()."""
        return "/".join(path.split("/")[:-1])

    def basename(self, path: str) -> str:
        """Mock os.path.basename()."""
        return path.split("/")[-1]

    def normpath(self, path: str) -> str:
        """Mock os.path.normpath()."""
        import os
        return os.path.normpath(path)

    def abspath(self, path: str) -> str:
        """Mock os.path.abspath()."""
        if path.startswith("/"):
            return path
        return f"/current/dir/{path}"
