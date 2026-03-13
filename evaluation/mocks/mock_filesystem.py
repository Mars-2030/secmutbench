"""
Mock File System for SecMutBench

Provides a mock filesystem for testing path traversal vulnerabilities.
"""

import os
from typing import Dict, List, Optional


class MockFileSystem:
    """Mock file system for testing path traversal."""

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"last_path", "base_dir"}

    def __init__(self, base_dir: str = "/var/data"):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.base_dir = base_dir
        self._default_files = {
            "/var/data/file1.txt": "content1",
            "/var/data/file2.txt": "content2",
            "/var/data/test.txt": "test content",
            "/var/data/sub/file.txt": "sub content",
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash",
            "/app/secrets/api_key.txt": "secret_key_12345",
        }
        self.files = dict(self._default_files)
        self.last_path = None

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockFileSystem.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset filesystem to initial state."""
        self.files = dict(self._default_files)
        self.last_path = None

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def write_file(self, path: str, content: str):
        """Write content to a file."""
        normalized = os.path.normpath(path)
        self.files[normalized] = content
        self.last_path = normalized

    def delete_file(self, path: str):
        """Delete a file."""
        normalized = os.path.normpath(path)
        if normalized in self.files:
            del self.files[normalized]

    def read_file(self, path: str) -> Optional[str]:
        """Read a file's content."""
        # Normalize path
        normalized = os.path.normpath(path)
        self.last_path = normalized

        # Check for path traversal (for testing detection)
        if not normalized.startswith(os.path.normpath(self.base_dir)):
            # Path traversal detected - still return for testing purposes
            pass

        return self.files.get(normalized)

    def file_exists(self, path: str) -> bool:
        """Check if file exists."""
        normalized = os.path.normpath(path)
        self.last_path = normalized
        return normalized in self.files

    def list_files(self, directory: str = None) -> List[str]:
        """List files in a directory."""
        if directory is None:
            directory = self.base_dir
        normalized = os.path.normpath(directory)
        return [f for f in self.files.keys() if f.startswith(normalized)]
