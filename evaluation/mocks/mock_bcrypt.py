"""
MockBcrypt - Mock for bcrypt password hashing

Used for testing weak cryptography (CWE-327).
bcrypt is a STRONG algorithm, so using it indicates secure code.
"""


class MockBcrypt:
    """
    Mock bcrypt module for password hashing testing.

    bcrypt is a strong, secure hashing algorithm designed for passwords.
    Using bcrypt indicates SECURE code for CWE-327.
    """

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset state."""
        self.hash_called = False
        self.check_called = False
        self.last_password = None

    def hashpw(self, password: bytes, salt: bytes) -> bytes:
        """Mock bcrypt.hashpw() - hash a password."""
        self.hash_called = True
        if isinstance(password, str):
            password = password.encode()
        self.last_password = password
        # Return a mock bcrypt hash (starts with $2b$)
        return b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.Q5Y5n5n5n5n5n5"

    def gensalt(self, rounds: int = 12) -> bytes:
        """Mock bcrypt.gensalt() - generate a salt."""
        return b"$2b$12$LQv3c1yqBWVHxkd0LHAkCO"

    def checkpw(self, password: bytes, hashed: bytes) -> bool:
        """Mock bcrypt.checkpw() - verify a password against hash."""
        self.check_called = True
        if isinstance(password, str):
            password = password.encode()
        # For testing, accept if hash looks like bcrypt
        if hashed and hashed.startswith(b"$2"):
            return True
        return False


# Create singleton instance
_mock_bcrypt = MockBcrypt()

# Module-level functions
def hashpw(*args, **kwargs):
    return _mock_bcrypt.hashpw(*args, **kwargs)

def gensalt(*args, **kwargs):
    return _mock_bcrypt.gensalt(*args, **kwargs)

def checkpw(*args, **kwargs):
    return _mock_bcrypt.checkpw(*args, **kwargs)

def reset():
    _mock_bcrypt.reset()
