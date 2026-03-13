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
        """Mock bcrypt.checkpw() - verify a password against hash.

        For security tests with fake credentials, returns False (credential rejected).
        Only returns True for known test passwords that match their hashes.

        This ensures:
        - Secure code with fake credentials → returns False → test PASSES
        - RMAUTH mutant (no bcrypt check) → bypasses this → test FAILS
        """
        self.check_called = True
        if isinstance(password, str):
            password = password.encode()
        if isinstance(hashed, str):
            hashed = hashed.encode()

        # Known test password-hash pairs (matching MockDatabase users)
        # These simulate successful authentication for functional tests
        known_pairs = {
            b"test_password_alice": b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_alice_hash",
            b"test_password_bob": b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_bob_hash",
            b"test_password_charlie": b"$2b$12$LQv3c1yqBWVHxkd0LHAkCOtest_charlie_hash",
            b"correct_password": b"$2b$12$LQv3c1yqBWVHxkd0LHAkCO",  # Generic test password
        }

        # Check if this is a known valid password-hash pair
        if password in known_pairs:
            # Return True only if the hash also matches
            if hashed and hashed.startswith(known_pairs[password][:30]):
                return True

        # For any fake/unknown password, return False (secure rejection)
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
