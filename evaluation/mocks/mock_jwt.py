"""
MockJWT - Mock for JWT operations

Used for testing authentication vulnerabilities (CWE-287).
"""


class InvalidTokenError(Exception):
    """Mock JWT invalid token error."""
    pass


class ExpiredSignatureError(InvalidTokenError):
    """Mock JWT expired signature error."""
    pass


class DecodeError(InvalidTokenError):
    """Mock JWT decode error."""
    pass


class MockJWT:
    """
    Mock jwt module for authentication testing.

    Security Contract:
    - SECURE: Validates signature with secret, checks expiration
    - INSECURE: No signature verification, or accepts any token

    Usage in tests:
        jwt.reset()
        result = verify_token("invalid_token")
        # Should raise InvalidTokenError for invalid tokens
    """

    # Export exception classes
    InvalidTokenError = InvalidTokenError
    ExpiredSignatureError = ExpiredSignatureError
    DecodeError = DecodeError

    def __init__(self):
        self.reset()
        self._valid_tokens = {
            # Pre-configured valid tokens for testing
            "valid_token_123": {"user": "admin", "exp": 9999999999},
        }

    def reset(self):
        """Reset state."""
        self.last_token = None
        self.last_secret = None
        self.last_algorithms = None
        self.decode_called = False
        self.verify_signature = True

    def encode(self, payload: dict, secret: str, algorithm: str = "HS256") -> str:
        """Mock jwt.encode() - create a token."""
        # Return a mock token
        return f"mock_jwt_token_{hash(str(payload)) % 10000}"

    def decode(
        self,
        token: str,
        key: str = None,
        algorithms: list = None,
        options: dict = None,
        **kwargs
    ) -> dict:
        """
        Mock jwt.decode() - decode and verify a token.

        Raises InvalidTokenError for invalid tokens (secure behavior).
        """
        self.decode_called = True
        self.last_token = token
        self.last_secret = key
        self.last_algorithms = algorithms

        # Check options for insecure configurations
        if options:
            if options.get("verify_signature") == False:
                self.verify_signature = False
            if options.get("verify_exp") == False:
                pass  # Insecure but might still work

        # Check if token is in our valid set
        if token in self._valid_tokens:
            return self._valid_tokens[token]

        # Check for obviously invalid tokens
        if not token or len(token) < 10:
            raise InvalidTokenError("Invalid token format")

        # Check for common invalid patterns
        if token.startswith("invalid") or token == "fake_token":
            raise InvalidTokenError("Invalid token")

        # For testing purposes, accept tokens that look like JWTs (have 2 dots)
        if token.count(".") == 2:
            # Looks like a JWT structure, decode it
            return {"user": "unknown", "decoded": True}

        # Default: reject as invalid
        raise InvalidTokenError(f"Could not decode token: {token[:20]}...")

    def get_unverified_header(self, token: str) -> dict:
        """Mock jwt.get_unverified_header()."""
        return {"alg": "HS256", "typ": "JWT"}


# Create singleton instance
_mock_jwt = MockJWT()

# Module-level functions that delegate to the singleton
def encode(*args, **kwargs):
    return _mock_jwt.encode(*args, **kwargs)

def decode(*args, **kwargs):
    return _mock_jwt.decode(*args, **kwargs)

def get_unverified_header(*args, **kwargs):
    return _mock_jwt.get_unverified_header(*args, **kwargs)

def reset():
    _mock_jwt.reset()
