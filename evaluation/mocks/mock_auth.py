"""
Mock Authenticator for SecMutBench

Provides a mock authenticator for testing authentication vulnerabilities.
"""

import hashlib
import time
from typing import Dict, Optional


class MockAuthenticator:
    """Mock authenticator for testing authentication vulnerabilities."""

    # Security-relevant attributes for observability tracking
    SECURITY_ATTRS = {"last_username", "last_password", "last_token", "auth_attempts", "failed_attempts"}

    def __init__(self):
        # Initialize security attribute access tracking
        object.__setattr__(self, "_accessed_security_attrs", set())
        self._valid_users = {
            "admin": {"password_hash": "5f4dcc3b5aa765d61d8327deb882cf99", "role": "admin"},
            "user1": {"password_hash": "ee11cbb19052e40b07aac0ca060c23ee", "role": "user"},
        }
        self._valid_sessions = {
            "valid_session_token_123": {"user": "admin", "expires": "2099-12-31"},
        }
        self._valid_tokens = {
            "valid_jwt_token": {"user": "admin", "exp": 9999999999},
        }
        self.last_username = None
        self.last_password = None
        self.last_token = None
        self.auth_attempts = 0
        self.failed_attempts = 0

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockAuthenticator.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset authenticator state."""
        self.last_username = None
        self.last_password = None
        self.last_token = None
        self.auth_attempts = 0
        self.failed_attempts = 0

    def reset_security_tracking(self):
        """Reset security attribute access tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def verify_password(self, username: str, password: str) -> bool:
        """Verify username/password combination."""
        self.last_username = username
        self.last_password = password
        self.auth_attempts += 1

        user = self._valid_users.get(username)
        if not user:
            self.failed_attempts += 1
            return False

        # Simple hash check (in real code would use bcrypt etc.)
        password_hash = hashlib.md5(password.encode()).hexdigest()
        if user["password_hash"] == password_hash:
            return True

        self.failed_attempts += 1
        return False

    def verify_session(self, session_token: str) -> Optional[Dict]:
        """Verify session token."""
        self.last_token = session_token
        return self._valid_sessions.get(session_token)

    def verify_jwt(self, token: str) -> Optional[Dict]:
        """Verify JWT token (mock - just checks against known valid tokens)."""
        self.last_token = token
        return self._valid_tokens.get(token)

    def create_session(self, username: str) -> str:
        """Create a new session for user."""
        token = hashlib.sha256(f"{username}{time.time()}".encode()).hexdigest()
        self._valid_sessions[token] = {"user": username, "expires": "2099-12-31"}
        return token

    def get_user_role(self, username: str) -> Optional[str]:
        """Get user's role."""
        user = self._valid_users.get(username)
        return user["role"] if user else None
