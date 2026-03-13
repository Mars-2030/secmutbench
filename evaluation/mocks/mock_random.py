"""
Mock Random Module for CWE-338 (Weak PRNG) Testing

Tracks whether code uses:
- random module (INSECURE for cryptographic purposes)
- secrets module (SECURE for cryptographic purposes)
- os.urandom (SECURE for cryptographic purposes)

Usage in tests:
    # Reset before test
    mock_random.reset()

    # Run code
    result = function_under_test()

    # Check usage
    assert not mock_random.weak_prng_used, "Weak PRNG used for security-sensitive operation"
    assert mock_random.secure_prng_used, "Should use secrets or os.urandom"
"""

import os as _real_os

# Import REAL modules BEFORE sys.modules patching to avoid recursion
import random as _real_random
import secrets as _real_secrets


class MockRandom:
    """Mock random module that tracks insecure vs secure PRNG usage."""

    SECURITY_ATTRS = {"weak_prng_used", "secure_prng_used"}

    def __init__(self):
        object.__setattr__(self, "_accessed_security_attrs", set())
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockRandom.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset tracking state."""
        self.weak_prng_used = False
        self.secure_prng_used = False
        self.call_log = []
        self._seed_value = None

    def reset_security_tracking(self):
        """Reset security attribute tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    # Weak PRNG methods (INSECURE)
    def random(self):
        """Track use of random.random() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append("random.random()")
        return _real_random.random()

    def randint(self, a, b):
        """Track use of random.randint() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append(f"random.randint({a}, {b})")
        return _real_random.randint(a, b)

    def randrange(self, *args):
        """Track use of random.randrange() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append(f"random.randrange({args})")
        return _real_random.randrange(*args)

    def choice(self, seq):
        """Track use of random.choice() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append("random.choice()")
        return _real_random.choice(seq)

    def choices(self, population, *args, **kwargs):
        """Track use of random.choices() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append("random.choices()")
        return _real_random.choices(population, *args, **kwargs)

    def shuffle(self, x):
        """Track use of random.shuffle() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append("random.shuffle()")
        return _real_random.shuffle(x)

    def sample(self, population, k):
        """Track use of random.sample() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append(f"random.sample(k={k})")
        return _real_random.sample(population, k)

    def seed(self, a=None):
        """Track use of random.seed() - indicates weak PRNG."""
        self._seed_value = a
        self.weak_prng_used = True
        self.call_log.append(f"random.seed({a})")
        return _real_random.seed(a)

    def getrandbits(self, k):
        """Track use of random.getrandbits() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append(f"random.getrandbits({k})")
        return _real_random.getrandbits(k)

    def uniform(self, a, b):
        """Track use of random.uniform() - INSECURE."""
        self.weak_prng_used = True
        self.call_log.append(f"random.uniform({a}, {b})")
        return _real_random.uniform(a, b)


class MockSecrets:
    """Mock secrets module that tracks secure PRNG usage."""

    SECURITY_ATTRS = {"call_log"}

    def __init__(self, mock_random_ref=None):
        object.__setattr__(self, "_accessed_security_attrs", set())
        self._mock_random = mock_random_ref
        self.reset()

    def __getattribute__(self, name):
        """Track access to security-relevant attributes."""
        value = object.__getattribute__(self, name)
        if name in MockSecrets.SECURITY_ATTRS:
            accessed = object.__getattribute__(self, "_accessed_security_attrs")
            accessed.add(name)
        return value

    def reset(self):
        """Reset tracking state."""
        self.call_log = []

    def reset_security_tracking(self):
        """Reset security attribute tracking."""
        object.__setattr__(self, "_accessed_security_attrs", set())

    def _mark_secure(self, method_name):
        """Mark that secure PRNG was used."""
        self.call_log.append(f"secrets.{method_name}")
        if self._mock_random:
            self._mock_random.secure_prng_used = True

    def token_bytes(self, nbytes=None):
        """Track use of secrets.token_bytes() - SECURE."""
        self._mark_secure("token_bytes()")
        return _real_secrets.token_bytes(nbytes)

    def token_hex(self, nbytes=None):
        """Track use of secrets.token_hex() - SECURE."""
        self._mark_secure("token_hex()")
        return _real_secrets.token_hex(nbytes)

    def token_urlsafe(self, nbytes=None):
        """Track use of secrets.token_urlsafe() - SECURE."""
        self._mark_secure("token_urlsafe()")
        return _real_secrets.token_urlsafe(nbytes)

    def randbelow(self, n):
        """Track use of secrets.randbelow() - SECURE."""
        self._mark_secure("randbelow()")
        return _real_secrets.randbelow(n)

    def choice(self, seq):
        """Track use of secrets.choice() - SECURE."""
        self._mark_secure("choice()")
        return _real_secrets.choice(seq)

    def randbits(self, k):
        """Track use of secrets.randbits() - SECURE."""
        self._mark_secure("randbits()")
        return _real_secrets.randbits(k)


# Create shared instances
_mock_random = MockRandom()
_mock_secrets = MockSecrets(_mock_random)
