"""
MockCrypto - Mock for cryptographic operations

Used for testing weak cryptography vulnerabilities (CWE-327).
Tracks hash algorithm usage to detect weak algorithms (MD5, SHA1).
"""

from typing import Optional, List


class MockHashObject:
    """Mock hash object returned by hashlib functions."""

    def __init__(self, algorithm: str, data: bytes = b""):
        self.algorithm = algorithm
        self.name = algorithm
        self._data = data
        self._digest_size = {
            "md5": 16,
            "sha1": 20,
            "sha256": 32,
            "sha384": 48,
            "sha512": 64,
            "blake2b": 64,
            "blake2s": 32,
        }.get(algorithm.lower(), 32)

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def update(self, data: bytes) -> None:
        """Update hash with more data."""
        if isinstance(data, str):
            data = data.encode()
        self._data += data

    def digest(self) -> bytes:
        """Return binary digest."""
        # Return a deterministic mock digest based on algorithm
        return b'\x00' * self._digest_size

    def hexdigest(self) -> str:
        """Return hex digest."""
        # Return mock hex string of appropriate length
        return '0' * (self._digest_size * 2)

    def copy(self) -> 'MockHashObject':
        """Return copy of hash object."""
        return MockHashObject(self.algorithm, self._data)


class MockCrypto:
    """
    Mock hashlib module for weak cryptography testing.

    Tracks all hash algorithm usage to allow security tests
    to verify that strong algorithms are used.

    Security Contract (per MITRE CWE-327):
    - WEAK (INSECURE): MD5, SHA1, DES, RC4
    - STRONG (SECURE): SHA-256, SHA-384, SHA-512, bcrypt, scrypt, Argon2

    Usage in tests:
        crypto.reset()
        result = hash_password("secret123")
        assert not crypto.weak_algorithm_used, \\
            f"Weak algorithm {crypto.last_algorithm} used"
    """

    # Weak algorithms per MITRE CWE-327
    # Note: Use exact names or patterns that won't match strong variants
    WEAK_ALGORITHMS = [
        "md5", "md4", "md2",
        "sha1",  # Don't use "sha" alone - it matches sha256!
        "des", "3des", "rc4", "rc2",
        "blowfish",  # When used with small keys
    ]

    # Strong algorithms - checked first for precedence
    STRONG_ALGORITHMS = [
        "sha256", "sha384", "sha512",
        "sha3_256", "sha3_384", "sha3_512",
        "sha3-256", "sha3-384", "sha3-512",
        "blake2b", "blake2s",
        "bcrypt", "scrypt", "argon2",
        "aes", "chacha20",
        "pbkdf2",  # When used with strong hash
    ]

    def __init__(self):
        self.reset()

    def reset(self):
        """Reset all state."""
        self.last_algorithm: Optional[str] = None
        self.algorithms_used: List[str] = []
        self.weak_algorithm_used: bool = False
        self.strong_algorithm_used: bool = False

    def _record_algorithm(self, algorithm: str):
        """Record algorithm usage and check weakness."""
        algo_lower = algorithm.lower()
        self.last_algorithm = algo_lower
        self.algorithms_used.append(algo_lower)

        # Check strong algorithms FIRST (they take precedence)
        # This prevents sha256 from being flagged as weak due to "sha1" partial match
        is_strong = any(strong in algo_lower for strong in self.STRONG_ALGORITHMS)
        if is_strong:
            self.strong_algorithm_used = True
        else:
            # Only check weak if not already identified as strong
            if any(weak in algo_lower for weak in self.WEAK_ALGORITHMS):
                self.weak_algorithm_used = True

    def md5(self, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.md5() - WEAK algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("md5")
        return MockHashObject("md5", data)

    def sha1(self, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.sha1() - WEAK algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("sha1")
        return MockHashObject("sha1", data)

    def sha256(self, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.sha256() - STRONG algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("sha256")
        return MockHashObject("sha256", data)

    def sha384(self, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.sha384() - STRONG algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("sha384")
        return MockHashObject("sha384", data)

    def sha512(self, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.sha512() - STRONG algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("sha512")
        return MockHashObject("sha512", data)

    def blake2b(self, data: bytes = b"", digest_size: int = 64) -> MockHashObject:
        """Mock hashlib.blake2b() - STRONG algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("blake2b")
        return MockHashObject("blake2b", data)

    def blake2s(self, data: bytes = b"", digest_size: int = 32) -> MockHashObject:
        """Mock hashlib.blake2s() - STRONG algorithm."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm("blake2s")
        return MockHashObject("blake2s", data)

    def new(self, name: str, data: bytes = b"") -> MockHashObject:
        """Mock hashlib.new() - general hash creation."""
        if isinstance(data, str):
            data = data.encode()
        self._record_algorithm(name)
        return MockHashObject(name, data)

    def pbkdf2_hmac(
        self,
        hash_name: str,
        password: bytes,
        salt: bytes,
        iterations: int,
        dklen: Optional[int] = None
    ) -> bytes:
        """Mock hashlib.pbkdf2_hmac() - Key derivation function."""
        self._record_algorithm(f"pbkdf2_{hash_name}")
        # Check if using weak base algorithm
        if hash_name.lower() in ["md5", "sha1"]:
            self.weak_algorithm_used = True
        else:
            self.strong_algorithm_used = True
        return b'\x00' * (dklen or 32)

    def scrypt(
        self,
        password: bytes,
        salt: bytes,
        n: int = 16384,
        r: int = 8,
        p: int = 1,
        dklen: int = 64
    ) -> bytes:
        """Mock hashlib.scrypt() - STRONG memory-hard KDF."""
        self._record_algorithm("scrypt")
        return b'\x00' * dklen

    @property
    def algorithms_guaranteed(self) -> set:
        """Return set of guaranteed algorithms."""
        return {"md5", "sha1", "sha224", "sha256", "sha384", "sha512", "blake2b", "blake2s"}

    @property
    def algorithms_available(self) -> set:
        """Return set of available algorithms."""
        return self.algorithms_guaranteed | {"sha3_256", "sha3_384", "sha3_512", "shake_128", "shake_256"}

    def is_weak(self, algorithm: str) -> bool:
        """Check if an algorithm is considered weak."""
        algo_lower = algorithm.lower()
        return any(weak in algo_lower for weak in self.WEAK_ALGORITHMS)

    def is_strong(self, algorithm: str) -> bool:
        """Check if an algorithm is considered strong."""
        algo_lower = algorithm.lower()
        return any(strong in algo_lower for strong in self.STRONG_ALGORITHMS)
