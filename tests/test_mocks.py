"""
Unit tests for SecMutBench mock objects.

Tests verify that mocks:
1. Track security-relevant attributes correctly
2. Detect injection/vulnerability patterns
3. Simulate realistic behavior
"""

import pytest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.mocks import (
    MockDatabase,
    MockSubprocess,
    MockCompletedProcess,
    MockFileSystem,
    MockCrypto,
    MockHTTPClient,
    MockXMLParser,
    MockAuthenticator,
    MockEnvironment,
    MockPickle,
    MockYAML,
    MockEval,
    MockRandom,
    MockSecrets,
)


class TestMockDatabase:
    """Tests for MockDatabase (CWE-89: SQL Injection)."""

    def test_parameterized_query(self):
        """Parameterized queries should be safe."""
        db = MockDatabase()
        db.execute("SELECT * FROM users WHERE id = ?", (1,))
        assert db.last_query == "SELECT * FROM users WHERE id = ?"
        assert db.last_params == (1,)

    def test_sql_injection_detection(self):
        """SQL injection patterns should be detected."""
        db = MockDatabase()
        # Injection attempt without parameterization
        db.execute("SELECT * FROM users WHERE id = '1' OR '1'='1'")
        # Should return all users (simulating injection success)
        results = db.fetchall()
        assert len(results) > 1  # Injection returned multiple rows

    def test_query_count_tracking(self):
        """Query count should be tracked."""
        db = MockDatabase()
        assert db.query_count == 0
        db.execute("SELECT * FROM users", ())
        assert db.query_count == 1
        db.execute("SELECT * FROM users", ())
        assert db.query_count == 2

    def test_security_attribute_tracking(self):
        """Security attribute access should be tracked."""
        db = MockDatabase()
        db.reset_security_tracking()

        # Access security attributes
        _ = db.last_query
        _ = db.last_params

        assert "last_query" in db._accessed_security_attrs
        assert "last_params" in db._accessed_security_attrs

    def test_reset_clears_state(self):
        """Reset should clear all state."""
        db = MockDatabase()
        db.execute("SELECT * FROM users", ())
        db.reset()
        assert db.last_query is None
        assert db.query_count == 0

    def test_table_operations(self):
        """Table CRUD operations should work."""
        db = MockDatabase()
        db.add_row("test_table", {"id": 1, "name": "test"})
        assert db.get_row("test_table", "id", 1) == {"id": 1, "name": "test"}

        db.update_row("test_table", "id", 1, {"name": "updated"})
        assert db.get_row("test_table", "id", 1)["name"] == "updated"

        db.delete_row("test_table", "id", 1)
        assert db.get_row("test_table", "id", 1) is None


class TestMockSubprocess:
    """Tests for MockSubprocess (CWE-78: Command Injection)."""

    def test_safe_command_list(self):
        """shell=False with list should be safe."""
        sp = MockSubprocess()
        sp.run(["ping", "-c", "1", "localhost"], shell=False)
        assert sp.last_shell is False
        assert sp.injection_detected is False

    def test_unsafe_shell_true(self):
        """shell=True with string should be flagged."""
        sp = MockSubprocess()
        sp.run("ping localhost", shell=True)
        assert sp.last_shell is True

    def test_injection_detection(self):
        """Injection patterns should be detected."""
        sp = MockSubprocess()
        sp.run("ping localhost; cat /etc/passwd", shell=True)
        assert sp.injection_detected is True
        assert sp.dangerous_command_detected is True

    def test_security_attribute_tracking(self):
        """Security attribute access should be tracked."""
        sp = MockSubprocess()
        sp.reset_security_tracking()

        sp.run(["echo", "test"], shell=False)
        _ = sp.last_shell
        _ = sp.injection_detected

        assert "last_shell" in sp._accessed_security_attrs
        assert "injection_detected" in sp._accessed_security_attrs

    def test_command_history(self):
        """Command execution history should be recorded."""
        sp = MockSubprocess()
        sp.run(["cmd1"], shell=False)
        sp.run("cmd2", shell=True)

        assert len(sp.commands_executed) == 2
        assert sp.commands_executed[0]["shell"] is False
        assert sp.commands_executed[1]["shell"] is True

    def test_popen_mock(self):
        """Popen should return mock object."""
        sp = MockSubprocess()
        proc = sp.Popen(["echo", "test"])
        stdout, stderr = proc.communicate()
        assert proc.returncode == 0

    def test_check_output(self):
        """check_output should return stdout."""
        sp = MockSubprocess()
        output = sp.check_output(["echo", "hello"])
        assert isinstance(output, str)


class TestMockCrypto:
    """Tests for MockCrypto (CWE-327: Weak Cryptography)."""

    def test_weak_algorithm_detection(self):
        """Weak algorithms (MD5, SHA1) should be flagged."""
        crypto = MockCrypto()
        crypto.md5(b"test")
        assert crypto.weak_algorithm_used is True
        assert "md5" in crypto.algorithms_used

    def test_strong_algorithm_detection(self):
        """Strong algorithms (SHA256+) should be flagged as safe."""
        crypto = MockCrypto()
        crypto.sha256(b"test")
        assert crypto.strong_algorithm_used is True
        assert "sha256" in crypto.algorithms_used

    def test_new_method(self):
        """new() method should work like hashlib.new()."""
        crypto = MockCrypto()
        h = crypto.new("sha256")
        h.update(b"test")
        digest = h.hexdigest()
        assert isinstance(digest, str)
        assert len(digest) > 0

    def test_security_attribute_tracking(self):
        """Security attribute access should be tracked."""
        crypto = MockCrypto()
        crypto.reset_security_tracking()

        crypto.md5(b"test")
        _ = crypto.weak_algorithm_used
        _ = crypto.last_algorithm

        assert "weak_algorithm_used" in crypto._accessed_security_attrs
        assert "last_algorithm" in crypto._accessed_security_attrs


class TestMockFileSystem:
    """Tests for MockFileSystem (CWE-22: Path Traversal)."""

    def test_normal_path_access(self):
        """Normal path access should work."""
        fs = MockFileSystem(base_dir="/app/uploads")
        content = fs.read_file("/app/uploads/file.txt")
        assert fs.last_path == "/app/uploads/file.txt"

    def test_path_traversal_detection(self):
        """Path traversal attempts should track the path."""
        fs = MockFileSystem(base_dir="/app/uploads")
        # Attempt traversal - filesystem tracks the path attempted
        fs.read_file("/app/uploads/../../../etc/passwd")
        # last_path tracks what was accessed
        assert fs.last_path is not None
        assert ".." in fs.last_path or "etc/passwd" in fs.last_path

    def test_write_file(self):
        """Write file should track the path."""
        fs = MockFileSystem()
        fs.write_file("/app/data.txt", "content")
        assert fs.last_path == "/app/data.txt"


class TestMockHTTPClient:
    """Tests for MockHTTPClient (CWE-918: SSRF)."""

    def test_normal_request(self):
        """Normal requests should work."""
        http = MockHTTPClient()
        response = http.get("https://api.example.com/data")
        assert http.last_url == "https://api.example.com/data"
        assert response.status_code == 200

    def test_ssrf_detection(self):
        """SSRF attempts should be detected."""
        http = MockHTTPClient()
        # Internal IP address
        http.get("http://169.254.169.254/metadata")
        assert http.ssrf_attempted is True

    def test_localhost_ssrf(self):
        """Localhost requests should be flagged as SSRF."""
        http = MockHTTPClient()
        http.get("http://localhost:8080/admin")
        assert http.ssrf_attempted is True


class TestMockEnvironment:
    """Tests for MockEnvironment (CWE-798: Hardcoded Credentials)."""

    def test_get_env_variable(self):
        """Environment variables should be retrievable."""
        env = MockEnvironment()
        env["API_KEY"] = "test_key"
        assert env.get("API_KEY") == "test_key"

    def test_sensitive_access_tracking(self):
        """Access to sensitive variables should be tracked."""
        env = MockEnvironment()
        env["DATABASE_PASSWORD"] = "secret123"
        _ = env.get("DATABASE_PASSWORD")
        # sensitive_accessed is a list of accessed sensitive keys
        assert len(env.sensitive_accessed) > 0
        assert "DATABASE_PASSWORD" in env.sensitive_accessed


class TestMockPickleYAML:
    """Tests for MockPickle/MockYAML (CWE-502: Insecure Deserialization)."""

    def test_pickle_loads_tracking(self):
        """pickle.loads should be tracked."""
        pkl = MockPickle()
        pkl.loads(b"test")
        assert pkl.unsafe_load_called is True
        assert pkl.load_count == 1

    def test_yaml_unsafe_load(self):
        """yaml.load without safe loader should be flagged."""
        yml = MockYAML()
        yml.load("key: value")
        assert yml.unsafe_load_called is True

    def test_yaml_safe_load(self):
        """yaml.safe_load should be flagged as safe."""
        yml = MockYAML()
        yml.safe_load("key: value")
        assert yml.safe_loader_used is True


class TestMockEval:
    """Tests for MockEval (CWE-94: Code Injection)."""

    def test_eval_tracking(self):
        """eval() calls should be tracked."""
        ev = MockEval()
        ev.eval("1 + 1")
        assert ev.unsafe_eval_called is True
        assert ev.last_code == "1 + 1"

    def test_exec_tracking(self):
        """exec() calls should be tracked."""
        ev = MockEval()
        ev.exec("x = 1")
        assert ev.unsafe_exec_called is True

    def test_injection_detection(self):
        """Dangerous code patterns should be detected."""
        ev = MockEval()
        ev.eval("__import__('os').system('rm -rf /')")
        assert ev.injection_detected is True


class TestMockAuthenticator:
    """Tests for MockAuthenticator (CWE-287/306: Authentication)."""

    def test_successful_auth(self):
        """Valid credentials should authenticate."""
        auth = MockAuthenticator()
        # "admin" user has password hash of "password"
        result = auth.verify_password("admin", "password")
        assert result is True
        assert auth.last_username == "admin"

    def test_failed_auth(self):
        """Invalid credentials should fail."""
        auth = MockAuthenticator()
        result = auth.verify_password("admin", "wrongpassword")
        assert result is False
        assert auth.failed_attempts > 0

    def test_auth_attempts_tracking(self):
        """Authentication attempts should be counted."""
        auth = MockAuthenticator()
        auth.verify_password("user1", "pass1")
        auth.verify_password("user2", "pass2")
        assert auth.auth_attempts == 2


class TestMockRandom:
    """Tests for MockRandom (CWE-338: Weak PRNG)."""

    def test_weak_prng_detection(self):
        """Using random module should flag weak PRNG."""
        rng = MockRandom()
        rng.randint(1, 100)
        assert rng.weak_prng_used is True

    def test_secure_prng_tracking(self):
        """MockSecrets should mark secure PRNG on MockRandom."""
        rng = MockRandom()
        sec = MockSecrets(mock_random_ref=rng)
        sec.token_hex(16)
        assert rng.secure_prng_used is True

    def test_security_attribute_tracking(self):
        """Security attribute access should be tracked."""
        rng = MockRandom()
        rng.reset_security_tracking()
        rng.random()
        _ = rng.weak_prng_used
        assert "weak_prng_used" in rng._accessed_security_attrs

    def test_reset_clears_state(self):
        """Reset should clear all tracking state."""
        rng = MockRandom()
        rng.randint(1, 10)
        assert rng.weak_prng_used is True
        rng.reset()
        assert rng.weak_prng_used is False
        assert len(rng.call_log) == 0

    def test_call_log(self):
        """Method calls should be logged."""
        rng = MockRandom()
        rng.random()
        rng.randint(1, 10)
        assert len(rng.call_log) == 2


class TestMockSecrets:
    """Tests for MockSecrets (CWE-338: Secure PRNG)."""

    def test_token_hex(self):
        """token_hex should return hex string."""
        sec = MockSecrets()
        token = sec.token_hex(16)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_bytes(self):
        """token_bytes should return bytes."""
        sec = MockSecrets()
        token = sec.token_bytes(16)
        assert isinstance(token, bytes)

    def test_call_log_tracking(self):
        """Calls should be logged."""
        sec = MockSecrets()
        sec.token_hex(16)
        sec.token_urlsafe(16)
        assert len(sec.call_log) == 2

    def test_reset_clears_state(self):
        """Reset should clear call log."""
        sec = MockSecrets()
        sec.token_hex(16)
        sec.reset()
        assert len(sec.call_log) == 0


class TestSecurityTrackingReset:
    """Tests for security tracking reset functionality."""

    def test_all_mocks_have_reset(self):
        """All mocks should have reset_security_tracking method."""
        mocks = [
            MockDatabase(),
            MockSubprocess(),
            MockCrypto(),
            MockFileSystem(),
            MockHTTPClient(),
            MockEnvironment(),
            MockPickle(),
            MockYAML(),
            MockEval(),
            MockAuthenticator(),
            MockRandom(),
            MockSecrets(),
        ]

        for mock in mocks:
            assert hasattr(mock, "reset_security_tracking"), f"{type(mock).__name__} missing reset_security_tracking"

    def test_reset_clears_tracking(self):
        """Reset should clear accessed attributes set."""
        db = MockDatabase()
        _ = db.last_query  # Access security attr
        assert len(db._accessed_security_attrs) > 0

        db.reset_security_tracking()
        assert len(db._accessed_security_attrs) == 0
