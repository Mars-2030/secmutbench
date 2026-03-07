"""
Conftest template for SecMutBench subprocess test runner.

This template is written to a temp directory's conftest.py before running pytest.
It sets up:
1. Mock injection into builtins (so target code finds db, subprocess, etc.)
2. Safety layer (SafeOS, sys.modules patches for dangerous modules)
3. ResultCollector pytest plugin for structured JSON output
"""

CONFTEST_TEMPLATE = '''
import builtins
import json
import os as _real_os
import sys
import pytest  # Make pytest available for pytest.raises() etc.

# ============================================================
# 1. Add project mocks to import path via PYTHONPATH
#    (set by the test runner before launching subprocess)
# ============================================================

# Import mock classes from the evaluation.mocks package
from evaluation.mocks import (
    MockDatabase,
    MockFileSystem,
    MockHTTPResponse,
    MockHTTPClient,
    MockXMLParser,
    MockAuthenticator,
    MockSubprocess,
    MockCompletedProcess,
    MockEnvironment,
    MockOS,
    MockCrypto,
    MockPickle,
    MockYAML,
    MockMarshal,
    MockEval,
    MockRandom,
    MockSecrets,
)
from evaluation.mocks import mock_jwt, mock_bcrypt, mock_flask, mock_mysql


# ============================================================
# 2. Safety Layer - SafeOS wrapper
# ============================================================
class SafeOS:
    """Wrapper around os module that blocks command execution."""
    _blocked = {
        "system", "popen", "spawn", "spawnl", "spawnle", "spawnlp",
        "spawnlpe", "spawnv", "spawnve", "spawnvp", "spawnvpe",
        "execl", "execle", "execlp", "execlpe", "execv", "execve",
        "execvp", "execvpe", "fork", "forkpty",
    }

    def __init__(self, real_os, mock_environ=None):
        object.__setattr__(self, "_real_os", real_os)
        object.__setattr__(self, "_mock_environ", mock_environ)

    def __getattr__(self, name):
        if name in self._blocked:
            raise PermissionError(f"os.{name}() blocked in sandbox")
        if name == "environ" and self._mock_environ is not None:
            return self._mock_environ
        return getattr(self._real_os, name)

    @property
    def path(self):
        return self._real_os.path


# ============================================================
# 3. Create shared mock instances
# ============================================================
_mock_db = MockDatabase()
_mock_fs = MockFileSystem()
_mock_subprocess = MockSubprocess()
_mock_env = MockEnvironment()
# Add common auth/security environment variables
_mock_env.set("JWT_SECRET", "test_jwt_secret_key_12345")
_mock_env.set("SECRET_KEY", "test_secret_key_12345")
_mock_env.set("OAUTH_CLIENT_ID", "test_oauth_client_id")
_mock_env.set("OAUTH_CLIENT_SECRET", "test_oauth_secret")
# Database and storage
_mock_env.set("DATABASE_URL", "sqlite:///test.db")
_mock_env.set("REDIS_URL", "redis://localhost:6379")
_mock_env.set("MONGO_URI", "mongodb://localhost:27017/test")
_mock_env.set("DB_HOST", "localhost")
_mock_env.set("DB_PORT", "5432")
_mock_env.set("DB_NAME", "testdb")
_mock_env.set("DB_USER", "testuser")
_mock_env.set("DB_PASSWORD", "db_password_12345")
# API and service keys
_mock_env.set("API_KEY", "test_api_key_12345")
_mock_env.set("API_SECRET", "test_api_secret_12345")
_mock_env.set("SERVICE_KEY", "test_service_key_12345")
# AWS credentials
_mock_env.set("AWS_ACCESS_KEY_ID", "AKIAIOSFODNN7EXAMPLE")
_mock_env.set("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
_mock_env.set("AWS_REGION", "us-east-1")
# Encryption and security
_mock_env.set("ENCRYPTION_KEY", "test_encryption_key_32bytes_long")
_mock_env.set("ADMIN_PASSWORD", "admin_password_12345")
_mock_env.set("PRIVATE_KEY", "-----BEGIN RSA PRIVATE KEY-----\\nMIIE...\\n-----END RSA PRIVATE KEY-----")
_mock_env.set("PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----\\nMIIB...\\n-----END PUBLIC KEY-----")
# Session and cookie
_mock_env.set("COOKIE_SECRET", "cookie_secret_key_12345")
_mock_env.set("SESSION_SECRET", "session_secret_key_12345")
# Framework secrets
_mock_env.set("FLASK_SECRET_KEY", "flask_secret_key_12345")
_mock_env.set("DJANGO_SECRET_KEY", "django_secret_key_12345")
_mock_env.set("APP_SECRET", "app_secret_12345")
_mock_env.set("TOKEN_SECRET", "token_secret_12345")
# HMAC and hashing
_mock_env.set("HMAC_KEY", "hmac_key_12345")
_mock_env.set("SALT", "test_salt_value")
_mock_env.set("PEPPER", "test_pepper_value")
_mock_env.set("IV", "0123456789abcdef")  # 16 bytes for AES
# Application settings
_mock_env.set("DEBUG", "False")
_mock_env.set("ENV", "test")
_mock_env.set("LOG_LEVEL", "INFO")
_mock_http = MockHTTPClient()
_mock_xml = MockXMLParser()
_mock_auth = MockAuthenticator()
_mock_crypto = MockCrypto()
_mock_pickle = MockPickle()
_mock_yaml = MockYAML()
_mock_marshal = MockMarshal()
_mock_eval = MockEval()
_mock_random = MockRandom()
_mock_secrets = MockSecrets(_mock_random)
_safe_os = SafeOS(_real_os, mock_environ=_mock_env)


# ============================================================
# 4. Inject mocks into builtins
#    Python name resolution: local -> enclosing -> global -> builtin
#    This makes db, subprocess, etc. available as free variables
#    in both target_module.py and test_generated.py without imports.
# ============================================================

# Database mocks (CWE-89)
builtins.db = _mock_db
builtins.mock_db = _mock_db
builtins.database = _mock_db

# Filesystem mocks (CWE-22)
builtins.fs = _mock_fs
builtins.mock_fs = _mock_fs
builtins.filesystem = _mock_fs

# Subprocess mocks (CWE-78)
builtins.subprocess = _mock_subprocess
builtins.mock_subprocess = _mock_subprocess

# Environment mocks (CWE-798)
builtins.env = _mock_env
builtins.mock_env = _mock_env
builtins.os_environ = _mock_env

# HTTP mocks (CWE-918)
builtins.response = MockHTTPResponse()
builtins.mock_response = MockHTTPResponse()
builtins.http_client = _mock_http
builtins.requests = _mock_http
builtins.mock_http = _mock_http

# XML parser mocks (CWE-611)
builtins.xml_parser = _mock_xml
builtins.mock_xml = _mock_xml

# Authentication mocks (CWE-287/306)
builtins.auth = _mock_auth
builtins.authenticator = _mock_auth
builtins.mock_auth = _mock_auth

# JWT and bcrypt mocks (CWE-287)
builtins.jwt = mock_jwt
builtins.bcrypt = mock_bcrypt

# Crypto mocks (CWE-327)
builtins.hashlib = _mock_crypto
builtins.mock_crypto = _mock_crypto

# Deserialization mocks (CWE-502)
builtins.pickle = _mock_pickle
builtins.mock_pickle = _mock_pickle
builtins.yaml = _mock_yaml
builtins.mock_yaml = _mock_yaml
builtins.marshal = _mock_marshal
builtins.mock_marshal = _mock_marshal

# Code execution mocks (CWE-94)
builtins.mock_eval = _mock_eval

# Random/Secrets mocks (CWE-338)
builtins.random = _mock_random
builtins.mock_random = _mock_random
builtins.secrets = _mock_secrets
builtins.mock_secrets = _mock_secrets

# MySQL mock
builtins.mysql = mock_mysql

# Flask mocks
builtins.flask = mock_flask
builtins.Flask = mock_flask.Flask if hasattr(mock_flask, "Flask") else type("Flask", (), {})

# OS with safety wrapper
builtins.os = _safe_os

# Bare OS functions (for CyberSecEval samples that use system() without os. prefix)
builtins.system = lambda cmd: _mock_subprocess.run(cmd, shell=True)
builtins.getcwd = lambda: _real_os.getcwd()
builtins.chdir = lambda path: _real_os.chdir(path)
builtins.getenv = lambda key, default=None: _mock_env.get(key, default)
builtins.popen = lambda cmd, mode='r': _mock_subprocess.Popen(cmd, shell=True)
builtins.execv = lambda path, args: None  # Block
builtins.execve = lambda path, args, env: None  # Block
builtins.fork = lambda: None  # Block

# Connection mock for CWE-798
builtins.connect = lambda **kwargs: {"connected": True, "password": kwargs.get("password")}

# Decorator stubs
builtins.csrf_exempt = lambda f: f
builtins.login_required = lambda f: f

# pytest - needed for pytest.raises() in generated tests
builtins.pytest = pytest

# Common undefined names that samples may reference
builtins.file_list = []
builtins.SCRIPT = ""
builtins.sequence_files = []
builtins.bde_user = "test_user"
builtins.MockRequest = type(
    "MockRequest", (),
    {"user": type("User", (), {"is_authenticated": True, "is_admin": False})()},
)

# Application configuration objects
builtins.config = {"debug": False, "secret_key": "test", "database_url": "sqlite:///test.db"}
builtins.settings = type("Settings", (), {
    "DEBUG": False,
    "SECRET_KEY": "test",
    "DATABASE_URL": "sqlite:///test.db",
    "ALLOWED_HOSTS": ["localhost", "127.0.0.1"],
})()
builtins.app = type("App", (), {
    "config": {"SECRET_KEY": "test", "DEBUG": False},
    "secret_key": "test",
    "debug": False,
    "route": lambda self, path: lambda f: f,
    "before_request": lambda self, f: f,
})()

# Logging
builtins.logger = type("Logger", (), {
    "info": lambda self, msg, *args: None,
    "debug": lambda self, msg, *args: None,
    "warning": lambda self, msg, *args: None,
    "error": lambda self, msg, *args: None,
    "critical": lambda self, msg, *args: None,
    "exception": lambda self, msg, *args: None,
})()
builtins.log = builtins.logger

# Caching and sessions
builtins.cache = {}
builtins.session = {}
builtins.g = type("G", (), {"__setattr__": lambda self, k, v: None, "__getattr__": lambda self, k: None})()

# User/auth context
builtins.current_user = type("User", (), {
    "id": 1,
    "username": "testuser",
    "email": "test@example.com",
    "is_authenticated": True,
    "is_admin": False,
    "is_active": True,
    "is_anonymous": False,
    "get_id": lambda self: "1",
})()

# Request object (Flask-style)
class _MockRequestObj:
    args = {"id": "1", "name": "test"}
    form = {"username": "testuser", "password": "testpass"}
    json = {"key": "value"}
    data = b"{}"
    headers = {"Content-Type": "application/json", "Authorization": "Bearer token123"}
    cookies = {"session_id": "abc123"}
    method = "GET"
    path = "/"
    url = "http://localhost/"
    base_url = "http://localhost"
    host = "localhost"
    remote_addr = "127.0.0.1"
    user_agent = type("UA", (), {"string": "Mozilla/5.0 TestAgent"})()
    files = {}
    values = {}

    def get_json(self, force=False, silent=False):
        return self.json

builtins.request = _MockRequestObj()

# Response helpers (Flask-style)
builtins.Response = type("Response", (), {
    "__init__": lambda self, response="", status=200, headers=None, mimetype="text/html": None,
    "set_cookie": lambda self, key, value, **kwargs: None,
    "delete_cookie": lambda self, key, **kwargs: None,
})
builtins.make_response = lambda *args: type("Response", (), {"set_cookie": lambda k, v, **kw: None})()
builtins.redirect = lambda url, code=302: {"redirect": url, "code": code}
builtins.url_for = lambda endpoint, **kwargs: f"/{endpoint}"
builtins.render_template = lambda template, **kwargs: f"<html>{template}</html>"
builtins.render_template_string = lambda source, **kwargs: source
builtins.jsonify = lambda *args, **kwargs: {"json": args[0] if args else kwargs}
builtins.abort = lambda code, description=None: (_ for _ in ()).throw(Exception(f"HTTP {code}: {description}"))
builtins.flash = lambda message, category="info": None

# Form/WTForms stubs
builtins.Form = type("Form", (), {"validate": lambda self: True})
builtins.StringField = type("StringField", (), {})
builtins.PasswordField = type("PasswordField", (), {})
builtins.validators = type("validators", (), {"DataRequired": lambda: None, "Email": lambda: None, "Length": lambda **kw: None})()

# Database query stubs
builtins.query = type("Query", (), {
    "filter_by": lambda self, **kw: self,
    "filter": lambda self, *args: self,
    "first": lambda self: None,
    "all": lambda self: [],
    "get": lambda self, id: None,
    "count": lambda self: 0,
})()

# Common constants
builtins.SECRET_KEY = "test_secret_key"
builtins.DEBUG = False
builtins.TESTING = True

# CWE-287 authentication helpers
def _get_valid_api_key():
    """Return a mock valid API key for HMAC comparison tests."""
    return "valid_api_key_abc123"

builtins.get_valid_api_key = _get_valid_api_key

# Sessions dict for CWE-287 session validation tests
import time as _time
_sessions = {
    "valid_session_123": {"user_id": 1, "expires": _time.time() + 3600},  # Valid, not expired
    "expired_session_456": {"user_id": 2, "expires": _time.time() - 3600},  # Expired
}
builtins.sessions = _sessions

# JSON module for token parsing
import json as _json
builtins.json = _json


# ============================================================
# 5. Patch sys.modules so `import X` gets our mocks
# ============================================================

# Generic mock module for packages that shouldn't crash on attribute access
class _MockModule:
    """Generic mock module that doesn't crash on attribute access."""
    def __init__(self, name="MockModule"):
        self._name = name

    def __getattr__(self, name):
        # Return a chainable mock for method calls (e.g., smtplib.SMTP().login())
        return _ChainableMock(f"{self._name}.{name}")

    def __call__(self, *args, **kwargs):
        # When called as a function, return chainable mock (e.g., SMTP(...) returns mock)
        return _ChainableMock(f"{self._name}()")

    def __repr__(self):
        return f"<MockModule({self._name})>"


class _ChainableMock:
    """Mock that supports method chaining without raising AttributeError."""
    def __init__(self, name="mock"):
        object.__setattr__(self, "_name", name)

    def __getattr__(self, name):
        return _ChainableMock(f"{self._name}.{name}")

    def __call__(self, *args, **kwargs):
        return _ChainableMock(f"{self._name}()")

    def __repr__(self):
        return f"<ChainableMock({self._name})>"

    def __bool__(self):
        return True

    def __iter__(self):
        return iter([])

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

# Create mock module instances for commonly imported packages
_mock_cryptography = _MockModule("cryptography")
_mock_crypto_cipher = _MockModule("Crypto")
_mock_passlib = _MockModule("passlib")
_mock_argon2 = _MockModule("argon2")
_mock_nacl = _MockModule("nacl")
_mock_paramiko = _MockModule("paramiko")
_mock_redis = _MockModule("redis")
_mock_pymongo = _MockModule("pymongo")
_mock_sqlalchemy = _MockModule("sqlalchemy")
_mock_django = _MockModule("django")
_mock_flask_login = _MockModule("flask_login")
_mock_werkzeug = _MockModule("werkzeug")
_mock_jinja2 = _MockModule("jinja2")
_mock_mako = _MockModule("mako")
_mock_lxml = _MockModule("lxml")
_mock_defusedxml = _MockModule("defusedxml")

# Core mocks
sys.modules["subprocess"] = _mock_subprocess
sys.modules["requests"] = _mock_http
sys.modules["hashlib"] = _mock_crypto
sys.modules["pickle"] = _mock_pickle
sys.modules["yaml"] = _mock_yaml
sys.modules["marshal"] = _mock_marshal
sys.modules["random"] = _mock_random
sys.modules["secrets"] = _mock_secrets
sys.modules["os"] = _safe_os
sys.modules["jwt"] = mock_jwt
sys.modules["bcrypt"] = mock_bcrypt
sys.modules["flask"] = mock_flask
sys.modules["mysql"] = mock_mysql
sys.modules["mysql.connector"] = mock_mysql

# Cryptography libraries
sys.modules["cryptography"] = _mock_cryptography
sys.modules["cryptography.fernet"] = _mock_cryptography
sys.modules["cryptography.hazmat"] = _mock_cryptography
sys.modules["cryptography.hazmat.primitives"] = _mock_cryptography
sys.modules["cryptography.hazmat.primitives.ciphers"] = _mock_cryptography
sys.modules["cryptography.hazmat.primitives.hashes"] = _mock_cryptography
sys.modules["cryptography.hazmat.backends"] = _mock_cryptography
sys.modules["Crypto"] = _mock_crypto_cipher
sys.modules["Crypto.Cipher"] = _mock_crypto_cipher
sys.modules["Crypto.Cipher.AES"] = _mock_crypto_cipher
sys.modules["Crypto.Hash"] = _mock_crypto_cipher

# Password hashing libraries
sys.modules["passlib"] = _mock_passlib
sys.modules["passlib.hash"] = _mock_passlib
sys.modules["passlib.context"] = _mock_passlib
sys.modules["argon2"] = _mock_argon2
sys.modules["argon2.exceptions"] = _mock_argon2

# Crypto libraries
sys.modules["nacl"] = _mock_nacl
sys.modules["nacl.secret"] = _mock_nacl
sys.modules["nacl.pwhash"] = _mock_nacl

# Network/SSH
sys.modules["paramiko"] = _mock_paramiko

# Database clients
sys.modules["redis"] = _mock_redis
sys.modules["pymongo"] = _mock_pymongo
sys.modules["psycopg2"] = _MockModule("psycopg2")
sys.modules["sqlite3"] = _MockModule("sqlite3")

# ORM/frameworks
sys.modules["sqlalchemy"] = _mock_sqlalchemy
sys.modules["sqlalchemy.orm"] = _mock_sqlalchemy
sys.modules["django"] = _mock_django
sys.modules["django.db"] = _mock_django
sys.modules["django.conf"] = _mock_django
sys.modules["django.http"] = _mock_django

# Flask extensions
sys.modules["flask_login"] = _mock_flask_login
sys.modules["flask_session"] = _MockModule("flask_session")
sys.modules["flask_wtf"] = _MockModule("flask_wtf")

# WSGI/HTTP utilities
sys.modules["werkzeug"] = _mock_werkzeug
sys.modules["werkzeug.security"] = _mock_werkzeug
sys.modules["werkzeug.utils"] = _mock_werkzeug

# Template engines
sys.modules["jinja2"] = _mock_jinja2
sys.modules["mako"] = _mock_mako
sys.modules["mako.template"] = _mock_mako

# XML libraries (safe alternatives)
sys.modules["lxml"] = _mock_lxml
sys.modules["lxml.etree"] = _mock_lxml
sys.modules["defusedxml"] = _mock_defusedxml
sys.modules["defusedxml.ElementTree"] = _mock_defusedxml

# HTTP clients
sys.modules["urllib3"] = _MockModule("urllib3")
sys.modules["httpx"] = _MockModule("httpx")
sys.modules["aiohttp"] = _MockModule("aiohttp")

# Email (CWE-798) - only mock smtplib, not stdlib email module
sys.modules["smtplib"] = _MockModule("smtplib")

# AWS SDK (CWE-798)
sys.modules["boto3"] = _MockModule("boto3")
sys.modules["botocore"] = _MockModule("botocore")
sys.modules["botocore.exceptions"] = _MockModule("botocore.exceptions")


# ============================================================
# 6. ResultCollector pytest plugin
# ============================================================

# All mock instances for security tracking
_all_mocks = {
    "db": _mock_db,
    "subprocess": _mock_subprocess,
    "fs": _mock_fs,
    "crypto": _mock_crypto,
    "http": _mock_http,
    "xml": _mock_xml,
    "auth": _mock_auth,
    "env": _mock_env,
    "pickle": _mock_pickle,
    "yaml": _mock_yaml,
    "eval": _mock_eval,
    "random": _mock_random,
    "secrets": _mock_secrets,
}


def _reset_all_security_tracking():
    """Reset security attribute tracking on all mocks."""
    for mock_obj in _all_mocks.values():
        if hasattr(mock_obj, "reset_security_tracking"):
            mock_obj.reset_security_tracking()


def _collect_mock_security_access():
    """Collect security attribute access from all mocks."""
    mock_access = {}
    for name, mock_obj in _all_mocks.items():
        accessed = getattr(mock_obj, "_accessed_security_attrs", set())
        if accessed:
            mock_access[name] = list(accessed)
    return mock_access


class ResultCollector:
    """Pytest plugin that collects test results and writes to JSON."""

    def __init__(self):
        self.results = []

    def pytest_runtest_setup(self, item):
        """Called before each test. Reset security tracking."""
        _reset_all_security_tracking()

    def pytest_runtest_makereport(self, item, call):
        """Called after each test phase (setup/call/teardown)."""
        if call.when == "call":
            error = None
            error_type = None
            if call.excinfo is not None:
                error_type = call.excinfo.typename
                if error_type == "AssertionError":
                    error = f"Assertion failed: {str(call.excinfo.value)}"
                else:
                    error = f"{error_type}: {str(call.excinfo.value)}"

            # Collect mock security attribute access
            mock_security_access = _collect_mock_security_access()

            self.results.append({
                "name": item.name,
                "passed": call.excinfo is None,
                "error": error,
                "error_type": error_type,
                "output": "",
                "mock_security_access": mock_security_access,
            })

    def pytest_sessionfinish(self, session, exitstatus):
        """Called after all tests complete. Write results to JSON."""
        results_path = _real_os.environ.get(
            "SECMUTBENCH_RESULTS_PATH",
            _real_os.path.join(_real_os.getcwd(), "results.json"),
        )
        with open(results_path, "w") as f:
            json.dump(self.results, f, indent=2)


_collector = ResultCollector()


def pytest_configure(config):
    """Register our result collector plugin with pytest."""
    config.pluginmanager.register(_collector, "secmutbench_collector")
'''


# =============================================================================
# No-Mock Conftest Template
# =============================================================================
# This template runs tests without mock injection - only includes the
# ResultCollector for structured output. Use with caution as tests may
# execute real operations (file I/O, network requests, etc.)

CONFTEST_TEMPLATE_NO_MOCKS = '''
import json
import os as _real_os

# ============================================================
# ResultCollector pytest plugin (no mock injection)
# ============================================================
class ResultCollector:
    """Pytest plugin that collects test results and writes to JSON."""

    def __init__(self):
        self.results = []

    def pytest_runtest_makereport(self, item, call):
        """Called after each test phase (setup/call/teardown)."""
        if call.when == "call":
            error = None
            error_type = None
            if call.excinfo is not None:
                error_type = call.excinfo.typename
                if error_type == "AssertionError":
                    error = f"Assertion failed: {str(call.excinfo.value)}"
                else:
                    error = f"{error_type}: {str(call.excinfo.value)}"

            self.results.append({
                "name": item.name,
                "passed": call.excinfo is None,
                "error": error,
                "error_type": error_type,
                "output": "",
                "mock_security_access": {},  # No mocks, always empty
            })

    def pytest_sessionfinish(self, session, exitstatus):
        """Called after all tests complete. Write results to JSON."""
        results_path = _real_os.environ.get(
            "SECMUTBENCH_RESULTS_PATH",
            _real_os.path.join(_real_os.getcwd(), "results.json"),
        )
        with open(results_path, "w") as f:
            json.dump(self.results, f, indent=2)


_collector = ResultCollector()


def pytest_configure(config):
    """Register our result collector plugin with pytest."""
    config.pluginmanager.register(_collector, "secmutbench_collector")
'''
