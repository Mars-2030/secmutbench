"""
SecMutBench Mock Objects

This module provides mock implementations of external dependencies
for safe test execution. All mocks track their state to allow
security tests to verify correct behavior.

Mock Classes:
- MockDatabase: SQL database mock for CWE-89 (SQL injection)
- MockFileSystem: Filesystem mock for CWE-22 (path traversal)
- MockHTTPClient/Response: HTTP mock for CWE-918 (SSRF)
- MockXMLParser: XML parser mock for CWE-611 (XXE)
- MockAuthenticator: Auth mock for CWE-287/306 (authentication)
- MockSubprocess: Subprocess mock for CWE-78 (command injection)
- MockEnvironment: Environment mock for CWE-798 (hardcoded credentials)
- MockCrypto: Hash algorithm mock for CWE-327 (weak cryptography)
- MockPickle/MockYAML: Deserialization mock for CWE-502 (insecure deserialization)
- MockEval: Code execution mock for CWE-94 (code injection)
"""

from .mock_subprocess import MockSubprocess, MockCompletedProcess
from .mock_environment import MockEnvironment, MockOS
from .mock_database import MockDatabase
from .mock_filesystem import MockFileSystem
from .mock_http import MockHTTPResponse, MockHTTPClient
from .mock_xml import MockXMLParser
from .mock_auth import MockAuthenticator
from .mock_crypto import MockCrypto, MockHashObject
from .mock_deserializer import MockPickle, MockYAML, MockMarshal
from .mock_eval import MockEval, MockBuiltins
from . import mock_jwt
from . import mock_bcrypt
from . import mock_flask
from . import mock_mysql

__all__ = [
    # Database (CWE-89)
    'MockDatabase',
    # Filesystem (CWE-22)
    'MockFileSystem',
    # HTTP (CWE-918)
    'MockHTTPResponse',
    'MockHTTPClient',
    # XML (CWE-611)
    'MockXMLParser',
    # Auth (CWE-287/306)
    'MockAuthenticator',
    # Subprocess (CWE-78)
    'MockSubprocess',
    'MockCompletedProcess',
    # Environment (CWE-798)
    'MockEnvironment',
    'MockOS',
    # Crypto (CWE-327)
    'MockCrypto',
    'MockHashObject',
    # Deserialization (CWE-502)
    'MockPickle',
    'MockYAML',
    'MockMarshal',
    # Eval/Exec (CWE-94)
    'MockEval',
    'MockBuiltins',
]
