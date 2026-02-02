"""
Test Runner for SecMutBench

Executes tests against code and mutants in a sandboxed environment.
"""

import sys
import io
import traceback
import tempfile
import os
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from contextlib import redirect_stdout, redirect_stderr
import importlib.util
import uuid

# Import all mock objects from consolidated mocks package
try:
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
        MockEval,
        mock_jwt,
        mock_bcrypt,
        mock_flask,
    )
    from evaluation.mocks import mock_mysql
except ImportError:
    # Fallback for running without package installation
    from .mocks import (
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
        MockEval,
        mock_jwt,
        mock_bcrypt,
        mock_flask,
    )
    from .mocks import mock_mysql


@dataclass
class TestResult:
    """Result of running a single test."""
    name: str
    passed: bool
    error: Optional[str] = None
    output: Optional[str] = None
    execution_time: float = 0.0


@dataclass
class TestSuiteResult:
    """Result of running a test suite."""
    tests: List[TestResult] = field(default_factory=list)
    total: int = 0
    passed: int = 0
    failed: int = 0
    errors: int = 0
    execution_time: float = 0.0
    line_coverage: float = 0.0
    lines_covered: int = 0
    lines_total: int = 0

    @property
    def all_passed(self) -> bool:
        return self.passed == self.total and self.total > 0

    @property
    def pass_rate(self) -> float:
        return self.passed / self.total if self.total > 0 else 0.0


# NOTE: Mock classes (MockDatabase, MockFileSystem, MockHTTPResponse, MockHTTPClient,
# MockXMLParser, MockAuthenticator) have been moved to evaluation/mocks/ for better
# organization. They are imported at the top of this file.


class RaisesContext:
    """Context manager for pytest.raises mock."""

    def __init__(self, expected_exception):
        self.expected_exception = expected_exception
        self.value = None
        self.excinfo = None

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            # No exception was raised
            raise AssertionError(f"Expected {self.expected_exception.__name__} but no exception was raised")

        if isinstance(exc_val, self.expected_exception):
            # Expected exception was raised
            self.value = exc_val
            return True  # Suppress the exception

        # Wrong exception type
        return False  # Let it propagate


class MockPytest:
    """Mock pytest module for test execution."""

    @staticmethod
    def raises(expected_exception, match=None):
        """Mock pytest.raises as context manager."""
        return RaisesContext(expected_exception)

    @staticmethod
    def fail(msg=""):
        """Mock pytest.fail."""
        raise AssertionError(msg)

    @staticmethod
    def skip(msg=""):
        """Mock pytest.skip."""
        raise Exception(f"SKIPPED: {msg}")

    class mark:
        @staticmethod
        def parametrize(*args, **kwargs):
            return lambda f: f

        @staticmethod
        def skip(*args, **kwargs):
            return lambda f: f

        @staticmethod
        def skipif(*args, **kwargs):
            return lambda f: f


class SafeOS:
    """Wrapper around os module that blocks command execution and uses mock environ."""
    _blocked = {'system', 'popen', 'spawn', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
                'spawnv', 'spawnve', 'spawnvp', 'spawnvpe', 'execl', 'execle', 'execlp',
                'execlpe', 'execv', 'execve', 'execvp', 'execvpe', 'fork', 'forkpty'}
    _real_os = __import__('os')  # Cache real os at class definition time

    def __init__(self, mock_environ=None):
        self._mock_environ = mock_environ

    def __getattr__(self, name):
        if name in self._blocked:
            raise PermissionError(f"os.{name}() blocked in sandbox")
        if name == 'environ' and self._mock_environ is not None:
            return self._mock_environ
        return getattr(self._real_os, name)


# Safe modules that can be imported (no dangerous side effects)
SAFE_MODULES = {'re', 'json', 'html', 'base64', 'urllib', 'urllib.parse', 'hmac',
                'secrets', 'ast', 'math', 'string', 'collections', 'itertools',
                'functools', 'operator', 'copy', 'types', 'datetime', 'time', 'random',
                'hashlib', 'typing', 'dataclasses', 'enum', 'abc', 'shlex', 'pathlib',
                'xml', 'xml.etree', 'xml.etree.ElementTree', 'defusedxml', 'inspect'}


def create_safe_import(mock_modules: Dict[str, Any]):
    """Create __import__ that returns mocks or allows only safe modules."""
    def safe_import(name, globals=None, locals=None, fromlist=(), level=0):
        # Return mock if available
        if name in mock_modules:
            return mock_modules[name]
        # Check parent (e.g., mysql.connector -> mysql)
        parent = name.split('.')[0]
        if parent in mock_modules:
            return mock_modules[parent]
        # Allow safe modules
        if name in SAFE_MODULES or parent in SAFE_MODULES:
            return __import__(name, globals, locals, fromlist, level)
        raise ImportError(f"Import of '{name}' blocked in sandbox")
    return safe_import


def create_test_globals() -> Dict[str, Any]:
    """Create a globals dict with mock objects for test execution."""
    # Create shared mock instances
    mock_db = MockDatabase()
    mock_fs = MockFileSystem()
    mock_subprocess = MockSubprocess()
    mock_env = MockEnvironment()
    mock_http = MockHTTPClient()
    mock_xml = MockXMLParser()
    mock_auth = MockAuthenticator()
    mock_crypto = MockCrypto()
    mock_pickle = MockPickle()
    mock_yaml = MockYAML()
    mock_eval = MockEval()
    safe_os = SafeOS(mock_environ=mock_env)

    # Modules that __import__ will return mocks for
    import_mocks = {
        'subprocess': mock_subprocess,
        'requests': mock_http,
        'hashlib': mock_crypto,
        'pickle': mock_pickle,
        'yaml': mock_yaml,
        'os': safe_os,
        'jwt': mock_jwt,
        'bcrypt': mock_bcrypt,
        'flask': mock_flask,
        'mysql': mock_mysql,
        'mysql.connector': mock_mysql,
    }

    # Create safe __import__ and inject into builtins copy
    safe_import = create_safe_import(import_mocks)
    safe_builtins = dict(__builtins__) if isinstance(__builtins__, dict) else vars(__builtins__).copy()
    safe_builtins['__import__'] = safe_import

    return {
        "__builtins__": safe_builtins,
        # Database mocks (CWE-89)
        "db": mock_db,
        "mock_db": mock_db,
        "database": mock_db,
        # Filesystem mocks (CWE-22)
        "fs": mock_fs,
        "mock_fs": mock_fs,
        "filesystem": mock_fs,
        # Subprocess mocks (CWE-78)
        "subprocess": mock_subprocess,
        "mock_subprocess": mock_subprocess,
        # Environment mocks (CWE-798)
        "env": mock_env,
        "mock_env": mock_env,
        "os_environ": mock_env,
        # HTTP mocks (CWE-918)
        "response": MockHTTPResponse(),
        "mock_response": MockHTTPResponse(),
        "http_client": mock_http,
        "requests": mock_http,
        "mock_http": mock_http,
        # XML parser mocks (CWE-611)
        "xml_parser": mock_xml,
        "mock_xml": mock_xml,
        # Authentication mocks (CWE-287/306)
        "auth": mock_auth,
        "authenticator": mock_auth,
        "mock_auth": mock_auth,
        # Crypto mocks (CWE-327)
        "hashlib": mock_crypto,
        "mock_crypto": mock_crypto,
        # Deserialization mocks (CWE-502)
        "pickle": mock_pickle,
        "mock_pickle": mock_pickle,
        "yaml": mock_yaml,
        "mock_yaml": mock_yaml,
        # Code execution mocks (CWE-94)
        "mock_eval": mock_eval,
        # MySQL mock (CWE-798)
        "mysql": mock_mysql,
        # Connection mock for CWE-798
        "connect": lambda **kwargs: {"connected": True, "password": kwargs.get("password")},
        # Common imports (SafeOS blocks command execution)
        "os": safe_os,
        "sys": __import__("sys"),
        "re": __import__("re"),
        "json": __import__("json"),
        "html": __import__("html"),
        "base64": __import__("base64"),
        "urllib": __import__("urllib"),
        "hmac": __import__("hmac"),
        "secrets": __import__("secrets"),
        "ast": __import__("ast"),
        # Test utilities
        "pytest": MockPytest,
    }


class TestRunner:
    """
    Runner for executing tests against code.

    Provides sandboxed execution of tests with mocked dependencies.
    """

    def __init__(self, timeout: float = 5.0):
        """
        Initialize the test runner.

        Args:
            timeout: Maximum execution time per test in seconds
        """
        self.timeout = timeout

    def run_tests(
        self,
        test_code: str,
        target_code: str,
        additional_globals: Optional[Dict] = None,
        measure_coverage: bool = True,
    ) -> TestSuiteResult:
        """
        Run tests against target code.

        Args:
            test_code: String containing test functions
            target_code: String containing code to test
            additional_globals: Additional globals to inject
            measure_coverage: Whether to measure line coverage

        Returns:
            TestSuiteResult with test outcomes
        """
        result = TestSuiteResult()

        # Create execution environment
        globals_dict = create_test_globals()
        if additional_globals:
            globals_dict.update(additional_globals)

        # Count executable lines in target code
        target_lines = self._count_executable_lines(target_code)
        result.lines_total = len(target_lines)

        # Inject mocks into sys.modules so 'import X' gets our mock
        # Save originals to restore later
        saved_modules = {}
        mock_modules = {
            'subprocess': globals_dict['subprocess'],
            'requests': globals_dict['requests'],
            'hashlib': globals_dict['hashlib'],
            'pickle': globals_dict['pickle'],
            'yaml': globals_dict['yaml'],
            'os': globals_dict['os'],  # SafeOS blocks os.system etc.
            'jwt': mock_jwt,
            'bcrypt': mock_bcrypt,
            'flask': mock_flask,
            'mysql': mock_mysql,
            'mysql.connector': mock_mysql,
        }
        for mod_name, mock_obj in mock_modules.items():
            if mod_name in sys.modules:
                saved_modules[mod_name] = sys.modules[mod_name]
            sys.modules[mod_name] = mock_obj

        try:
            # Execute target code first
            try:
                exec(target_code, globals_dict)
            except Exception as e:
                result.errors = 1
                result.total = 1
                result.tests.append(TestResult(
                    name="target_code_execution",
                    passed=False,
                    error=f"Failed to execute target code: {str(e)}"
                ))
                return result

            # Execute test code to define test functions
            try:
                exec(test_code, globals_dict)
            except Exception as e:
                result.errors = 1
                result.total = 1
                result.tests.append(TestResult(
                    name="test_code_parsing",
                    passed=False,
                    error=f"Failed to parse test code: {str(e)}"
                ))
                return result

            # Find and run test functions
            test_functions = [
                (name, func)
                for name, func in globals_dict.items()
                if name.startswith("test_") and callable(func)
            ]

            result.total = len(test_functions)

            # Track executed lines for coverage
            executed_lines = set()

            for name, func in test_functions:
                test_result, lines_hit = self._run_single_test_with_coverage(
                    name, func, globals_dict, measure_coverage
                )
                result.tests.append(test_result)
                executed_lines.update(lines_hit)

                if test_result.passed:
                    result.passed += 1
                elif test_result.error:
                    result.errors += 1
                    result.failed += 1
                else:
                    result.failed += 1

            # Calculate coverage
            if result.lines_total > 0 and measure_coverage:
                # Intersect executed lines with target code lines
                covered = len(executed_lines & target_lines)
                result.lines_covered = covered
                result.line_coverage = covered / result.lines_total
            else:
                result.line_coverage = 0.0

            return result

        finally:
            # Restore original modules
            for mod_name, orig_mod in saved_modules.items():
                sys.modules[mod_name] = orig_mod
            # Remove mocks that weren't originally in sys.modules
            for mod_name in mock_modules:
                if mod_name not in saved_modules and mod_name in sys.modules:
                    if sys.modules[mod_name] is mock_modules[mod_name]:
                        del sys.modules[mod_name]

    def _count_executable_lines(self, code: str) -> set:
        """Count executable lines in code (excluding comments, blanks, docstrings)."""
        import ast
        try:
            tree = ast.parse(code)
            executable_lines = set()
            for node in ast.walk(tree):
                if hasattr(node, 'lineno'):
                    # Skip docstrings
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str):
                            continue
                    executable_lines.add(node.lineno)
            return executable_lines
        except:
            # Fallback: count non-empty, non-comment lines
            lines = set()
            for i, line in enumerate(code.split('\n'), 1):
                stripped = line.strip()
                if stripped and not stripped.startswith('#'):
                    lines.add(i)
            return lines

    def _run_single_test_with_coverage(
        self,
        name: str,
        func: callable,
        globals_dict: Dict,
        measure_coverage: bool = True,
    ) -> Tuple[TestResult, set]:
        """Run a single test function with optional coverage tracking."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        executed_lines = set()

        def trace_lines(frame, event, arg):
            if event == 'line':
                # Only track lines from dynamically executed code (target code)
                # Filter by checking if it's in the exec'd code's namespace
                # The target code is executed with filename "<string>"
                if frame.f_code.co_filename == "<string>":
                    executed_lines.add(frame.f_lineno)
            return trace_lines

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                if measure_coverage:
                    old_trace = sys.gettrace()
                    sys.settrace(trace_lines)
                try:
                    # Apply timeout using signal (Unix only) or threading
                    import signal

                    def timeout_handler(signum, frame):
                        raise TimeoutError(f"Test {name} timed out after {self.timeout}s")

                    # Set timeout (only on Unix systems)
                    if hasattr(signal, 'SIGALRM'):
                        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
                        signal.alarm(int(self.timeout))

                    try:
                        func()
                    finally:
                        if hasattr(signal, 'SIGALRM'):
                            signal.alarm(0)
                            signal.signal(signal.SIGALRM, old_handler)
                finally:
                    if measure_coverage:
                        sys.settrace(old_trace)

            return TestResult(
                name=name,
                passed=True,
                output=stdout_capture.getvalue(),
            ), executed_lines

        except AssertionError as e:
            return TestResult(
                name=name,
                passed=False,
                error=f"Assertion failed: {str(e)}",
                output=stdout_capture.getvalue(),
            ), executed_lines

        except Exception as e:
            return TestResult(
                name=name,
                passed=False,
                error=f"{type(e).__name__}: {str(e)}",
                output=stdout_capture.getvalue(),
            ), executed_lines

    def _run_single_test(
        self,
        name: str,
        func: callable,
        globals_dict: Dict,
    ) -> TestResult:
        """Run a single test function."""
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()

        try:
            with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
                func()

            return TestResult(
                name=name,
                passed=True,
                output=stdout_capture.getvalue(),
            )

        except AssertionError as e:
            return TestResult(
                name=name,
                passed=False,
                error=f"Assertion failed: {str(e)}",
                output=stdout_capture.getvalue(),
            )

        except Exception as e:
            return TestResult(
                name=name,
                passed=False,
                error=f"{type(e).__name__}: {str(e)}",
                output=stdout_capture.getvalue(),
            )

    def check_mutant_killed(
        self,
        test_code: str,
        original_code: str,
        mutant_code: str,
    ) -> Tuple[bool, str]:
        """
        Check if a mutant is killed by the tests.

        A mutant is killed if:
        1. Tests pass on original code
        2. Tests fail on mutant code

        Args:
            test_code: Test suite
            original_code: Original (secure) code
            mutant_code: Mutated (vulnerable) code

        Returns:
            Tuple of (killed: bool, reason: str)
        """
        # Run tests on original
        original_result = self.run_tests(test_code, original_code)

        if not original_result.all_passed:
            return False, "Tests don't pass on original code"

        # Run tests on mutant
        mutant_result = self.run_tests(test_code, mutant_code)

        if not mutant_result.all_passed:
            return True, f"Mutant killed: {mutant_result.failed} test(s) failed"
        else:
            return False, "Mutant survived: all tests passed"


def run_tests(
    test_code: str,
    target_code: str,
    additional_globals: Optional[Dict] = None,
) -> TestSuiteResult:
    """
    Convenience function to run tests.

    Args:
        test_code: String containing test functions
        target_code: String containing code to test
        additional_globals: Additional globals to inject

    Returns:
        TestSuiteResult with test outcomes
    """
    runner = TestRunner()
    return runner.run_tests(test_code, target_code, additional_globals)


def check_vulnerability_detection(
    security_tests: str,
    secure_code: str,
    insecure_code: str,
) -> Dict[str, Any]:
    """
    Check if security tests can distinguish secure from insecure code.

    Args:
        security_tests: Security test suite
        secure_code: Secure implementation
        insecure_code: Vulnerable implementation

    Returns:
        Dict with detection results
    """
    runner = TestRunner()

    secure_result = runner.run_tests(security_tests, secure_code)
    insecure_result = runner.run_tests(security_tests, insecure_code)

    return {
        "secure_passes": secure_result.all_passed,
        "insecure_fails": not insecure_result.all_passed,
        "vulnerability_detected": secure_result.all_passed and not insecure_result.all_passed,
        "secure_result": secure_result,
        "insecure_result": insecure_result,
    }


if __name__ == "__main__":
    # Test the test runner
    target_code = '''
def get_user(username):
    query = "SELECT * FROM users WHERE name = ?"
    return db.execute(query, (username,))
'''

    test_code = '''
def test_normal_user():
    result = get_user("alice")
    assert result is not None

def test_sql_injection():
    result = get_user("' OR '1'='1")
    assert len(result) <= 1
'''

    runner = TestRunner()
    result = runner.run_tests(test_code, target_code)

    print(f"Total: {result.total}")
    print(f"Passed: {result.passed}")
    print(f"Failed: {result.failed}")

    for test in result.tests:
        status = "PASS" if test.passed else "FAIL"
        print(f"  [{status}] {test.name}")
        if test.error:
            print(f"    Error: {test.error}")
