"""
Test Runner for SecMutBench

Executes tests against code using subprocess isolation with pytest.
Each run_tests() call spawns a fresh subprocess with:
- Real Python imports (no custom __import__ sandbox)
- Mock objects injected via builtins for security state tracking
- Safety layer blocking dangerous operations (os.system, subprocess.run, etc.)
- Structured JSON result collection via pytest plugin
"""

import sys
import os
import json
import subprocess
import tempfile
import ast
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field

from evaluation.conftest_template import CONFTEST_TEMPLATE, CONFTEST_TEMPLATE_NO_MOCKS


@dataclass
class TestResult:
    """Result of running a single test."""
    name: str
    passed: bool
    error: Optional[str] = None
    output: Optional[str] = None
    execution_time: float = 0.0
    mock_security_access: Optional[Dict[str, List[str]]] = None  # NEW: Track mock attr access


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


class TestRunner:
    """
    Runner for executing tests against code.

    Uses subprocess isolation with pytest for reliable test execution.
    Mock objects are injected via builtins in a conftest.py template.
    """

    # Project root for PYTHONPATH injection
    _project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    def __init__(self, timeout: float = 300.0, use_mocks: bool = True):
        """
        Initialize the test runner.

        Args:
            timeout: Maximum execution time for the entire test suite in seconds
            use_mocks: Whether to inject mock objects (default: True).
                       Set to False for no-mock comparison experiments.
                       WARNING: Without mocks, tests may execute real operations!
        """
        self.timeout = timeout
        self.use_mocks = use_mocks

    def run_tests(
        self,
        test_code: str,
        target_code: str,
        additional_globals: Optional[Dict] = None,
        measure_coverage: bool = False,
        use_mocks: Optional[bool] = None,
    ) -> TestSuiteResult:
        """
        Run tests against target code in an isolated subprocess.

        Args:
            test_code: String containing test functions
            target_code: String containing code to test
            additional_globals: Additional globals to inject (currently unused in subprocess mode)
            measure_coverage: Whether to measure line coverage (requires pytest-cov)
            use_mocks: Override instance-level use_mocks setting for this call

        Returns:
            TestSuiteResult with test outcomes
        """
        result = TestSuiteResult()

        # Determine whether to use mocks (call parameter overrides instance setting)
        _use_mocks = use_mocks if use_mocks is not None else self.use_mocks

        # Count executable lines in target code
        target_lines = self._count_executable_lines(target_code)
        result.lines_total = len(target_lines)

        with tempfile.TemporaryDirectory(prefix="secmutbench_") as tmp_dir:
            # 1. Write target_module.py
            target_path = os.path.join(tmp_dir, "target_module.py")
            with open(target_path, "w") as f:
                f.write(target_code)

            # 2. Write test_generated.py with import preamble
            test_path = os.path.join(tmp_dir, "test_generated.py")
            test_preamble = "from target_module import *\n\n"
            with open(test_path, "w") as f:
                f.write(test_preamble + test_code)

            # 3. Write conftest.py from template (with or without mocks)
            conftest_path = os.path.join(tmp_dir, "conftest.py")
            conftest_template = CONFTEST_TEMPLATE if _use_mocks else CONFTEST_TEMPLATE_NO_MOCKS
            with open(conftest_path, "w") as f:
                f.write(conftest_template)

            # 4. Set up environment with PYTHONPATH so conftest can import evaluation.mocks
            results_json_path = os.path.join(tmp_dir, "results.json")
            coverage_json_path = os.path.join(tmp_dir, "coverage.json")
            env = os.environ.copy()
            # Prepend project root so `from evaluation.mocks import ...` works
            existing_pythonpath = env.get("PYTHONPATH", "")
            env["PYTHONPATH"] = self._project_root + (
                os.pathsep + existing_pythonpath if existing_pythonpath else ""
            )
            env["SECMUTBENCH_RESULTS_PATH"] = results_json_path

            # 5. Build pytest command
            pytest_cmd = [
                sys.executable, "-m", "pytest", "test_generated.py",
                "--tb=short", "-q", "--no-header"
            ]

            # Add coverage instrumentation if requested
            # Note: requires pytest-cov to be installed (pip install pytest-cov)
            _measure_coverage = measure_coverage
            if measure_coverage:
                try:
                    import pytest_cov
                    pytest_cmd.extend([
                        "--cov=target_module",
                        "--cov-report=json:" + coverage_json_path,
                        "--cov-report=",  # Suppress terminal output
                    ])
                except ImportError:
                    # pytest-cov not installed, skip coverage measurement
                    _measure_coverage = False

            # 6. Run pytest in subprocess
            try:
                proc = subprocess.run(
                    pytest_cmd,
                    cwd=tmp_dir,
                    timeout=self.timeout,
                    capture_output=True,
                    text=True,
                    env=env,
                )
            except subprocess.TimeoutExpired:
                result.errors = 1
                result.total = 1
                result.tests.append(TestResult(
                    name="timeout",
                    passed=False,
                    error=f"TimeoutError: Test suite timed out after {self.timeout}s",
                ))
                return result

            # 7. Parse test results
            if os.path.exists(results_json_path):
                result = self._parse_results_json(results_json_path, result)

            # If no tests were collected (e.g., target module syntax error causing
            # import failure), fall back to parsing pytest output for error info
            if result.total == 0 and proc.returncode != 0:
                result = self._parse_pytest_output(proc, result)

            # 8. Parse coverage results if available
            if _measure_coverage and os.path.exists(coverage_json_path):
                result = self._parse_coverage_json(coverage_json_path, result)

        return result

    def _parse_results_json(self, json_path: str, result: TestSuiteResult) -> TestSuiteResult:
        """Parse the results.json written by the conftest ResultCollector plugin."""
        try:
            with open(json_path, "r") as f:
                data = json.load(f)
        except (json.JSONDecodeError, IOError):
            result.errors = 1
            result.total = 1
            result.tests.append(TestResult(
                name="result_parse_error",
                passed=False,
                error="Failed to parse test results JSON",
            ))
            return result

        for test_data in data:
            test_result = TestResult(
                name=test_data.get("name", "unknown"),
                passed=test_data.get("passed", False),
                error=test_data.get("error"),
                output=test_data.get("output", ""),
                mock_security_access=test_data.get("mock_security_access"),
            )
            result.tests.append(test_result)
            if test_result.passed:
                result.passed += 1
            else:
                if test_result.error:
                    result.errors += 1
                result.failed += 1

        result.total = len(result.tests)
        return result

    def _parse_pytest_output(
        self, proc: subprocess.CompletedProcess, result: TestSuiteResult
    ) -> TestSuiteResult:
        """Fallback: parse pytest text output if results.json was not written."""
        combined = (proc.stdout or "") + "\n" + (proc.stderr or "")
        combined = combined.strip()

        # If pytest couldn't even start (e.g., conftest import error, syntax error in test)
        if proc.returncode != 0 and not result.tests:
            error_msg = combined[:1000] if combined else f"pytest exited with code {proc.returncode}"

            # Try to extract the actual error type from the output
            if "SyntaxError" in error_msg:
                error_msg = f"SyntaxError: {error_msg}"
            elif "ImportError" in error_msg:
                error_msg = f"ImportError: {error_msg}"
            elif "ModuleNotFoundError" in error_msg:
                error_msg = f"ModuleNotFoundError: {error_msg}"

            result.errors = 1
            result.total = 1
            result.tests.append(TestResult(
                name="pytest_execution",
                passed=False,
                error=error_msg,
            ))

        return result

    def _parse_coverage_json(self, json_path: str, result: TestSuiteResult) -> TestSuiteResult:
        """Parse coverage.json from pytest-cov and update result with coverage metrics."""
        try:
            with open(json_path, "r") as f:
                data = json.load(f)

            # Coverage.py JSON format has "files" dict with file paths as keys
            # Each file has "executed_lines", "missing_lines", "summary"
            files = data.get("files", {})

            # Find target_module.py in the coverage data
            for file_path, file_data in files.items():
                if "target_module.py" in file_path:
                    summary = file_data.get("summary", {})
                    result.lines_covered = summary.get("covered_lines", 0)
                    result.lines_total = summary.get("num_statements", result.lines_total)

                    # Calculate coverage percentage
                    if result.lines_total > 0:
                        result.line_coverage = result.lines_covered / result.lines_total
                    break

            # Also check totals if target_module not found individually
            if result.lines_covered == 0:
                totals = data.get("totals", {})
                if totals:
                    result.lines_covered = totals.get("covered_lines", 0)
                    result.lines_total = totals.get("num_statements", result.lines_total)
                    if result.lines_total > 0:
                        result.line_coverage = result.lines_covered / result.lines_total

        except (json.JSONDecodeError, IOError, KeyError):
            # Coverage parsing failed, leave defaults (0)
            pass

        return result

    def _count_executable_lines(self, code: str) -> set:
        """Count executable lines in code (excluding comments, blanks, docstrings)."""
        try:
            tree = ast.parse(code)
            executable_lines = set()
            for node in ast.walk(tree):
                if hasattr(node, "lineno"):
                    # Skip docstrings
                    if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant):
                        if isinstance(node.value.value, str):
                            continue
                    executable_lines.add(node.lineno)
            return executable_lines
        except Exception:
            # Fallback: count non-empty, non-comment lines
            lines = set()
            for i, line in enumerate(code.split("\n"), 1):
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    lines.add(i)
            return lines

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
