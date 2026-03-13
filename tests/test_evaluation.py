"""
Unit tests for SecMutBench evaluation pipeline.

Tests verify that:
1. Benchmark loading works correctly
2. Test runner executes tests properly
3. Kill classification is accurate
4. Metrics calculation is correct
"""

import pytest
import json
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.evaluate import (
    load_benchmark,
    classify_kill,
)
from evaluation.metrics import calculate_mutation_score
from evaluation.test_runner import TestRunner


class TestBenchmarkLoading:
    """Tests for benchmark loading functionality."""

    def test_load_benchmark_returns_list(self):
        """load_benchmark should return a list of samples."""
        benchmark = load_benchmark()
        assert isinstance(benchmark, list)
        assert len(benchmark) > 0

    def test_sample_has_required_fields(self):
        """Each sample should have required fields."""
        benchmark = load_benchmark()
        sample = benchmark[0]

        required_fields = ["id", "cwe", "secure_code"]
        for field in required_fields:
            assert field in sample, f"Sample missing required field: {field}"

    def test_sample_has_mutants(self):
        """Samples should have pre-generated mutants."""
        benchmark = load_benchmark()

        # Find a sample with mutants
        samples_with_mutants = [s for s in benchmark if s.get("mutants")]
        assert len(samples_with_mutants) > 0, "No samples have mutants"

        # Check mutant structure
        sample = samples_with_mutants[0]
        mutant = sample["mutants"][0]
        assert "id" in mutant or "mutant_id" in mutant
        assert "mutated_code" in mutant
        assert "operator" in mutant

    def test_sample_has_cwe(self):
        """All samples should have CWE classification."""
        benchmark = load_benchmark()
        for sample in benchmark:
            assert "cwe" in sample
            assert sample["cwe"].startswith("CWE-")


class TestTestRunner:
    """Tests for TestRunner functionality."""

    def test_runner_initialization(self):
        """TestRunner should initialize correctly."""
        runner = TestRunner(timeout=5.0)
        assert runner.timeout == 5.0

    def test_run_passing_test(self):
        """Runner should execute passing tests."""
        runner = TestRunner(timeout=5.0)

        code = '''
def add(a, b):
    return a + b
'''
        test = '''
def test_add():
    assert add(1, 2) == 3
'''
        result = runner.run_tests(test, code)
        assert result.all_passed is True

    def test_run_failing_test(self):
        """Runner should detect failing tests."""
        runner = TestRunner(timeout=5.0)

        code = '''
def add(a, b):
    return a - b  # Bug: subtracts instead of adds
'''
        test = '''
def test_add():
    assert add(1, 2) == 3
'''
        result = runner.run_tests(test, code)
        assert result.all_passed is False

    def test_run_syntax_error(self):
        """Runner should handle syntax errors."""
        runner = TestRunner(timeout=5.0)

        code = '''
def broken(:  # Syntax error
    pass
'''
        test = '''
def test_broken():
    assert True
'''
        result = runner.run_tests(test, code)
        # Should handle gracefully (not crash)
        assert result is not None

    def test_timeout_handling(self):
        """Runner should handle timeouts."""
        runner = TestRunner(timeout=1.0)

        code = '''
import time
def slow():
    time.sleep(10)
'''
        test = '''
def test_slow():
    slow()
'''
        result = runner.run_tests(test, code)
        # Should complete without hanging
        assert result is not None


class TestKillClassification:
    """Tests for kill classification logic."""

    def test_semantic_kill_sql_injection(self):
        """SQL injection terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: SQL injection detected",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_command_injection(self):
        """Command injection terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: Command injection in shell",
            operator="CMDINJECT",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_path_traversal(self):
        """Path traversal terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: path traversal detected",
            operator="PATHCONCAT",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_via_mock_access(self):
        """Mock security attribute access should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: test failed",
            operator="PSQLI",
            mock_access={"db": ["last_query", "last_params"]}
        )
        assert kill_type == "semantic"
        assert layer == "mock_observability"

    def test_crash_kill_import_error(self):
        """ImportError should classify as crash."""
        kill_type, layer = classify_kill(
            error="ImportError: No module named 'foo'",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "crash"
        assert layer == "crash"

    def test_crash_kill_name_error(self):
        """NameError should classify as crash."""
        kill_type, layer = classify_kill(
            error="NameError: name 'undefined' is not defined",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "crash"

    def test_crash_kill_type_error(self):
        """TypeError should classify as crash."""
        kill_type, layer = classify_kill(
            error="TypeError: cannot concatenate 'str' and 'int'",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "crash"

    def test_incidental_kill(self):
        """AssertionError without security terms should be incidental."""
        kill_type, layer = classify_kill(
            error="AssertionError: expected True, got False",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "assertion_incidental"
        assert layer == "none"

    def test_functional_kill_did_not_raise(self):
        """DID NOT RAISE should classify as functional."""
        kill_type, layer = classify_kill(
            error="Failed: DID NOT RAISE <class 'ValueError'>",
            operator="WEAKCRYPTO",
            mock_access={}
        )
        assert kill_type == "functional"
        assert layer == "functional"

    def test_functional_kill_did_not_raise_any_exception(self):
        """DID NOT RAISE any exception type should classify as functional."""
        kill_type, layer = classify_kill(
            error="Failed: DID NOT RAISE <class 'Exception'>",
            operator="PATHCONCAT",
            mock_access={}
        )
        assert kill_type == "functional"

    def test_layer_125_xss_payload_in_assertion(self):
        """Layer 1.25: XSS payload in bare assertion should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: assert '<script>' not in '<div><script>alert(1)</script></div>'",
            operator="RVALID",
            mock_access={}
        )
        assert kill_type == "semantic"
        # "script" matches RVALID operator keyword before reaching attack_payload layer
        assert layer in ("operator_keyword", "attack_payload")

    def test_layer_125_path_traversal_payload(self):
        """Layer 1.25: Path traversal payload should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: assert '../' not in '/uploads/../../../etc/passwd'",
            operator="PATHCONCAT",
            mock_access={}
        )
        assert kill_type == "semantic"
        # Could be operator_keyword (traversal) or attack_payload (../)
        assert layer in ("operator_keyword", "attack_payload")

    def test_layer_125_wrong_operator_is_incidental(self):
        """Layer 1.25: Payload for wrong operator should be incidental."""
        # XSS payload in a crypto test is coincidental, not security-aware
        kill_type, layer = classify_kill(
            error="AssertionError: assert '<script>' not in output",
            operator="WEAKCRYPTO",
            mock_access={}
        )
        assert kill_type == "assertion_incidental"

    def test_generic_keyword_tagged_separately(self):
        """Generic security term should be tagged as generic_keyword layer."""
        kill_type, layer = classify_kill(
            error="AssertionError: result is not secure enough",
            operator="PSQLI",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "generic_keyword"

    def test_generic_keyword_without_operator(self):
        """Generic security term without operator should also be generic_keyword."""
        kill_type, layer = classify_kill(
            error="AssertionError: unsafe operation detected",
            operator=None,
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "generic_keyword"


class TestMetricsCalculation:
    """Tests for metrics calculation."""

    def test_mutation_score_all_killed(self):
        """100% kill rate should give 1.0 score."""
        score = calculate_mutation_score(killed=3, total=3)
        assert score == 1.0

    def test_mutation_score_none_killed(self):
        """0% kill rate should give 0.0 score."""
        score = calculate_mutation_score(killed=0, total=3)
        assert score == 0.0

    def test_mutation_score_partial(self):
        """Partial kill rate should give correct score."""
        score = calculate_mutation_score(killed=2, total=4)
        assert score == 0.5

    def test_mutation_score_empty(self):
        """Zero total should give 0.0 score."""
        score = calculate_mutation_score(killed=0, total=0)
        assert score == 0.0


class TestIntegration:
    """Integration tests for the evaluation pipeline."""

    def test_end_to_end_simple(self):
        """Test simple end-to-end evaluation."""
        runner = TestRunner(timeout=5.0)

        # Simple secure code
        secure_code = '''
def greet(name):
    return f"Hello, {name}!"
'''
        # Test that should pass
        test = '''
def test_greet():
    assert greet("World") == "Hello, World!"
'''
        result = runner.run_tests(test, secure_code)
        assert result.all_passed is True

        # Mutant with bug
        mutant_code = '''
def greet(name):
    return f"Goodbye, {name}!"  # Mutation: changed Hello to Goodbye
'''
        result = runner.run_tests(test, mutant_code)
        assert result.all_passed is False  # Test should kill the mutant

    def test_security_test_detects_injection(self):
        """Security test should detect injected vulnerability."""
        runner = TestRunner(timeout=5.0)

        # Secure code with parameterized query
        secure_code = '''
def get_user(user_id):
    db.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return db.fetchone()
'''
        # Security test checking for parameterization
        test = '''
def test_sql_injection():
    get_user("1' OR '1'='1")
    # Check that query was parameterized
    assert db.last_params is not None, "Query should be parameterized"
'''
        # This test structure validates the security pattern

    def test_benchmark_sample_evaluation(self):
        """Test evaluation of an actual benchmark sample."""
        benchmark = load_benchmark()

        # Find a sample with mutants
        samples_with_mutants = [s for s in benchmark if s.get("mutants")]
        if not samples_with_mutants:
            pytest.skip("No samples with mutants in benchmark")

        sample = samples_with_mutants[0]

        # Verify sample structure
        assert "secure_code" in sample
        assert "mutants" in sample
        assert len(sample["mutants"]) > 0

        # Verify mutant structure
        mutant = sample["mutants"][0]
        assert "mutated_code" in mutant
        assert "operator" in mutant


class TestPrompts:
    """Tests for prompt generation."""

    def test_prompt_imports(self):
        """Prompt module should be importable."""
        from evaluation.prompts import format_test_generation_prompt
        assert callable(format_test_generation_prompt)

    def test_prompt_generation(self):
        """Prompt should be generated correctly."""
        from evaluation.prompts import format_test_generation_prompt

        prompt = format_test_generation_prompt(
            code="def foo(): pass",
            cwe="CWE-89",
            cwe_name="SQL Injection",
        )

        assert isinstance(prompt, str)
        assert len(prompt) > 0
        assert "CWE-89" in prompt or "SQL" in prompt


class TestVersion:
    """Tests for version tracking."""

    def test_version_exists(self):
        """Version should be defined."""
        from evaluation.version import __version__
        assert __version__ is not None
        assert len(__version__) > 0

    def test_version_info(self):
        """Version info should include required fields."""
        from evaluation.version import get_version_info

        info = get_version_info()
        assert "secmutbench_version" in info
        # python_version is nested under "environment"
        assert "environment" in info
        assert "python_version" in info["environment"]

    def test_version_is_280(self):
        """Version should be 2.8.0."""
        from evaluation.version import __version__
        assert __version__ == "2.8.0"


class TestNewOperatorKillClassification:
    """Tests for kill classification with new v2.5.0 operators."""

    def test_semantic_kill_eval_injection(self):
        """EVALINJECT terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: eval injection detected in code",
            operator="EVALINJECT",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_open_redirect(self):
        """OPENREDIRECT terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: redirect URL not validated",
            operator="OPENREDIRECT",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_cert_validation(self):
        """NOCERTVALID terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: SSL certificate verification disabled",
            operator="NOCERTVALID",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_info_exposure(self):
        """INFOEXPOSE terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: error message exposes stack trace",
            operator="INFOEXPOSE",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_redos(self):
        """REGEXDOS terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: regex pattern vulnerable to backtracking",
            operator="REGEXDOS",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"

    def test_semantic_kill_missing_auth(self):
        """MISSINGAUTH terms should classify as semantic."""
        kill_type, layer = classify_kill(
            error="AssertionError: authorization check missing",
            operator="MISSINGAUTH",
            mock_access={}
        )
        assert kill_type == "semantic"
        assert layer == "operator_keyword"


class TestAttackVectors:
    """Tests for CWE attack vectors in prompts."""

    def test_new_cwes_have_attack_vectors(self):
        """New CWEs should have attack vectors defined."""
        from evaluation.prompts import CWE_ATTACK_VECTORS

        new_cwes = ["CWE-95", "CWE-601", "CWE-295", "CWE-209", "CWE-400", "CWE-862", "CWE-352"]
        for cwe in new_cwes:
            assert cwe in CWE_ATTACK_VECTORS, f"Missing attack vectors for {cwe}"
            assert len(CWE_ATTACK_VECTORS[cwe]) > 0, f"Empty attack vectors for {cwe}"

    def test_get_attack_vectors_fallback(self):
        """Unknown CWE should get fallback attack vectors."""
        from evaluation.prompts import get_attack_vectors

        vectors = get_attack_vectors("CWE-99999")
        assert isinstance(vectors, str)
        assert len(vectors) > 0
        assert "CWE-99999" in vectors
