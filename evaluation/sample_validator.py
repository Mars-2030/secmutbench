"""
Sample Quality Pre-Check for SecMutBench

Quick validation of samples before expensive model runs.
Performs rule-based checks without LLM calls.
"""

import difflib
from dataclasses import dataclass, field
from typing import Dict, List, Tuple, Optional


@dataclass
class ValidationResult:
    """Result of sample validation."""
    sample_id: str
    is_valid: bool
    overall_score: float  # 0-1

    # Individual checks
    syntax_valid: bool = False
    structure_valid: bool = False
    codes_differ: bool = False
    entry_point_exists: bool = False
    tests_exist: bool = False
    meaningful_content: bool = False

    # Issues found
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []


class SampleValidator:
    """
    Validates SecMutBench samples before evaluation.

    Performs quick, rule-based checks:
    - Syntax validation (all code compiles)
    - Structure validation (required fields present)
    - Code difference check (secure != insecure)
    - Entry point verification
    - Test existence check
    - Meaningful content check
    """

    REQUIRED_FIELDS = [
        "id", "cwe", "secure_code", "insecure_code",
        "security_tests", "entry_point"
    ]

    OPTIONAL_FIELDS = [
        "cwe_name", "difficulty", "functional_tests", "source"
    ]

    def validate(self, sample: Dict) -> ValidationResult:
        """Run all validation checks on a sample."""
        sample_id = sample.get("id", "unknown")
        errors = []
        warnings = []
        check_results = {}

        # Run all checks
        checks = [
            ("syntax", self._check_syntax),
            ("structure", self._check_structure),
            ("code_difference", self._check_code_difference),
            ("entry_point", self._check_entry_point),
            ("tests_exist", self._check_tests_exist),
            ("meaningful", self._check_meaningful_content),
        ]

        for name, check_func in checks:
            passed, issues, warns = check_func(sample)
            check_results[name] = passed
            errors.extend(issues)
            warnings.extend(warns)

        # Calculate score
        passed_checks = sum(check_results.values())
        total_checks = len(check_results)
        overall_score = passed_checks / total_checks if total_checks > 0 else 0

        return ValidationResult(
            sample_id=sample_id,
            is_valid=len(errors) == 0,
            overall_score=overall_score,
            syntax_valid=check_results.get("syntax", False),
            structure_valid=check_results.get("structure", False),
            codes_differ=check_results.get("code_difference", False),
            entry_point_exists=check_results.get("entry_point", False),
            tests_exist=check_results.get("tests_exist", False),
            meaningful_content=check_results.get("meaningful", False),
            errors=errors,
            warnings=warnings,
        )

    def validate_batch(self, samples: List[Dict]) -> Tuple[List[ValidationResult], Dict]:
        """Validate multiple samples and return summary."""
        results = [self.validate(sample) for sample in samples]

        valid_count = sum(1 for r in results if r.is_valid)
        invalid_count = len(results) - valid_count

        # Aggregate error types
        error_types = {}
        for result in results:
            for error in result.errors:
                error_type = error.split(":")[0] if ":" in error else error[:50]
                error_types[error_type] = error_types.get(error_type, 0) + 1

        summary = {
            "total": len(results),
            "valid": valid_count,
            "invalid": invalid_count,
            "validation_rate": valid_count / len(results) if results else 0,
            "avg_score": sum(r.overall_score for r in results) / len(results) if results else 0,
            "common_errors": sorted(error_types.items(), key=lambda x: -x[1])[:5],
        }

        return results, summary

    def _check_syntax(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check all code fields are syntactically valid Python."""
        errors = []
        warnings = []
        fields = ["secure_code", "insecure_code", "security_tests"]

        # Also check functional_tests if present
        if sample.get("functional_tests"):
            fields.append("functional_tests")

        for field_name in fields:
            code = sample.get(field_name, "")
            if not code:
                continue

            try:
                compile(code, f"<{field_name}>", "exec")
            except SyntaxError as e:
                errors.append(f"Syntax error in {field_name} (line {e.lineno}): {e.msg}")

        return len(errors) == 0, errors, warnings

    def _check_structure(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check required fields are present and non-empty."""
        errors = []
        warnings = []

        for field_name in self.REQUIRED_FIELDS:
            if field_name not in sample:
                errors.append(f"Missing required field: {field_name}")
            elif not sample[field_name]:
                errors.append(f"Empty required field: {field_name}")

        # Check optional fields
        for field_name in self.OPTIONAL_FIELDS:
            if field_name not in sample or not sample[field_name]:
                warnings.append(f"Missing optional field: {field_name}")

        return len(errors) == 0, errors, warnings

    def _check_code_difference(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check secure and insecure code are meaningfully different."""
        errors = []
        warnings = []

        secure = sample.get("secure_code", "").strip()
        insecure = sample.get("insecure_code", "").strip()

        if not secure or not insecure:
            return True, errors, warnings  # Handled by structure check

        if secure == insecure:
            errors.append("Secure and insecure code are identical")
            return False, errors, warnings

        # Check they're meaningfully different (not just whitespace/comments)
        similarity = difflib.SequenceMatcher(None, secure, insecure).ratio()
        if similarity > 0.98:
            errors.append(f"Codes are nearly identical ({similarity:.1%} similar)")
            return False, errors, warnings

        if similarity > 0.90:
            warnings.append(f"Codes are very similar ({similarity:.1%}) - verify the fix is meaningful")

        return True, errors, warnings

    def _check_entry_point(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check entry point function exists in both code versions."""
        errors = []
        warnings = []

        entry = sample.get("entry_point", "")
        if not entry:
            return True, errors, warnings  # Handled by structure check

        secure_code = sample.get("secure_code", "")
        insecure_code = sample.get("insecure_code", "")

        # Check for function definition
        def_pattern = f"def {entry}("

        if def_pattern not in secure_code:
            errors.append(f"Entry point '{entry}' not found in secure_code")

        if def_pattern not in insecure_code:
            errors.append(f"Entry point '{entry}' not found in insecure_code")

        return len(errors) == 0, errors, warnings

    def _check_tests_exist(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check that test functions exist."""
        errors = []
        warnings = []

        security_tests = sample.get("security_tests", "")

        if not security_tests:
            return True, errors, warnings  # Handled by structure check

        if "def test_" not in security_tests:
            errors.append("No test functions (def test_*) found in security_tests")

        # Count tests
        test_count = security_tests.count("def test_")
        if test_count < 2:
            warnings.append(f"Only {test_count} test(s) found - consider adding more")

        # Check for assertions
        if "assert" not in security_tests:
            errors.append("No assertions found in security_tests")
        elif "assert True" in security_tests and security_tests.count("assert") == security_tests.count("assert True"):
            errors.append("Only 'assert True' found - tests have no meaningful assertions")

        # Check functional tests if present
        functional_tests = sample.get("functional_tests", "")
        if functional_tests:
            if "def test_" not in functional_tests:
                warnings.append("No test functions found in functional_tests")

        return len(errors) == 0, errors, warnings

    def _check_meaningful_content(self, sample: Dict) -> Tuple[bool, List[str], List[str]]:
        """Check code has meaningful content (not just pass/comments)."""
        errors = []
        warnings = []

        for field_name in ["secure_code", "insecure_code"]:
            code = sample.get(field_name, "")
            if not code:
                continue

            # Count meaningful lines (not empty, not comments, not just pass)
            lines = code.split('\n')
            meaningful_lines = [
                line for line in lines
                if line.strip()
                and not line.strip().startswith('#')
                and line.strip() != 'pass'
            ]

            if len(meaningful_lines) < 3:
                errors.append(f"{field_name} has insufficient meaningful content ({len(meaningful_lines)} lines)")

        return len(errors) == 0, errors, warnings


def validate_sample(sample: Dict) -> ValidationResult:
    """Convenience function to validate a single sample."""
    return SampleValidator().validate(sample)


def validate_dataset(samples: List[Dict]) -> Tuple[List[ValidationResult], Dict]:
    """Convenience function to validate a dataset."""
    return SampleValidator().validate_batch(samples)


def filter_valid_samples(samples: List[Dict]) -> Tuple[List[Dict], List[Dict]]:
    """
    Filter samples into valid and invalid sets.

    Returns:
        Tuple of (valid_samples, invalid_samples)
    """
    validator = SampleValidator()
    valid = []
    invalid = []

    for sample in samples:
        result = validator.validate(sample)
        if result.is_valid:
            valid.append(sample)
        else:
            invalid.append(sample)

    return valid, invalid


def format_validation_report(results: List[ValidationResult], summary: Dict) -> str:
    """Format a human-readable validation report."""
    lines = [
        "Sample Validation Report",
        "=" * 50,
        f"Total Samples: {summary['total']}",
        f"Valid: {summary['valid']} ({summary['validation_rate']:.1%})",
        f"Invalid: {summary['invalid']}",
        f"Average Score: {summary['avg_score']:.1%}",
        "",
    ]

    if summary.get("common_errors"):
        lines.append("Common Errors:")
        for error, count in summary["common_errors"]:
            lines.append(f"  - {error}: {count} samples")
        lines.append("")

    # List invalid samples
    invalid_results = [r for r in results if not r.is_valid]
    if invalid_results:
        lines.append("Invalid Samples:")
        for result in invalid_results[:10]:  # Limit to first 10
            lines.append(f"  {result.sample_id}:")
            for error in result.errors[:3]:  # Limit errors shown
                lines.append(f"    - {error}")
        if len(invalid_results) > 10:
            lines.append(f"  ... and {len(invalid_results) - 10} more")

    return "\n".join(lines)


if __name__ == "__main__":
    # Demo
    sample = {
        "id": "sql_injection_001",
        "cwe": "CWE-89",
        "secure_code": """
def get_user(user_id):
    cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))
    return cursor.fetchone()
""",
        "insecure_code": """
def get_user(user_id):
    cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')
    return cursor.fetchone()
""",
        "security_tests": """
def test_sql_injection():
    result = get_user("1 OR 1=1")
    assert result is None or len(result) <= 1

def test_parameterized():
    get_user(1)
    assert db.last_params is not None
""",
        "entry_point": "get_user",
    }

    result = validate_sample(sample)
    print(f"Sample: {result.sample_id}")
    print(f"Valid: {result.is_valid}")
    print(f"Score: {result.overall_score:.1%}")
    if result.errors:
        print("Errors:")
        for error in result.errors:
            print(f"  - {error}")
    if result.warnings:
        print("Warnings:")
        for warning in result.warnings:
            print(f"  - {warning}")
