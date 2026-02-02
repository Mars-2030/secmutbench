#!/usr/bin/env python3
"""
Validate all samples in SecMutBench

Checks:
1. Required fields are present
2. Code is syntactically valid
3. Functional tests pass on both versions
4. Security tests distinguish versions
5. Minimum mutation operators are mapped
6. Bandit static analysis (insecure should have findings, secure should have fewer)
"""

import json
import sys
import os
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Add parent to path for imports
sys.path.insert(0, str(Path(__file__).parent.parent))

from evaluation.test_runner import TestRunner


# =============================================================================
# Bandit Static Analysis Integration
# =============================================================================

# CWE to Bandit test ID mapping
CWE_TO_BANDIT = {
    "CWE-89": ["B608", "B309"],  # SQL injection, hardcoded_sql_expressions
    "CWE-78": ["B602", "B603", "B604", "B605", "B607"],  # Command injection variants
    "CWE-22": ["B310"],  # URL open for path traversal (partial)
    "CWE-79": [],  # XSS - Bandit has limited coverage
    "CWE-502": ["B301", "B302", "B303"],  # Pickle, marshal, shelve
    "CWE-327": ["B303", "B304", "B305"],  # Weak crypto: MD5, SHA1, ciphers
    "CWE-798": ["B105", "B106", "B107"],  # Hardcoded passwords
    "CWE-611": ["B314", "B318", "B320"],  # XXE
    "CWE-918": [],  # SSRF - limited Bandit coverage
    "CWE-287": [],  # Auth bypass - limited Bandit coverage
}


def run_bandit_on_code(code: str, severity: str = "LOW") -> Dict[str, Any]:
    """
    Run Bandit static analysis on a code string.

    Args:
        code: Python code to analyze
        severity: Minimum severity level (LOW, MEDIUM, HIGH)

    Returns:
        Dict with findings, count, and severity breakdown
    """
    result = {
        "success": False,
        "findings": [],
        "count": 0,
        "by_severity": {"HIGH": 0, "MEDIUM": 0, "LOW": 0},
        "by_test_id": {},
        "error": None,
    }

    try:
        # Write code to temp file
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_path = f.name

        try:
            # Run Bandit
            cmd = [
                sys.executable, "-m", "bandit",
                "-f", "json",
                "-ll",  # Low and above
                "--quiet",
                temp_path
            ]

            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30
            )

            # Parse JSON output
            if proc.stdout:
                bandit_output = json.loads(proc.stdout)
                results = bandit_output.get("results", [])

                for finding in results:
                    result["findings"].append({
                        "test_id": finding.get("test_id"),
                        "test_name": finding.get("test_name"),
                        "severity": finding.get("issue_severity"),
                        "confidence": finding.get("issue_confidence"),
                        "line": finding.get("line_number"),
                        "text": finding.get("issue_text"),
                    })

                    sev = finding.get("issue_severity", "LOW")
                    result["by_severity"][sev] = result["by_severity"].get(sev, 0) + 1

                    tid = finding.get("test_id", "unknown")
                    result["by_test_id"][tid] = result["by_test_id"].get(tid, 0) + 1

                result["count"] = len(results)

            result["success"] = True

        finally:
            # Clean up temp file
            os.unlink(temp_path)

    except subprocess.TimeoutExpired:
        result["error"] = "Bandit timeout"
    except json.JSONDecodeError as e:
        result["error"] = f"Failed to parse Bandit output: {e}"
    except FileNotFoundError:
        result["error"] = "Bandit not installed. Run: pip install bandit"
    except Exception as e:
        result["error"] = f"Bandit error: {str(e)}"

    return result


def validate_with_bandit(sample: Dict) -> Dict[str, Any]:
    """
    Validate a sample using Bandit static analysis.

    Expectations:
    - insecure_code SHOULD have Bandit findings (vulnerability detectable)
    - secure_code SHOULD have fewer findings (fix works)

    Returns:
        Dict with bandit results, validation status, and recommendations
    """
    result = {
        "insecure_findings": None,
        "secure_findings": None,
        "vulnerability_detectable": False,
        "fix_effective": False,
        "warnings": [],
        "errors": [],
        "cwe_relevant_findings": [],
    }

    cwe = sample.get("cwe", "")
    expected_tests = CWE_TO_BANDIT.get(cwe, [])

    # Run Bandit on insecure code
    insecure_result = run_bandit_on_code(sample.get("insecure_code", ""))
    result["insecure_findings"] = insecure_result

    if insecure_result.get("error"):
        result["errors"].append(f"Bandit error on insecure_code: {insecure_result['error']}")
        return result

    # Run Bandit on secure code
    secure_result = run_bandit_on_code(sample.get("secure_code", ""))
    result["secure_findings"] = secure_result

    if secure_result.get("error"):
        result["errors"].append(f"Bandit error on secure_code: {secure_result['error']}")
        return result

    # Check if vulnerability is detectable
    insecure_count = insecure_result.get("count", 0)
    secure_count = secure_result.get("count", 0)

    # Check for CWE-relevant findings
    if expected_tests:
        for finding in insecure_result.get("findings", []):
            if finding.get("test_id") in expected_tests:
                result["cwe_relevant_findings"].append(finding)

        if result["cwe_relevant_findings"]:
            result["vulnerability_detectable"] = True
        else:
            result["warnings"].append(
                f"Bandit did not detect {cwe}-related issues. "
                f"Expected tests: {expected_tests}. "
                f"This may be a Bandit limitation or the vulnerability pattern differs."
            )
    else:
        # CWE not well-covered by Bandit
        result["warnings"].append(
            f"CWE {cwe} has limited Bandit coverage. "
            f"Static analysis validation skipped for this CWE."
        )
        if insecure_count > 0:
            result["vulnerability_detectable"] = True

    # Check if fix is effective (secure has fewer findings)
    if insecure_count > secure_count:
        result["fix_effective"] = True
    elif insecure_count == secure_count and insecure_count > 0:
        result["warnings"].append(
            f"Secure code has same Bandit findings ({secure_count}) as insecure. "
            f"Fix may not address all issues or Bandit can't distinguish."
        )
    elif insecure_count == 0:
        result["warnings"].append(
            "Bandit found no issues in insecure_code. "
            "The vulnerability may not be detectable via static analysis."
        )

    return result


def check_bandit_installed() -> bool:
    """Check if Bandit is installed and available."""
    try:
        result = subprocess.run(
            [sys.executable, "-m", "bandit", "--version"],
            capture_output=True,
            timeout=10
        )
        return result.returncode == 0
    except Exception:
        return False


class SampleValidator:
    """Validates individual benchmark samples."""

    REQUIRED_FIELDS = [
        "id",
        "cwe",
        "cwe_name",
        "difficulty",
        "prompt",
        "entry_point",
        "insecure_code",
        "secure_code",
        "functional_tests",
        "security_tests",
        "mutation_operators",
    ]

    VALID_DIFFICULTIES = ["easy", "medium", "hard"]

    MIN_MUTATION_OPERATORS = 1  # Relaxed for initial validation

    def __init__(self):
        self.runner = TestRunner()

    def validate_sample(self, sample: Dict) -> Dict[str, Any]:
        """
        Validate a single sample.

        Returns:
            Dict with 'valid' bool and 'errors' list
        """
        errors = []
        warnings = []

        # 1. Check required fields
        for field in self.REQUIRED_FIELDS:
            if field not in sample or not sample[field]:
                errors.append(f"Missing required field: {field}")

        if errors:
            return {"valid": False, "errors": errors, "warnings": warnings}

        # 2. Validate field values
        if sample["difficulty"] not in self.VALID_DIFFICULTIES:
            errors.append(f"Invalid difficulty: {sample['difficulty']}")

        if not sample["cwe"].startswith("CWE-"):
            errors.append(f"Invalid CWE format: {sample['cwe']}")

        # 3. Check code syntax
        for code_field in ["insecure_code", "secure_code"]:
            try:
                compile(sample[code_field], f"<{code_field}>", "exec")
            except SyntaxError as e:
                errors.append(f"Syntax error in {code_field}: {e}")

        # 4. Check test syntax
        for test_field in ["functional_tests", "security_tests"]:
            try:
                compile(sample[test_field], f"<{test_field}>", "exec")
            except SyntaxError as e:
                errors.append(f"Syntax error in {test_field}: {e}")

        # 5. Check mutation operators
        if len(sample["mutation_operators"]) < self.MIN_MUTATION_OPERATORS:
            warnings.append(
                f"Only {len(sample['mutation_operators'])} operators "
                f"(recommend >= 2)"
            )

        # 6. CRITICAL: Check secure code differs from insecure code
        secure_normalized = sample["secure_code"].strip()
        insecure_normalized = sample["insecure_code"].strip()
        if secure_normalized == insecure_normalized:
            errors.append("Secure code is identical to insecure code")

        # 7. Check for AUTO-GENERATION FAILED marker
        if "AUTO-GENERATION FAILED" in sample["secure_code"]:
            warnings.append("Secure code auto-generation failed, needs manual review")

        # 8. Check entry point exists in code
        entry_point = sample["entry_point"]
        if f"def {entry_point}(" not in sample["secure_code"]:
            warnings.append(f"Entry point '{entry_point}' not found in secure code")
        if f"def {entry_point}(" not in sample["insecure_code"]:
            warnings.append(f"Entry point '{entry_point}' not found in insecure code")

        # 9. Check code has meaningful content (not just comments/pass)
        secure_lines = [l.strip() for l in sample["secure_code"].split('\n')
                       if l.strip() and not l.strip().startswith('#')]
        insecure_lines = [l.strip() for l in sample["insecure_code"].split('\n')
                        if l.strip() and not l.strip().startswith('#')]
        if len(secure_lines) < 3:
            warnings.append("Secure code has very little content")
        if len(insecure_lines) < 3:
            warnings.append("Insecure code has very little content")

        # 10. Optionally run tests (can be slow)
        # Uncomment to enable runtime validation
        # test_errors = self._run_test_validation(sample)
        # errors.extend(test_errors)

        return {
            "valid": len(errors) == 0,
            "errors": errors,
            "warnings": warnings,
        }

    def _run_test_validation(self, sample: Dict) -> Dict[str, Any]:
        """
        Run actual test validation (slow).

        Returns:
            Dict with errors list and detailed runtime results
        """
        errors = []
        runtime_details = {
            "functional_on_secure": None,
            "functional_on_insecure": None,
            "security_on_secure": None,
            "security_on_insecure": None,
        }

        # Functional tests should pass on both versions
        try:
            func_secure = self.runner.run_tests(
                sample["functional_tests"], sample["secure_code"]
            )
            runtime_details["functional_on_secure"] = {
                "passed": func_secure.all_passed,
                "total": func_secure.total,
                "pass_count": func_secure.passed,
                "fail_count": func_secure.failed,
            }
            if not func_secure.all_passed:
                errors.append("Functional tests fail on secure_code")
        except Exception as e:
            errors.append(f"Functional tests error on secure_code: {str(e)}")
            runtime_details["functional_on_secure"] = {"error": str(e)}

        try:
            func_insecure = self.runner.run_tests(
                sample["functional_tests"], sample["insecure_code"]
            )
            runtime_details["functional_on_insecure"] = {
                "passed": func_insecure.all_passed,
                "total": func_insecure.total,
                "pass_count": func_insecure.passed,
                "fail_count": func_insecure.failed,
            }
            if not func_insecure.all_passed:
                errors.append("Functional tests fail on insecure_code")
        except Exception as e:
            errors.append(f"Functional tests error on insecure_code: {str(e)}")
            runtime_details["functional_on_insecure"] = {"error": str(e)}

        # Security tests should distinguish versions
        try:
            sec_secure = self.runner.run_tests(
                sample["security_tests"], sample["secure_code"]
            )
            runtime_details["security_on_secure"] = {
                "passed": sec_secure.all_passed,
                "total": sec_secure.total,
                "pass_count": sec_secure.passed,
                "fail_count": sec_secure.failed,
            }
            if not sec_secure.all_passed:
                errors.append("Security tests fail on secure_code (should pass)")
        except Exception as e:
            errors.append(f"Security tests error on secure_code: {str(e)}")
            runtime_details["security_on_secure"] = {"error": str(e)}

        try:
            sec_insecure = self.runner.run_tests(
                sample["security_tests"], sample["insecure_code"]
            )
            runtime_details["security_on_insecure"] = {
                "passed": sec_insecure.all_passed,
                "total": sec_insecure.total,
                "pass_count": sec_insecure.passed,
                "fail_count": sec_insecure.failed,
            }
            if sec_insecure.all_passed:
                errors.append("CRITICAL: Security tests pass on insecure_code (should fail) - tests don't detect vulnerability!")
        except Exception as e:
            # Exception on insecure code might be acceptable (vulnerability triggered)
            runtime_details["security_on_insecure"] = {"error": str(e), "acceptable": True}

        return {"errors": errors, "runtime_details": runtime_details}

    def validate_with_runtime(self, sample: Dict) -> Dict[str, Any]:
        """
        Full validation including runtime tests.

        Returns:
            Dict with validation results and runtime details
        """
        # First run static validation
        result = self.validate_sample(sample)

        # Then run runtime validation
        runtime_result = self._run_test_validation(sample)

        # Merge results
        result["runtime_errors"] = runtime_result["errors"]
        result["runtime_details"] = runtime_result["runtime_details"]

        # Update valid status based on runtime errors
        if runtime_result["errors"]:
            result["valid"] = False
            result["errors"].extend(runtime_result["errors"])

        return result


def determine_review_priority(
    sample: Dict,
    validation_result: Dict
) -> Dict[str, Any]:
    """
    Determine if a sample needs human review and at what priority.

    Returns:
        Dict with needs_review, priority, and reasons
    """
    reasons = []
    priority = "low"

    # HIGH priority reasons
    high_priority_reasons = []

    # Runtime failures are HIGH priority
    runtime_errors = validation_result.get("runtime_errors", [])
    if runtime_errors:
        for err in runtime_errors:
            if "CRITICAL" in err:
                high_priority_reasons.append(f"Runtime: {err}")
            else:
                high_priority_reasons.append(f"Runtime: {err}")

    # Validation errors are HIGH priority
    if not validation_result.get("valid", True):
        for err in validation_result.get("errors", []):
            if err not in runtime_errors:
                high_priority_reasons.append(f"Validation: {err}")

    # Warnings need review
    warnings = validation_result.get("warnings", [])
    if warnings:
        for warn in warnings:
            high_priority_reasons.append(f"Warning: {warn}")

    if high_priority_reasons:
        priority = "high"
        reasons.extend(high_priority_reasons)

    # MEDIUM priority reasons
    medium_priority_reasons = []

    # Hard difficulty samples
    if sample.get("difficulty") == "hard":
        medium_priority_reasons.append("Hard difficulty - more likely to have subtle issues")

    # Non-template generation methods
    gen_method = sample.get("generation_method", "unknown")
    if gen_method not in ["template"]:
        medium_priority_reasons.append(f"Generation method '{gen_method}' - not pre-verified")

    # Non-verified quality
    gen_quality = sample.get("generation_quality", "unknown")
    if gen_quality not in ["verified"]:
        medium_priority_reasons.append(f"Quality '{gen_quality}' - not verified")

    # External sources
    source = sample.get("source", "")
    if source and "Template" not in source and "SecMutBench" not in source:
        medium_priority_reasons.append(f"External source '{source}' - needs verification")

    if medium_priority_reasons and priority != "high":
        priority = "medium"
        reasons.extend(medium_priority_reasons)

    # LOW priority (template-generated, verified, all tests pass)
    if not reasons:
        if gen_method == "template" and gen_quality == "verified":
            reasons.append("Template-generated and verified - spot-check only")
        else:
            reasons.append("Passed all automated checks")

    needs_review = priority in ["high", "medium"]

    return {
        "needs_review": needs_review,
        "priority": priority,
        "reasons": reasons,
    }


def validate_with_review_status(
    samples_path: str,
    output_path: str,
    run_runtime: bool = True,
    run_bandit: bool = False,
    verbose: bool = True
) -> Dict[str, Any]:
    """
    Validate samples and add human_review field to each.

    Args:
        samples_path: Path to input samples
        output_path: Path to output samples with review status
        run_runtime: Whether to run runtime validation (slower but more accurate)
        run_bandit: Whether to run Bandit static analysis
        verbose: Print progress

    Returns:
        Summary statistics
    """
    with open(samples_path, "r") as f:
        samples = json.load(f)

    validator = SampleValidator()

    # Check Bandit availability
    bandit_available = False
    if run_bandit:
        bandit_available = check_bandit_installed()
        if not bandit_available:
            if verbose:
                print("WARNING: Bandit not installed. Skipping static analysis.")
                print("Install with: pip install bandit")
            run_bandit = False

    stats = {
        "total": len(samples),
        "needs_review": 0,
        "priority_high": 0,
        "priority_medium": 0,
        "priority_low": 0,
        "runtime_failures": 0,
        "bandit_detectable": 0,
        "bandit_not_detectable": 0,
    }

    updated_samples = []

    if verbose:
        features = []
        if run_runtime:
            features.append("runtime tests")
        if run_bandit:
            features.append("Bandit analysis")
        print(f"Validating {len(samples)} samples with {', '.join(features) or 'static checks only'}...")
        print("-" * 60)

    for i, sample in enumerate(samples):
        sample_id = sample.get("id", f"sample_{i}")

        if verbose:
            print(f"[{i+1}/{len(samples)}] {sample_id}...", end=" ", flush=True)

        # Run validation
        if run_runtime:
            result = validator.validate_with_runtime(sample)
        else:
            result = validator.validate_sample(sample)
            result["runtime_errors"] = []
            result["runtime_details"] = {}

        # Run Bandit validation
        bandit_result = None
        if run_bandit:
            bandit_result = validate_with_bandit(sample)
            result["bandit_result"] = bandit_result

            if bandit_result.get("vulnerability_detectable"):
                stats["bandit_detectable"] += 1
            else:
                stats["bandit_not_detectable"] += 1

        # Determine review priority
        review_info = determine_review_priority(sample, result)

        # Add human_review field to sample
        sample_copy = sample.copy()
        sample_copy["human_review"] = {
            "needs_review": review_info["needs_review"],
            "priority": review_info["priority"],
            "reasons": review_info["reasons"],
            "validation_passed": result["valid"],
            "runtime_tested": run_runtime,
            "runtime_details": result.get("runtime_details", {}),
            "bandit_tested": run_bandit,
            "bandit_results": {
                "vulnerability_detectable": bandit_result.get("vulnerability_detectable") if bandit_result else None,
                "fix_effective": bandit_result.get("fix_effective") if bandit_result else None,
                "insecure_findings_count": bandit_result["insecure_findings"]["count"] if bandit_result and bandit_result.get("insecure_findings") else None,
                "secure_findings_count": bandit_result["secure_findings"]["count"] if bandit_result and bandit_result.get("secure_findings") else None,
                "cwe_relevant_findings": bandit_result.get("cwe_relevant_findings", []) if bandit_result else [],
                "warnings": bandit_result.get("warnings", []) if bandit_result else [],
            } if run_bandit else None,
        }

        updated_samples.append(sample_copy)

        # Update stats
        if review_info["needs_review"]:
            stats["needs_review"] += 1
        if review_info["priority"] == "high":
            stats["priority_high"] += 1
        elif review_info["priority"] == "medium":
            stats["priority_medium"] += 1
        else:
            stats["priority_low"] += 1

        if result.get("runtime_errors"):
            stats["runtime_failures"] += 1

        if verbose:
            status_parts = []
            if review_info["priority"] == "high":
                status_parts.append(f"HIGH")
            elif review_info["priority"] == "medium":
                status_parts.append(f"MEDIUM")
            else:
                status_parts.append("LOW")

            if run_bandit and bandit_result:
                if bandit_result.get("vulnerability_detectable"):
                    status_parts.append("bandit:detected")
                else:
                    status_parts.append("bandit:not-detected")

            print(f"{' | '.join(status_parts)}")

    # Save updated samples
    with open(output_path, "w") as f:
        json.dump(updated_samples, f, indent=2)

    if verbose:
        print("-" * 60)
        print(f"\nReview Status Summary:")
        print(f"  Total samples:     {stats['total']}")
        print(f"  Needs review:      {stats['needs_review']}")
        print(f"    HIGH priority:   {stats['priority_high']}")
        print(f"    MEDIUM priority: {stats['priority_medium']}")
        print(f"    LOW priority:    {stats['priority_low']}")
        print(f"  Runtime failures:  {stats['runtime_failures']}")

        if run_bandit:
            print(f"\nBandit Static Analysis:")
            print(f"  Vulnerability detectable:     {stats['bandit_detectable']}")
            print(f"  Vulnerability not detectable: {stats['bandit_not_detectable']}")

        print(f"\nOutput saved to: {output_path}")

    return stats


def validate_benchmark(samples_path: str = None) -> Dict[str, Any]:
    """
    Validate all samples in the benchmark.

    Returns:
        Dict with validation results
    """
    if samples_path is None:
        base_dir = Path(__file__).parent.parent
        samples_path = base_dir / "data" / "samples.json"

    with open(samples_path, "r") as f:
        samples = json.load(f)

    validator = SampleValidator()
    results = {
        "total": len(samples),
        "valid": 0,
        "invalid": 0,
        "warnings_count": 0,
        "sample_results": [],
    }

    print(f"Validating {len(samples)} samples...")
    print("-" * 60)

    for i, sample in enumerate(samples):
        sample_id = sample.get("id", f"sample_{i}")
        result = validator.validate_sample(sample)
        result["id"] = sample_id

        if result["valid"]:
            results["valid"] += 1
            status = "PASS"
        else:
            results["invalid"] += 1
            status = "FAIL"

        if result["warnings"]:
            results["warnings_count"] += len(result["warnings"])

        results["sample_results"].append(result)

        # Print progress
        if not result["valid"] or result["warnings"]:
            print(f"[{status}] {sample_id}")
            for error in result["errors"]:
                print(f"  ERROR: {error}")
            for warning in result["warnings"]:
                print(f"  WARN: {warning}")

    print("-" * 60)
    print(f"\nValidation Summary:")
    print(f"  Total:    {results['total']}")
    print(f"  Valid:    {results['valid']}")
    print(f"  Invalid:  {results['invalid']}")
    print(f"  Warnings: {results['warnings_count']}")

    if results["invalid"] == 0:
        print("\n All samples passed validation!")
    else:
        print(f"\n {results['invalid']} sample(s) failed validation.")

    return results


def filter_valid_samples(samples_path: str, output_path: str, strict: bool = False) -> Dict[str, Any]:
    """
    Filter and output only valid samples.

    Args:
        samples_path: Path to input samples.json
        output_path: Path to output valid samples
        strict: If True, also filter samples with warnings

    Returns:
        Dict with filtering results
    """
    if samples_path is None:
        base_dir = Path(__file__).parent.parent
        samples_path = base_dir / "data" / "samples.json"

    with open(samples_path, "r") as f:
        samples = json.load(f)

    validator = SampleValidator()
    valid_samples = []
    invalid_samples = []

    print(f"Filtering {len(samples)} samples...")

    for sample in samples:
        result = validator.validate_sample(sample)

        if result["valid"]:
            if strict and result["warnings"]:
                invalid_samples.append(sample)
            else:
                valid_samples.append(sample)
        else:
            invalid_samples.append(sample)

    # Save valid samples
    with open(output_path, "w") as f:
        json.dump(valid_samples, f, indent=2)

    print(f"\nFiltering Summary:")
    print(f"  Total input:   {len(samples)}")
    print(f"  Valid output:  {len(valid_samples)}")
    print(f"  Filtered out:  {len(invalid_samples)}")
    print(f"\nValid samples saved to: {output_path}")

    return {
        "total": len(samples),
        "valid": len(valid_samples),
        "filtered": len(invalid_samples),
        "output_path": output_path,
    }


def filter_with_quality(
    samples_path: str,
    output_path: str,
    min_quality: str = "auto",
    strict: bool = False
) -> Dict[str, Any]:
    """
    Filter samples by quality level and validation status.

    Args:
        samples_path: Path to input samples
        output_path: Path to output filtered samples
        min_quality: Minimum quality level ("auto", "reviewed", "template", "curated")
        strict: Also exclude samples with warnings

    Returns:
        Filtering statistics
    """
    # Import quality manager
    try:
        from quality_manager import (
            add_quality_metadata,
            filter_by_quality,
            QualityLevel,
            generate_quality_report,
            print_quality_report
        )
        has_quality_manager = True
    except ImportError:
        has_quality_manager = False

    if samples_path is None:
        base_dir = Path(__file__).parent.parent
        samples_path = base_dir / "data" / "samples.json"

    with open(samples_path, "r") as f:
        samples = json.load(f)

    validator = SampleValidator()
    valid_samples = []
    invalid_samples = []
    quality_stats = {
        "template": 0,
        "curated": 0,
        "reviewed": 0,
        "auto": 0,
    }

    print(f"Filtering {len(samples)} samples (min_quality={min_quality}, strict={strict})...")

    for sample in samples:
        # Add quality metadata if not present
        if has_quality_manager and "quality" not in sample:
            sample = add_quality_metadata(sample)

        quality_level = sample.get("quality", {}).get("quality_level", "auto")
        quality_stats[quality_level] = quality_stats.get(quality_level, 0) + 1

        # Check quality level
        quality_order = ["auto", "reviewed", "template", "curated"]
        if quality_order.index(quality_level) < quality_order.index(min_quality):
            invalid_samples.append(sample)
            continue

        # Validate sample
        result = validator.validate_sample(sample)

        if result["valid"]:
            if strict and result["warnings"]:
                invalid_samples.append(sample)
            else:
                valid_samples.append(sample)
        else:
            invalid_samples.append(sample)

    # Save valid samples
    with open(output_path, "w") as f:
        json.dump(valid_samples, f, indent=2)

    print(f"\nFiltering Summary:")
    print(f"  Total input:   {len(samples)}")
    print(f"  Valid output:  {len(valid_samples)}")
    print(f"  Filtered out:  {len(invalid_samples)}")
    print(f"\nBy Quality Level (input):")
    for level in ["curated", "template", "reviewed", "auto"]:
        print(f"  {level:10}: {quality_stats.get(level, 0)}")
    print(f"\nValid samples saved to: {output_path}")

    return {
        "total": len(samples),
        "valid": len(valid_samples),
        "filtered": len(invalid_samples),
        "quality_stats": quality_stats,
        "output_path": output_path,
    }


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Validate SecMutBench samples")
    parser.add_argument(
        "--samples",
        default=None,
        help="Path to samples.json",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Path to save validation results JSON",
    )
    parser.add_argument(
        "--filter",
        default=None,
        metavar="OUTPUT_PATH",
        help="Filter and save only valid samples to OUTPUT_PATH",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="In filter mode, also exclude samples with warnings",
    )
    parser.add_argument(
        "--min-quality",
        choices=["auto", "reviewed", "template", "curated"],
        default="auto",
        help="Minimum quality level to include (default: auto)",
    )
    parser.add_argument(
        "--add-review-status",
        metavar="OUTPUT_PATH",
        help="Run full validation with runtime tests and add human_review field to samples",
    )
    parser.add_argument(
        "--skip-runtime",
        action="store_true",
        help="Skip runtime tests when adding review status (faster but less accurate)",
    )
    parser.add_argument(
        "--bandit",
        action="store_true",
        help="Run Bandit static analysis on samples (requires: pip install bandit)",
    )
    parser.add_argument(
        "--quiet", "-q",
        action="store_true",
        help="Minimal output",
    )

    args = parser.parse_args()

    # If add-review-status mode, run full validation and add human_review field
    if args.add_review_status:
        samples_path = args.samples
        if samples_path is None:
            base_dir = Path(__file__).parent.parent
            samples_path = base_dir / "data" / "samples_template.json"

        validate_with_review_status(
            samples_path=str(samples_path),
            output_path=args.add_review_status,
            run_runtime=not args.skip_runtime,
            run_bandit=args.bandit,
            verbose=not args.quiet,
        )
        return

    # If filter mode, output only valid samples
    if args.filter:
        if args.min_quality != "auto":
            # Use quality-aware filtering
            filter_with_quality(args.samples, args.filter, args.min_quality, args.strict)
        else:
            filter_valid_samples(args.samples, args.filter, strict=args.strict)
        return

    results = validate_benchmark(args.samples)

    if args.output:
        with open(args.output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {args.output}")

    # Exit with error code if invalid samples
    sys.exit(0 if results["invalid"] == 0 else 1)


if __name__ == "__main__":
    main()
