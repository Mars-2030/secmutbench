#!/usr/bin/env python3
"""
Static Analysis Baselines for SecMutBench

Runs Bandit and optionally Semgrep on benchmark samples to compare
static analysis vulnerability detection against mutation testing.

This provides a baseline comparison point:
- What do traditional static analysis tools detect?
- How does this compare to LLM-generated security tests?
- Where does mutation testing add value?

Usage:
    python baselines/run_static_analysis.py
    python baselines/run_static_analysis.py --tool bandit --max-samples 50
    python baselines/run_static_analysis.py --tool semgrep --rules p/python
    python baselines/run_static_analysis.py --tool both --output results/static_analysis.json
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Project root
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from evaluation.version import get_version_info


# =============================================================================
# CWE Classification for Fair Comparison
# =============================================================================

# CWEs that Bandit HAS rules for (syntax/pattern-based detection possible)
STATIC_ANALYZABLE_CWES = {
    "CWE-78",   # Command Injection - shell=True pattern
    "CWE-89",   # SQL Injection - string formatting in queries
    "CWE-94",   # Code Injection - eval/exec usage
    "CWE-95",   # Code Injection via eval - eval/exec usage (alias of 94)
    "CWE-327",  # Weak Crypto - MD5/SHA1 usage
    "CWE-328",  # Weak Hash - reversible hash
    "CWE-338",  # Weak PRNG - random module usage
    "CWE-502",  # Deserialization - pickle/yaml.load usage
    "CWE-611",  # XXE - xml parsing without defused
    "CWE-798",  # Hardcoded Credentials - password in string
    "CWE-295",  # Certificate Validation - verify=False pattern
    "CWE-400",  # ReDoS - nested quantifiers (partial, with semgrep)
    "CWE-1333", # ReDoS - inefficient regex (alias of 400)
}

# CWEs that require dynamic/semantic analysis (logic flaws, missing controls)
DYNAMIC_ONLY_CWES = {
    "CWE-20",   # Input Validation - logic flaw, no syntax pattern
    "CWE-22",   # Path Traversal - open() is normal, validation is logic
    "CWE-79",   # XSS - missing escaping in custom functions
    "CWE-287",  # Auth Bypass - logic flaw
    "CWE-306",  # Missing Auth - absence of decorator/check
    "CWE-352",  # CSRF - missing token validation
    "CWE-284",  # Access Control - logic flaw
    "CWE-639",  # IDOR - authorization logic
    "CWE-918",  # SSRF - URL validation logic (partial static support)
    "CWE-1004", # HttpOnly Cookie - config issue
    "CWE-319",  # Cleartext Transmission - config issue
    "CWE-942",  # CORS - config issue
    "CWE-1336", # SSTI - context-dependent
    # === New CWEs added in v2.5.0 ===
    "CWE-601",  # Open Redirect - URL validation logic
    "CWE-209",  # Information Exposure - error handling logic
    "CWE-862",  # Missing Authorization - absence of checks
    "CWE-778",  # Insufficient Logging - absence of logging
}

# Why each dynamic CWE can't be detected by static analysis
DYNAMIC_CWE_REASONS = {
    "CWE-20": "Input validation is a logic property - no syntax pattern for 'missing validation'",
    "CWE-22": "Path traversal uses normal open()/Path operations - vulnerability is missing checks",
    "CWE-79": "XSS in custom render functions - static tools can't know what needs escaping",
    "CWE-287": "Authentication bypass is a logic flaw - correct code structure, wrong logic",
    "CWE-306": "Missing authentication = absence of code - can't detect what's not there",
    "CWE-352": "CSRF requires understanding request flow - missing token is absence",
    "CWE-284": "Access control is authorization logic - requires understanding data flow",
    "CWE-639": "IDOR requires understanding ownership model - semantic, not syntactic",
    "CWE-918": "SSRF URL validation is logic - requests.get() is normal usage",
    "CWE-1004": "Cookie flags are configuration - requires understanding security requirements",
    "CWE-319": "TLS configuration - requires understanding deployment context",
    "CWE-942": "CORS policy is configuration - requires understanding trust model",
    "CWE-1336": "SSTI depends on template context - requires data flow analysis",
    # === New CWEs added in v2.5.0 ===
    "CWE-601": "Open redirect uses normal redirect() - vulnerability is missing URL validation",
    "CWE-209": "Error exposure is about what info is logged - requires understanding sensitivity",
    "CWE-862": "Missing authorization = absence of checks - can't detect what's not there",
    "CWE-778": "Insufficient logging = absence of audit code - can't detect what's not there",
}


# =============================================================================
# CWE Mapping for Bandit
# =============================================================================

# Bandit test IDs to CWE mapping
# See: https://bandit.readthedocs.io/en/latest/plugins/index.html
BANDIT_TO_CWE = {
    # Shell injection
    "B602": "CWE-78",  # subprocess_popen_with_shell_equals_true
    "B603": "CWE-78",  # subprocess_without_shell_equals_true
    "B604": "CWE-78",  # any_other_function_with_shell_equals_true
    "B605": "CWE-78",  # start_process_with_a_shell
    "B606": "CWE-78",  # start_process_with_no_shell
    "B607": "CWE-78",  # start_process_with_partial_path

    # SQL Injection
    "B608": "CWE-89",  # hardcoded_sql_expressions

    # Command injection
    "B609": "CWE-78",  # linux_commands_wildcard_injection

    # Cryptography
    "B303": "CWE-327",  # blacklist: MD5, SHA1
    "B304": "CWE-327",  # blacklist: DES, Blowfish
    "B305": "CWE-327",  # blacklist: cipher modes
    "B311": "CWE-338",  # random (not cryptographically secure)
    "B324": "CWE-327",  # hashlib (insecure hash)

    # Deserialization
    "B301": "CWE-502",  # pickle
    "B302": "CWE-502",  # marshal
    "B506": "CWE-502",  # yaml_load

    # Hardcoded credentials
    "B105": "CWE-798",  # hardcoded_password_string
    "B106": "CWE-798",  # hardcoded_password_funcarg
    "B107": "CWE-798",  # hardcoded_password_default

    # SSL/TLS
    "B501": "CWE-295",  # request_with_no_cert_validation
    "B502": "CWE-327",  # ssl_with_bad_version
    "B503": "CWE-327",  # ssl_with_bad_defaults
    "B504": "CWE-327",  # ssl_with_no_version

    # Path traversal (partial)
    "B108": "CWE-22",   # hardcoded_tmp_directory

    # XML
    "B313": "CWE-611",  # xml_bad_cElementTree
    "B314": "CWE-611",  # xml_bad_ElementTree
    "B315": "CWE-611",  # xml_bad_expatreader
    "B316": "CWE-611",  # xml_bad_expatbuilder
    "B317": "CWE-611",  # xml_bad_sax
    "B318": "CWE-611",  # xml_bad_minidom
    "B319": "CWE-611",  # xml_bad_pulldom
    "B320": "CWE-611",  # xml_bad_etree

    # Eval/Exec
    "B307": "CWE-94",   # eval
    "B102": "CWE-78",   # exec_used

    # Additional mappings for v2.5.0 CWEs (some Bandit tests map to multiple CWEs)
    # B307 also covers CWE-95 (eval-based code injection)
    # B501 covers CWE-295 (certificate validation) - already mapped above

    # Flask debug
    "B201": "CWE-489",  # flask_debug_true

    # Assert
    "B101": "CWE-703",  # assert_used

    # Try/Except pass
    "B110": "CWE-390",  # try_except_pass

    # Permissions
    "B103": "CWE-732",  # set_bad_file_permissions

    # Binding
    "B104": "CWE-200",  # hardcoded_bind_all_interfaces
}

# Reverse mapping: CWE to Bandit tests
CWE_TO_BANDIT = defaultdict(list)
for bandit_id, cwe in BANDIT_TO_CWE.items():
    CWE_TO_BANDIT[cwe].append(bandit_id)


# =============================================================================
# Semgrep CWE Rules
# =============================================================================

# Common Semgrep rulesets for Python security
SEMGREP_RULESETS = {
    "default": "p/python",
    "security": "p/security-audit",
    "owasp": "p/owasp-top-ten",
    "bandit": "p/bandit",
}


# =============================================================================
# Bandit Runner
# =============================================================================

class BanditRunner:
    """Run Bandit static analysis on code samples."""

    def __init__(self, severity: str = "all"):
        """
        Initialize Bandit runner.

        Args:
            severity: Minimum severity level ("low", "medium", "high", "all")
        """
        self.severity = severity
        self._check_bandit_installed()

    def _check_bandit_installed(self):
        """Verify Bandit is installed."""
        try:
            result = subprocess.run(
                ["bandit", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError("Bandit not found")
        except FileNotFoundError:
            raise RuntimeError(
                "Bandit is not installed. Install with: pip install bandit"
            )

    def analyze_code(self, code: str, filename: str = "target.py") -> Dict[str, Any]:
        """
        Run Bandit on a code snippet.

        Args:
            code: Python source code to analyze
            filename: Virtual filename for the code

        Returns:
            Dict with findings and metadata
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)
            with open(filepath, "w") as f:
                f.write(code)

            # Run Bandit with JSON output
            cmd = [
                "bandit",
                "-f", "json",
                "-q",  # Quiet mode
                filepath,
            ]

            if self.severity != "all":
                cmd.extend(["-l", self.severity])

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # Parse JSON output
            try:
                output = json.loads(result.stdout) if result.stdout else {}
            except json.JSONDecodeError:
                output = {"errors": [result.stderr]}

            return self._process_bandit_output(output)

    def _process_bandit_output(self, output: Dict) -> Dict[str, Any]:
        """Process Bandit JSON output into standardized format."""
        findings = []
        cwes_found = set()

        for issue in output.get("results", []):
            test_id = issue.get("test_id", "")
            cwe = BANDIT_TO_CWE.get(test_id)

            finding = {
                "test_id": test_id,
                "test_name": issue.get("test_name", ""),
                "severity": issue.get("severity", ""),
                "confidence": issue.get("confidence", ""),
                "cwe": cwe,
                "line_number": issue.get("line_number"),
                "line_range": issue.get("line_range", []),
                "issue_text": issue.get("issue_text", ""),
                "more_info": issue.get("more_info", ""),
            }
            findings.append(finding)

            if cwe:
                cwes_found.add(cwe)

        return {
            "tool": "bandit",
            "findings": findings,
            "finding_count": len(findings),
            "cwes_found": sorted(list(cwes_found)),
            "metrics": output.get("metrics", {}),
            "errors": output.get("errors", []),
        }

    def analyze_sample(
        self,
        sample: Dict,
        analyze_secure: bool = True,
        analyze_insecure: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze a benchmark sample with Bandit.

        Args:
            sample: Benchmark sample dict
            analyze_secure: Whether to analyze secure code
            analyze_insecure: Whether to analyze insecure code

        Returns:
            Dict with analysis results
        """
        result = {
            "sample_id": sample["id"],
            "cwe": sample["cwe"],
            "difficulty": sample.get("difficulty", "unknown"),
        }

        if analyze_secure and "secure_code" in sample:
            result["secure_analysis"] = self.analyze_code(
                sample["secure_code"],
                f"{sample['id']}_secure.py"
            )

        if analyze_insecure and "insecure_code" in sample:
            result["insecure_analysis"] = self.analyze_code(
                sample["insecure_code"],
                f"{sample['id']}_insecure.py"
            )

        # Determine if Bandit detected the vulnerability
        if "insecure_analysis" in result:
            target_cwe = sample["cwe"]
            found_cwes = result["insecure_analysis"]["cwes_found"]
            result["vulnerability_detected"] = target_cwe in found_cwes
            result["detection_details"] = {
                "target_cwe": target_cwe,
                "found_cwes": found_cwes,
                "match": target_cwe in found_cwes,
            }

        return result


# =============================================================================
# Semgrep Runner
# =============================================================================

class SemgrepRunner:
    """Run Semgrep static analysis on code samples."""

    def __init__(self, ruleset: str = "p/python"):
        """
        Initialize Semgrep runner.

        Args:
            ruleset: Semgrep ruleset to use
        """
        self.ruleset = ruleset
        self._check_semgrep_installed()

    def _check_semgrep_installed(self):
        """Verify Semgrep is installed."""
        try:
            result = subprocess.run(
                ["semgrep", "--version"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                raise RuntimeError("Semgrep not found")
        except FileNotFoundError:
            raise RuntimeError(
                "Semgrep is not installed. Install with: pip install semgrep"
            )

    def analyze_code(self, code: str, filename: str = "target.py") -> Dict[str, Any]:
        """
        Run Semgrep on a code snippet.

        Args:
            code: Python source code to analyze
            filename: Virtual filename for the code

        Returns:
            Dict with findings and metadata
        """
        with tempfile.TemporaryDirectory() as tmpdir:
            filepath = os.path.join(tmpdir, filename)
            with open(filepath, "w") as f:
                f.write(code)

            # Run Semgrep with JSON output
            cmd = [
                "semgrep",
                "--config", self.ruleset,
                "--json",
                "--quiet",
                filepath,
            ]

            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
            )

            # Parse JSON output
            try:
                output = json.loads(result.stdout) if result.stdout else {}
            except json.JSONDecodeError:
                output = {"errors": [result.stderr]}

            return self._process_semgrep_output(output)

    def _process_semgrep_output(self, output: Dict) -> Dict[str, Any]:
        """Process Semgrep JSON output into standardized format."""
        findings = []
        cwes_found = set()

        for result in output.get("results", []):
            # Extract CWE from metadata if present
            metadata = result.get("extra", {}).get("metadata", {})
            cwe = None

            # Check various metadata fields for CWE
            if "cwe" in metadata:
                cwe_data = metadata["cwe"]
                if isinstance(cwe_data, list) and cwe_data:
                    cwe = cwe_data[0] if isinstance(cwe_data[0], str) else str(cwe_data[0])
                elif isinstance(cwe_data, str):
                    cwe = cwe_data

            # Normalize CWE format
            if cwe and not cwe.startswith("CWE-"):
                cwe = f"CWE-{cwe}"

            finding = {
                "rule_id": result.get("check_id", ""),
                "severity": result.get("extra", {}).get("severity", ""),
                "cwe": cwe,
                "line_start": result.get("start", {}).get("line"),
                "line_end": result.get("end", {}).get("line"),
                "message": result.get("extra", {}).get("message", ""),
                "metadata": metadata,
            }
            findings.append(finding)

            if cwe:
                cwes_found.add(cwe)

        return {
            "tool": "semgrep",
            "ruleset": self.ruleset,
            "findings": findings,
            "finding_count": len(findings),
            "cwes_found": sorted(list(cwes_found)),
            "errors": output.get("errors", []),
        }

    def analyze_sample(
        self,
        sample: Dict,
        analyze_secure: bool = True,
        analyze_insecure: bool = True,
    ) -> Dict[str, Any]:
        """
        Analyze a benchmark sample with Semgrep.

        Args:
            sample: Benchmark sample dict
            analyze_secure: Whether to analyze secure code
            analyze_insecure: Whether to analyze insecure code

        Returns:
            Dict with analysis results
        """
        result = {
            "sample_id": sample["id"],
            "cwe": sample["cwe"],
            "difficulty": sample.get("difficulty", "unknown"),
        }

        if analyze_secure and "secure_code" in sample:
            result["secure_analysis"] = self.analyze_code(
                sample["secure_code"],
                f"{sample['id']}_secure.py"
            )

        if analyze_insecure and "insecure_code" in sample:
            result["insecure_analysis"] = self.analyze_code(
                sample["insecure_code"],
                f"{sample['id']}_insecure.py"
            )

        # Determine if Semgrep detected the vulnerability
        if "insecure_analysis" in result:
            target_cwe = sample["cwe"]
            found_cwes = result["insecure_analysis"]["cwes_found"]
            result["vulnerability_detected"] = target_cwe in found_cwes
            result["detection_details"] = {
                "target_cwe": target_cwe,
                "found_cwes": found_cwes,
                "match": target_cwe in found_cwes,
            }

        return result


# =============================================================================
# Baseline Evaluation
# =============================================================================

def run_static_analysis_baseline(
    samples: List[Dict],
    tool: str = "bandit",
    semgrep_ruleset: str = "p/python",
    max_samples: Optional[int] = None,
    verbose: bool = False,
) -> Dict[str, Any]:
    """
    Run static analysis baseline on benchmark samples.

    Args:
        samples: List of benchmark samples
        tool: "bandit", "semgrep", or "both"
        semgrep_ruleset: Semgrep ruleset to use
        max_samples: Maximum number of samples to analyze
        verbose: Print progress

    Returns:
        Dict with baseline results including fair comparison metrics
    """
    if max_samples:
        samples = samples[:max_samples]

    results = {
        "version_info": get_version_info(),
        "metadata": {
            "tool": tool,
            "semgrep_ruleset": semgrep_ruleset if tool in ["semgrep", "both"] else None,
            "total_samples": len(samples),
            "timestamp": datetime.now().isoformat(),
        },
        "samples": [],
        "summary": {},
    }

    # Initialize runners
    bandit_runner = None
    semgrep_runner = None

    if tool in ["bandit", "both"]:
        try:
            bandit_runner = BanditRunner()
        except RuntimeError as e:
            print(f"Warning: {e}")

    if tool in ["semgrep", "both"]:
        try:
            semgrep_runner = SemgrepRunner(ruleset=semgrep_ruleset)
        except RuntimeError as e:
            print(f"Warning: {e}")

    if not bandit_runner and not semgrep_runner:
        raise RuntimeError("No static analysis tools available")

    # Analyze samples
    detection_counts = defaultdict(lambda: {"detected": 0, "total": 0})
    static_analyzable_counts = {"detected": 0, "total": 0}
    dynamic_only_counts = {"detected": 0, "total": 0}

    for i, sample in enumerate(samples):
        if verbose:
            print(f"Analyzing {i+1}/{len(samples)}: {sample['id']}")

        cwe = sample["cwe"]
        is_static_analyzable = cwe in STATIC_ANALYZABLE_CWES

        sample_result = {
            "sample_id": sample["id"],
            "cwe": cwe,
            "difficulty": sample.get("difficulty", "unknown"),
            "is_static_analyzable": is_static_analyzable,
        }

        detected_by_any = False

        if bandit_runner:
            bandit_result = bandit_runner.analyze_sample(sample)
            sample_result["bandit"] = bandit_result
            if bandit_result.get("vulnerability_detected"):
                detected_by_any = True

        if semgrep_runner:
            semgrep_result = semgrep_runner.analyze_sample(sample)
            sample_result["semgrep"] = semgrep_result
            if semgrep_result.get("vulnerability_detected"):
                detected_by_any = True

        sample_result["detected_by_any"] = detected_by_any
        results["samples"].append(sample_result)

        # Track per-CWE detection
        detection_counts[cwe]["total"] += 1
        if detected_by_any:
            detection_counts[cwe]["detected"] += 1

        # Track by analyzability category
        if is_static_analyzable:
            static_analyzable_counts["total"] += 1
            if detected_by_any:
                static_analyzable_counts["detected"] += 1
        else:
            dynamic_only_counts["total"] += 1
            if detected_by_any:
                dynamic_only_counts["detected"] += 1

    # Calculate summary statistics
    total_detected = sum(1 for s in results["samples"] if s["detected_by_any"])
    total_samples = len(results["samples"])

    # Per-CWE breakdown with analyzability classification
    per_cwe = {}
    for cwe, counts in detection_counts.items():
        is_static = cwe in STATIC_ANALYZABLE_CWES
        per_cwe[cwe] = {
            "detected": counts["detected"],
            "total": counts["total"],
            "rate": counts["detected"] / counts["total"] if counts["total"] > 0 else 0,
            "is_static_analyzable": is_static,
            "category": "static_analyzable" if is_static else "dynamic_only",
            "limitation_reason": DYNAMIC_CWE_REASONS.get(cwe) if not is_static else None,
        }

    results["summary"] = {
        "total_samples": total_samples,
        "total_detected": total_detected,
        "overall_detection_rate": total_detected / total_samples if total_samples > 0 else 0,
        "per_cwe": per_cwe,
        # Fair comparison metrics
        "fair_comparison": {
            "static_analyzable": {
                "description": "CWEs where static analysis has detection rules",
                "cwes": sorted([c for c in detection_counts.keys() if c in STATIC_ANALYZABLE_CWES]),
                "samples": static_analyzable_counts["total"],
                "detected": static_analyzable_counts["detected"],
                "rate": (static_analyzable_counts["detected"] / static_analyzable_counts["total"]
                        if static_analyzable_counts["total"] > 0 else 0),
            },
            "dynamic_only": {
                "description": "CWEs requiring semantic/dynamic analysis (logic flaws, missing controls)",
                "cwes": sorted([c for c in detection_counts.keys() if c in DYNAMIC_ONLY_CWES]),
                "samples": dynamic_only_counts["total"],
                "detected": dynamic_only_counts["detected"],
                "rate": (dynamic_only_counts["detected"] / dynamic_only_counts["total"]
                        if dynamic_only_counts["total"] > 0 else 0),
            },
        },
    }

    # Add tool-specific summaries
    if bandit_runner:
        bandit_detected = sum(
            1 for s in results["samples"]
            if s.get("bandit", {}).get("vulnerability_detected")
        )
        results["summary"]["bandit"] = {
            "detected": bandit_detected,
            "rate": bandit_detected / total_samples if total_samples > 0 else 0,
        }

    if semgrep_runner:
        semgrep_detected = sum(
            1 for s in results["samples"]
            if s.get("semgrep", {}).get("vulnerability_detected")
        )
        results["summary"]["semgrep"] = {
            "detected": semgrep_detected,
            "rate": semgrep_detected / total_samples if total_samples > 0 else 0,
        }

    return results


def print_summary(results: Dict[str, Any]):
    """Print a formatted summary of static analysis results."""
    summary = results["summary"]

    print(f"\n{'='*70}")
    print("Static Analysis Baseline Results")
    print(f"{'='*70}")

    print(f"\nTotal Samples: {summary['total_samples']}")
    print(f"Vulnerabilities Detected: {summary['total_detected']}")
    print(f"Overall Detection Rate: {summary['overall_detection_rate']:.1%}")

    if "bandit" in summary:
        print(f"\nBandit Detection Rate: {summary['bandit']['rate']:.1%}")

    if "semgrep" in summary:
        print(f"Semgrep Detection Rate: {summary['semgrep']['rate']:.1%}")

    # Fair comparison section
    fair = summary.get("fair_comparison", {})
    if fair:
        print(f"\n{'='*70}")
        print("Fair Comparison Analysis")
        print(f"{'='*70}")

        static = fair.get("static_analyzable", {})
        dynamic = fair.get("dynamic_only", {})

        print(f"\n┌─ Static-Analyzable CWEs (syntax/pattern-based)")
        print(f"│  {static.get('description', '')}")
        print(f"│  CWEs: {', '.join(static.get('cwes', []))}")
        print(f"│  Samples: {static.get('samples', 0)}")
        print(f"│  Detected: {static.get('detected', 0)}")
        print(f"│  Detection Rate: {static.get('rate', 0):.1%}")
        print(f"│")
        print(f"└─ Dynamic-Only CWEs (logic flaws, missing controls)")
        print(f"   {dynamic.get('description', '')}")
        print(f"   CWEs: {', '.join(dynamic.get('cwes', []))}")
        print(f"   Samples: {dynamic.get('samples', 0)}")
        print(f"   Detected: {dynamic.get('detected', 0)}")
        print(f"   Detection Rate: {dynamic.get('rate', 0):.1%}")

    print(f"\n{'='*70}")
    print("Detection Rate by CWE")
    print(f"{'='*70}")

    # Group by category
    static_cwes = []
    dynamic_cwes = []

    for cwe, stats in sorted(summary["per_cwe"].items()):
        if stats.get("is_static_analyzable", False):
            static_cwes.append((cwe, stats))
        else:
            dynamic_cwes.append((cwe, stats))

    if static_cwes:
        print("\n[Static-Analyzable CWEs] - Bandit has detection rules")
        for cwe, stats in static_cwes:
            bar = "█" * int(stats["rate"] * 20) + "░" * (20 - int(stats["rate"] * 20))
            print(f"  {cwe:12} {bar} {stats['rate']:5.1%} ({stats['detected']}/{stats['total']})")

    if dynamic_cwes:
        print("\n[Dynamic-Only CWEs] - Require semantic analysis")
        for cwe, stats in dynamic_cwes:
            bar = "█" * int(stats["rate"] * 20) + "░" * (20 - int(stats["rate"] * 20))
            reason = stats.get("limitation_reason", "")
            print(f"  {cwe:12} {bar} {stats['rate']:5.1%} ({stats['detected']}/{stats['total']})")
            if reason and stats["rate"] == 0:
                print(f"               └─ {reason[:60]}...")


def compare_with_mutation_testing(
    static_results: Dict[str, Any],
    mutation_results_path: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Compare static analysis results with mutation testing results.

    Args:
        static_results: Results from run_static_analysis_baseline
        mutation_results_path: Path to mutation testing results JSON

    Returns:
        Dict with comparison metrics suitable for paper
    """
    summary = static_results["summary"]
    fair = summary.get("fair_comparison", {})

    comparison = {
        "static_analysis": {
            "overall_detection_rate": summary["overall_detection_rate"],
            "static_analyzable_rate": fair.get("static_analyzable", {}).get("rate", 0),
            "dynamic_only_rate": fair.get("dynamic_only", {}).get("rate", 0),
            "per_cwe": summary["per_cwe"],
        },
        "mutation_testing": None,
        "paper_metrics": None,
    }

    if mutation_results_path and os.path.exists(mutation_results_path):
        with open(mutation_results_path) as f:
            mutation_data = json.load(f)

        # Extract mutation testing metrics
        mt_summary = mutation_data.get("summary", {})
        mt_by_cwe = mutation_data.get("by_cwe", {})

        comparison["mutation_testing"] = {
            "mutation_score": mt_summary.get("avg_mutation_score", 0),
            "vuln_detection": mt_summary.get("avg_vuln_detection", 0),
            "security_mutation_score": mt_summary.get("security_mutation_score", 0),
            "per_cwe": mt_by_cwe,
        }

        # Calculate paper-ready metrics
        static_overall = comparison["static_analysis"]["overall_detection_rate"]
        static_analyzable = comparison["static_analysis"]["static_analyzable_rate"]
        dynamic_only = comparison["static_analysis"]["dynamic_only_rate"]
        mt_vuln = comparison["mutation_testing"]["vuln_detection"]
        mt_score = comparison["mutation_testing"]["mutation_score"]

        comparison["paper_metrics"] = {
            "headline": {
                "static_analysis_overall": static_overall,
                "mutation_testing_detection": mt_vuln,
                "mutation_score": mt_score,
                "absolute_improvement": mt_vuln - static_overall,
                "relative_improvement": (
                    (mt_vuln - static_overall) / static_overall
                    if static_overall > 0 else float("inf")
                ),
            },
            "fair_comparison": {
                "static_analyzable_cwes": {
                    "static_analysis": static_analyzable,
                    "mutation_testing": mt_vuln,  # Need per-category MT data
                    "note": "On CWEs where static analysis has rules, both approaches work",
                },
                "dynamic_only_cwes": {
                    "static_analysis": dynamic_only,
                    "mutation_testing": mt_vuln,  # Need per-category MT data
                    "note": "On logic-flaw CWEs, mutation testing provides unique value",
                },
            },
            "key_findings": [
                f"Static analysis detects {static_overall:.1%} of vulnerabilities overall",
                f"On pattern-based CWEs, static analysis achieves {static_analyzable:.1%}",
                f"On logic-flaw CWEs, static analysis achieves only {dynamic_only:.1%}",
                f"Mutation testing achieves {mt_vuln:.1%} vulnerability detection",
                f"Mutation testing provides {(mt_vuln - static_overall):.1%} absolute improvement",
            ],
        }

    return comparison


def generate_latex_table(results: Dict[str, Any]) -> str:
    """Generate a LaTeX table for the paper."""
    summary = results["summary"]
    per_cwe = summary["per_cwe"]

    lines = [
        r"\begin{table}[h]",
        r"\centering",
        r"\caption{Static Analysis Detection Rates by CWE Category}",
        r"\label{tab:static-analysis}",
        r"\begin{tabular}{llrr}",
        r"\toprule",
        r"CWE & Category & Samples & Detection Rate \\",
        r"\midrule",
    ]

    # Static analyzable
    for cwe, stats in sorted(per_cwe.items()):
        if stats.get("is_static_analyzable"):
            lines.append(
                f"{cwe} & Static & {stats['total']} & {stats['rate']:.1%} \\\\"
            )

    lines.append(r"\midrule")

    # Dynamic only
    for cwe, stats in sorted(per_cwe.items()):
        if not stats.get("is_static_analyzable"):
            lines.append(
                f"{cwe} & Dynamic & {stats['total']} & {stats['rate']:.1%} \\\\"
            )

    lines.extend([
        r"\bottomrule",
        r"\end{tabular}",
        r"\end{table}",
    ])

    return "\n".join(lines)


# =============================================================================
# Main
# =============================================================================

def main():
    parser = argparse.ArgumentParser(
        description="Run static analysis baselines for SecMutBench",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "--dataset",
        default=str(PROJECT_ROOT / "data" / "dataset.json"),
        help="Path to dataset.json",
    )
    parser.add_argument(
        "--tool",
        choices=["bandit", "semgrep", "both"],
        default="bandit",
        help="Static analysis tool to use",
    )
    parser.add_argument(
        "--semgrep-rules",
        default="p/python",
        help="Semgrep ruleset (default: p/python)",
    )
    parser.add_argument(
        "--max-samples",
        type=int,
        default=None,
        help="Maximum number of samples to analyze",
    )
    parser.add_argument(
        "--cwe",
        type=str,
        default=None,
        help="Filter to specific CWE",
    )
    parser.add_argument(
        "--output",
        type=str,
        default=None,
        help="Output JSON file path",
    )
    parser.add_argument(
        "--compare-mutation",
        type=str,
        default=None,
        help="Path to mutation testing results for comparison",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Print progress",
    )
    parser.add_argument(
        "--latex",
        action="store_true",
        help="Generate LaTeX table for paper",
    )

    args = parser.parse_args()

    # Load dataset
    print(f"Loading dataset from {args.dataset}...")
    with open(args.dataset) as f:
        data = json.load(f)

    samples = data.get("samples", data)
    if isinstance(samples, dict):
        samples = samples.get("samples", [])

    print(f"Loaded {len(samples)} samples")

    # Filter by CWE if specified
    if args.cwe:
        samples = [s for s in samples if s["cwe"] == args.cwe]
        print(f"Filtered to {len(samples)} samples with CWE {args.cwe}")

    # Run analysis
    print(f"\nRunning {args.tool} analysis...")
    results = run_static_analysis_baseline(
        samples=samples,
        tool=args.tool,
        semgrep_ruleset=args.semgrep_rules,
        max_samples=args.max_samples,
        verbose=args.verbose,
    )

    # Print summary
    print_summary(results)

    # Compare with mutation testing if provided
    if args.compare_mutation:
        print(f"\n{'='*60}")
        print("Comparison with Mutation Testing")
        print(f"{'='*60}")

        comparison = compare_with_mutation_testing(results, args.compare_mutation)

        if comparison["mutation_testing"]:
            print(f"\nStatic Analysis Detection Rate: {comparison['static_analysis']['detection_rate']:.1%}")
            print(f"Mutation Testing Detection Rate: {comparison['mutation_testing']['vuln_detection']:.1%}")
            print(f"Improvement: {comparison['comparison']['improvement']:+.1%}")
        else:
            print(f"\nMutation testing results not found at: {args.compare_mutation}")

    # Generate LaTeX table if requested
    if args.latex:
        print(f"\n{'='*70}")
        print("LaTeX Table")
        print(f"{'='*70}")
        print(generate_latex_table(results))

    # Save results
    if args.output:
        output_path = Path(args.output)
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {output_path}")
    else:
        default_output = PROJECT_ROOT / "results" / "static_analysis_baseline.json"
        default_output.parent.mkdir(parents=True, exist_ok=True)
        with open(default_output, "w") as f:
            json.dump(results, f, indent=2)
        print(f"\nResults saved to: {default_output}")


if __name__ == "__main__":
    main()
