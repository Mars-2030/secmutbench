#!/usr/bin/env python3
"""
Dataset Builder - Main Orchestrator for SecMutBench

This is the single entry point for building the SecMutBench dataset.
It consolidates functionality from:
- rebuild_dataset.py
- generate_benchmark.py
- fix_dataset_issues.py

Usage:
    python scripts/dataset_builder.py --target 150 --output data/dataset.json
    python scripts/dataset_builder.py --validate-only
    python scripts/dataset_builder.py --skip-contamination
"""

import argparse
import json
import random
import re
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple

# Import from new modular components
from source_ingestion import SourceManager, CWE_REGISTRY, normalize_cwe
from sample_generator import (
    SampleGenerator, Sample, generate_id,
    get_fallback_audit_log, clear_fallback_audit_log
)

# Import existing utilities
try:
    from contamination_prevention import PerturbationPipeline
    CONTAMINATION_AVAILABLE = True
except ImportError:
    CONTAMINATION_AVAILABLE = False
    print("Warning: contamination_prevention not available")

# Import operator registry for CWE filtering
try:
    import sys
    operators_dir = str(Path(__file__).parent.parent / "operators")
    if operators_dir not in sys.path:
        sys.path.insert(0, operators_dir)
    from operators.operator_registry import CWE_OPERATOR_MAP, OPERATORS
    OPERATOR_REGISTRY_AVAILABLE = True
except ImportError:
    try:
        # Try alternate import path
        sys.path.insert(0, str(Path(__file__).parent.parent))
        from operators.operator_registry import CWE_OPERATOR_MAP, OPERATORS
        OPERATOR_REGISTRY_AVAILABLE = True
    except ImportError as e:
        OPERATOR_REGISTRY_AVAILABLE = False
        CWE_OPERATOR_MAP = {}
        OPERATORS = {}
        print(f"Warning: operator_registry not available ({e})")

try:
    from quality_manager import (
        add_quality_metadata,
        generate_quality_report,
        print_quality_report,
        filter_by_quality,
        QualityLevel
    )
    QUALITY_MANAGER_AVAILABLE = True
except ImportError:
    QUALITY_MANAGER_AVAILABLE = False
    print("Warning: quality_manager not available")

# Import mutation engine for pre-generating mutants
try:
    eval_dir = str(Path(__file__).parent.parent)
    if eval_dir not in sys.path:
        sys.path.insert(0, eval_dir)
    from evaluation.mutation_engine import MutationEngine
    MUTATION_ENGINE_AVAILABLE = True
except ImportError:
    MUTATION_ENGINE_AVAILABLE = False
    print("Warning: mutation_engine not available, mutants will not be pre-generated")

# Import test runner for VD validation
try:
    from evaluation.test_runner import TestRunner
    TEST_RUNNER_AVAILABLE = True
except ImportError:
    TEST_RUNNER_AVAILABLE = False
    print("Warning: test_runner not available, VD validation will be skipped")

# Import version
try:
    from evaluation.version import __version__ as SECMUTBENCH_VERSION
except ImportError:
    SECMUTBENCH_VERSION = "2.6.1"


# =============================================================================
# Configuration
# =============================================================================

# Distribution weights by CWE (relative weights, not absolute counts)
# Higher weight = more samples allocated during distribution balancing
# Includes ALL CWEs with SecMutBench templates to ensure they are selected
# CWEs excluded from dataset (with justification)
EXCLUDED_CWES = {
    "CWE-78",  # Removed: input validation prevents shell=True exploitation (0% kill rate)
}

# Sample IDs excluded from dataset (with justification)
EXCLUDED_SAMPLE_IDS = {
    "4766d397da50",  # CWE-306: undefined is_authenticated() causes NameError (0/13 mutants killed)
    "0563bd4bcf06",  # C5: CWE-327 SecCodePLT encrypt_password() wrong arg types (ValueError on secure+mutant)
    "3ea75447ddcf",  # C5: CWE-327 SecCodePLT encrypt_password() wrong arg types (ValueError on secure+mutant)
}

DEFAULT_CWE_WEIGHTS = {
    # Tier 1: High priority - most common/critical (weight 10-15)
    "CWE-89": 15,   # SQL Injection
    "CWE-79": 15,   # XSS
    "CWE-77": 12,   # Command Injection
    "CWE-22": 12,   # Path Traversal
    "CWE-20": 10,   # Input Validation
    "CWE-74": 10,   # Injection (generic)

    # Tier 2: Important security issues (weight 6-8)
    "CWE-287": 8,   # Improper Authentication
    "CWE-798": 8,   # Hardcoded Credentials
    "CWE-502": 8,   # Insecure Deserialization
    "CWE-306": 8,   # Missing Authentication
    "CWE-327": 6,   # Weak Cryptography
    "CWE-328": 6,   # Weak Hash
    "CWE-352": 6,   # CSRF
    "CWE-611": 6,   # XXE
    "CWE-918": 6,   # SSRF
    "CWE-94": 6,    # Code Injection
    "CWE-95": 6,    # Eval Injection

    # Tier 3: Additional security concerns (weight 4-5)
    "CWE-295": 5,   # Certificate Validation
    "CWE-319": 5,   # Cleartext Transmission
    "CWE-312": 5,   # Cleartext Storage
    "CWE-338": 5,   # Weak PRNG
    "CWE-434": 5,   # Unrestricted Upload
    "CWE-601": 5,   # Open Redirect
    "CWE-639": 5,   # IDOR
    "CWE-862": 5,   # Missing Authorization
    "CWE-863": 5,   # Incorrect Authorization
    "CWE-942": 5,   # Permissive CORS
    "CWE-1336": 5,  # SSTI

    # Tier 4: Specialized CWEs (weight 3-4)
    "CWE-116": 4,   # Improper Output Encoding
    "CWE-200": 4,   # Information Exposure
    "CWE-209": 4,   # Error Message Exposure
    "CWE-269": 4,   # Privilege Management
    "CWE-276": 4,   # Incorrect Permissions
    "CWE-281": 4,   # Improper Permissions
    "CWE-284": 4,   # Access Control
    "CWE-347": 4,   # Crypto Signature
    "CWE-362": 4,   # Race Condition
    "CWE-367": 4,   # TOCTOU
    "CWE-400": 4,   # Resource Exhaustion
    "CWE-522": 4,   # Protected Credentials
    "CWE-732": 4,   # Permission Assignment
    "CWE-770": 4,   # Resource Limits
    "CWE-915": 4,   # Mass Assignment
    "CWE-1333": 4,  # ReDoS

    # Tier 5: Path traversal variants and misc (weight 2-3)
    "CWE-16": 3,    # Configuration
    "CWE-24": 3,    # Path Traversal ../
    "CWE-32": 3,    # Path Traversal ...
    "CWE-36": 3,    # Absolute Path Traversal
    "CWE-37": 3,    # Path Traversal /absolute
    "CWE-39": 3,    # Path Traversal Windows
    "CWE-40": 3,    # Path Traversal UNC
    "CWE-73": 3,    # External Control of File Name

    # Tier 6: Additional CWEs from operator registry (weight 2)
    "CWE-90": 2,    # LDAP Injection
    "CWE-113": 2,   # HTTP Response Splitting
    "CWE-117": 2,   # Log Injection
    "CWE-215": 2,   # Debug Info Exposure
    "CWE-259": 2,   # Hardcoded Password
    "CWE-297": 2,   # Certificate Host Mismatch
    "CWE-311": 2,   # Missing Encryption
    "CWE-326": 2,   # Inadequate Encryption Strength
    "CWE-330": 2,   # Insufficiently Random Values
    "CWE-331": 2,   # Insufficient Entropy
    "CWE-346": 2,   # Origin Validation Error
    "CWE-521": 2,   # Weak Password Requirements
    "CWE-643": 2,   # XPath Injection
    "CWE-776": 2,   # Recursive Entity References (XML Bomb)
    "CWE-1004": 2,  # Sensitive Cookie Without HttpOnly
}


# =============================================================================
# Tautological Test Detection
# =============================================================================

# Patterns that indicate useless assertions (always pass, test nothing)
TAUTOLOGICAL_PATTERNS = [
    r'assert\s+True\b',                                    # assert True
    r'assert\s+result\s+is\s+not\s+None\s+or\s+result\s+is\s+None',  # always true
    r'assert\s+1\s*==\s*1',                                # assert 1 == 1
    r'assert\s+["\'].*["\']\s*$',                          # assert "string" (truthy)
    r"assert\s+['\"].*['\"]\s*$",                          # assert 'string'
]


def has_real_security_test(security_tests: str) -> bool:
    """
    Check if security tests have real assertions (not just tautological ones).

    Tautological assertions like `assert True` always pass and don't actually
    test any security property. Samples with only such assertions should be
    dropped as they inflate mutation scores without detecting real vulnerabilities.

    Args:
        security_tests: The security test code string

    Returns:
        True if at least one non-tautological assertion exists, False otherwise
    """
    if not security_tests or not security_tests.strip():
        return False

    # Remove comments and docstrings to avoid false positives
    code = re.sub(r'#.*$', '', security_tests, flags=re.MULTILINE)
    code = re.sub(r'""".*?"""', '', code, flags=re.DOTALL)
    code = re.sub(r"'''.*?'''", '', code, flags=re.DOTALL)

    # Find all assert statements
    # Match: assert <expression> (optionally followed by comma and message)
    asserts = re.findall(r'assert\s+[^,\n]+', code)

    if not asserts:
        return False  # No assertions at all

    # Check if ALL asserts are tautological
    for assertion in asserts:
        assertion_clean = assertion.strip()
        is_tautological = any(
            re.search(pat, assertion_clean, re.IGNORECASE)
            for pat in TAUTOLOGICAL_PATTERNS
        )
        if not is_tautological:
            return True  # Found at least one real assertion

    return False  # All assertions are tautological


# =============================================================================
# Dataset Builder Class
# =============================================================================

class DatasetBuilder:
    """
    Main orchestrator for building SecMutBench dataset.

    Usage:
        builder = DatasetBuilder(target_samples=150)
        samples = builder.build()
        builder.save(samples, "data/dataset.json")
    """

    def __init__(self, target_samples: int = 150, seed: int = 42):
        """
        Initialize dataset builder.

        Args:
            target_samples: Target number of samples
            seed: Random seed for reproducibility
        """
        self.target_samples = target_samples
        self.seed = seed
        self.random = random.Random(seed)

        # Initialize components
        self.source_manager = SourceManager()
        self.generator = SampleGenerator()

        if CONTAMINATION_AVAILABLE:
            self.perturbation = PerturbationPipeline(seed=seed)
        else:
            self.perturbation = None

        # Base directory
        self.base_dir = Path(__file__).parent.parent
        self.data_dir = self.base_dir / "data"

    def _load_variations(self, variations_file: str) -> List[Sample]:
        """
        Load LLM-generated variations from JSON file.

        Converts variation dicts to Sample objects with generated tests.

        Args:
            variations_file: Path to variations JSON file

        Returns:
            List of Sample objects from variations
        """
        from sample_generator import generate_functional_test, generate_security_test

        variations_path = Path(variations_file)
        if not variations_path.exists():
            print(f"  Warning: Variations file not found: {variations_file}")
            return []

        with open(variations_path) as f:
            data = json.load(f)

        variations = data.get("variations", [])
        samples = []

        for var in variations:
            cwe = var.get("cwe", "")
            entry_point = var.get("entry_point", "")
            secure_code = var.get("secure_code", "")
            insecure_code = var.get("insecure_code", "")
            prompt = var.get("prompt", "")
            difficulty = var.get("difficulty", "medium")

            if not all([cwe, entry_point, secure_code, insecure_code]):
                continue

            # Generate tests for the variation
            func_tests = generate_functional_test(entry_point, cwe, secure_code)
            sec_tests = generate_security_test(entry_point, cwe, secure_code)

            # Get CWE name and operators
            cwe_info = CWE_REGISTRY.get(cwe, {})
            cwe_name = cwe_info.get("name", cwe)
            operators = cwe_info.get("operators", [])

            sample = Sample(
                id=var.get("id", generate_id(f"llm_var_{cwe}_{entry_point}")),
                cwe=cwe,
                cwe_name=cwe_name,
                difficulty=difficulty,
                prompt=prompt,
                entry_point=entry_point,
                insecure_code=insecure_code,
                secure_code=secure_code,
                functional_tests=func_tests,
                security_tests=sec_tests,
                mutation_operators=operators,
                source="LLM_Variation",
                original_id=var.get("source_sample_id", "")
            )
            samples.append(sample)

        return samples

    def build(self,
              distribution: Optional[Dict[str, int]] = None,
              apply_contamination_prevention: bool = True,
              validate: bool = True,
              deep_validate: bool = False,
              min_samples_per_cwe: int = 3,
              skip_vd_validation: bool = False,
              variations_file: Optional[str] = None,
              verbose_drop: bool = False) -> List[Sample]:
        """
        Build the complete dataset.

        Args:
            distribution: Target samples per CWE (default: balanced)
            apply_contamination_prevention: Whether to apply perturbation
            validate: Whether to validate samples
            deep_validate: Whether to run comprehensive validation (runtime tests, Bandit)
            min_samples_per_cwe: Minimum samples per CWE to include (default: 3)
            skip_vd_validation: Skip VD validation (security tests pass on secure, fail on insecure)
            variations_file: Path to LLM-generated variations JSON file
            verbose_drop: Print detailed CWE drop reasons during filtering

        Returns:
            List of validated samples
        """
        print(f"\n{'='*60}")
        print(f"SecMutBench Dataset Builder v{SECMUTBENCH_VERSION}")
        print(f"Target: {self.target_samples} samples")
        print(f"{'='*60}\n")

        # Clear fallback audit log for fresh run
        clear_fallback_audit_log()

        # Step 1: Generate all samples from all sources
        print("Step 1: Generating samples from all sources...")
        all_samples = self.generator.generate_all(include_external=True)
        print(f"  Total raw samples: {len(all_samples)}")

        # Step 1b: Load LLM-generated variations if provided
        if variations_file:
            print(f"\nStep 1b: Loading LLM variations from {variations_file}...")
            variations = self._load_variations(variations_file)
            all_samples.extend(variations)
            print(f"  Added {len(variations)} variations, total: {len(all_samples)}")

        # Step 1.5a: Apply exclusions (CWEs and sample IDs)
        before_excl = len(all_samples)
        all_samples = [s for s in all_samples
                       if s.cwe not in EXCLUDED_CWES and s.id not in EXCLUDED_SAMPLE_IDS]
        excl_count = before_excl - len(all_samples)
        if excl_count > 0:
            print(f"  Excluded {excl_count} samples (blocked CWEs/IDs)")

        # Step 1.5b: Structural deduplication
        print("\nStep 1.5: Structural deduplication...")
        all_samples = self._structural_dedup(all_samples, max_per_pattern=2)
        print(f"  After dedup: {len(all_samples)} samples")

        # Step 2: Select samples according to distribution
        print("\nStep 2: Selecting samples for balanced distribution...")
        distribution = distribution or DEFAULT_CWE_WEIGHTS
        selected = self._select_samples(all_samples, distribution)
        print(f"  Selected: {len(selected)} samples")

        # Step 3: Apply contamination prevention (optional)
        if apply_contamination_prevention and self.perturbation:
            print("\nStep 3: Applying contamination prevention...")
            selected = self._apply_contamination_prevention(selected)
            print(f"  After perturbation: {len(selected)} samples")
        else:
            print("\nStep 3: Skipping contamination prevention")

        # Step 4: Validate samples
        if validate:
            if deep_validate:
                print("\nStep 4: Running deep validation (runtime tests + Bandit)...")
                try:
                    from validate import SampleValidator
                    deep_validator = SampleValidator()
                    valid = []
                    invalid = []
                    for sample in selected:
                        sample_dict = sample.to_dict()
                        result = deep_validator.validate_with_runtime(sample_dict)
                        if result["valid"]:
                            valid.append(sample)
                        else:
                            invalid.append({"id": sample.id, "issues": result["errors"]})
                    print(f"  Valid: {len(valid)}, Invalid: {len(invalid)}")
                    if invalid:
                        print(f"  Removed {len(invalid)} invalid samples")
                        for info in invalid[:5]:
                            print(f"    - {info['id']}: {info['issues'][:2]}")
                    selected = valid
                except ImportError as e:
                    print(f"  Warning: Deep validation unavailable ({e}), using fast validation")
                    valid, invalid = self.generator.validate_samples(selected)
                    selected = valid
            else:
                print("\nStep 4: Validating samples (fast mode)...")
                valid, invalid = self.generator.validate_samples(selected)
                print(f"  Valid: {len(valid)}, Invalid: {len(invalid)}")
                if invalid:
                    print(f"  Removed {len(invalid)} invalid samples")
                    for info in invalid[:5]:
                        print(f"    - {info['id']}: {info['issues'][:2]}")
                selected = valid
        else:
            print("\nStep 4: Skipping validation")

        # Step 5: Filter to CWEs with operators and sufficient samples
        print(f"\nStep 5: Filtering to CWEs with operators and {min_samples_per_cwe}+ samples...")
        filtered, filter_stats = self._filter_to_usable_cwes(
            selected, min_samples=min_samples_per_cwe, verbose=verbose_drop
        )
        print(f"  Before: {len(selected)} samples across {filter_stats['cwes_before']} CWEs")
        print(f"  After: {len(filtered)} samples across {filter_stats['cwes_after']} CWEs")
        if filter_stats['removed_cwes']:
            print(f"  Removed CWEs (no operator or <5 samples): {len(filter_stats['removed_cwes'])}")
        selected = filtered

        # Step 6: Fix any remaining issues
        print("\nStep 6: Fixing remaining issues...")
        fixed = self._fix_samples(selected)
        print(f"  Fixed: {len(fixed)} samples")

        # Step 7: Final validation (ensure operators fire, signatures match, VD correct)
        vd_msg = " + VD validation" if not skip_vd_validation else ""
        print(f"\nStep 7: Final validation (verify operators fire, signatures match{vd_msg})...")
        validated, val_stats = self._final_validation(fixed, skip_vd_validation=skip_vd_validation)
        print(f"  Before: {val_stats['before']} samples")
        print(f"  After: {val_stats['after']} samples")
        if val_stats['dropped']['no_operators_fire'] > 0:
            print(f"  Dropped (no operators fire): {val_stats['dropped']['no_operators_fire']}")
        if val_stats['dropped']['no_mutants_produced'] > 0:
            print(f"  Dropped (no mutants produced): {val_stats['dropped']['no_mutants_produced']}")
        if val_stats['dropped']['trivial_diff'] > 0:
            print(f"  Dropped (trivial diff): {val_stats['dropped']['trivial_diff']}")
        if val_stats['dropped']['empty_code'] > 0:
            print(f"  Dropped (empty code): {val_stats['dropped']['empty_code']}")
        if val_stats['dropped']['signature_mismatch'] > 0:
            print(f"  Dropped (signature mismatch): {val_stats['dropped']['signature_mismatch']}")
        if val_stats['dropped']['insecure_secure_code'] > 0:
            print(f"  Dropped (insecure secure_code): {val_stats['dropped']['insecure_secure_code']}")
        if val_stats['dropped']['tautological_security_test'] > 0:
            print(f"  Dropped (tautological security test): {val_stats['dropped']['tautological_security_test']}")
        if val_stats['dropped'].get('vd_both_pass', 0) > 0:
            print(f"  Dropped (VD both pass - test doesn't detect vuln): {val_stats['dropped']['vd_both_pass']}")
        if val_stats['dropped'].get('vd_both_fail', 0) > 0:
            print(f"  Dropped (VD both fail - test crashes): {val_stats['dropped']['vd_both_fail']}")
        if val_stats['dropped'].get('vd_inverted', 0) > 0:
            print(f"  Dropped (VD inverted - secure fails): {val_stats['dropped']['vd_inverted']}")

        # Print VD diagnostic breakdown if available
        vd_diag = val_stats.get('vd_diagnostics', {})
        if vd_diag:
            print("\n  VD Failure Diagnostics (by CWE|Source|Error):")
            for drop_type in ['vd_both_fail', 'vd_both_pass', 'vd_inverted']:
                if drop_type in vd_diag:
                    print(f"    {drop_type}:")
                    # Sort by count descending, show top 10
                    sorted_items = sorted(vd_diag[drop_type].items(), key=lambda x: -x[1])[:10]
                    for key, count in sorted_items:
                        print(f"      {count:4d}x {key}")

        fixed = validated

        # Step 7.5: Pre-generate mutants for each sample
        if MUTATION_ENGINE_AVAILABLE:
            print("\nStep 7.5: Pre-generating mutants...")
            fixed = self._pregenerate_mutants(fixed)
        else:
            print("\nStep 7.5: Skipping mutant pre-generation (engine not available)")

        # Step 8: Add quality metadata
        if QUALITY_MANAGER_AVAILABLE:
            print("\nStep 8: Adding quality metadata...")
            fixed = self._add_quality_metadata(fixed)
            print(f"  Quality metadata added to {len(fixed)} samples")
        else:
            print("\nStep 8: Skipping quality metadata (module not available)")

        # Step 9: Final stats
        self._print_stats(fixed)

        return fixed

    def _filter_to_usable_cwes(self, samples: List[Sample],
                               min_samples: int = 3,
                               verbose: bool = False) -> Tuple[List[Sample], Dict]:
        """
        Filter samples to only include CWEs that:
        1. Have a matching mutation operator in CWE_OPERATOR_MAP
        2. Have at least min_samples samples

        This ensures all retained samples can be mutation-tested.

        Args:
            samples: List of samples to filter
            min_samples: Minimum samples required per CWE (default: 2)
            verbose: Print detailed drop reasons for each CWE

        Returns:
            Tuple of (filtered_samples, stats_dict)
        """
        # Count samples per CWE
        cwe_counts = defaultdict(int)
        for s in samples:
            cwe_counts[s.cwe] += 1

        cwes_before = len(cwe_counts)

        # Determine which CWEs to keep
        usable_cwes = set()
        removed_cwes = []

        for cwe, count in sorted(cwe_counts.items()):
            has_operator = cwe in CWE_OPERATOR_MAP if OPERATOR_REGISTRY_AVAILABLE else True
            has_enough_samples = count >= min_samples

            if has_operator and has_enough_samples:
                usable_cwes.add(cwe)
            else:
                reason = []
                if not has_operator:
                    reason.append("no operator")
                if not has_enough_samples:
                    reason.append(f"only {count} samples (need {min_samples})")
                removed_cwes.append((cwe, ", ".join(reason)))

        # Verbose logging of drop reasons
        if verbose and removed_cwes:
            print("\n  CWE Drop Details:")
            for cwe, reason in removed_cwes:
                print(f"    [DROP] {cwe}: {reason}")
            print(f"\n  Kept CWEs ({len(usable_cwes)}): {sorted(usable_cwes)}")

        # Filter samples
        filtered = [s for s in samples if s.cwe in usable_cwes]

        stats = {
            "cwes_before": cwes_before,
            "cwes_after": len(usable_cwes),
            "samples_before": len(samples),
            "samples_after": len(filtered),
            "removed_cwes": removed_cwes,
            "usable_cwes": list(usable_cwes)
        }

        return filtered, stats

    def _select_samples(self, samples: List[Sample],
                        distribution: Dict[str, int],
                        max_per_cwe: int = 20) -> List[Sample]:
        """Select samples according to target distribution.

        Args:
            samples: All available samples
            distribution: CWE weight distribution
            max_per_cwe: Maximum samples per CWE to prevent over-representation
        """
        # Group by CWE
        by_cwe = defaultdict(list)
        for sample in samples:
            by_cwe[sample.cwe].append(sample)

        selected = []

        # Scale targets to match total
        total_target = sum(distribution.values())
        scale = self.target_samples / total_target if total_target > 0 else 1

        for cwe, target in distribution.items():
            scaled_target = max(1, int(target * scale))
            available = by_cwe.get(cwe, [])

            if not available:
                continue

            # Apply CWE cap to prevent over-representation (e.g., CWE-79)
            # Cap at max_per_cwe or scaled_target, whichever is smaller
            count = min(scaled_target, len(available), max_per_cwe)
            selected.extend(available[:count])

        # If we haven't reached target, add more from any CWE (respecting caps)
        if len(selected) < self.target_samples:
            # Count how many we already have per CWE
            cwe_counts = defaultdict(int)
            for s in selected:
                cwe_counts[s.cwe] += 1

            # Add remaining samples, respecting max_per_cwe
            remaining = []
            for s in samples:
                if s not in selected and cwe_counts[s.cwe] < max_per_cwe:
                    remaining.append(s)

            self.random.shuffle(remaining)
            needed = self.target_samples - len(selected)

            for s in remaining[:needed]:
                if cwe_counts[s.cwe] < max_per_cwe:
                    selected.append(s)
                    cwe_counts[s.cwe] += 1

        return selected

    def _structural_dedup(self, samples: List[Sample], max_per_pattern: int = 2) -> List[Sample]:
        """Remove structural near-duplicates from external sources.

        SecCodePLT generates variations by renaming variables/functions.
        After normalizing identifiers, many samples collapse to 1 structural pattern.
        Keep at most max_per_pattern representatives per structural group.

        Also removes exact secure_code duplicates (keep only 1 per identical code
        within same CWE+source), since they produce identical evaluation results.
        """
        result = []
        by_cwe_source = defaultdict(list)

        for s in samples:
            if s.source in ("SecCodePLT", "CWEval"):
                by_cwe_source[(s.cwe, s.source)].append(s)
            else:
                result.append(s)

        exact_dedup_count = 0
        structural_dedup_count = 0

        for (cwe, source), group in by_cwe_source.items():
            # Phase 1: Exact secure_code dedup (keep only 1 per identical code)
            exact_groups = defaultdict(list)
            for s in group:
                exact_groups[s.secure_code].append(s)

            unique_samples = []
            for code_key, samps in exact_groups.items():
                unique_samples.append(samps[0])
                exact_dedup_count += len(samps) - 1

            # Phase 2: Structural dedup on the unique samples
            patterns = defaultdict(list)
            for s in unique_samples:
                normalized = re.sub(r'\b[a-zA-Z_]\w*\b', 'X', s.secure_code)
                patterns[normalized].append(s)

            for pattern_key, samps in patterns.items():
                kept = samps[:max_per_pattern]
                result.extend(kept)
                structural_dedup_count += len(samps) - len(kept)

        if exact_dedup_count > 0:
            print(f"  Exact dedup: removed {exact_dedup_count} samples with identical secure_code")
        if structural_dedup_count > 0:
            print(f"  Structural dedup: removed {structural_dedup_count} near-duplicate samples")

        # Phase 3: Cross-source similarity check (catch >95% similar pairs)
        from difflib import SequenceMatcher
        similarity_dedup_count = 0
        by_cwe = defaultdict(list)
        for s in result:
            by_cwe[s.cwe].append(s)

        final_result = []
        for cwe, group in by_cwe.items():
            kept = []
            for s in group:
                is_near_dupe = False
                for existing in kept:
                    sim = SequenceMatcher(None, s.secure_code, existing.secure_code).ratio()
                    if sim > 0.95:
                        is_near_dupe = True
                        similarity_dedup_count += 1
                        break
                if not is_near_dupe:
                    kept.append(s)
            final_result.extend(kept)

        if similarity_dedup_count > 0:
            print(f"  Cross-source similarity dedup (>95%): removed {similarity_dedup_count} near-duplicate samples")

        return final_result

    def _apply_contamination_prevention(self, samples: List[Sample]) -> List[Sample]:
        """Apply perturbation pipeline to external samples."""
        if not self.perturbation:
            return samples

        perturbed = []
        for sample in samples:
            # Only perturb external samples
            if sample.source in ["SecurityEval", "CyberSecEval"]:
                try:
                    # Perturb insecure code and get rename map
                    new_insecure, rename_map = self.perturbation.rename_identifiers(
                        sample.insecure_code
                    )

                    # Apply SAME renames to secure code using regex substitution
                    # (not calling rename_identifiers again which would generate different names)
                    new_secure = sample.secure_code
                    for old_name, new_name in rename_map.items():
                        new_secure = re.sub(rf'\b{re.escape(old_name)}\b', new_name, new_secure)

                    # Update entry point if renamed
                    new_entry = rename_map.get(sample.entry_point, sample.entry_point)

                    # Update tests with new entry point
                    new_func_tests = sample.functional_tests.replace(
                        sample.entry_point, new_entry
                    )
                    new_sec_tests = sample.security_tests.replace(
                        sample.entry_point, new_entry
                    )

                    # Create new sample with perturbed code
                    perturbed_sample = Sample(
                        id=generate_id(f"perturbed_{sample.id}_{new_insecure[:50]}"),
                        cwe=sample.cwe,
                        cwe_name=sample.cwe_name,
                        difficulty=sample.difficulty,
                        prompt=sample.prompt,
                        entry_point=new_entry,
                        insecure_code=new_insecure,
                        secure_code=new_secure,
                        functional_tests=new_func_tests,
                        security_tests=new_sec_tests,
                        mutation_operators=sample.mutation_operators,
                        source=sample.source,
                        original_id=sample.original_id
                    )
                    perturbed.append(perturbed_sample)
                except Exception as e:
                    # Keep original if perturbation fails
                    perturbed.append(sample)
            else:
                perturbed.append(sample)

        return perturbed

    def _fix_samples(self, samples: List[Sample]) -> List[Sample]:
        """
        Fix common issues in samples.

        Consolidates logic from fix_dataset_issues.py:
        1. Add assertions to security tests that don't have them
        2. Generate CWE-specific security tests if missing
        3. Ensure proper difficulty estimation
        """
        fixed = []
        fixes_applied = {"assertions_added": 0, "tests_regenerated": 0, "difficulty_fixed": 0}

        for sample in samples:
            sec_tests = sample.security_tests
            difficulty = sample.difficulty

            # Fix 1: Ensure security tests have assertions
            if sec_tests and "assert" not in sec_tests:
                sec_tests = self._add_assertions_to_test(sec_tests, sample.entry_point, sample.cwe)
                fixes_applied["assertions_added"] += 1

            # Fix 2: Regenerate empty/placeholder security tests
            if not sec_tests or "# Placeholder" in sec_tests or len(sec_tests.strip()) < 50:
                sec_tests = self._generate_cwe_security_test(sample.entry_point, sample.cwe, sample.secure_code)
                fixes_applied["tests_regenerated"] += 1

            # Fix 3: Ensure proper difficulty
            if not difficulty or difficulty not in ["easy", "medium", "hard"]:
                from sample_generator import estimate_difficulty
                difficulty = estimate_difficulty(sample.insecure_code, sample.cwe)
                fixes_applied["difficulty_fixed"] += 1

            # Create fixed sample
            fixed_sample = Sample(
                id=sample.id,
                cwe=sample.cwe,
                cwe_name=sample.cwe_name,
                difficulty=difficulty,
                prompt=sample.prompt,
                entry_point=sample.entry_point,
                insecure_code=sample.insecure_code,
                secure_code=sample.secure_code,
                functional_tests=sample.functional_tests,
                security_tests=sec_tests,
                mutation_operators=sample.mutation_operators,
                source=sample.source,
                original_id=sample.original_id
            )
            fixed.append(fixed_sample)

        # Report fixes
        if any(fixes_applied.values()):
            print(f"    Fixes: {fixes_applied['assertions_added']} assertions added, "
                  f"{fixes_applied['tests_regenerated']} tests regenerated, "
                  f"{fixes_applied['difficulty_fixed']} difficulties fixed")

        return fixed

    def _add_assertions_to_test(self, test: str, entry_point: str, cwe: str) -> str:
        """Add assertions to security tests that don't have them."""
        if "assert" in test:
            return test

        lines = test.rstrip().split("\n")

        # Add assertions based on result variable presence
        has_result = any("result = " in line or "result=" in line for line in lines)

        if has_result:
            assertions = [
                "    # Security assertions",
                "    assert result is not None, 'Function returned None'",
            ]
        else:
            assertions = [
                "    # Security assertions",
                "    assert True, 'Security test completed'",
            ]

        return "\n".join(lines + assertions)

    def _generate_cwe_security_test(self, entry_point: str, cwe: str, code: str = "") -> str:
        """Generate CWE-specific security test (delegates to sample_generator)."""
        from sample_generator import generate_security_test
        # Get base CWE (without _hard suffix)
        cwe_base = cwe.split("_")[0] if "_" in cwe else cwe
        return generate_security_test(entry_point, cwe_base, code)

    def _final_validation(self, samples: List[Sample], skip_vd_validation: bool = False) -> Tuple[List[Sample], Dict]:
        """
        Final validation pass to remove samples that can't produce meaningful results.

        This is the last filter before saving, ensuring:
        1. At least one assigned operator actually fires on the code
        2. Secure code differs meaningfully from insecure code
        3. Function signature matches test calls (no TypeError at runtime)
        4. Security tests pass on secure code and fail on insecure code (VD validation)

        Args:
            samples: List of samples to validate
            skip_vd_validation: Skip VD validation step

        Returns:
            Tuple of (valid_samples, stats_dict)
        """
        import ast

        # Try to import OPERATORS for validation
        try:
            from operators.operator_registry import OPERATORS
            operators_available = True
        except ImportError:
            operators_available = False
            OPERATORS = {}

        valid = []
        dropped = {
            "no_operators_fire": 0,
            "no_mutants_produced": 0,
            "trivial_diff": 0,
            "empty_code": 0,
            "signature_mismatch": 0,
            "insecure_secure_code": 0,
            "tautological_security_test": 0,
            "vd_both_pass": 0,      # Test passes on insecure code (doesn't detect vuln)
            "vd_both_fail": 0,      # Test fails on secure code too
            "vd_inverted": 0,       # Secure fails, insecure passes
        }
        dropped_details = []

        # Initialize test runner for VD validation
        vd_runner = None
        if TEST_RUNNER_AVAILABLE:
            try:
                vd_runner = TestRunner(timeout=5.0)
            except Exception as e:
                print(f"Warning: Could not initialize TestRunner: {e}")

        # Patterns that indicate insecure code - these should NOT appear in secure_code
        INSECURE_PATTERNS = {
            'CWE-89': [
                r'\.execute\s*\([^)]*%[sd].*%',  # String formatting in SQL
                r'\.execute\s*\([^)]*\.format\(',  # .format() in SQL
                r'f["\'].*\{.*\}.*(?:SELECT|INSERT|UPDATE|DELETE)',  # f-string SQL
            ],
            'CWE-77': [
                r'shell\s*=\s*True',  # shell=True is inherently unsafe for command injection
            ],
            'CWE-78': [
                r'\bos\.popen\s*\(',  # os.popen is inherently unsafe
                r'\bos\.system\s*\(',  # os.system is inherently unsafe
                r'shell\s*=\s*True',  # shell=True without proper sanitization
            ],
        }

        def operators_produce_mutants(code: str, operator_names: List[str]) -> Tuple[bool, List[str]]:
            """Check if operators actually produce mutants (not just applies_to)."""
            working_ops = []
            for op_name in operator_names:
                if op_name in OPERATORS:
                    op = OPERATORS[op_name]
                    if op.applies_to(code):
                        mutants = op.generate_valid_mutants(code)
                        if mutants:
                            working_ops.append(op_name)
            return len(working_ops) > 0, working_ops

        def get_function_param_count(code: str, func_name: str) -> Optional[int]:
            """Get the number of parameters for a function definition."""
            try:
                tree = ast.parse(code)
                for node in ast.walk(tree):
                    if isinstance(node, ast.FunctionDef) and node.name == func_name:
                        # Count args excluding 'self' for methods
                        args = node.args.args
                        param_count = len(args)
                        # Exclude 'self' if present (method)
                        if args and args[0].arg == 'self':
                            param_count -= 1
                        return param_count
                return None
            except SyntaxError:
                return None

        def test_passes_arguments(test_code: str, func_name: str) -> bool:
            """Check if test code passes arguments to the function."""
            # Look for patterns like: func_name("...) or func_name(var)
            # But not func_name() with no arguments
            pattern = rf'\b{re.escape(func_name)}\s*\(\s*["\'\w]'
            return bool(re.search(pattern, test_code))

        for sample in samples:
            # Check 1: Non-empty code
            if not sample.secure_code.strip() or not sample.insecure_code.strip():
                dropped["empty_code"] += 1
                dropped_details.append((sample.id, "empty_code"))
                continue

            # Check 2: At least one CWE-appropriate operator produces mutants
            # IMPORTANT: Only use operators mapped to this sample's CWE to prevent
            # cross-contamination (e.g., WEAKCRYPTO firing on CWE-89 samples)
            if operators_available:
                assigned_ops = sample.mutation_operators or []

                # If no operators assigned, get from CWE_OPERATOR_MAP (strict CWE matching)
                if not assigned_ops and sample.cwe in CWE_OPERATOR_MAP:
                    assigned_ops = CWE_OPERATOR_MAP[sample.cwe]

                has_mutants, working_ops = operators_produce_mutants(sample.secure_code, assigned_ops)

                if not has_mutants:
                    # RESTRICTED fallback: only try operators for THIS CWE, not all operators
                    # This prevents cross-contamination (e.g., NULLCHECK on CWE-89)
                    cwe_ops = CWE_OPERATOR_MAP.get(sample.cwe, [])
                    if cwe_ops and cwe_ops != assigned_ops:
                        has_mutants, working_ops = operators_produce_mutants(sample.secure_code, cwe_ops)

                    if has_mutants:
                        # Update sample's operators to CWE-appropriate ones that fire
                        sample = Sample(
                            id=sample.id,
                            cwe=sample.cwe,
                            cwe_name=sample.cwe_name,
                            difficulty=sample.difficulty,
                            prompt=sample.prompt,
                            entry_point=sample.entry_point,
                            insecure_code=sample.insecure_code,
                            secure_code=sample.secure_code,
                            functional_tests=sample.functional_tests,
                            security_tests=sample.security_tests,
                            mutation_operators=working_ops[:3],  # Limit to top 3
                            source=sample.source,
                            original_id=sample.original_id
                        )
                    else:
                        # No CWE-appropriate operators fire - drop sample
                        dropped["no_mutants_produced"] += 1
                        dropped_details.append((sample.id, f"no_mutants_produced (CWE: {sample.cwe}, tried: {assigned_ops})"))
                        continue

            # Check 3: Meaningful difference between secure and insecure
            normalized_secure = re.sub(r'\s+', '', sample.secure_code)
            normalized_insecure = re.sub(r'\s+', '', sample.insecure_code)
            if normalized_secure == normalized_insecure:
                dropped["trivial_diff"] += 1
                dropped_details.append((sample.id, "trivial_diff"))
                continue

            # Check 4: Function signature matches test calls
            # If tests pass arguments but function takes none, it will crash with TypeError
            if sample.entry_point:
                param_count = get_function_param_count(sample.secure_code, sample.entry_point)
                if param_count is not None and param_count == 0:
                    # Function takes no parameters - check if tests try to pass arguments
                    all_tests = (sample.functional_tests or "") + (sample.security_tests or "")
                    if test_passes_arguments(all_tests, sample.entry_point):
                        dropped["signature_mismatch"] += 1
                        dropped_details.append((sample.id, f"signature_mismatch: {sample.entry_point}() takes 0 args but tests pass args"))
                        continue

            # Check 5: Detect insecure patterns in secure_code
            # The secure_code should NOT contain patterns that are inherently insecure
            if sample.cwe in INSECURE_PATTERNS:
                is_insecure = False
                matched_pattern = None
                for pattern in INSECURE_PATTERNS[sample.cwe]:
                    if re.search(pattern, sample.secure_code, re.IGNORECASE):
                        is_insecure = True
                        matched_pattern = pattern
                        break
                if is_insecure:
                    dropped["insecure_secure_code"] += 1
                    dropped_details.append((sample.id, f"insecure_secure_code: matched {matched_pattern}"))
                    continue

            # Check 6: Drop samples with tautological security tests
            # Tests like `assert True` always pass and don't detect any vulnerabilities
            if not has_real_security_test(sample.security_tests):
                dropped["tautological_security_test"] += 1
                dropped_details.append((sample.id, "tautological_security_test: only useless assertions"))
                continue

            # Check 7: VD Validation - security tests must pass on secure, fail on insecure
            # This ensures the tests actually detect the vulnerability
            if not skip_vd_validation and vd_runner and sample.security_tests:
                try:
                    # Run tests on secure code - should PASS
                    secure_result = vd_runner.run_tests(sample.security_tests, sample.secure_code)
                    secure_pass = secure_result.all_passed

                    # Run tests on insecure code - should FAIL
                    insecure_result = vd_runner.run_tests(sample.security_tests, sample.insecure_code)
                    insecure_pass = insecure_result.all_passed

                    if secure_pass and insecure_pass:
                        # Test doesn't detect the vulnerability - drop it
                        dropped["vd_both_pass"] += 1
                        # DIAGNOSTIC: Log CWE, source, and test snippet for analysis
                        test_snippet = sample.security_tests[:100].replace('\n', '\\n')
                        dropped_details.append((
                            sample.id,
                            f"vd_both_pass|{sample.cwe}|{sample.source}|{test_snippet}"
                        ))
                        continue
                    elif not secure_pass and not insecure_pass:
                        # Test fails on secure code too (crash or assertion issue)
                        err = secure_result.tests[0].error if secure_result.tests else "unknown"
                        # Extract full error type for diagnosis
                        err_type = err.split(":")[0] if ":" in str(err) else str(err)[:50]
                        dropped["vd_both_fail"] += 1
                        # DIAGNOSTIC: Log CWE, source, and full error
                        dropped_details.append((
                            sample.id,
                            f"vd_both_fail|{sample.cwe}|{sample.source}|{err_type}|{str(err)[:100]}"
                        ))
                        continue
                    elif not secure_pass and insecure_pass:
                        # Inverted: secure fails but insecure passes
                        err = secure_result.tests[0].error if secure_result.tests else "unknown"
                        dropped["vd_inverted"] += 1
                        dropped_details.append((
                            sample.id,
                            f"vd_inverted|{sample.cwe}|{sample.source}|{str(err)[:100]}"
                        ))
                        continue
                    # else: secure_pass and not insecure_pass - correct VD behavior
                except Exception as e:
                    # VD validation failed, skip this check but don't drop sample
                    pass

            valid.append(sample)

        # Build diagnostic summary by CWE and error type
        vd_diagnostics = defaultdict(lambda: defaultdict(int))
        for sample_id, detail in dropped_details:
            if "|" in detail:
                parts = detail.split("|")
                drop_type = parts[0]
                cwe = parts[1] if len(parts) > 1 else "unknown"
                source = parts[2] if len(parts) > 2 else "unknown"
                err_type = parts[3] if len(parts) > 3 else ""
                vd_diagnostics[drop_type][f"{cwe}|{source}|{err_type}"] += 1

        stats = {
            "before": len(samples),
            "after": len(valid),
            "dropped": dropped,
            "dropped_details": dropped_details[:50],  # More details for diagnosis
            "vd_diagnostics": dict(vd_diagnostics),  # By CWE/source/error
        }

        return valid, stats

    def _add_quality_metadata(self, samples: List[Sample]) -> List[Sample]:
        """Add quality metadata to all samples."""
        if not QUALITY_MANAGER_AVAILABLE:
            return samples

        updated = []
        for sample in samples:
            # Convert to dict, add quality, convert back
            sample_dict = sample.to_dict()
            sample_dict = add_quality_metadata(sample_dict)

            # Store quality in a way that can be serialized
            # The Sample dataclass doesn't have a quality field, so we'll
            # add it during save() by converting to dict
            sample._quality = sample_dict.get("quality", {})
            updated.append(sample)

        return updated

    def _pregenerate_mutants(self, samples: List[Sample], max_mutants: int = 30) -> List[Sample]:
        """
        Pre-generate mutants for each sample and attach as _mutants attribute.

        This ensures deterministic, reproducible mutant sets across evaluation runs.
        Uses expanded operators that generate multiple variants per mutation location.

        Args:
            samples: List of validated samples
            max_mutants: Maximum mutants per sample (increased to 30 for broader coverage)

        Returns:
            Same samples list with _mutants attribute set
        """
        total_mutants = 0
        samples_with_mutants = 0

        for sample in samples:
            # STRICT: Only use operators mapped to this sample's CWE
            # This prevents cross-contamination (e.g., HARDCODE on CWE-79)
            cwe_ops = CWE_OPERATOR_MAP.get(sample.cwe, [])
            ops = list(sample.mutation_operators or [])

            # Add any CWE-mapped operators not already assigned
            for cwe_op in cwe_ops:
                if cwe_op not in ops:
                    ops.append(cwe_op)

            engine = MutationEngine(ops if ops else None)

            try:
                mutation_result = engine.generate_mutants(
                    sample.secure_code,
                    cwe=None,
                    max_mutants=max_mutants,
                    allow_additional=False,  # Prevent cross-CWE contamination
                )

                mutants_data = []
                for mutant in mutation_result.mutants:
                    mutants_data.append({
                        "id": mutant.id,
                        "operator": mutant.operator,
                        "description": mutant.description,
                        "mutated_code": mutant.mutated_code,
                        "variant_type": mutant.variant_type,
                    })

                sample._mutants = mutants_data
                # Update mutation_operators to reflect actual operators that fired
                actual_ops = list(dict.fromkeys(m['operator'] for m in mutants_data))
                if actual_ops:
                    sample.mutation_operators = actual_ops
                total_mutants += len(mutants_data)
                if mutants_data:
                    samples_with_mutants += 1

            except Exception as e:
                sample._mutants = []
                print(f"  Warning: mutant generation failed for {sample.id}: {e}")

        avg = total_mutants / len(samples) if samples else 0
        print(f"  Total mutants: {total_mutants} across {samples_with_mutants} samples")
        print(f"  Avg mutants/sample: {avg:.1f}")
        return samples

    def _print_stats(self, samples: List[Sample]):
        """Print dataset statistics."""
        print(f"\n{'='*60}")
        print("Dataset Statistics")
        print(f"{'='*60}")

        print(f"\nTotal samples: {len(samples)}")

        # By CWE
        by_cwe = defaultdict(int)
        for s in samples:
            by_cwe[s.cwe] += 1
        print(f"\nBy CWE ({len(by_cwe)} unique):")
        for cwe in sorted(by_cwe.keys()):
            print(f"  {cwe}: {by_cwe[cwe]}")

        # By difficulty
        by_diff = defaultdict(int)
        for s in samples:
            by_diff[s.difficulty] += 1
        print(f"\nBy difficulty:")
        for diff in ["easy", "medium", "hard"]:
            print(f"  {diff}: {by_diff.get(diff, 0)}")

        # By source
        by_source = defaultdict(int)
        for s in samples:
            by_source[s.source] += 1
        print(f"\nBy source:")
        for source, count in sorted(by_source.items()):
            print(f"  {source}: {count}")

        # Quality statistics (if available)
        if QUALITY_MANAGER_AVAILABLE:
            by_quality = defaultdict(int)
            for s in samples:
                quality_level = getattr(s, '_quality', {}).get('quality_level', 'unknown')
                by_quality[quality_level] += 1
            if by_quality:
                print(f"\nBy quality level:")
                for level in ["curated", "template", "reviewed", "auto", "unknown"]:
                    if level in by_quality:
                        pct = by_quality[level] / len(samples) * 100
                        print(f"  {level}: {by_quality[level]} ({pct:.1f}%)")

    def create_splits(self, samples: List[Sample]) -> Dict[str, List[Sample]]:
        """
        Create difficulty-based splits for evaluation.

        Returns splits by difficulty level (easy/medium/hard) since
        SecMutBench is a benchmark for evaluation, not training.
        """
        splits = {"easy": [], "medium": [], "hard": []}

        for sample in samples:
            diff = sample.difficulty if sample.difficulty in splits else "medium"
            splits[diff].append(sample)

        # Shuffle each split
        for split_name in splits:
            self.random.shuffle(splits[split_name])

        return splits

    def save(self, samples: List[Sample], output_path: str):
        """
        Save dataset to JSON file.

        Args:
            samples: List of samples
            output_path: Output file path
        """
        output_path = Path(output_path)
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Build metadata
        metadata = {
            "name": "SecMutBench",
            "version": SECMUTBENCH_VERSION,
            "created": datetime.now().isoformat(),
            "total_samples": len(samples),
            "stats": {
                "by_cwe": {},
                "by_difficulty": {"easy": 0, "medium": 0, "hard": 0},
                "by_source": {}
            }
        }

        for sample in samples:
            metadata["stats"]["by_cwe"][sample.cwe] = \
                metadata["stats"]["by_cwe"].get(sample.cwe, 0) + 1
            if sample.difficulty in metadata["stats"]["by_difficulty"]:
                metadata["stats"]["by_difficulty"][sample.difficulty] += 1
            metadata["stats"]["by_source"][sample.source] = \
                metadata["stats"]["by_source"].get(sample.source, 0) + 1

        # Build dataset structure with quality metadata and pre-generated mutants
        samples_data = []
        for s in samples:
            sample_dict = s.to_dict()
            # Add quality metadata if present
            if hasattr(s, '_quality') and s._quality:
                sample_dict['quality'] = s._quality
            # Add pre-generated mutants if present
            if hasattr(s, '_mutants') and s._mutants:
                sample_dict['mutants'] = s._mutants
            samples_data.append(sample_dict)

        # Add quality stats to metadata if available
        if QUALITY_MANAGER_AVAILABLE:
            by_quality = defaultdict(int)
            for s in samples:
                level = getattr(s, '_quality', {}).get('quality_level', 'unknown')
                by_quality[level] += 1
            metadata["stats"]["by_quality"] = dict(by_quality)

        # Add operator alignment audit for paper reporting
        # Tracks which samples used CWE-aligned vs fallback operators
        fallback_log = get_fallback_audit_log()
        if fallback_log:
            cwe_aligned_fallbacks = [e for e in fallback_log if e['type'] == 'cwe_aligned_fallback']
            no_fire = [e for e in fallback_log if e['type'] == 'no_operators_fire']
            metadata["operator_audit"] = {
                "cwe_aligned_fallback_count": len(cwe_aligned_fallbacks),
                "no_operators_fire_count": len(no_fire),
                "fallback_details": cwe_aligned_fallbacks[:20],  # First 20 for inspection
                "note": "All operators are CWE-aligned. No cross-contamination fallback used."
            }

        # C11 fix: Count actual mutants per operator, not just samples
        op_counts = defaultdict(int)
        for s in samples:
            if hasattr(s, '_mutants') and s._mutants:
                for m in s._mutants:
                    op_name = m.get('operator', '')
                    if op_name:
                        op_counts[op_name] += 1
            else:
                # Fallback: count sample operators if no pre-generated mutants
                for op in (s.mutation_operators or []):
                    op_counts[op] += 1
        metadata["stats"]["by_operator"] = dict(sorted(op_counts.items(), key=lambda x: -x[1]))
        # Also store sample-level counts for reference
        op_sample_counts = defaultdict(int)
        for s in samples:
            for op in (s.mutation_operators or []):
                op_sample_counts[op] += 1
        metadata["stats"]["by_operator_samples"] = dict(sorted(op_sample_counts.items(), key=lambda x: -x[1]))

        dataset = {
            "metadata": metadata,
            "samples": samples_data
        }

        # Save
        with open(output_path, 'w') as f:
            json.dump(dataset, f, indent=2)

        print(f"\nSaved {len(samples)} samples to {output_path}")

    def save_splits(self, splits: Dict[str, List[Sample]], output_dir: str):
        """Save difficulty-based splits to separate files (easy/medium/hard)."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)

        for difficulty, samples in splits.items():
            output_path = output_dir / f"{difficulty}.json"
            # Include quality metadata and pre-generated mutants in split files
            samples_data = []
            for s in samples:
                sample_dict = s.to_dict()
                if hasattr(s, '_quality') and s._quality:
                    sample_dict['quality'] = s._quality
                if hasattr(s, '_mutants') and s._mutants:
                    sample_dict['mutants'] = s._mutants
                samples_data.append(sample_dict)
            with open(output_path, 'w') as f:
                json.dump(samples_data, f, indent=2)
            print(f"Saved {len(samples)} {difficulty} samples to {output_path}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Build SecMutBench dataset",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python dataset_builder.py --target 150
  python dataset_builder.py --target 200 --skip-contamination
  python dataset_builder.py --validate-only
        """
    )

    parser.add_argument("--target", type=int, default=150,
                        help="Target number of samples (default: 150)")
    # Use absolute paths relative to project root
    project_root = Path(__file__).parent.parent
    default_output = project_root / "data" / "dataset.json"
    default_splits = project_root / "data" / "splits"

    parser.add_argument("--output", type=str, default=str(default_output),
                        help=f"Output file path (default: {default_output})")
    parser.add_argument("--splits-dir", type=str, default=str(default_splits),
                        help="Directory for train/val/test splits")
    parser.add_argument("--skip-contamination", action="store_true",
                        help="Skip contamination prevention")
    parser.add_argument("--skip-validation", action="store_true",
                        help="Skip sample validation")
    parser.add_argument("--deep-validate", action="store_true",
                        help="Run comprehensive validation (runtime tests, Bandit analysis)")
    parser.add_argument("--validate-only", action="store_true",
                        help="Only validate existing dataset")
    parser.add_argument("--seed", type=int, default=42,
                        help="Random seed (default: 42)")
    parser.add_argument("--min-samples", type=int, default=3,
                        help="Minimum samples per CWE to include (default: 3)")
    parser.add_argument("--skip-vd-validation", action="store_true",
                        help="Skip VD validation (tests pass on secure, fail on insecure)")
    parser.add_argument("--include-variations", type=str, default=None,
                        help="Include LLM-generated variations from JSON file (e.g., data/variations.json)")
    parser.add_argument("--verbose-drop", action="store_true",
                        help="Show detailed CWE drop reasons during filtering")

    args = parser.parse_args()

    # Add scripts directory to path for imports (but don't change cwd)
    import os
    import sys
    scripts_dir = Path(__file__).parent
    if str(scripts_dir) not in sys.path:
        sys.path.insert(0, str(scripts_dir))

    if args.validate_only:
        # Just validate existing dataset
        dataset_path = Path(args.output)
        if not dataset_path.exists():
            print(f"Dataset not found: {dataset_path}")
            return

        with open(dataset_path) as f:
            data = json.load(f)

        samples_data = data.get("samples", data)
        print(f"\nValidating {len(samples_data)} samples...")

        # Convert to Sample objects for validation
        generator = SampleGenerator()
        samples = []
        for s in samples_data:
            sample = Sample(
                id=s.get("id", ""),
                cwe=s.get("cwe", ""),
                cwe_name=s.get("cwe_name", ""),
                difficulty=s.get("difficulty", "medium"),
                prompt=s.get("prompt", ""),
                entry_point=s.get("entry_point", ""),
                insecure_code=s.get("insecure_code", ""),
                secure_code=s.get("secure_code", ""),
                functional_tests=s.get("functional_tests", ""),
                security_tests=s.get("security_tests", ""),
                mutation_operators=s.get("mutation_operators", []),
                source=s.get("source", ""),
                original_id=s.get("original_id", "")
            )
            samples.append(sample)

        valid, invalid = generator.validate_samples(samples)
        print(f"\nValidation Results:")
        print(f"  Valid: {len(valid)}")
        print(f"  Invalid: {len(invalid)}")

        if invalid:
            print("\nInvalid samples:")
            for info in invalid:
                print(f"  {info['id']} ({info['cwe']}): {info['issues']}")

        return

    # Build dataset
    builder = DatasetBuilder(target_samples=args.target, seed=args.seed)

    samples = builder.build(
        apply_contamination_prevention=not args.skip_contamination,
        validate=not args.skip_validation,
        deep_validate=args.deep_validate,
        min_samples_per_cwe=args.min_samples,
        skip_vd_validation=args.skip_vd_validation,
        variations_file=args.include_variations,
        verbose_drop=args.verbose_drop
    )

    # Save main dataset
    builder.save(samples, args.output)

    # Create and save splits
    splits = builder.create_splits(samples)
    builder.save_splits(splits, args.splits_dir)

    print(f"\n{'='*60}")
    print("Dataset build complete!")
    print(f"{'='*60}")


if __name__ == "__main__":
    main()
