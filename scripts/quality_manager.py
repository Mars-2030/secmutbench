#!/usr/bin/env python3
"""
Quality Management for SecMutBench

Implements a hybrid approach with quality levels:
- template: Pre-verified template-generated samples (highest quality)
- curated: Human-reviewed and verified samples
- reviewed: Auto-generated but manually reviewed
- auto: Auto-generated, unreviewed (lowest quality)

Provides:
- Quality level assignment
- Sample merging from multiple sources
- Quality-aware filtering
- Statistics and reporting
"""

import json
import hashlib
from enum import Enum
from typing import Dict, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
from datetime import datetime


class QualityLevel(Enum):
    """Quality levels for benchmark samples."""
    TEMPLATE = "template"      # Pre-verified template-generated (highest)
    CURATED = "curated"        # Human-written and verified
    REVIEWED = "reviewed"      # Auto-generated, manually reviewed
    AUTO = "auto"              # Auto-generated, unreviewed (lowest)

    @property
    def confidence(self) -> float:
        """Confidence score for this quality level."""
        return {
            QualityLevel.TEMPLATE: 0.95,
            QualityLevel.CURATED: 0.99,
            QualityLevel.REVIEWED: 0.80,
            QualityLevel.AUTO: 0.50,
        }[self]

    @classmethod
    def from_string(cls, s: str) -> "QualityLevel":
        """Parse quality level from string."""
        return cls(s.lower())


@dataclass
class QualityMetadata:
    """Quality metadata for a sample."""
    level: QualityLevel
    generation_method: str  # "template", "transform", "manual"
    source_dataset: str     # "SecurityEval", "CyberSecEval", "SecMutBench"
    transformation_applied: bool = False
    validation_passed: bool = False
    reviewer: Optional[str] = None
    review_date: Optional[str] = None
    notes: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict:
        """Convert to dictionary for JSON serialization."""
        return {
            "quality_level": self.level.value,
            "generation_method": self.generation_method,
            "source_dataset": self.source_dataset,
            "transformation_applied": self.transformation_applied,
            "validation_passed": self.validation_passed,
            "reviewer": self.reviewer,
            "review_date": self.review_date,
            "notes": self.notes,
            "confidence": self.level.confidence,
        }


def assess_sample_quality(sample: Dict) -> Tuple[QualityLevel, List[str]]:
    """
    Assess the quality level of a sample based on its characteristics.

    Returns:
        Tuple of (quality_level, issues_found)
    """
    issues = []

    # Check for explicit quality markers
    if sample.get("generation_quality") == "verified":
        return QualityLevel.TEMPLATE, []

    if sample.get("generation_method") == "template":
        return QualityLevel.TEMPLATE, []

    if sample.get("source") == "SecMutBench" and sample.get("manually_reviewed"):
        return QualityLevel.CURATED, []

    # Check code quality indicators
    secure_code = sample.get("secure_code", "")
    insecure_code = sample.get("insecure_code", "")

    # Issue: AUTO-GENERATION FAILED marker
    if "AUTO-GENERATION FAILED" in secure_code:
        issues.append("Secure code generation failed")
        return QualityLevel.AUTO, issues

    # Issue: Secure same as insecure
    if secure_code.strip() == insecure_code.strip():
        issues.append("Secure code identical to insecure")
        return QualityLevel.AUTO, issues

    # Check syntax validity
    try:
        compile(secure_code, "<secure>", "exec")
        compile(insecure_code, "<insecure>", "exec")
    except SyntaxError as e:
        issues.append(f"Syntax error: {e}")
        return QualityLevel.AUTO, issues

    # Check entry point exists
    entry_point = sample.get("entry_point", "")
    if entry_point and f"def {entry_point}(" not in secure_code:
        issues.append(f"Entry point '{entry_point}' not in secure code")

    # Check tests compile
    for test_field in ["functional_tests", "security_tests"]:
        tests = sample.get(test_field, "")
        if tests:
            try:
                compile(tests, f"<{test_field}>", "exec")
            except SyntaxError:
                issues.append(f"{test_field} has syntax error")

    # Determine level based on issues and source
    if not issues:
        if sample.get("reviewed"):
            return QualityLevel.REVIEWED, issues
        else:
            return QualityLevel.AUTO, issues  # Valid but unreviewed
    else:
        return QualityLevel.AUTO, issues


def add_quality_metadata(sample: Dict) -> Dict:
    """Add quality metadata to a sample."""
    level, issues = assess_sample_quality(sample)

    # Determine generation method
    if sample.get("generation_method"):
        gen_method = sample["generation_method"]
    elif "AUTO-GENERATION FAILED" in sample.get("secure_code", ""):
        gen_method = "transform_failed"
    else:
        gen_method = "transform"

    # Create metadata
    metadata = QualityMetadata(
        level=level,
        generation_method=gen_method,
        source_dataset=sample.get("source", "unknown"),
        transformation_applied=gen_method.startswith("transform"),
        validation_passed=len(issues) == 0,
        notes=issues,
    )

    # Add to sample
    sample_with_quality = sample.copy()
    sample_with_quality["quality"] = metadata.to_dict()

    return sample_with_quality


def merge_sample_sources(
    template_samples: List[Dict],
    transformed_samples: List[Dict],
    curated_samples: Optional[List[Dict]] = None,
    dedupe: bool = True
) -> List[Dict]:
    """
    Merge samples from multiple sources with quality-aware deduplication.

    Priority (highest first):
    1. Curated samples
    2. Template samples
    3. Transformed samples

    Args:
        template_samples: Samples from template generator
        transformed_samples: Samples from transform_datasets.py
        curated_samples: Manually curated samples (optional)
        dedupe: Whether to deduplicate by CWE+entry_point

    Returns:
        Merged list of samples with quality metadata
    """
    merged = []
    seen_keys: Set[str] = set()

    def get_sample_key(sample: Dict) -> str:
        """Generate deduplication key."""
        cwe = sample.get("cwe", "")
        entry = sample.get("entry_point", "")
        # Also include a hash of the code for more precise deduping
        code_hash = hashlib.md5(sample.get("insecure_code", "").encode()).hexdigest()[:8]
        return f"{cwe}_{entry}_{code_hash}"

    # Process in priority order
    all_sources = []

    if curated_samples:
        for s in curated_samples:
            s = add_quality_metadata(s)
            s["quality"]["quality_level"] = "curated"
            all_sources.append((s, 1))  # Priority 1

    for s in template_samples:
        s = add_quality_metadata(s)
        all_sources.append((s, 2))  # Priority 2

    for s in transformed_samples:
        s = add_quality_metadata(s)
        all_sources.append((s, 3))  # Priority 3

    # Sort by priority
    all_sources.sort(key=lambda x: x[1])

    # Merge with deduplication
    for sample, _ in all_sources:
        key = get_sample_key(sample)

        if dedupe and key in seen_keys:
            continue

        seen_keys.add(key)
        merged.append(sample)

    return merged


def filter_by_quality(
    samples: List[Dict],
    min_level: QualityLevel = QualityLevel.AUTO,
    exclude_failed_validation: bool = False
) -> List[Dict]:
    """
    Filter samples by minimum quality level.

    Args:
        samples: List of samples with quality metadata
        min_level: Minimum quality level to include
        exclude_failed_validation: Whether to exclude samples that failed validation

    Returns:
        Filtered list of samples
    """
    level_order = [QualityLevel.AUTO, QualityLevel.REVIEWED, QualityLevel.TEMPLATE, QualityLevel.CURATED]
    min_index = level_order.index(min_level)

    filtered = []
    for sample in samples:
        quality = sample.get("quality", {})
        level_str = quality.get("quality_level", "auto")

        try:
            level = QualityLevel.from_string(level_str)
        except ValueError:
            level = QualityLevel.AUTO

        level_index = level_order.index(level)

        # Check level
        if level_index < min_index:
            continue

        # Check validation
        if exclude_failed_validation and not quality.get("validation_passed", True):
            continue

        filtered.append(sample)

    return filtered


def generate_quality_report(samples: List[Dict]) -> Dict:
    """Generate a quality report for the dataset."""
    report = {
        "total_samples": len(samples),
        "by_quality_level": {},
        "by_generation_method": {},
        "by_source": {},
        "validation_stats": {
            "passed": 0,
            "failed": 0,
        },
        "common_issues": {},
        "recommendations": [],
    }

    for sample in samples:
        quality = sample.get("quality", {})

        # By level
        level = quality.get("quality_level", "unknown")
        report["by_quality_level"][level] = report["by_quality_level"].get(level, 0) + 1

        # By generation method
        method = quality.get("generation_method", "unknown")
        report["by_generation_method"][method] = report["by_generation_method"].get(method, 0) + 1

        # By source
        source = quality.get("source_dataset", "unknown")
        report["by_source"][source] = report["by_source"].get(source, 0) + 1

        # Validation
        if quality.get("validation_passed", True):
            report["validation_stats"]["passed"] += 1
        else:
            report["validation_stats"]["failed"] += 1

        # Issues
        for note in quality.get("notes", []):
            issue_type = note.split(":")[0] if ":" in note else note
            report["common_issues"][issue_type] = report["common_issues"].get(issue_type, 0) + 1

    # Generate recommendations
    total = report["total_samples"]
    if total > 0:
        auto_pct = report["by_quality_level"].get("auto", 0) / total * 100
        if auto_pct > 50:
            report["recommendations"].append(
                f"High percentage ({auto_pct:.1f}%) of auto-generated samples. "
                "Consider adding more template or curated samples."
            )

        failed_pct = report["validation_stats"]["failed"] / total * 100
        if failed_pct > 10:
            report["recommendations"].append(
                f"High validation failure rate ({failed_pct:.1f}%). "
                "Review and fix failing samples."
            )

        if "Secure code identical to insecure" in report["common_issues"]:
            count = report["common_issues"]["Secure code identical to insecure"]
            report["recommendations"].append(
                f"{count} samples have identical secure/insecure code. "
                "These need transformation fixes."
            )

    return report


def print_quality_report(report: Dict):
    """Print a formatted quality report."""
    print("\n" + "=" * 60)
    print("QUALITY REPORT")
    print("=" * 60)

    print(f"\nTotal Samples: {report['total_samples']}")

    print("\nBy Quality Level:")
    for level, count in sorted(report["by_quality_level"].items()):
        pct = count / report["total_samples"] * 100 if report["total_samples"] > 0 else 0
        print(f"  {level:12}: {count:4} ({pct:5.1f}%)")

    print("\nBy Generation Method:")
    for method, count in sorted(report["by_generation_method"].items()):
        print(f"  {method:16}: {count}")

    print("\nBy Source Dataset:")
    for source, count in sorted(report["by_source"].items()):
        print(f"  {source:20}: {count}")

    print("\nValidation:")
    print(f"  Passed: {report['validation_stats']['passed']}")
    print(f"  Failed: {report['validation_stats']['failed']}")

    if report["common_issues"]:
        print("\nCommon Issues:")
        for issue, count in sorted(report["common_issues"].items(), key=lambda x: -x[1])[:5]:
            print(f"  {issue}: {count}")

    if report["recommendations"]:
        print("\nRecommendations:")
        for rec in report["recommendations"]:
            print(f"  - {rec}")

    print("=" * 60)


def upgrade_existing_samples(samples_path: str, output_path: str) -> Dict:
    """
    Upgrade existing samples with quality metadata.

    Args:
        samples_path: Path to existing samples.json
        output_path: Path for output with quality metadata

    Returns:
        Summary of upgrade process
    """
    with open(samples_path, "r") as f:
        samples = json.load(f)

    print(f"Upgrading {len(samples)} samples with quality metadata...")

    upgraded = []
    for sample in samples:
        upgraded.append(add_quality_metadata(sample))

    # Generate report
    report = generate_quality_report(upgraded)

    # Save upgraded samples
    with open(output_path, "w") as f:
        json.dump(upgraded, f, indent=2)

    print(f"Upgraded samples saved to: {output_path}")

    return report


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Quality management for SecMutBench")
    subparsers = parser.add_subparsers(dest="command", help="Command to run")

    # Upgrade command
    upgrade_parser = subparsers.add_parser("upgrade", help="Add quality metadata to samples")
    upgrade_parser.add_argument("--input", "-i", default="data/samples.json")
    upgrade_parser.add_argument("--output", "-o", default="data/samples_with_quality.json")

    # Report command
    report_parser = subparsers.add_parser("report", help="Generate quality report")
    report_parser.add_argument("--input", "-i", default="data/samples.json")

    # Filter command
    filter_parser = subparsers.add_parser("filter", help="Filter samples by quality")
    filter_parser.add_argument("--input", "-i", default="data/samples.json")
    filter_parser.add_argument("--output", "-o", required=True)
    filter_parser.add_argument("--min-level", choices=["auto", "reviewed", "template", "curated"],
                               default="auto")
    filter_parser.add_argument("--exclude-failed", action="store_true")

    # Merge command
    merge_parser = subparsers.add_parser("merge", help="Merge samples from multiple sources")
    merge_parser.add_argument("--template", help="Template samples file")
    merge_parser.add_argument("--transformed", help="Transformed samples file")
    merge_parser.add_argument("--curated", help="Curated samples file")
    merge_parser.add_argument("--output", "-o", required=True)

    args = parser.parse_args()

    if args.command == "upgrade":
        report = upgrade_existing_samples(args.input, args.output)
        print_quality_report(report)

    elif args.command == "report":
        with open(args.input, "r") as f:
            samples = json.load(f)

        # Add quality if not present
        samples_with_quality = []
        for s in samples:
            if "quality" not in s:
                s = add_quality_metadata(s)
            samples_with_quality.append(s)

        report = generate_quality_report(samples_with_quality)
        print_quality_report(report)

    elif args.command == "filter":
        with open(args.input, "r") as f:
            samples = json.load(f)

        # Add quality if not present
        samples = [add_quality_metadata(s) if "quality" not in s else s for s in samples]

        min_level = QualityLevel.from_string(args.min_level)
        filtered = filter_by_quality(samples, min_level, args.exclude_failed)

        with open(args.output, "w") as f:
            json.dump(filtered, f, indent=2)

        print(f"Filtered {len(samples)} -> {len(filtered)} samples")
        print(f"Output: {args.output}")

    elif args.command == "merge":
        template_samples = []
        transformed_samples = []
        curated_samples = []

        if args.template and Path(args.template).exists():
            with open(args.template) as f:
                template_samples = json.load(f)
            print(f"Loaded {len(template_samples)} template samples")

        if args.transformed and Path(args.transformed).exists():
            with open(args.transformed) as f:
                transformed_samples = json.load(f)
            print(f"Loaded {len(transformed_samples)} transformed samples")

        if args.curated and Path(args.curated).exists():
            with open(args.curated) as f:
                curated_samples = json.load(f)
            print(f"Loaded {len(curated_samples)} curated samples")

        merged = merge_sample_sources(
            template_samples,
            transformed_samples,
            curated_samples if curated_samples else None
        )

        with open(args.output, "w") as f:
            json.dump(merged, f, indent=2)

        print(f"\nMerged {len(merged)} samples to {args.output}")
        report = generate_quality_report(merged)
        print_quality_report(report)

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
