#!/usr/bin/env python3
"""
DataGenerator Sub-Agent

Generates new samples for SecMutBench dataset using the consolidated pipeline.

Tasks:
- I001/I005: Generate samples for Tier 1 CWEs (SQL Injection, XSS, Command Injection, etc.)
- I002/I006: Generate samples for Tier 2 CWEs (Auth, CSRF, Deserialization, etc.)
- REBUILD: Full dataset rebuild
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional
from datetime import datetime

# Add SecMutBench root to path for imports
SECMUTBENCH_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(SECMUTBENCH_ROOT))
sys.path.insert(0, str(SECMUTBENCH_ROOT / "scripts"))

# Import from new consolidated modules
try:
    from scripts.dataset_builder import DatasetBuilder
    from scripts.sample_generator import Sample, SampleGenerator
    from scripts.source_ingestion import SAMPLE_TEMPLATES, CWE_REGISTRY
    REBUILD_AVAILABLE = True
except ImportError:
    try:
        # Try direct import if scripts is in path
        from dataset_builder import DatasetBuilder
        from sample_generator import Sample, SampleGenerator
        from source_ingestion import SAMPLE_TEMPLATES, CWE_REGISTRY
        REBUILD_AVAILABLE = True
    except ImportError as e:
        print(f"Warning: Could not import consolidated modules: {e}")
        REBUILD_AVAILABLE = False

# CWE Tier definitions (always available)
TIER1_CWES = ["CWE-89", "CWE-79", "CWE-78", "CWE-22", "CWE-20"]
TIER2_CWES = ["CWE-287", "CWE-306", "CWE-352", "CWE-502", "CWE-798"]


class DataGenerator:
    """Sub-agent for generating SecMutBench samples using rebuild_dataset."""

    BASE_DIR = SECMUTBENCH_ROOT
    DATASET_FILE = BASE_DIR / "data" / "dataset.json"
    OUTPUT_DIR = Path(__file__).parent.parent.parent / "outputs" / "data_generation"

    def __init__(self):
        """Initialize DataGenerator."""
        self.OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    def run(self, task_id: str, description: str) -> Dict:
        """Execute a data generation task."""
        if task_id in ("I001", "I005"):  # I001 is new ID, I005 is legacy
            return self.generate_tier1_samples()
        elif task_id in ("I002", "I006"):  # I002 is new ID, I006 is legacy
            return self.generate_tier2_samples()
        elif task_id == "REBUILD":
            return self.rebuild_full_dataset()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def generate_tier1_samples(self) -> Dict:
        """Generate samples for Tier 1 CWEs (high priority)."""
        return self._generate_samples(TIER1_CWES, tier=1, samples_per_cwe=20)

    def generate_tier2_samples(self) -> Dict:
        """Generate samples for Tier 2 CWEs."""
        return self._generate_samples(TIER2_CWES, tier=2, samples_per_cwe=10)

    def _generate_samples(self, cwes: List[str], tier: int, samples_per_cwe: int) -> Dict:
        """Generate samples for specified CWEs using consolidated modules."""
        if not REBUILD_AVAILABLE:
            return {
                "status": "error",
                "message": "Consolidated modules not available - run scripts/dataset_builder.py directly",
                "tier": tier,
                "cwes": cwes
            }

        generated = []
        errors = []
        generator = SampleGenerator()

        for cwe in cwes:
            try:
                # Check if templates exist for this CWE
                if cwe not in SAMPLE_TEMPLATES:
                    errors.append(f"{cwe}: No templates available")
                    continue

                # Generate samples from templates using new module
                samples = generator.from_templates(cwe)
                count = min(samples_per_cwe, len(samples))
                generated.extend(samples[:count])
                print(f"Generated {count} samples for {cwe}")
            except Exception as e:
                errors.append(f"{cwe}: {str(e)}")
                print(f"Error generating samples for {cwe}: {e}")

        # Save generated samples
        output_file = self.OUTPUT_DIR / f"tier{tier}_samples_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(output_file, "w") as f:
            json.dump([s.to_dict() if hasattr(s, 'to_dict') else s for s in generated], f, indent=2)

        return {
            "status": "completed" if not errors else "partial",
            "tier": tier,
            "cwes": cwes,
            "samples_per_cwe": samples_per_cwe,
            "total_generated": len(generated),
            "errors": errors,
            "output_file": str(output_file)
        }

    def rebuild_full_dataset(self) -> Dict:
        """Rebuild the full dataset using consolidated dataset_builder."""
        if not REBUILD_AVAILABLE:
            return {
                "status": "error",
                "message": "Consolidated modules not available"
            }

        try:
            print("Starting full dataset rebuild with DatasetBuilder...")

            # Use new consolidated DatasetBuilder
            builder = DatasetBuilder(target_samples=150)
            samples = builder.build()
            builder.save(samples, str(self.DATASET_FILE))

            # Create splits
            splits = builder.create_splits(samples)
            splits_dir = self.BASE_DIR / "data" / "splits"
            builder.save_splits(splits, str(splits_dir))

            # Load stats
            with open(self.DATASET_FILE) as f:
                data = json.load(f)

            stats = data.get("metadata", {}).get("stats", {})

            return {
                "status": "completed",
                "stats": stats,
                "dataset_file": str(self.DATASET_FILE),
                "timestamp": datetime.now().isoformat()
            }
        except Exception as e:
            return {
                "status": "error",
                "message": str(e),
                "timestamp": datetime.now().isoformat()
            }

    def get_dataset_stats(self) -> Dict:
        """Get current dataset statistics."""
        if not self.DATASET_FILE.exists():
            return {"error": "Dataset file not found"}

        with open(self.DATASET_FILE) as f:
            data = json.load(f)

        samples = data.get("samples", data) if isinstance(data, dict) else data

        # Count by CWE
        cwe_counts = {}
        difficulty_counts = {"easy": 0, "medium": 0, "hard": 0}
        source_counts = {}

        for sample in samples:
            cwe = sample.get("cwe", "unknown")
            cwe_counts[cwe] = cwe_counts.get(cwe, 0) + 1

            difficulty = sample.get("difficulty", "unknown")
            if difficulty in difficulty_counts:
                difficulty_counts[difficulty] += 1

            source = sample.get("source", "unknown")
            source_counts[source] = source_counts.get(source, 0) + 1

        return {
            "total_samples": len(samples),
            "unique_cwes": len(cwe_counts),
            "cwe_distribution": cwe_counts,
            "difficulty_distribution": difficulty_counts,
            "source_distribution": source_counts
        }

    def validate_samples(self) -> Dict:
        """Validate all samples in the dataset."""
        if not self.DATASET_FILE.exists():
            return {"error": "Dataset file not found"}

        with open(self.DATASET_FILE) as f:
            data = json.load(f)

        samples = data.get("samples", data) if isinstance(data, dict) else data

        issues = []
        valid_count = 0

        required_fields = ["id", "cwe", "secure_code", "insecure_code", "security_tests"]

        for i, sample in enumerate(samples):
            sample_issues = []

            # Check required fields
            for field in required_fields:
                if field not in sample or not sample[field]:
                    sample_issues.append(f"Missing or empty field: {field}")

            # Check code compiles
            if "secure_code" in sample:
                try:
                    compile(sample["secure_code"], "<string>", "exec")
                except SyntaxError as e:
                    sample_issues.append(f"Secure code syntax error: {e}")

            if "insecure_code" in sample:
                try:
                    compile(sample["insecure_code"], "<string>", "exec")
                except SyntaxError as e:
                    sample_issues.append(f"Insecure code syntax error: {e}")

            if "security_tests" in sample:
                try:
                    compile(sample["security_tests"], "<string>", "exec")
                except SyntaxError as e:
                    sample_issues.append(f"Security tests syntax error: {e}")

            if sample_issues:
                issues.append({
                    "sample_id": sample.get("id", f"index_{i}"),
                    "issues": sample_issues
                })
            else:
                valid_count += 1

        return {
            "total_samples": len(samples),
            "valid_samples": valid_count,
            "invalid_samples": len(issues),
            "validation_rate": valid_count / len(samples) if samples else 0,
            "issues": issues[:20]  # Limit to first 20 issues
        }


if __name__ == "__main__":
    gen = DataGenerator()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]

        if task_id == "--stats":
            result = gen.get_dataset_stats()
        elif task_id == "--validate":
            result = gen.validate_samples()
        else:
            result = gen.run(task_id, "")

        print(json.dumps(result, indent=2))
    else:
        print("Usage: python data_generator.py <task_id>")
        print("Tasks:")
        print("  I005     - Generate Tier 1 CWE samples")
        print("  I006     - Generate Tier 2 CWE samples")
        print("  REBUILD  - Full dataset rebuild")
        print("  --stats  - Show dataset statistics")
        print("  --validate - Validate all samples")
        print(f"\nRebuild module available: {REBUILD_AVAILABLE}")
