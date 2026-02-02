#!/usr/bin/env python3
"""
DatasetImprover Sub-Agent

Implements improvements to SecMutBench based on review recommendations.

Tasks:
- F005: Add samples for weak CWEs
- F006: Fix or remove problematic samples
- F007: Update mutation operators
- F008: Apply all improvements and rebuild dataset
"""

import json
import sys
import shutil
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, asdict
from datetime import datetime
import hashlib

# Add SecMutBench root to path
SECMUTBENCH_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(SECMUTBENCH_ROOT))

try:
    from scripts.rebuild_dataset import rebuild_dataset
    REBUILD_AVAILABLE = True
except ImportError:
    REBUILD_AVAILABLE = False

try:
    from evaluation.sample_validator import SampleValidator
    VALIDATOR_AVAILABLE = True
except ImportError:
    VALIDATOR_AVAILABLE = False


class ImprovementsLogger:
    """Logs improvements to IMPROVEMENTS_LOG.md for tracking."""

    LOG_FILE = Path(__file__).parent.parent.parent / "IMPROVEMENTS_LOG.md"
    MARKER = "<!-- AUTOMATED ENTRIES BELOW - DO NOT EDIT MANUALLY -->"

    @classmethod
    def log_improvement(
        cls,
        improvement_type: str,
        component: str,
        author: str,
        experiment_id: str,
        description: str,
        changes: List[str]
    ) -> bool:
        """
        Log an improvement to the improvements log file.

        Args:
            improvement_type: Type of improvement (FEATURE, FIX, DATASET, OPERATOR, etc.)
            component: Component affected (Dataset, ModelRunner, etc.)
            author: Who made the change (Manual, DatasetImprover, etc.)
            experiment_id: Related experiment ID or N/A
            description: Description of the improvement
            changes: List of specific changes made

        Returns:
            True if logged successfully, False otherwise
        """
        try:
            # Create entry
            date = datetime.now().strftime("%Y-%m-%d")
            entry = f"\n### {date} - {improvement_type} - {component}\n"
            entry += f"**Author**: {author}\n"
            entry += f"**Experiment**: {experiment_id}\n\n"
            entry += f"{description}\n\n"
            entry += "**Changes:**\n"
            for change in changes:
                entry += f"- {change}\n"
            entry += "\n---\n"

            # Read current log
            if not cls.LOG_FILE.exists():
                cls._create_log_file()

            content = cls.LOG_FILE.read_text()

            # Find marker and insert after it
            if cls.MARKER in content:
                parts = content.split(cls.MARKER)
                new_content = parts[0] + cls.MARKER + entry + parts[1] if len(parts) > 1 else parts[0] + cls.MARKER + entry
            else:
                # Append at the end
                new_content = content + entry

            cls.LOG_FILE.write_text(new_content)
            return True

        except Exception as e:
            print(f"Warning: Could not log improvement: {e}")
            return False

    @classmethod
    def _create_log_file(cls):
        """Create the improvements log file if it doesn't exist."""
        initial_content = """# SecMutBench Improvements Log

This file tracks all improvements made to SecMutBench.

---

<!-- AUTOMATED ENTRIES BELOW - DO NOT EDIT MANUALLY -->
"""
        cls.LOG_FILE.write_text(initial_content)

    @classmethod
    def log_dataset_improvement(
        cls,
        experiment_id: str,
        samples_added: int,
        samples_fixed: int,
        samples_removed: int,
        details: List[str] = None
    ) -> bool:
        """Convenience method for logging dataset improvements."""
        changes = []
        if samples_added > 0:
            changes.append(f"Added {samples_added} new sample(s)")
        if samples_fixed > 0:
            changes.append(f"Fixed/flagged {samples_fixed} sample(s)")
        if samples_removed > 0:
            changes.append(f"Removed {samples_removed} sample(s)")
        if details:
            changes.extend(details)

        if not changes:
            return False

        return cls.log_improvement(
            improvement_type="DATASET",
            component="Dataset",
            author="DatasetImprover",
            experiment_id=experiment_id,
            description="Automated dataset improvements based on experiment results.",
            changes=changes
        )

    @classmethod
    def log_operator_improvement(
        cls,
        experiment_id: str,
        operators: List[str],
        recommendation: str
    ) -> bool:
        """Convenience method for logging operator improvements."""
        return cls.log_improvement(
            improvement_type="OPERATOR",
            component="Mutation Operators",
            author="DatasetImprover",
            experiment_id=experiment_id,
            description=recommendation,
            changes=[f"Operator: {op}" for op in operators]
        )


@dataclass
class ImprovementAction:
    """A single improvement action taken."""
    action_type: str  # "add", "fix", "remove", "update"
    target: str  # sample_id, cwe, operator
    description: str
    status: str  # "completed", "failed", "skipped"
    details: Dict


@dataclass
class ImprovementReport:
    """Report of all improvements made."""
    experiment_id: str
    improved_at: str
    recommendations_processed: int
    actions_taken: List[Dict]
    samples_added: int
    samples_fixed: int
    samples_removed: int
    operators_updated: int
    dataset_rebuilt: bool
    new_dataset_path: Optional[str]


class DatasetImprover:
    """Sub-agent for implementing dataset improvements."""

    SECMUTBENCH_ROOT = SECMUTBENCH_ROOT
    DATA_DIR = SECMUTBENCH_ROOT / "data"
    DATASET_FILE = DATA_DIR / "dataset.json"
    EXPERIMENTS_DIR = Path(__file__).parent.parent.parent / "outputs" / "experiments"
    BACKUP_DIR = DATA_DIR / "backups"

    # CWE templates for generating new samples
    CWE_TEMPLATES = {
        "CWE-89": {
            "name": "SQL Injection",
            "patterns": ["parameterized_query", "orm_usage", "stored_procedure"],
            "operators": ["PSQLI"]
        },
        "CWE-78": {
            "name": "OS Command Injection",
            "patterns": ["subprocess_list", "shlex_quote", "allowlist"],
            "operators": ["CMDINJECT"]
        },
        "CWE-22": {
            "name": "Path Traversal",
            "patterns": ["realpath_check", "chroot", "allowlist_paths"],
            "operators": ["PATHCONCAT"]
        },
        "CWE-79": {
            "name": "Cross-Site Scripting",
            "patterns": ["html_escape", "content_security_policy", "sanitize_lib"],
            "operators": ["RVALID"]
        },
        "CWE-798": {
            "name": "Hardcoded Credentials",
            "patterns": ["env_var", "config_file", "secrets_manager"],
            "operators": ["HARDCODE"]
        },
        "CWE-502": {
            "name": "Insecure Deserialization",
            "patterns": ["json_only", "schema_validation", "allowlist_classes"],
            "operators": ["DESERIAL"]
        },
        "CWE-327": {
            "name": "Weak Cryptography",
            "patterns": ["strong_hash", "key_derivation", "secure_random"],
            "operators": ["WEAKCRYPTO"]
        },
        "CWE-287": {
            "name": "Improper Authentication",
            "patterns": ["session_management", "mfa", "rate_limiting"],
            "operators": ["RMAUTH"]
        },
    }

    def __init__(self, experiment_id: str = None):
        """Initialize with experiment directory."""
        if experiment_id:
            self.experiment_id = experiment_id
            self.EXPERIMENT_DIR = self.EXPERIMENTS_DIR / experiment_id
        else:
            # Find most recent experiment
            if self.EXPERIMENTS_DIR.exists():
                experiments = sorted([d for d in self.EXPERIMENTS_DIR.iterdir() if d.is_dir()])
                if experiments:
                    self.experiment_id = experiments[-1].name
                    self.EXPERIMENT_DIR = experiments[-1]
                else:
                    self.experiment_id = "default"
                    self.EXPERIMENT_DIR = self.EXPERIMENTS_DIR / "default"
            else:
                self.experiment_id = "default"
                self.EXPERIMENT_DIR = self.EXPERIMENTS_DIR / "default"

        # Ensure backup directory exists
        self.BACKUP_DIR.mkdir(parents=True, exist_ok=True)

    def run(self, task_id: str, description: str) -> Dict:
        """Execute improvement task."""
        if task_id == "F005":
            return self.add_samples_for_weak_cwes()
        elif task_id == "F006":
            return self.fix_problematic_samples()
        elif task_id == "F007":
            return self.update_operators()
        elif task_id == "F008":
            return self.apply_all_improvements()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def apply_all_improvements(self) -> Dict:
        """F008: Apply all improvements based on recommendations."""
        print(f"Applying improvements for experiment: {self.experiment_id}")

        # Load review results
        review_file = self.EXPERIMENT_DIR / "review_results.json"
        if not review_file.exists():
            return {"status": "skipped", "reason": "No review results found"}

        with open(review_file) as f:
            review = json.load(f)

        recommendations = review.get("recommendations", [])
        if not recommendations:
            return {"status": "skipped", "reason": "No recommendations to process"}

        # Backup current dataset
        backup_path = self._backup_dataset()
        print(f"Dataset backed up to: {backup_path}")

        # Load current dataset
        dataset = self._load_dataset()

        actions = []
        samples_added = 0
        samples_fixed = 0
        samples_removed = 0

        # Process recommendations by category
        for rec in recommendations:
            category = rec.get("category", "")
            priority = rec.get("priority", "low")
            target = rec.get("target", "")

            # Only process critical and high priority for now
            if priority not in ("critical", "high"):
                continue

            if category == "dataset" and "CWE-" in target:
                # Add samples for weak CWE
                result = self._add_sample_for_cwe(dataset, target, rec)
                if result["status"] == "completed":
                    samples_added += result.get("samples_added", 0)
                actions.append(result)

            elif category == "sample":
                # Fix or flag problematic sample
                result = self._handle_problematic_sample(dataset, target, rec)
                if result["status"] == "completed":
                    if result.get("action") == "fixed":
                        samples_fixed += 1
                    elif result.get("action") == "removed":
                        samples_removed += 1
                actions.append(result)

        # Save updated dataset
        dataset_rebuilt = False
        new_dataset_path = None

        if samples_added > 0 or samples_fixed > 0 or samples_removed > 0:
            new_dataset_path = self._save_dataset(dataset)
            dataset_rebuilt = True
            print(f"Dataset updated: +{samples_added} added, {samples_fixed} fixed, -{samples_removed} removed")

        # Generate improvement report
        report = ImprovementReport(
            experiment_id=self.experiment_id,
            improved_at=datetime.now().isoformat(),
            recommendations_processed=len(recommendations),
            actions_taken=actions,
            samples_added=samples_added,
            samples_fixed=samples_fixed,
            samples_removed=samples_removed,
            operators_updated=0,
            dataset_rebuilt=dataset_rebuilt,
            new_dataset_path=str(new_dataset_path) if new_dataset_path else None
        )

        # Save report
        report_path = self.EXPERIMENT_DIR / "improvement_report.json"
        with open(report_path, "w") as f:
            json.dump(asdict(report), f, indent=2)

        # Log improvements to IMPROVEMENTS_LOG.md
        if samples_added > 0 or samples_fixed > 0 or samples_removed > 0:
            details = []
            for action in actions:
                if action.get("status") == "completed":
                    details.append(f"{action.get('action', 'processed')}: {action.get('target', 'unknown')} - {action.get('description', '')}")

            ImprovementsLogger.log_dataset_improvement(
                experiment_id=self.experiment_id,
                samples_added=samples_added,
                samples_fixed=samples_fixed,
                samples_removed=samples_removed,
                details=details[:10]  # Limit to 10 details
            )
            print(f"Improvements logged to IMPROVEMENTS_LOG.md")

        return {
            "status": "completed",
            "samples_added": samples_added,
            "samples_fixed": samples_fixed,
            "samples_removed": samples_removed,
            "dataset_rebuilt": dataset_rebuilt,
            "report_path": str(report_path),
            "logged_to_improvements": True
        }

    def add_samples_for_weak_cwes(self) -> Dict:
        """F005: Add samples for CWEs with low scores."""
        review_file = self.EXPERIMENT_DIR / "review_results.json"
        if not review_file.exists():
            return {"status": "skipped", "reason": "No review results found"}

        with open(review_file) as f:
            review = json.load(f)

        weak_cwes = review.get("weak_cwes", [])
        if not weak_cwes:
            return {"status": "skipped", "reason": "No weak CWEs identified"}

        dataset = self._load_dataset()
        samples_added = 0
        results = []

        for cwe_info in weak_cwes[:5]:  # Process top 5 weak CWEs
            cwe = cwe_info["cwe"]
            result = self._add_sample_for_cwe(dataset, cwe, cwe_info)
            results.append(result)
            if result["status"] == "completed":
                samples_added += result.get("samples_added", 0)

        if samples_added > 0:
            self._save_dataset(dataset)

        return {
            "status": "completed",
            "cwes_processed": len(weak_cwes[:5]),
            "samples_added": samples_added,
            "details": results
        }

    def fix_problematic_samples(self) -> Dict:
        """F006: Fix or remove problematic samples."""
        review_file = self.EXPERIMENT_DIR / "review_results.json"
        if not review_file.exists():
            return {"status": "skipped", "reason": "No review results found"}

        with open(review_file) as f:
            review = json.load(f)

        problematic = review.get("problematic_samples", [])
        if not problematic:
            return {"status": "skipped", "reason": "No problematic samples identified"}

        dataset = self._load_dataset()
        fixed = 0
        removed = 0
        results = []

        for sample_info in problematic[:10]:  # Process top 10
            sample_id = sample_info["sample_id"]
            result = self._handle_problematic_sample(dataset, sample_id, sample_info)
            results.append(result)
            if result.get("action") == "fixed":
                fixed += 1
            elif result.get("action") == "removed":
                removed += 1

        if fixed > 0 or removed > 0:
            self._save_dataset(dataset)

        return {
            "status": "completed",
            "samples_processed": len(problematic[:10]),
            "samples_fixed": fixed,
            "samples_removed": removed,
            "details": results
        }

    def update_operators(self) -> Dict:
        """F007: Update mutation operators based on effectiveness."""
        review_file = self.EXPERIMENT_DIR / "review_results.json"
        if not review_file.exists():
            return {"status": "skipped", "reason": "No review results found"}

        with open(review_file) as f:
            review = json.load(f)

        operator_issues = review.get("operator_issues", [])

        # For now, just generate a report - operator changes require manual review
        recommendations = []
        for issue in operator_issues:
            recommendations.append({
                "operator": issue["operator"],
                "issue": issue["issue"],
                "recommendation": issue["recommendation"],
                "requires_manual_review": True
            })

        # Save operator recommendations
        output_path = self.EXPERIMENT_DIR / "operator_recommendations.json"
        with open(output_path, "w") as f:
            json.dump(recommendations, f, indent=2)

        # Log operator recommendations
        if recommendations:
            operators = [r["operator"] for r in recommendations]
            ImprovementsLogger.log_operator_improvement(
                experiment_id=self.experiment_id,
                operators=operators,
                recommendation=f"Generated {len(recommendations)} operator improvement recommendations"
            )

        return {
            "status": "completed",
            "operators_analyzed": len(operator_issues),
            "recommendations": recommendations,
            "output_path": str(output_path),
            "note": "Operator changes require manual review"
        }

    def _load_dataset(self) -> Dict:
        """Load the current dataset."""
        if not self.DATASET_FILE.exists():
            return {"metadata": {}, "samples": []}

        with open(self.DATASET_FILE) as f:
            return json.load(f)

    def _save_dataset(self, dataset: Dict) -> Path:
        """Save updated dataset with new version."""
        # Update metadata
        dataset["metadata"]["version"] = str(float(dataset["metadata"].get("version", "2.0")) + 0.1)
        dataset["metadata"]["last_improved"] = datetime.now().isoformat()
        dataset["metadata"]["total_samples"] = len(dataset.get("samples", []))

        with open(self.DATASET_FILE, "w") as f:
            json.dump(dataset, f, indent=2)

        return self.DATASET_FILE

    def _backup_dataset(self) -> Path:
        """Create a backup of the current dataset."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = self.BACKUP_DIR / f"dataset_backup_{timestamp}.json"

        if self.DATASET_FILE.exists():
            shutil.copy(self.DATASET_FILE, backup_path)

        return backup_path

    def _add_sample_for_cwe(self, dataset: Dict, cwe: str, context: Dict) -> Dict:
        """Add a new sample for a specific CWE."""
        # Check if we have a template for this CWE
        template = self.CWE_TEMPLATES.get(cwe)

        if not template:
            return {
                "status": "skipped",
                "target": cwe,
                "reason": f"No template available for {cwe}"
            }

        # Generate sample ID
        sample_id = self._generate_sample_id(cwe)

        # Check if we already have enough samples
        existing_count = sum(1 for s in dataset.get("samples", []) if s.get("cwe") == cwe)
        if existing_count >= 10:
            return {
                "status": "skipped",
                "target": cwe,
                "reason": f"Already have {existing_count} samples for {cwe}"
            }

        # Create a placeholder sample that needs human review
        new_sample = {
            "id": sample_id,
            "cwe": cwe,
            "cwe_name": template["name"],
            "difficulty": "medium",
            "prompt": f"Write a function that demonstrates secure handling of {template['name']}",
            "entry_point": "secure_function",
            "secure_code": f"# TODO: Implement secure version for {cwe}\ndef secure_function(input_data):\n    pass",
            "insecure_code": f"# TODO: Implement insecure version for {cwe}\ndef secure_function(input_data):\n    pass",
            "security_tests": f"# TODO: Implement security tests for {cwe}\ndef test_security():\n    assert True",
            "functional_tests": "def test_basic():\n    assert True",
            "mutation_operators": template["operators"],
            "source": "SecMutBench-AutoGen",
            "needs_review": True,
            "generated_from": context.get("issue", "weak CWE score"),
            "generated_at": datetime.now().isoformat()
        }

        # Add to dataset
        if "samples" not in dataset:
            dataset["samples"] = []

        dataset["samples"].append(new_sample)

        return {
            "status": "completed",
            "action": "add",
            "target": cwe,
            "sample_id": sample_id,
            "samples_added": 1,
            "needs_review": True,
            "description": f"Added placeholder sample for {cwe}"
        }

    def _handle_problematic_sample(self, dataset: Dict, sample_id: str, context: Dict) -> Dict:
        """Handle a problematic sample - fix or flag for removal."""
        samples = dataset.get("samples", [])
        sample_idx = None

        for idx, sample in enumerate(samples):
            if sample.get("id") == sample_id:
                sample_idx = idx
                break

        if sample_idx is None:
            return {
                "status": "skipped",
                "target": sample_id,
                "reason": "Sample not found in dataset"
            }

        issues = context.get("issues", [])
        sample = samples[sample_idx]

        # Determine action based on issues
        if "zero_kills" in issues or context.get("avg_score", 1.0) < 0.1:
            # Flag for review rather than auto-remove
            sample["needs_review"] = True
            sample["review_reason"] = "Zero or near-zero mutation kills"
            sample["flagged_at"] = datetime.now().isoformat()

            return {
                "status": "completed",
                "action": "flagged",
                "target": sample_id,
                "description": "Flagged for manual review due to zero kills"
            }

        elif "has_errors" in issues:
            # Flag for fixing
            sample["needs_review"] = True
            sample["review_reason"] = "Execution errors detected"
            sample["flagged_at"] = datetime.now().isoformat()

            return {
                "status": "completed",
                "action": "flagged",
                "target": sample_id,
                "description": "Flagged for fixing due to execution errors"
            }

        elif "high_variance" in issues:
            # Note the variance but keep the sample
            sample["notes"] = sample.get("notes", "") + f" High variance across models ({context.get('avg_score', 0):.1%})."

            return {
                "status": "completed",
                "action": "noted",
                "target": sample_id,
                "description": "Added note about high variance"
            }

        else:
            # Low score but not critical - add improvement note
            sample["improvement_suggested"] = True
            sample["improvement_note"] = f"Low average score ({context.get('avg_score', 0):.1%})"

            return {
                "status": "completed",
                "action": "noted",
                "target": sample_id,
                "description": "Added improvement suggestion"
            }

    def _generate_sample_id(self, cwe: str) -> str:
        """Generate a unique sample ID."""
        timestamp = datetime.now().isoformat()
        hash_input = f"{cwe}_{timestamp}"
        return hashlib.md5(hash_input.encode()).hexdigest()[:12]


if __name__ == "__main__":
    import sys

    improver = DatasetImprover()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]
        result = improver.run(task_id, "")
        print(json.dumps(result, indent=2, default=str))
    else:
        # Run full improvement
        result = improver.apply_all_improvements()
        print(f"\nImprovement Complete:")
        print(f"  Status: {result.get('status')}")
        print(f"  Samples Added: {result.get('samples_added', 0)}")
        print(f"  Samples Fixed: {result.get('samples_fixed', 0)}")
        print(f"  Samples Removed: {result.get('samples_removed', 0)}")
        print(f"  Dataset Rebuilt: {result.get('dataset_rebuilt', False)}")
