#!/usr/bin/env python3
"""
ResultReviewer Sub-Agent

Analyzes evaluation results to identify improvement opportunities for SecMutBench.

Tasks:
- F001: Identify weak CWEs (low mutation scores)
- F002: Flag problematic samples (zero kills, invalid tests)
- F003: Analyze operator effectiveness
- F004: Generate improvement recommendations
"""

import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from datetime import datetime

# Add SecMutBench root to path
SECMUTBENCH_ROOT = Path(__file__).parent.parent.parent.parent
sys.path.insert(0, str(SECMUTBENCH_ROOT))


@dataclass
class ImprovementRecommendation:
    """A single improvement recommendation."""
    category: str  # "dataset", "operator", "sample", "prompt"
    priority: str  # "critical", "high", "medium", "low"
    target: str  # CWE, sample_id, operator name
    issue: str  # Description of the problem
    recommendation: str  # Suggested fix
    evidence: Dict  # Supporting data


@dataclass
class ReviewResult:
    """Result of the review process."""
    experiment_id: str
    reviewed_at: str
    total_samples_reviewed: int
    total_models_reviewed: int

    # Findings
    weak_cwes: List[Dict]
    problematic_samples: List[Dict]
    operator_issues: List[Dict]
    attack_coverage_gaps: List[Dict]

    # Recommendations
    recommendations: List[Dict]

    # Summary
    overall_health: str  # "good", "needs_improvement", "critical"
    improvement_score: float  # 0-1, how much improvement is needed


class ResultReviewer:
    """Sub-agent for reviewing evaluation results and identifying improvements."""

    EXPERIMENTS_DIR = Path(__file__).parent.parent.parent / "outputs" / "experiments"

    # Thresholds for identifying issues
    WEAK_CWE_THRESHOLD = 0.5  # CWEs with avg score below this need attention
    PROBLEMATIC_SAMPLE_THRESHOLD = 0.3  # Samples below this are problematic
    ZERO_KILL_THRESHOLD = 0.1  # Samples that kill < 10% of mutants
    MIN_SAMPLES_PER_CWE = 3  # CWEs with fewer samples need more
    ATTACK_COVERAGE_THRESHOLD = 0.6  # Attack coverage below this is concerning

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
                    raise ValueError("No experiments found")
            else:
                raise ValueError("Experiments directory not found")

    def run(self, task_id: str, description: str) -> Dict:
        """Execute review task."""
        if task_id == "F001":
            return self.identify_weak_cwes()
        elif task_id == "F002":
            return self.flag_problematic_samples()
        elif task_id == "F003":
            return self.analyze_operator_effectiveness()
        elif task_id == "F004":
            return self.generate_recommendations()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def full_review(self) -> ReviewResult:
        """Run complete review and generate all recommendations."""
        print(f"Reviewing experiment: {self.experiment_id}")

        # Load all results
        all_results = self._load_all_results()

        if not all_results:
            return ReviewResult(
                experiment_id=self.experiment_id,
                reviewed_at=datetime.now().isoformat(),
                total_samples_reviewed=0,
                total_models_reviewed=0,
                weak_cwes=[],
                problematic_samples=[],
                operator_issues=[],
                attack_coverage_gaps=[],
                recommendations=[],
                overall_health="unknown",
                improvement_score=0.0
            )

        # Run all analyses
        weak_cwes = self._find_weak_cwes(all_results)
        problematic_samples = self._find_problematic_samples(all_results)
        operator_issues = self._analyze_operators(all_results)
        attack_gaps = self._find_attack_coverage_gaps(all_results)

        # Generate recommendations
        recommendations = self._generate_all_recommendations(
            weak_cwes, problematic_samples, operator_issues, attack_gaps
        )

        # Calculate overall health
        critical_count = sum(1 for r in recommendations if r["priority"] == "critical")
        high_count = sum(1 for r in recommendations if r["priority"] == "high")

        if critical_count > 3:
            overall_health = "critical"
        elif critical_count > 0 or high_count > 5:
            overall_health = "needs_improvement"
        else:
            overall_health = "good"

        # Improvement score (higher = more improvement needed)
        improvement_score = min(1.0, (critical_count * 0.3 + high_count * 0.1 + len(recommendations) * 0.02))

        # Count unique samples and models
        sample_ids = set()
        model_names = set()
        for model_results in all_results.values():
            model_names.add(model_results.get("model", "unknown"))
            for sample in model_results.get("samples", []):
                sample_ids.add(sample.get("sample_id", ""))

        result = ReviewResult(
            experiment_id=self.experiment_id,
            reviewed_at=datetime.now().isoformat(),
            total_samples_reviewed=len(sample_ids),
            total_models_reviewed=len(model_names),
            weak_cwes=weak_cwes,
            problematic_samples=problematic_samples,
            operator_issues=operator_issues,
            attack_coverage_gaps=attack_gaps,
            recommendations=recommendations,
            overall_health=overall_health,
            improvement_score=improvement_score
        )

        # Save review results
        self._save_review(result)

        return result

    def identify_weak_cwes(self) -> Dict:
        """F001: Identify CWEs with low mutation scores."""
        all_results = self._load_all_results()
        weak_cwes = self._find_weak_cwes(all_results)

        return {
            "status": "completed",
            "weak_cwes": weak_cwes,
            "threshold": self.WEAK_CWE_THRESHOLD,
            "count": len(weak_cwes)
        }

    def flag_problematic_samples(self) -> Dict:
        """F002: Flag samples with issues."""
        all_results = self._load_all_results()
        problematic = self._find_problematic_samples(all_results)

        return {
            "status": "completed",
            "problematic_samples": problematic,
            "count": len(problematic)
        }

    def analyze_operator_effectiveness(self) -> Dict:
        """F003: Analyze mutation operator effectiveness."""
        all_results = self._load_all_results()
        issues = self._analyze_operators(all_results)

        return {
            "status": "completed",
            "operator_issues": issues,
            "count": len(issues)
        }

    def generate_recommendations(self) -> Dict:
        """F004: Generate improvement recommendations."""
        review = self.full_review()

        return {
            "status": "completed",
            "recommendations": review.recommendations,
            "overall_health": review.overall_health,
            "improvement_score": review.improvement_score,
            "output": str(self.EXPERIMENT_DIR / "review_results.json")
        }

    def _load_all_results(self) -> Dict[str, Dict]:
        """Load all model results from experiment."""
        results = {}

        for model_dir in self.EXPERIMENT_DIR.iterdir():
            if not model_dir.is_dir() or model_dir.name in ("charts", "reports", "checkpoints"):
                continue

            model_results = {"model": model_dir.name, "samples": []}

            # Load summary
            summary_file = model_dir / "summary.json"
            if summary_file.exists():
                with open(summary_file) as f:
                    model_results["summary"] = json.load(f)

            # Load individual sample results
            results_dir = model_dir / "results"
            if results_dir.exists():
                for result_file in results_dir.glob("*.json"):
                    try:
                        with open(result_file) as f:
                            sample_result = json.load(f)
                        model_results["samples"].append(sample_result)
                    except Exception as e:
                        print(f"Error loading {result_file}: {e}")

            if model_results["samples"]:
                results[model_dir.name] = model_results

        return results

    def _find_weak_cwes(self, all_results: Dict) -> List[Dict]:
        """Find CWEs with consistently low scores."""
        cwe_scores = {}  # cwe -> list of scores
        cwe_samples = {}  # cwe -> count of samples

        for model_name, model_data in all_results.items():
            for sample in model_data.get("samples", []):
                cwe = sample.get("cwe_id", sample.get("cwe", "unknown"))
                score = sample.get("mutation_score", 0)

                if cwe not in cwe_scores:
                    cwe_scores[cwe] = []
                    cwe_samples[cwe] = set()

                cwe_scores[cwe].append(score)
                cwe_samples[cwe].add(sample.get("sample_id", ""))

        weak_cwes = []
        for cwe, scores in cwe_scores.items():
            avg_score = sum(scores) / len(scores) if scores else 0
            sample_count = len(cwe_samples.get(cwe, set()))

            if avg_score < self.WEAK_CWE_THRESHOLD:
                weak_cwes.append({
                    "cwe": cwe,
                    "avg_score": avg_score,
                    "sample_count": sample_count,
                    "evaluation_count": len(scores),
                    "needs_more_samples": sample_count < self.MIN_SAMPLES_PER_CWE,
                    "severity": "critical" if avg_score < 0.2 else "high" if avg_score < 0.35 else "medium"
                })

        # Sort by severity
        weak_cwes.sort(key=lambda x: x["avg_score"])
        return weak_cwes

    def _find_problematic_samples(self, all_results: Dict) -> List[Dict]:
        """Find samples with issues across models."""
        sample_scores = {}  # sample_id -> {model: score, ...}
        sample_meta = {}  # sample_id -> metadata

        for model_name, model_data in all_results.items():
            for sample in model_data.get("samples", []):
                sample_id = sample.get("sample_id", "unknown")
                score = sample.get("mutation_score", 0)

                if sample_id not in sample_scores:
                    sample_scores[sample_id] = {}
                    sample_meta[sample_id] = {
                        "cwe": sample.get("cwe_id", sample.get("cwe", "")),
                        "errors": []
                    }

                sample_scores[sample_id][model_name] = score

                # Collect errors
                if sample.get("errors"):
                    sample_meta[sample_id]["errors"].extend(sample["errors"])

        problematic = []
        for sample_id, scores in sample_scores.items():
            avg_score = sum(scores.values()) / len(scores) if scores else 0
            max_score = max(scores.values()) if scores else 0

            issues = []

            # Check for consistently low scores
            if avg_score < self.PROBLEMATIC_SAMPLE_THRESHOLD:
                issues.append("low_avg_score")

            # Check for zero kills
            if max_score < self.ZERO_KILL_THRESHOLD:
                issues.append("zero_kills")

            # Check for errors
            if sample_meta[sample_id]["errors"]:
                issues.append("has_errors")

            # Check for high variance (inconsistent across models)
            if len(scores) > 1:
                variance = sum((s - avg_score) ** 2 for s in scores.values()) / len(scores)
                if variance > 0.1:  # High variance threshold
                    issues.append("high_variance")

            if issues:
                problematic.append({
                    "sample_id": sample_id,
                    "cwe": sample_meta[sample_id]["cwe"],
                    "avg_score": avg_score,
                    "max_score": max_score,
                    "model_scores": scores,
                    "issues": issues,
                    "error_count": len(sample_meta[sample_id]["errors"]),
                    "severity": "critical" if "zero_kills" in issues else "high" if "low_avg_score" in issues else "medium"
                })

        # Sort by severity
        problematic.sort(key=lambda x: (x["severity"] != "critical", x["severity"] != "high", x["avg_score"]))
        return problematic

    def _analyze_operators(self, all_results: Dict) -> List[Dict]:
        """Analyze mutation operator effectiveness."""
        operator_stats = {}  # operator -> {killed: int, total: int, cwes: set}

        for model_name, model_data in all_results.items():
            for sample in model_data.get("samples", []):
                mutant_details = sample.get("mutant_details", [])
                cwe = sample.get("cwe_id", sample.get("cwe", ""))

                for mutant in mutant_details:
                    op = mutant.get("operator", "unknown")
                    killed = mutant.get("killed", False)

                    if op not in operator_stats:
                        operator_stats[op] = {"killed": 0, "total": 0, "cwes": set()}

                    operator_stats[op]["total"] += 1
                    if killed:
                        operator_stats[op]["killed"] += 1
                    operator_stats[op]["cwes"].add(cwe)

        issues = []
        for op, stats in operator_stats.items():
            kill_rate = stats["killed"] / stats["total"] if stats["total"] > 0 else 0

            # Operators with very high kill rate might be too easy
            if kill_rate > 0.95 and stats["total"] > 10:
                issues.append({
                    "operator": op,
                    "issue": "too_easy",
                    "kill_rate": kill_rate,
                    "total_mutants": stats["total"],
                    "cwes_affected": list(stats["cwes"]),
                    "recommendation": "Consider making operator mutations more subtle"
                })

            # Operators with very low kill rate might be too hard or broken
            elif kill_rate < 0.2 and stats["total"] > 10:
                issues.append({
                    "operator": op,
                    "issue": "too_hard_or_broken",
                    "kill_rate": kill_rate,
                    "total_mutants": stats["total"],
                    "cwes_affected": list(stats["cwes"]),
                    "recommendation": "Review operator implementation or test expectations"
                })

            # Operators with few uses
            elif stats["total"] < 5:
                issues.append({
                    "operator": op,
                    "issue": "underutilized",
                    "kill_rate": kill_rate,
                    "total_mutants": stats["total"],
                    "cwes_affected": list(stats["cwes"]),
                    "recommendation": "Add more samples that trigger this operator"
                })

        return issues

    def _find_attack_coverage_gaps(self, all_results: Dict) -> List[Dict]:
        """Find gaps in attack vector coverage."""
        gaps = []

        for model_name, model_data in all_results.items():
            for sample in model_data.get("samples", []):
                attack_coverage = sample.get("attack_coverage", 1.0)
                missing_attacks = sample.get("missing_attacks", [])

                if attack_coverage < self.ATTACK_COVERAGE_THRESHOLD and missing_attacks:
                    gaps.append({
                        "sample_id": sample.get("sample_id", "unknown"),
                        "cwe": sample.get("cwe_id", sample.get("cwe", "")),
                        "model": model_name,
                        "attack_coverage": attack_coverage,
                        "missing_attacks": missing_attacks[:5],  # Top 5
                        "severity": "high" if attack_coverage < 0.3 else "medium"
                    })

        # Deduplicate by sample_id (keep worst coverage)
        seen = {}
        for gap in gaps:
            sid = gap["sample_id"]
            if sid not in seen or gap["attack_coverage"] < seen[sid]["attack_coverage"]:
                seen[sid] = gap

        return list(seen.values())

    def _generate_all_recommendations(
        self,
        weak_cwes: List[Dict],
        problematic_samples: List[Dict],
        operator_issues: List[Dict],
        attack_gaps: List[Dict]
    ) -> List[Dict]:
        """Generate actionable recommendations from all findings."""
        recommendations = []

        # Recommendations for weak CWEs
        for cwe_info in weak_cwes:
            rec = ImprovementRecommendation(
                category="dataset",
                priority=cwe_info["severity"],
                target=cwe_info["cwe"],
                issue=f"Low average mutation score ({cwe_info['avg_score']:.1%})",
                recommendation="Add more samples with varied complexity for this CWE" if cwe_info["needs_more_samples"]
                              else "Review and improve existing samples for this CWE",
                evidence={"avg_score": cwe_info["avg_score"], "sample_count": cwe_info["sample_count"]}
            )
            recommendations.append(asdict(rec))

        # Recommendations for problematic samples
        for sample_info in problematic_samples[:20]:  # Limit to top 20
            if "zero_kills" in sample_info["issues"]:
                issue = "No mutants killed by any model"
                rec_text = "Review sample - tests may not detect the vulnerability pattern"
            elif "has_errors" in sample_info["issues"]:
                issue = f"Execution errors ({sample_info['error_count']})"
                rec_text = "Fix syntax or runtime errors in sample"
            else:
                issue = f"Low scores across models ({sample_info['avg_score']:.1%})"
                rec_text = "Improve security tests or simplify vulnerability pattern"

            rec = ImprovementRecommendation(
                category="sample",
                priority=sample_info["severity"],
                target=sample_info["sample_id"],
                issue=issue,
                recommendation=rec_text,
                evidence={"cwe": sample_info["cwe"], "avg_score": sample_info["avg_score"]}
            )
            recommendations.append(asdict(rec))

        # Recommendations for operator issues
        for op_info in operator_issues:
            rec = ImprovementRecommendation(
                category="operator",
                priority="medium",
                target=op_info["operator"],
                issue=f"Operator issue: {op_info['issue']} (kill rate: {op_info['kill_rate']:.1%})",
                recommendation=op_info["recommendation"],
                evidence={"kill_rate": op_info["kill_rate"], "total_mutants": op_info["total_mutants"]}
            )
            recommendations.append(asdict(rec))

        # Recommendations for attack coverage gaps
        cwe_attack_gaps = {}
        for gap in attack_gaps:
            cwe = gap["cwe"]
            if cwe not in cwe_attack_gaps:
                cwe_attack_gaps[cwe] = {"count": 0, "missing": set()}
            cwe_attack_gaps[cwe]["count"] += 1
            cwe_attack_gaps[cwe]["missing"].update(gap["missing_attacks"])

        for cwe, gap_info in cwe_attack_gaps.items():
            rec = ImprovementRecommendation(
                category="dataset",
                priority="high" if gap_info["count"] > 3 else "medium",
                target=cwe,
                issue=f"Missing attack vector coverage in {gap_info['count']} samples",
                recommendation=f"Add tests covering: {', '.join(list(gap_info['missing'])[:3])}",
                evidence={"samples_affected": gap_info["count"], "missing_attacks": list(gap_info["missing"])}
            )
            recommendations.append(asdict(rec))

        # Sort by priority
        priority_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        recommendations.sort(key=lambda x: priority_order.get(x["priority"], 4))

        return recommendations

    def _save_review(self, result: ReviewResult):
        """Save review results to file."""
        output_path = self.EXPERIMENT_DIR / "review_results.json"
        with open(output_path, "w") as f:
            json.dump(asdict(result), f, indent=2, default=str)
        print(f"Review saved to: {output_path}")


if __name__ == "__main__":
    import sys

    reviewer = ResultReviewer()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]
        result = reviewer.run(task_id, "")
        print(json.dumps(result, indent=2, default=str))
    else:
        # Run full review
        result = reviewer.full_review()
        print(f"\nReview Complete:")
        print(f"  Overall Health: {result.overall_health}")
        print(f"  Improvement Score: {result.improvement_score:.1%}")
        print(f"  Weak CWEs: {len(result.weak_cwes)}")
        print(f"  Problematic Samples: {len(result.problematic_samples)}")
        print(f"  Recommendations: {len(result.recommendations)}")
