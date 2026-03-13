"""
Metrics Calculation for SecMutBench

Computes mutation scores and other evaluation metrics.
"""

from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from collections import defaultdict
import statistics


@dataclass
class SurvivedMutant:
    """Details of a mutant that survived (was not killed by tests)."""
    id: str
    operator: str
    description: str
    sample_id: str
    cwe: str


@dataclass
class MutationMetrics:
    """Metrics for mutation testing."""
    total_mutants: int = 0
    killed_mutants: int = 0
    survived_mutants: int = 0
    equivalent_mutants: int = 0
    timeout_mutants: int = 0
    error_mutants: int = 0

    @property
    def mutation_score(self) -> float:
        """Calculate mutation score (killed / killable)."""
        killable = self.total_mutants - self.equivalent_mutants
        if killable <= 0:
            return 0.0
        return self.killed_mutants / killable

    @property
    def survival_rate(self) -> float:
        """Calculate survival rate (survived / total)."""
        if self.total_mutants <= 0:
            return 0.0
        return self.survived_mutants / self.total_mutants

    @property
    def kill_rate(self) -> float:
        """Calculate raw kill rate (killed / total)."""
        if self.total_mutants <= 0:
            return 0.0
        return self.killed_mutants / self.total_mutants


@dataclass
class CoverageMetrics:
    """Code coverage metrics."""
    lines_covered: int = 0
    total_lines: int = 0
    branches_covered: int = 0
    total_branches: int = 0

    @property
    def line_coverage(self) -> float:
        if self.total_lines <= 0:
            return 0.0
        return self.lines_covered / self.total_lines

    @property
    def branch_coverage(self) -> float:
        if self.total_branches <= 0:
            return 0.0
        return self.branches_covered / self.total_branches


@dataclass
class SampleMetrics:
    """Complete metrics for a single sample."""
    sample_id: str
    cwe: str
    difficulty: str
    vuln_detected: bool = False
    mutation: MutationMetrics = field(default_factory=MutationMetrics)
    coverage: CoverageMetrics = field(default_factory=CoverageMetrics)
    test_count: int = 0
    execution_time: float = 0.0
    errors: List[str] = field(default_factory=list)


@dataclass
class AggregateMetrics:
    """Aggregated metrics across multiple samples."""
    samples: int = 0
    avg_mutation_score: float = 0.0
    avg_vuln_detection: float = 0.0
    avg_line_coverage: float = 0.0
    avg_branch_coverage: float = 0.0
    total_mutants: int = 0
    total_killed: int = 0


def calculate_mutation_score(
    killed: int,
    total: int,
    equivalent: int = 0,
) -> float:
    """
    Calculate mutation score.

    Args:
        killed: Number of killed mutants
        total: Total number of mutants
        equivalent: Number of equivalent mutants

    Returns:
        Mutation score as a float between 0 and 1
    """
    killable = total - equivalent
    if killable <= 0:
        return 0.0
    return killed / killable


def calculate_metrics(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate aggregate metrics from sample results.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict containing aggregate metrics
    """
    if not sample_results:
        return {"error": "No results provided"}

    # Extract values
    mutation_scores = []
    vuln_detections = []
    line_coverages = []
    branch_coverages = []
    total_mutants = 0
    total_killed = 0

    valid_mutation_scores = 0
    total_samples_with_scores = 0

    for result in sample_results:
        metrics = result.get("metrics", {})

        # Only include valid mutation scores (not None)
        if "mutation_score" in metrics:
            total_samples_with_scores += 1
            if metrics["mutation_score"] is not None:
                mutation_scores.append(metrics["mutation_score"])
                valid_mutation_scores += 1

        if "vuln_detected" in metrics:
            vuln_detections.append(1 if metrics["vuln_detected"] else 0)

        if "line_coverage" in metrics:
            line_coverages.append(metrics["line_coverage"])

        if "branch_coverage" in metrics:
            branch_coverages.append(metrics["branch_coverage"])

        if "mutants_total" in metrics:
            total_mutants += metrics["mutants_total"]

        if "mutants_killed" in metrics:
            total_killed += metrics["mutants_killed"]

    total_survived = total_mutants - total_killed

    # Secure-pass rate: fraction of samples whose tests pass on secure code
    secure_pass_count = sum(
        1 for r in sample_results
        if r.get("metrics", {}).get("secure_passes", False)
    )
    secure_pass_rate = secure_pass_count / len(sample_results) if sample_results else 0.0

    # Effective MS = avg_ms * secure_pass_rate
    # This corrects for the M2 gate: MS is only computed over passing samples,
    # so raw avg_ms is inflated when secure_pass_rate is low.
    avg_ms = statistics.mean(mutation_scores) if mutation_scores else 0.0
    effective_mutation_score = avg_ms * secure_pass_rate

    return {
        "samples": len(sample_results),
        "valid_mutation_scores": valid_mutation_scores,  # Samples with non-None mutation score
        "samples_with_scores": total_samples_with_scores,  # Total samples that attempted mutation
        "avg_mutation_score": avg_ms,
        "std_mutation_score": statistics.stdev(mutation_scores) if len(mutation_scores) > 1 else 0.0,
        "effective_mutation_score": effective_mutation_score,
        "secure_pass_rate": secure_pass_rate,
        "secure_pass_count": secure_pass_count,
        "avg_vuln_detection": statistics.mean(vuln_detections) if vuln_detections else 0.0,
        "avg_line_coverage": statistics.mean(line_coverages) if line_coverages else 0.0,
        "avg_branch_coverage": statistics.mean(branch_coverages) if branch_coverages else 0.0,
        "total_mutants": total_mutants,
        "total_killed": total_killed,
        "total_survived": total_survived,
        "overall_mutation_score": total_killed / total_mutants if total_mutants > 0 else 0.0,
        "overall_survival_rate": total_survived / total_mutants if total_mutants > 0 else 0.0,
    }


def aggregate_by_cwe(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate metrics by CWE type.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict mapping CWE to aggregated metrics
    """
    by_cwe = defaultdict(list)

    for result in sample_results:
        cwe = result.get("cwe", "unknown")
        by_cwe[cwe].append(result)

    aggregated = {}
    for cwe, results in by_cwe.items():
        aggregated[cwe] = calculate_metrics(results)
        aggregated[cwe]["samples_count"] = len(results)
        aggregated[cwe]["low_confidence"] = len(results) < 5

    return aggregated


def aggregate_by_difficulty(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate metrics by difficulty level.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict mapping difficulty to aggregated metrics
    """
    by_difficulty = defaultdict(list)

    for result in sample_results:
        difficulty = result.get("difficulty", "unknown")
        by_difficulty[difficulty].append(result)

    aggregated = {}
    for difficulty, results in by_difficulty.items():
        aggregated[difficulty] = calculate_metrics(results)
        aggregated[difficulty]["samples_count"] = len(results)

    return aggregated


def aggregate_by_source_type(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate metrics by source type (original vs variation).

    This enables reporting per-original-sample metrics alongside full-dataset
    metrics, addressing construct validity concerns from LLM-generated variations.

    Args:
        sample_results: List of per-sample result dicts (must include 'source_type')

    Returns:
        Dict mapping source_type to aggregated metrics
    """
    by_source = defaultdict(list)

    for result in sample_results:
        source_type = result.get("source_type", "unknown")
        by_source[source_type].append(result)

    aggregated = {}
    for source_type, results in by_source.items():
        aggregated[source_type] = calculate_metrics(results)
        aggregated[source_type]["samples_count"] = len(results)

    return aggregated


def aggregate_by_mutant_category(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate kill rates by mutant category (cwe_specific vs generic).

    This distinguishes between CWE-specific and generic mutation kills,
    enabling separate reporting of security-aware vs guard-removal detection.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict mapping mutant_category to kill/survival statistics
    """
    category_stats = defaultdict(lambda: {"total": 0, "killed": 0, "survived": 0})

    for result in sample_results:
        mutant_details = result.get("mutant_details", [])
        for mutant in mutant_details:
            category = mutant.get("mutant_category", "unknown")
            category_stats[category]["total"] += 1
            if mutant.get("killed", False):
                category_stats[category]["killed"] += 1
            else:
                category_stats[category]["survived"] += 1

    for category, stats in category_stats.items():
        stats["kill_rate"] = stats["killed"] / stats["total"] if stats["total"] > 0 else 0.0

    return dict(category_stats)


def aggregate_by_operator(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Dict[str, Any]]:
    """
    Aggregate metrics by mutation operator.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict mapping operator to kill/survival statistics
    """
    operator_stats = defaultdict(lambda: {"total": 0, "killed": 0, "survived": 0})

    for result in sample_results:
        mutant_details = result.get("mutant_details", [])
        for mutant in mutant_details:
            operator = mutant.get("operator", "unknown")
            operator_stats[operator]["total"] += 1
            if mutant.get("killed", False):
                operator_stats[operator]["killed"] += 1
            else:
                operator_stats[operator]["survived"] += 1

    # Calculate rates
    for operator, stats in operator_stats.items():
        stats["kill_rate"] = stats["killed"] / stats["total"] if stats["total"] > 0 else 0.0
        stats["survival_rate"] = stats["survived"] / stats["total"] if stats["total"] > 0 else 0.0

    return dict(operator_stats)


def get_survived_mutants(
    sample_results: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Get details of all mutants that survived (were not killed by tests).

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        List of survived mutant details with sample context
    """
    survived = []

    for result in sample_results:
        sample_id = result.get("sample_id", "unknown")
        cwe = result.get("cwe", "unknown")
        mutant_details = result.get("mutant_details", [])

        for mutant in mutant_details:
            if not mutant.get("killed", False):
                survived.append({
                    "mutant_id": mutant.get("id", "unknown"),
                    "operator": mutant.get("operator", "unknown"),
                    "description": mutant.get("description", ""),
                    "sample_id": sample_id,
                    "cwe": cwe,
                })

    return survived


def analyze_survival_patterns(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Analyze patterns in mutant survival to identify test weaknesses.

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict with survival analysis including:
        - survival_by_operator: Which operators have highest survival
        - survival_by_cwe: Which CWEs have highest survival
        - most_survived_samples: Samples with most survived mutants
    """
    survived_mutants = get_survived_mutants(sample_results)

    # Survival by operator
    by_operator = defaultdict(int)
    for m in survived_mutants:
        by_operator[m["operator"]] += 1

    # Survival by CWE
    by_cwe = defaultdict(int)
    for m in survived_mutants:
        by_cwe[m["cwe"]] += 1

    # Survival by sample
    by_sample = defaultdict(int)
    for m in survived_mutants:
        by_sample[m["sample_id"]] += 1

    # Get operator stats for context
    operator_stats = aggregate_by_operator(sample_results)

    # Calculate survival rates per operator
    operator_survival = {}
    for op, count in by_operator.items():
        total = operator_stats.get(op, {}).get("total", count)
        operator_survival[op] = {
            "survived": count,
            "total": total,
            "survival_rate": count / total if total > 0 else 0.0,
        }

    # Sort by survival rate (descending) - these are the weak spots
    weak_operators = sorted(
        operator_survival.items(),
        key=lambda x: x[1]["survival_rate"],
        reverse=True
    )

    # Top samples with most survivors
    top_samples = sorted(by_sample.items(), key=lambda x: x[1], reverse=True)[:10]

    return {
        "total_survived": len(survived_mutants),
        "survival_by_operator": dict(by_operator),
        "survival_by_cwe": dict(by_cwe),
        "operator_survival_rates": operator_survival,
        "weak_operators": weak_operators[:5],  # Top 5 operators with highest survival
        "samples_with_most_survivors": top_samples,
        "survived_mutants": survived_mutants,
    }


def calculate_kill_breakdown(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate mutation score breakdown by kill type.

    Kill types:
    - semantic: AssertionError with security-related terms (validates security property)
    - functional: Test expected exception not raised (behavioral detection via pytest.raises)
    - assertion_incidental: AssertionError without security terms (caught change incidentally)
    - crash: ImportError, TypeError, etc. (code structure issue)
    - other: Any other exception

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict containing:
        - total_mutants: Total mutants generated
        - total_killed: Total mutants killed (any reason)
        - semantic_kills: Kills with security-aware assertions
        - functional_kills: Kills from pytest.raises (expected exception not raised)
        - incidental_kills: Assertion kills without security terms
        - crash_kills: Kills due to crashes
        - other_kills: Other kills
        - mutation_score: Overall mutation score
        - security_mutation_score: Semantic kills / total mutants
        - functional_score: Functional kills / total mutants
        - incidental_score: Incidental kills / total mutants
        - crash_score: Crash kills / total mutants
    """
    total_mutants = 0
    total_killed = 0
    semantic_kills = 0
    functional_kills = 0
    incidental_kills = 0
    crash_kills = 0
    other_kills = 0
    # Track semantic kills by classification layer for strict vs relaxed SMS
    semantic_by_layer = {
        "mock_observability": 0,
        "operator_keyword": 0,
        "generic_keyword": 0,
        "attack_payload": 0,
    }

    for result in sample_results:
        mutant_details = result.get("mutant_details", [])
        for mutant in mutant_details:
            total_mutants += 1
            if mutant.get("killed", False):
                total_killed += 1
                kill_type = mutant.get("kill_type", "other")
                if kill_type == "semantic":
                    semantic_kills += 1
                    layer = mutant.get("classification_layer", "operator_keyword")
                    if layer in semantic_by_layer:
                        semantic_by_layer[layer] += 1
                elif kill_type == "functional":
                    functional_kills += 1
                elif kill_type == "assertion_incidental":
                    incidental_kills += 1
                elif kill_type == "crash":
                    crash_kills += 1
                else:
                    other_kills += 1

    _zero = {
        "total_mutants": 0,
        "total_killed": 0,
        "semantic_kills": 0,
        "semantic_by_layer": semantic_by_layer,
        "functional_kills": 0,
        "incidental_kills": 0,
        "crash_kills": 0,
        "other_kills": 0,
        "mutation_score": None,
        "security_mutation_score": None,
        "security_mutation_score_strict": None,
        "functional_score": None,
        "incidental_score": None,
        "crash_score": None,
    }

    if total_mutants == 0:
        return _zero

    # strict SMS excludes generic_keyword matches (stronger evidence only)
    strict_semantic = semantic_kills - semantic_by_layer["generic_keyword"]

    return {
        "total_mutants": total_mutants,
        "total_killed": total_killed,
        "semantic_kills": semantic_kills,
        "semantic_by_layer": semantic_by_layer,
        "functional_kills": functional_kills,
        "incidental_kills": incidental_kills,
        "crash_kills": crash_kills,
        "other_kills": other_kills,
        "mutation_score": total_killed / total_mutants,
        "security_mutation_score": semantic_kills / total_mutants,
        "security_mutation_score_strict": strict_semantic / total_mutants,
        "functional_score": functional_kills / total_mutants,
        "incidental_score": incidental_kills / total_mutants,
        "crash_score": crash_kills / total_mutants,
    }


def calculate_security_precision(
    sample_results: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Calculate security precision: proportion of samples where tests both
    pass on secure code AND detect the vulnerability.

    Security Precision = VD / secure_passes

    This metric answers: "Of the tests that actually work on secure code,
    what fraction also catch the vulnerability?"

    Args:
        sample_results: List of per-sample result dicts

    Returns:
        Dict with secure_passes, vuln_detected_count, security_precision
    """
    secure_passes = 0
    vuln_detected = 0

    for result in sample_results:
        metrics = result.get("metrics", {})
        if metrics.get("secure_passes", False):
            secure_passes += 1
            if metrics.get("vuln_detected", False):
                vuln_detected += 1

    return {
        "secure_passes": secure_passes,
        "vuln_detected_count": vuln_detected,
        "security_precision": vuln_detected / secure_passes if secure_passes > 0 else None,
    }


def format_metrics_report(
    metrics: Dict[str, Any],
    by_cwe: Optional[Dict[str, Dict[str, Any]]] = None,
    by_difficulty: Optional[Dict[str, Dict[str, Any]]] = None,
    survival_analysis: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Format metrics as a human-readable report.

    Args:
        metrics: Overall metrics dict
        by_cwe: Optional per-CWE metrics
        by_difficulty: Optional per-difficulty metrics
        survival_analysis: Optional survival pattern analysis

    Returns:
        Formatted report string
    """
    lines = [
        "=" * 60,
        "SecMutBench Evaluation Report",
        "=" * 60,
        "",
        "Overall Metrics:",
        f"  Samples Evaluated:     {metrics.get('samples', 0)}",
        f"  Avg Mutation Score:    {metrics.get('avg_mutation_score', 0):.2%}  (over M2-passing samples only)",
        f"  Effective Mut. Score:  {metrics.get('effective_mutation_score', 0):.2%}  (= avg_MS * secure_pass_rate)",
        f"  Secure-Pass Rate:      {metrics.get('secure_pass_rate', 0):.2%}  ({metrics.get('secure_pass_count', 0)}/{metrics.get('samples', 0)})",
        f"  Std Mutation Score:    {metrics.get('std_mutation_score', 0):.2%}",
        f"  Avg Vuln Detection:    {metrics.get('avg_vuln_detection', 0):.2%}",
        "",
        "Mutation Statistics:",
        f"  Total Mutants:         {metrics.get('total_mutants', 0)}",
        f"  Killed:                {metrics.get('total_killed', 0)}",
        f"  Survived:              {metrics.get('total_survived', 0)}",
        f"  Kill Rate:             {metrics.get('overall_mutation_score', 0):.2%}",
        f"  Survival Rate:         {metrics.get('overall_survival_rate', 0):.2%}",
        "",
    ]

    # Kill Breakdown (if available)
    kb = metrics.get("kill_breakdown")
    if kb and kb.get("total_mutants", 0) > 0:
        lines.extend([
            "Kill Breakdown:",
            f"  Semantic (security):   {kb.get('semantic_kills', 0)}",
            f"  Functional (behavior): {kb.get('functional_kills', 0)}",
            f"  Incidental:            {kb.get('incidental_kills', 0)}",
            f"  Crash:                 {kb.get('crash_kills', 0)}",
            f"  Other:                 {kb.get('other_kills', 0)}",
            f"  Security Mut. Score:   {kb.get('security_mutation_score', 0):.2%}",
            f"  Functional Score:      {kb.get('functional_score', 0):.2%}",
            f"  Crash Score:           {kb.get('crash_score', 0):.2%}",
            "",
        ])

    sp = metrics.get("security_precision")
    if sp is not None:
        lines.extend([
            f"  Security Precision:    {sp:.2%}  (VD / secure_passes)",
            "",
        ])

    if by_cwe:
        lines.extend([
            "-" * 60,
            "Metrics by CWE:",
            "",
        ])
        for cwe, cwe_metrics in sorted(by_cwe.items()):
            confidence = "" if not cwe_metrics.get("low_confidence") else " [!low-n]"
            lines.append(
                f"  {cwe}: "
                f"Score={cwe_metrics.get('avg_mutation_score', 0):.2%}, "
                f"Detection={cwe_metrics.get('avg_vuln_detection', 0):.2%}, "
                f"Samples={cwe_metrics.get('samples_count', 0)}{confidence}"
            )
        lines.append("")

    if by_difficulty:
        lines.extend([
            "-" * 60,
            "Metrics by Difficulty:",
            "",
        ])
        for difficulty in ["easy", "medium", "hard"]:
            if difficulty in by_difficulty:
                diff_metrics = by_difficulty[difficulty]
                lines.append(
                    f"  {difficulty.capitalize():8}: "
                    f"Score={diff_metrics.get('avg_mutation_score', 0):.2%}, "
                    f"Detection={diff_metrics.get('avg_vuln_detection', 0):.2%}, "
                    f"Samples={diff_metrics.get('samples_count', 0)}"
                )
        lines.append("")

    if survival_analysis:
        lines.extend([
            "-" * 60,
            "Mutation Survival Analysis:",
            "",
            f"  Total Survived:        {survival_analysis.get('total_survived', 0)}",
            "",
            "  Weak Operators (highest survival - tests may be missing):",
        ])
        weak_ops = survival_analysis.get('weak_operators', [])
        for op, stats in weak_ops[:5]:
            lines.append(
                f"    {op}: {stats['survived']}/{stats['total']} survived "
                f"({stats['survival_rate']:.0%})"
            )
        lines.append("")

        lines.append("  Survival by CWE:")
        survival_by_cwe = survival_analysis.get('survival_by_cwe', {})
        for cwe, count in sorted(survival_by_cwe.items(), key=lambda x: -x[1])[:5]:
            lines.append(f"    {cwe}: {count} mutants survived")
        lines.append("")

    lines.append("=" * 60)

    return "\n".join(lines)


def compare_models(
    results: Dict[str, List[Dict[str, Any]]],
) -> str:
    """
    Compare metrics across multiple models.

    Args:
        results: Dict mapping model name to list of sample results

    Returns:
        Formatted comparison table
    """
    lines = [
        "Model Comparison",
        "=" * 80,
        f"{'Model':<20} {'Samples':<10} {'Mut Score':<12} {'Vuln Det':<12} {'Coverage':<12}",
        "-" * 80,
    ]

    for model_name, sample_results in sorted(results.items()):
        metrics = calculate_metrics(sample_results)
        lines.append(
            f"{model_name:<20} "
            f"{metrics.get('samples', 0):<10} "
            f"{metrics.get('avg_mutation_score', 0):<12.2%} "
            f"{metrics.get('avg_vuln_detection', 0):<12.2%} "
            f"{metrics.get('avg_line_coverage', 0):<12.2%}"
        )

    lines.append("=" * 80)

    return "\n".join(lines)
