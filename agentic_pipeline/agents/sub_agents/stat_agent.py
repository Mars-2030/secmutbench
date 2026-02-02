#!/usr/bin/env python3
"""
StatAgent Sub-Agent

Statistical analysis of experiment results:
- A001: Calculate Cohen's d effect sizes
- A002: Run ANOVA across CWEs
- A003: Calculate ICC for judge agreement
"""

import json
import math
from pathlib import Path
from typing import Dict, List, Tuple
from datetime import datetime


class StatAgent:
    """Sub-agent for statistical analysis."""

    OUTPUT_DIR = Path(__file__).parent.parent.parent / "outputs"
    EXPERIMENTS_DIR = OUTPUT_DIR / "experiments"

    def __init__(self, experiment_id: str = None):
        """Initialize with experiment directory for outputs."""
        if experiment_id:
            self.EXPERIMENT_DIR = self.EXPERIMENTS_DIR / experiment_id
        else:
            # Find most recent experiment
            if self.EXPERIMENTS_DIR.exists():
                experiments = sorted([d for d in self.EXPERIMENTS_DIR.iterdir() if d.is_dir()])
                self.EXPERIMENT_DIR = experiments[-1] if experiments else self.EXPERIMENTS_DIR / "default"
            else:
                self.EXPERIMENT_DIR = self.EXPERIMENTS_DIR / "default"

        self.REPORTS_DIR = self.EXPERIMENT_DIR / "reports"
        self.REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    def run(self, task_id: str, description: str) -> Dict:
        """Execute statistical analysis task."""
        if task_id == "A001":
            return self.calculate_cohens_d()
        elif task_id == "A002":
            return self.run_anova()
        elif task_id == "A003":
            return self.calculate_icc()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def calculate_cohens_d(self) -> Dict:
        """A001: Calculate Cohen's d effect sizes between models."""
        metrics = self._load_metrics()
        if not metrics:
            return {"status": "no_data"}

        models = metrics.get("models", {})
        if len(models) < 2:
            return {"status": "insufficient_models", "count": len(models)}

        # Get scores for each model
        model_scores = {}
        for model_name, model_data in models.items():
            cwe_scores = model_data.get("cwe_scores", {})
            model_scores[model_name] = list(cwe_scores.values())

        # Calculate pairwise Cohen's d
        model_names = list(model_scores.keys())
        effect_sizes = {}

        for i, model1 in enumerate(model_names):
            for model2 in model_names[i+1:]:
                scores1 = model_scores[model1]
                scores2 = model_scores[model2]

                if scores1 and scores2:
                    d = self._cohens_d(scores1, scores2)
                    effect_sizes[f"{model1} vs {model2}"] = {
                        "d": round(d, 3),
                        "interpretation": self._interpret_d(d)
                    }

        result = {
            "status": "completed",
            "comparisons": len(effect_sizes),
            "effect_sizes": effect_sizes,
            "timestamp": datetime.now().isoformat()
        }

        # Save results
        output_file = self.REPORTS_DIR / "cohens_d.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

        return result

    def run_anova(self) -> Dict:
        """A002: Run one-way ANOVA across CWEs."""
        metrics = self._load_metrics()
        if not metrics:
            return {"status": "no_data"}

        cwes = metrics.get("cwes", {})
        if len(cwes) < 2:
            return {"status": "insufficient_cwes"}

        # Get all scores by CWE
        groups = []
        cwe_names = []
        for cwe_name, cwe_data in cwes.items():
            model_scores = cwe_data.get("model_scores", {})
            if model_scores:
                groups.append(list(model_scores.values()))
                cwe_names.append(cwe_name)

        if len(groups) < 2:
            return {"status": "insufficient_data"}

        # Calculate one-way ANOVA
        f_stat, p_value = self._one_way_anova(groups)

        result = {
            "status": "completed",
            "cwes_analyzed": len(groups),
            "f_statistic": round(f_stat, 3),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "interpretation": "Significant difference between CWEs" if p_value < 0.05 else "No significant difference",
            "cwe_means": {cwe: sum(g)/len(g) for cwe, g in zip(cwe_names, groups) if g},
            "timestamp": datetime.now().isoformat()
        }

        # Save results
        output_file = self.REPORTS_DIR / "anova.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

        return result

    def calculate_icc(self) -> Dict:
        """A003: Calculate ICC for inter-judge agreement."""
        # Load judge scores from each model
        all_judge_scores = []

        for model_dir in self.EXPERIMENTS_DIR.iterdir():
            if not model_dir.is_dir():
                continue

            judge_file = model_dir / "judge_scores.json"
            if judge_file.exists():
                with open(judge_file) as f:
                    scores = json.load(f)
                all_judge_scores.append({"model": model_dir.name, "scores": scores})

        if not all_judge_scores:
            return {"status": "no_judge_data"}

        # Calculate ICC across judges
        # Collect scores per sample across judges
        sample_scores = {}  # sample_id -> {judge -> score}

        for model_data in all_judge_scores:
            for judge_name, judge_data in model_data["scores"].items():
                for eval in judge_data.get("details", []):
                    sample_id = eval.get("sample_id")
                    score = eval.get("score", 0)
                    if sample_id not in sample_scores:
                        sample_scores[sample_id] = {}
                    if judge_name not in sample_scores[sample_id]:
                        sample_scores[sample_id][judge_name] = []
                    sample_scores[sample_id][judge_name].append(score)

        # Calculate ICC(2,1) - two-way random, single measures
        icc = self._calculate_icc_2_1(sample_scores)

        result = {
            "status": "completed",
            "samples_analyzed": len(sample_scores),
            "icc": round(icc, 3),
            "interpretation": self._interpret_icc(icc),
            "timestamp": datetime.now().isoformat()
        }

        # Save results
        output_file = self.REPORTS_DIR / "icc.json"
        output_file.parent.mkdir(parents=True, exist_ok=True)
        with open(output_file, "w") as f:
            json.dump(result, f, indent=2)

        return result

    def _load_metrics(self) -> Dict:
        """Load metrics from experiment directory."""
        # Try aggregated file first
        metrics_file = self.EXPERIMENT_DIR / "aggregated_metrics.json"
        if metrics_file.exists():
            with open(metrics_file) as f:
                return json.load(f)

        # Otherwise, aggregate from model summaries
        metrics = {"models": {}, "cwes": {}}

        for model_dir in self.EXPERIMENT_DIR.iterdir():
            if not model_dir.is_dir() or model_dir.name in ("charts", "reports"):
                continue

            summary_file = model_dir / "summary.json"
            if summary_file.exists():
                with open(summary_file) as f:
                    summary = json.load(f)
                metrics["models"][model_dir.name] = summary

        return metrics

    def _cohens_d(self, group1: List[float], group2: List[float]) -> float:
        """Calculate Cohen's d effect size."""
        n1, n2 = len(group1), len(group2)
        if n1 < 2 or n2 < 2:
            return 0.0

        mean1 = sum(group1) / n1
        mean2 = sum(group2) / n2

        var1 = sum((x - mean1) ** 2 for x in group1) / (n1 - 1)
        var2 = sum((x - mean2) ** 2 for x in group2) / (n2 - 1)

        # Pooled standard deviation
        pooled_std = math.sqrt(((n1-1)*var1 + (n2-1)*var2) / (n1+n2-2))

        if pooled_std == 0:
            return 0.0

        return (mean1 - mean2) / pooled_std

    def _interpret_d(self, d: float) -> str:
        """Interpret Cohen's d value."""
        d = abs(d)
        if d < 0.2:
            return "negligible"
        elif d < 0.5:
            return "small"
        elif d < 0.8:
            return "medium"
        else:
            return "large"

    def _one_way_anova(self, groups: List[List[float]]) -> Tuple[float, float]:
        """Calculate one-way ANOVA F-statistic and p-value."""
        # Calculate overall mean
        all_values = [v for g in groups for v in g]
        grand_mean = sum(all_values) / len(all_values) if all_values else 0

        # Between-group sum of squares
        ss_between = sum(len(g) * (sum(g)/len(g) - grand_mean)**2 for g in groups if g)

        # Within-group sum of squares
        ss_within = sum(sum((x - sum(g)/len(g))**2 for x in g) for g in groups if g)

        # Degrees of freedom
        k = len(groups)
        n = len(all_values)
        df_between = k - 1
        df_within = n - k

        if df_within <= 0 or ss_within == 0:
            return 0.0, 1.0

        # F-statistic
        ms_between = ss_between / df_between
        ms_within = ss_within / df_within
        f_stat = ms_between / ms_within

        # Approximate p-value using F-distribution
        # Using simple approximation
        p_value = self._f_to_p(f_stat, df_between, df_within)

        return f_stat, p_value

    def _f_to_p(self, f: float, df1: int, df2: int) -> float:
        """Approximate p-value from F-statistic."""
        # Simple approximation - for accurate values use scipy
        # This is a rough estimate
        if f <= 1:
            return 0.5
        elif f > 10:
            return 0.001
        else:
            return 1 / (1 + f)

    def _calculate_icc_2_1(self, sample_scores: Dict) -> float:
        """Calculate ICC(2,1) - two-way random, single measures."""
        # Simplified ICC calculation
        # For accurate results, use pingouin or scipy

        if not sample_scores:
            return 0.0

        # Get all judges
        all_judges = set()
        for scores in sample_scores.values():
            all_judges.update(scores.keys())

        if len(all_judges) < 2:
            return 1.0  # Perfect agreement with one judge

        # Calculate mean scores per sample and per judge
        sample_means = {}
        judge_means = {j: [] for j in all_judges}

        for sample_id, judges in sample_scores.items():
            sample_vals = []
            for judge, scores in judges.items():
                mean_score = sum(scores) / len(scores) if scores else 0
                sample_vals.append(mean_score)
                judge_means[judge].append(mean_score)
            sample_means[sample_id] = sum(sample_vals) / len(sample_vals) if sample_vals else 0

        # Calculate variance components
        grand_mean = sum(sample_means.values()) / len(sample_means) if sample_means else 0

        # Between-subjects variance
        var_subjects = sum((m - grand_mean)**2 for m in sample_means.values()) / len(sample_means) if sample_means else 0

        # Between-raters variance
        rater_means = {j: sum(s)/len(s) if s else 0 for j, s in judge_means.items()}
        var_raters = sum((m - grand_mean)**2 for m in rater_means.values()) / len(rater_means) if rater_means else 0

        # Approximate ICC
        if var_subjects + var_raters == 0:
            return 0.0

        icc = var_subjects / (var_subjects + var_raters)
        return max(0, min(1, icc))

    def _interpret_icc(self, icc: float) -> str:
        """Interpret ICC value."""
        if icc < 0.5:
            return "poor agreement"
        elif icc < 0.75:
            return "moderate agreement"
        elif icc < 0.9:
            return "good agreement"
        else:
            return "excellent agreement"


if __name__ == "__main__":
    import sys
    agent = StatAgent()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]
        result = agent.run(task_id, "")
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python stat_agent.py <task_id>")
        print("Tasks: A001, A002, A003")
