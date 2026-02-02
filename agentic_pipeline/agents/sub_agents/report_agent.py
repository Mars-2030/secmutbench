#!/usr/bin/env python3
"""
ReportAgent Sub-Agent

Generates final reports from experiment results:
- A007: Create evaluation report (Markdown)
- A008: Create paper tables (LaTeX)
"""

import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class ReportAgent:
    """Sub-agent for generating reports."""

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
        """Execute report generation task."""
        if task_id == "A007":
            return self.create_markdown_report()
        elif task_id == "A008":
            return self.create_latex_tables()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def create_markdown_report(self) -> Dict:
        """A007: Create comprehensive Markdown evaluation report."""
        metrics = self._load_metrics()
        stats = self._load_stats()

        report = f"""# SecMutBench Evaluation Report

Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Executive Summary

This report presents the evaluation results of multiple LLM models on the SecMutBench security test generation benchmark.

### Key Findings

"""
        # Add key findings from metrics
        if metrics:
            overall = metrics.get("overall", {})
            report += f"""
- **Models Evaluated**: {overall.get('total_models', 0)}
- **Total Samples**: {overall.get('total_samples_evaluated', 0)}
- **Average Mutation Score**: {overall.get('grand_avg_mutation_score', 0):.2%}
- **Score Range**: {overall.get('score_range', {}).get('min', 0):.2%} - {overall.get('score_range', {}).get('max', 0):.2%}
"""
            # Best model
            rankings = metrics.get("rankings", {})
            if rankings.get("by_mutation_score"):
                best = rankings["by_mutation_score"][0]
                report += f"- **Best Performing Model**: {best['model']} ({best['score']:.2%})\n"

        report += """
## Detailed Results

### Model Performance

| Model | Avg Score | Min | Max | CWE Coverage |
|-------|-----------|-----|-----|--------------|
"""
        # Model table
        if metrics:
            models = metrics.get("models", {})
            rankings = metrics.get("rankings", {})
            coverage_map = {r["model"]: r["coverage"] for r in rankings.get("by_cwe_coverage", [])}

            for model_name, model_data in sorted(models.items(), key=lambda x: x[1].get("avg_mutation_score", 0), reverse=True):
                report += f"| {model_name} | {model_data.get('avg_mutation_score', 0):.2%} | "
                report += f"{model_data.get('min_score', 0):.2%} | {model_data.get('max_score', 0):.2%} | "
                report += f"{coverage_map.get(model_name, 0)} CWEs |\n"

        report += """
### CWE Analysis

| CWE | Description | Avg Score | Best Model |
|-----|-------------|-----------|------------|
"""
        # CWE table
        cwe_descriptions = {
            "CWE-89": "SQL Injection",
            "CWE-79": "Cross-Site Scripting",
            "CWE-78": "OS Command Injection",
            "CWE-22": "Path Traversal",
            "CWE-20": "Input Validation",
            "CWE-798": "Hardcoded Credentials",
            "CWE-287": "Authentication Bypass",
            "CWE-306": "Missing Authentication",
            "CWE-352": "CSRF",
            "CWE-502": "Insecure Deserialization",
        }

        if metrics:
            cwes = metrics.get("cwes", {})
            for cwe_name, cwe_data in sorted(cwes.items(), key=lambda x: x[1].get("avg_score", 0), reverse=True):
                desc = cwe_descriptions.get(cwe_name, "Other")
                best = cwe_data.get("best_model", "N/A")
                report += f"| {cwe_name} | {desc} | {cwe_data.get('avg_score', 0):.2%} | {best} |\n"

        report += """
### Statistical Analysis

"""
        # Cohen's d
        if stats.get("cohens_d"):
            report += "#### Effect Sizes (Cohen's d)\n\n"
            report += "| Comparison | d | Interpretation |\n"
            report += "|------------|---|----------------|\n"
            for comp, data in stats["cohens_d"].get("effect_sizes", {}).items():
                report += f"| {comp} | {data['d']:.3f} | {data['interpretation']} |\n"
            report += "\n"

        # ANOVA
        if stats.get("anova"):
            anova = stats["anova"]
            report += f"""#### ANOVA Results

- F-statistic: {anova.get('f_statistic', 0):.3f}
- p-value: {anova.get('p_value', 0):.4f}
- Significant: {'Yes' if anova.get('significant') else 'No'}
- Interpretation: {anova.get('interpretation', 'N/A')}

"""

        # ICC
        if stats.get("icc"):
            icc = stats["icc"]
            report += f"""#### Inter-Judge Agreement (ICC)

- ICC: {icc.get('icc', 0):.3f}
- Interpretation: {icc.get('interpretation', 'N/A')}
- Samples Analyzed: {icc.get('samples_analyzed', 0)}

"""

        report += """
## Visualizations

The following charts are available in the `outputs/charts/` directory:

1. **mutation_score_heatmap.png** - Heatmap of mutation scores by model and CWE
2. **model_comparison.png** - Bar chart comparing model performance
3. **cwe_distribution.png** - Box plots showing score distribution by CWE

## Methodology

### Mutation Testing

Each generated test was evaluated using security-specific mutation operators:
- SQL Injection mutations (PSQLI, ISQLI)
- XSS mutations (RXSS, SXSS)
- Command Injection mutations (CMDINJECT)
- Path Traversal mutations (PATHTRAVERSAL)
- Input Validation mutations (RVALID)
- Credential mutations (CREDLEAK)

### LLM-as-Judge

Generated tests were additionally evaluated by multiple LLM judges:
- GPT-5
- GPT-4
- Gemini Pro
- Claude 3 Opus

## Recommendations

Based on the evaluation results:

1. **Model Selection**: Use the highest-scoring model for security test generation
2. **CWE Focus**: Pay attention to CWEs with low scores - may need specialized prompting
3. **Test Quality**: Ensure generated tests have meaningful assertions, not just `assert True`

---

*Report generated by SecMutBench Multi-Agent System*
"""

        # Save report
        output_path = self.REPORTS_DIR / "EVALUATION_REPORT.md"
        with open(output_path, "w") as f:
            f.write(report)

        return {
            "status": "completed",
            "output": str(output_path),
            "sections": ["summary", "models", "cwes", "statistics", "methodology"]
        }

    def create_latex_tables(self) -> Dict:
        """A008: Create LaTeX tables for paper."""
        metrics = self._load_metrics()

        tables = []

        # Table 1: Model comparison
        table1 = r"""\begin{table}[htbp]
\centering
\caption{Model Performance on SecMutBench}
\label{tab:model-performance}
\begin{tabular}{lccc}
\toprule
\textbf{Model} & \textbf{Avg. Score} & \textbf{Min} & \textbf{Max} \\
\midrule
"""
        if metrics:
            models = metrics.get("models", {})
            for model_name, model_data in sorted(models.items(), key=lambda x: x[1].get("avg_mutation_score", 0), reverse=True):
                name = model_name.replace("_", "\\_")
                table1 += f"{name} & {model_data.get('avg_mutation_score', 0):.2f} & "
                table1 += f"{model_data.get('min_score', 0):.2f} & {model_data.get('max_score', 0):.2f} \\\\\n"

        table1 += r"""\bottomrule
\end{tabular}
\end{table}
"""
        tables.append(table1)

        # Table 2: CWE scores
        table2 = r"""\begin{table}[htbp]
\centering
\caption{Mutation Scores by CWE}
\label{tab:cwe-scores}
\begin{tabular}{lcc}
\toprule
\textbf{CWE} & \textbf{Avg. Score} & \textbf{Std. Dev.} \\
\midrule
"""
        if metrics:
            cwes = metrics.get("cwes", {})
            for cwe_name, cwe_data in sorted(cwes.items()):
                table2 += f"{cwe_name} & {cwe_data.get('avg_score', 0):.2f} & {cwe_data.get('std_dev', 0):.2f} \\\\\n"

        table2 += r"""\bottomrule
\end{tabular}
\end{table}
"""
        tables.append(table2)

        # Save all tables
        output_path = self.REPORTS_DIR / "paper_tables.tex"
        with open(output_path, "w") as f:
            f.write("% SecMutBench Paper Tables\n")
            f.write(f"% Generated: {datetime.now().isoformat()}\n\n")
            f.write("\n\n".join(tables))

        return {
            "status": "completed",
            "output": str(output_path),
            "tables": len(tables)
        }

    def _load_metrics(self) -> Dict:
        """Load metrics from experiment directory."""
        # Try aggregated file first
        metrics_file = self.EXPERIMENT_DIR / "aggregated_metrics.json"
        if metrics_file.exists():
            with open(metrics_file) as f:
                return json.load(f)

        # Otherwise, aggregate from model summaries
        metrics = {"models": {}, "cwes": {}, "overall": {}, "rankings": {}}

        for model_dir in self.EXPERIMENT_DIR.iterdir():
            if not model_dir.is_dir() or model_dir.name in ("charts", "reports"):
                continue

            summary_file = model_dir / "summary.json"
            if summary_file.exists():
                with open(summary_file) as f:
                    summary = json.load(f)
                metrics["models"][model_dir.name] = summary

                # Aggregate CWE scores
                for cwe, score in summary.get("cwe_scores", {}).items():
                    if cwe not in metrics["cwes"]:
                        metrics["cwes"][cwe] = {"model_scores": {}}
                    metrics["cwes"][cwe]["model_scores"][model_dir.name] = score

        # Calculate rankings
        if metrics["models"]:
            rankings = sorted(
                [(name, data.get("avg_mutation_score", 0)) for name, data in metrics["models"].items()],
                key=lambda x: x[1], reverse=True
            )
            metrics["rankings"]["by_mutation_score"] = [{"model": m, "score": s} for m, s in rankings]

            # Overall stats
            scores = [data.get("avg_mutation_score", 0) for data in metrics["models"].values()]
            metrics["overall"] = {
                "total_models": len(metrics["models"]),
                "grand_avg_mutation_score": sum(scores) / len(scores) if scores else 0,
                "score_range": {"min": min(scores), "max": max(scores)} if scores else {}
            }

        return metrics

    def _load_stats(self) -> Dict:
        """Load statistical analysis results."""
        stats = {}

        for stat_file in ["cohens_d.json", "anova.json", "icc.json"]:
            path = self.REPORTS_DIR / stat_file
            if path.exists():
                with open(path) as f:
                    stats[stat_file.replace(".json", "")] = json.load(f)

        return stats


if __name__ == "__main__":
    import sys
    agent = ReportAgent()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]
        result = agent.run(task_id, "")
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python report_agent.py <task_id>")
        print("Tasks: A007, A008")
