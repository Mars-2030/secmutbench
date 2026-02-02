#!/usr/bin/env python3
"""
ChartAgent Sub-Agent

Generates visualizations for experiment results:
- A004: Generate mutation score heatmap
- A005: Generate model comparison charts
- A006: Generate CWE distribution plots
"""

import json
from pathlib import Path
from typing import Dict, List
from datetime import datetime


class ChartAgent:
    """Sub-agent for generating charts and visualizations."""

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

        self.CHARTS_DIR = self.EXPERIMENT_DIR / "charts"
        self.CHARTS_DIR.mkdir(parents=True, exist_ok=True)

    def run(self, task_id: str, description: str) -> Dict:
        """Execute chart generation task."""
        if task_id == "A004":
            return self.generate_heatmap()
        elif task_id == "A005":
            return self.generate_model_comparison()
        elif task_id == "A006":
            return self.generate_cwe_distribution()
        else:
            raise ValueError(f"Unknown task: {task_id}")

    def generate_heatmap(self) -> Dict:
        """A004: Generate mutation score heatmap (model x CWE)."""
        metrics = self._load_metrics()
        if not metrics:
            return {"status": "no_data"}

        # Build heatmap data
        models = list(metrics.get("models", {}).keys())
        cwes = list(metrics.get("cwes", {}).keys())

        heatmap_data = []
        for cwe in cwes:
            row = {"cwe": cwe}
            cwe_data = metrics["cwes"].get(cwe, {})
            model_scores = cwe_data.get("model_scores", {})
            for model in models:
                row[model] = model_scores.get(model, 0)
            heatmap_data.append(row)

        # Try to generate actual chart with matplotlib
        chart_path = self._create_heatmap_matplotlib(models, cwes, heatmap_data)

        if not chart_path:
            # Fallback: save as JSON for later visualization
            chart_path = self.CHARTS_DIR / "heatmap_data.json"
            with open(chart_path, "w") as f:
                json.dump({
                    "type": "heatmap",
                    "models": models,
                    "cwes": cwes,
                    "data": heatmap_data
                }, f, indent=2)

        return {
            "status": "completed",
            "chart_type": "heatmap",
            "output": str(chart_path),
            "models": len(models),
            "cwes": len(cwes)
        }

    def generate_model_comparison(self) -> Dict:
        """A005: Generate model comparison bar charts."""
        metrics = self._load_metrics()
        if not metrics:
            return {"status": "no_data"}

        models = metrics.get("models", {})

        # Prepare data for bar chart
        chart_data = []
        for model_name, model_data in models.items():
            chart_data.append({
                "model": model_name,
                "avg_score": model_data.get("avg_mutation_score", 0),
                "min_score": model_data.get("min_score", 0),
                "max_score": model_data.get("max_score", 0)
            })

        # Sort by average score
        chart_data.sort(key=lambda x: x["avg_score"], reverse=True)

        # Try matplotlib
        chart_path = self._create_bar_chart_matplotlib(chart_data)

        if not chart_path:
            chart_path = self.CHARTS_DIR / "model_comparison.json"
            with open(chart_path, "w") as f:
                json.dump({
                    "type": "bar_chart",
                    "data": chart_data
                }, f, indent=2)

        return {
            "status": "completed",
            "chart_type": "bar_chart",
            "output": str(chart_path),
            "models": len(chart_data)
        }

    def generate_cwe_distribution(self) -> Dict:
        """A006: Generate CWE distribution box plots."""
        metrics = self._load_metrics()
        if not metrics:
            return {"status": "no_data"}

        cwes = metrics.get("cwes", {})

        # Prepare data for box plot
        chart_data = []
        for cwe_name, cwe_data in cwes.items():
            model_scores = cwe_data.get("model_scores", {})
            scores = list(model_scores.values())
            if scores:
                chart_data.append({
                    "cwe": cwe_name,
                    "scores": scores,
                    "avg": cwe_data.get("avg_score", 0),
                    "min": cwe_data.get("min_score", 0),
                    "max": cwe_data.get("max_score", 0),
                    "std": cwe_data.get("std_dev", 0)
                })

        # Sort by average score
        chart_data.sort(key=lambda x: x["avg"], reverse=True)

        # Try matplotlib
        chart_path = self._create_boxplot_matplotlib(chart_data)

        if not chart_path:
            chart_path = self.CHARTS_DIR / "cwe_distribution.json"
            with open(chart_path, "w") as f:
                json.dump({
                    "type": "box_plot",
                    "data": chart_data
                }, f, indent=2)

        return {
            "status": "completed",
            "chart_type": "box_plot",
            "output": str(chart_path),
            "cwes": len(chart_data)
        }

    def _load_metrics(self) -> Dict:
        """Load metrics from experiment directory."""
        # Try aggregated file first
        metrics_file = self.EXPERIMENT_DIR / "aggregated_metrics.json"
        if metrics_file.exists():
            with open(metrics_file) as f:
                return json.load(f)

        # Otherwise, aggregate from model summaries
        metrics = {"models": {}, "cwes": {}, "overall": {}}

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

        return metrics

    def _create_heatmap_matplotlib(self, models: List[str], cwes: List[str], data: List[Dict]) -> Path:
        """Create heatmap using matplotlib."""
        try:
            import matplotlib.pyplot as plt
            import numpy as np

            # Build matrix
            matrix = []
            for row in data:
                matrix.append([row.get(m, 0) for m in models])

            matrix = np.array(matrix)

            fig, ax = plt.subplots(figsize=(12, 8))
            im = ax.imshow(matrix, cmap='RdYlGn', aspect='auto', vmin=0, vmax=1)

            # Labels
            ax.set_xticks(range(len(models)))
            ax.set_xticklabels([m[:15] for m in models], rotation=45, ha='right')
            ax.set_yticks(range(len(cwes)))
            ax.set_yticklabels(cwes)

            # Colorbar
            plt.colorbar(im, label='Mutation Score')

            # Values in cells
            for i in range(len(cwes)):
                for j in range(len(models)):
                    ax.text(j, i, f'{matrix[i,j]:.2f}', ha='center', va='center')

            ax.set_title('Mutation Score by Model and CWE')
            plt.tight_layout()

            output_path = self.CHARTS_DIR / "mutation_score_heatmap.png"
            plt.savefig(output_path, dpi=150)
            plt.close()

            return output_path

        except ImportError:
            return None

    def _create_bar_chart_matplotlib(self, data: List[Dict]) -> Path:
        """Create bar chart using matplotlib."""
        try:
            import matplotlib.pyplot as plt
            import numpy as np

            models = [d["model"][:15] for d in data]
            scores = [d["avg_score"] for d in data]
            mins = [d["min_score"] for d in data]
            maxs = [d["max_score"] for d in data]

            fig, ax = plt.subplots(figsize=(12, 6))

            x = np.arange(len(models))
            bars = ax.bar(x, scores, color='steelblue', edgecolor='black')

            # Error bars for min/max
            ax.errorbar(x, scores,
                       yerr=[np.array(scores) - np.array(mins),
                             np.array(maxs) - np.array(scores)],
                       fmt='none', color='black', capsize=5)

            ax.set_xlabel('Model')
            ax.set_ylabel('Mutation Score')
            ax.set_title('Model Comparison - Average Mutation Scores')
            ax.set_xticks(x)
            ax.set_xticklabels(models, rotation=45, ha='right')
            ax.set_ylim(0, 1)

            # Add value labels
            for bar, score in zip(bars, scores):
                ax.text(bar.get_x() + bar.get_width()/2, bar.get_height() + 0.02,
                       f'{score:.2f}', ha='center', va='bottom')

            plt.tight_layout()

            output_path = self.CHARTS_DIR / "model_comparison.png"
            plt.savefig(output_path, dpi=150)
            plt.close()

            return output_path

        except ImportError:
            return None

    def _create_boxplot_matplotlib(self, data: List[Dict]) -> Path:
        """Create box plot using matplotlib."""
        try:
            import matplotlib.pyplot as plt

            fig, ax = plt.subplots(figsize=(12, 6))

            cwes = [d["cwe"] for d in data]
            scores_data = [d["scores"] for d in data]

            bp = ax.boxplot(scores_data, labels=cwes, patch_artist=True)

            # Color boxes
            colors = plt.cm.viridis([i/len(data) for i in range(len(data))])
            for patch, color in zip(bp['boxes'], colors):
                patch.set_facecolor(color)

            ax.set_xlabel('CWE')
            ax.set_ylabel('Mutation Score')
            ax.set_title('Mutation Score Distribution by CWE')
            ax.set_ylim(0, 1)

            plt.xticks(rotation=45, ha='right')
            plt.tight_layout()

            output_path = self.CHARTS_DIR / "cwe_distribution.png"
            plt.savefig(output_path, dpi=150)
            plt.close()

            return output_path

        except ImportError:
            return None


if __name__ == "__main__":
    import sys
    agent = ChartAgent()

    if len(sys.argv) > 1:
        task_id = sys.argv[1]
        result = agent.run(task_id, "")
        print(json.dumps(result, indent=2))
    else:
        print("Usage: python chart_agent.py <task_id>")
        print("Tasks: A004, A005, A006")
