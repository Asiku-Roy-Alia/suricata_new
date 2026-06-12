#!/usr/bin/env python3
"""Step 6: Consolidate everything into a single markdown report.

Output:
  results/final_report.md
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime
from pathlib import Path

import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, setup_logging, project_path  # noqa: E402


def read_if_exists(path: Path) -> str:
    if path.exists():
        return path.read_text()
    return f"(file not found: {path})"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    logger = setup_logging(cfg, "06_report")

    results = project_path(cfg, "results_dir")
    loaco = project_path(cfg, "loaco_dir")

    lines = []
    lines.append("# Hybrid IDS: Final Results Report\n")
    lines.append(f"_Generated {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}_\n")

    lines.append("\n## 1. Dataset Preparation\n")
    lines.append("```\n" + read_if_exists(project_path(cfg, "processed_data_dir", "prepared_summary.txt")) + "\n```\n")

    lines.append("\n## 2. Exploratory Data Analysis\n")
    eda_dir = project_path(cfg, "results_dir", "eda")
    eda_summary = eda_dir / "eda_summary.txt"
    if eda_summary.exists():
        lines.append("```\n" + read_if_exists(eda_summary) + "\n```\n")
        lines.append("\nEDA artefacts written to `results/eda/`:\n")
        for plot_name, description in [
            ("01_class_distribution.png", "Class distribution (linear scale)"),
            ("02_class_distribution_log.png", "Class distribution (log scale, exposes minority classes)"),
            ("03_missing_values.png", "Missing-value audit"),
            ("04_correlation_heatmap.png", "Correlation matrix of top-30 features by variance"),
            ("05_top_features_by_correlation.png", "Top 15 features by correlation with attack label"),
            ("06_feature_distributions.png", "Per-class boxplots of the most discriminative features"),
        ]:
            if (eda_dir / plot_name).exists():
                lines.append(f"- **{description}**: `results/eda/{plot_name}`")
        lines.append("")

    lines.append("\n## 3. Feature Pipeline\n")
    lines.append("```\n" + read_if_exists(project_path(cfg, "processed_data_dir", "feature_info.txt")) + "\n```\n")

    lines.append("\n## 4. Standard Held-Out Evaluation\n")
    metrics_csv = results / "metrics_summary.csv"
    if metrics_csv.exists():
        df = pd.read_csv(metrics_csv)
        lines.append("### 4.1 Headline metrics\n")
        lines.append(df.round(4).to_markdown(index=False) + "\n")

    per_cat_csv = results / "per_category_recall.csv"
    if per_cat_csv.exists():
        df = pd.read_csv(per_cat_csv, index_col=0)
        lines.append("\n### 4.2 Per-category recall\n")
        lines.append(df.round(4).to_markdown() + "\n")

    lines.append("\n### 4.3 Confusion matrices\n")
    lines.append("```\n" + read_if_exists(results / "confusion_matrices.txt") + "\n```\n")

    lines.append("\n## 5. Leave-One-Attack-Category-Out (LOACO)\n")
    loaco_csv = loaco / "loaco_results.csv"
    if loaco_csv.exists():
        df = pd.read_csv(loaco_csv)
        lines.append("Each row below represents a full retraining run in which the "
                     "named attack category was removed from the training set entirely. "
                     "The *novel_recall* column measures the model's ability to detect "
                     "that category at test time without ever having seen it during training.\n")
        lines.append(df.round(4).to_markdown(index=False) + "\n")
        novel_mean = df["novel_recall"].mean()
        known_mean = df["known_attack_recall"].mean()
        lines.append(f"\n**Average novel-category recall:** {novel_mean:.4f}  \n")
        lines.append(f"**Average recall on remaining known attacks:** {known_mean:.4f}  \n")
        lines.append(f"**Detection gap (known minus novel):** {known_mean - novel_mean:.4f}\n")
    else:
        lines.append("(LOACO results not produced yet)\n")

    lines.append("\n## 6. Plots\n")
    plot_entries = [
        ("Reliability diagram (hybrid)", project_path(cfg, "plots_dir", "reliability_hybrid.png")),
        ("Precision-recall curves", project_path(cfg, "plots_dir", "pr_curves.png")),
        ("LOACO bar chart", project_path(cfg, "loaco_dir", "loaco_plot.png")),
    ]
    for name, p in plot_entries:
        if p.exists():
            rel = p.relative_to(Path(cfg["paths"]["results_dir"]).parent)
            lines.append(f"- **{name}**: `{rel}`")
    lines.append("")

    lines.append("\n## 7. Interpretation Notes\n")
    lines.append("""
The standard held-out evaluation in Section 4 reports what the literature
typically calls benchmark performance. Numbers in that section should be
compared to the 2024 to 2025 peer-reviewed literature on CIC-IDS-2017, where
macro F1 above 0.95 is now routinely achieved by stacked ensembles.

The LOACO section is the more scientifically demanding test. A model that
matches benchmark accuracy but collapses on LOACO is not detecting novel
attacks, it is memorising attack signatures present in the training set. The
gap between known-attack recall and novel-category recall is the quantity to
discuss in the dissertation.

The reliability diagram in Section 6 shows whether the hybrid model's
probability outputs are trustworthy. A curve close to the diagonal indicates
that a predicted probability of 0.8 for an attack is empirically associated
with roughly 80% attack occurrence in that bin. Poor calibration undermines
any downstream decision threshold.
""")

    out = results / "final_report.md"
    out.write_text("\n".join(lines))
    logger.info("Wrote %s", out)


if __name__ == "__main__":
    main()
