#!/usr/bin/env python3
"""Step 0b: Exploratory Data Analysis on the cleaned CIC-IDS-2017 sample.

Run this AFTER 01_prepare_data.py (which writes prepared.parquet). It produces
publication-quality figures and tables suitable for the EDA section of the
dissertation. None of the numbers here are training inputs; this is purely
descriptive analysis.

Output:
  results/eda/
    01_class_distribution.png
    02_class_distribution_log.png
    03_missing_values.png
    04_correlation_heatmap.png
    05_top_features_by_correlation.png
    06_feature_distributions.png
    07_outlier_summary.csv
    08_per_class_feature_stats.csv
    eda_summary.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import seaborn as sns

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402

sns.set_style("whitegrid")
sns.set_palette("Blues")


# ---------------------------------------------------------------------------
# Plot helpers
# ---------------------------------------------------------------------------
def _save(fig, path: Path, dpi: int = 130):
    path.parent.mkdir(parents=True, exist_ok=True)
    fig.tight_layout()
    fig.savefig(path, dpi=dpi, bbox_inches="tight")
    plt.close(fig)


def plot_class_distribution(df: pd.DataFrame, eda_dir: Path, log_scale: bool = False):
    counts = df["Category"].value_counts()
    fig, ax = plt.subplots(figsize=(9, 5))
    bars = ax.bar(counts.index, counts.values,
                  color=sns.color_palette("Blues_r", n_colors=len(counts)))
    if log_scale:
        ax.set_yscale("log")
        ax.set_title("Class distribution (log scale) — CIC-IDS-2017 stratified sample",
                     fontsize=13, fontweight="bold")
        out = eda_dir / "02_class_distribution_log.png"
    else:
        ax.set_title("Class distribution — CIC-IDS-2017 stratified sample",
                     fontsize=13, fontweight="bold")
        out = eda_dir / "01_class_distribution.png"
    ax.set_xlabel("Attack category")
    ax.set_ylabel("Flow count")
    ax.tick_params(axis="x", rotation=20)
    for bar, value in zip(bars, counts.values):
        ax.text(bar.get_x() + bar.get_width() / 2,
                bar.get_height() * (1.02 if not log_scale else 1.10),
                f"{value:,}", ha="center", va="bottom", fontsize=9)
    _save(fig, out)
    return out


def plot_missing_summary(df: pd.DataFrame, eda_dir: Path):
    """Bar chart of non-null counts per column. Mirrors msno.bar()."""
    feature_cols = [c for c in df.columns if c not in ("Label", "Category")]
    missing = df[feature_cols].isna().sum().sort_values(ascending=False)
    if missing.sum() == 0:
        # Plot a simple confirmation bar at full count for the most-checked columns
        sample_cols = feature_cols[:30]
        completeness = pd.Series([len(df)] * len(sample_cols), index=sample_cols)
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(range(len(sample_cols)), completeness.values, color="#4F81BD")
        ax.set_xticks(range(len(sample_cols)))
        ax.set_xticklabels(sample_cols, rotation=90, fontsize=7)
        ax.set_ylabel("Non-null count")
        ax.set_title(
            f"Missing-value audit (post-cleaning): all {len(df):,} rows complete across "
            f"{len(feature_cols)} feature columns",
            fontsize=12, fontweight="bold",
        )
    else:
        top_missing = missing.head(20)
        fig, ax = plt.subplots(figsize=(10, 5))
        ax.bar(range(len(top_missing)), top_missing.values, color="#C0504D")
        ax.set_xticks(range(len(top_missing)))
        ax.set_xticklabels(top_missing.index, rotation=90, fontsize=8)
        ax.set_ylabel("Missing count")
        ax.set_title("Top 20 columns by missing count", fontsize=12, fontweight="bold")
    out = eda_dir / "03_missing_values.png"
    _save(fig, out)
    return out


def plot_correlation_heatmap(df: pd.DataFrame, eda_dir: Path, max_features: int = 30):
    """Correlation heatmap on the most-variable features."""
    feature_cols = [c for c in df.columns if c not in ("Label", "Category")]
    feat = df[feature_cols].select_dtypes(include=[np.number])

    # Pick the top features by variance to keep the heatmap readable
    variances = feat.var().sort_values(ascending=False)
    selected = variances.head(max_features).index.tolist()

    corr = feat[selected].corr().round(2)
    fig, ax = plt.subplots(figsize=(13, 11))
    sns.heatmap(corr, cmap="coolwarm", annot=False, square=True,
                linewidths=0.3, linecolor="white", cbar_kws={"shrink": 0.7}, ax=ax)
    ax.set_title(f"Correlation matrix — top {max_features} features by variance",
                 fontsize=13, fontweight="bold")
    ax.tick_params(axis="x", rotation=90, labelsize=8)
    ax.tick_params(axis="y", rotation=0, labelsize=8)
    out = eda_dir / "04_correlation_heatmap.png"
    _save(fig, out)
    return out


def plot_top_features_by_attack_correlation(df: pd.DataFrame, eda_dir: Path,
                                            top_k: int = 15):
    """Bar chart of features with the strongest correlation to attack label."""
    feature_cols = [c for c in df.columns if c not in ("Label", "Category")]
    feat = df[feature_cols].select_dtypes(include=[np.number]).copy()
    feat["__is_attack__"] = (df["Category"] != "BENIGN").astype(int)

    corr_with_attack = feat.corr()["__is_attack__"].drop("__is_attack__")
    abs_corr = corr_with_attack.abs().sort_values(ascending=False).head(top_k)
    signed = corr_with_attack.loc[abs_corr.index]

    colors = ["#C0504D" if v < 0 else "#4F81BD" for v in signed.values]
    fig, ax = plt.subplots(figsize=(9, 6))
    ax.barh(range(len(signed)), signed.values[::-1], color=colors[::-1])
    ax.set_yticks(range(len(signed)))
    ax.set_yticklabels(signed.index[::-1], fontsize=9)
    ax.axvline(0, color="black", linewidth=0.5)
    ax.set_xlabel("Pearson correlation with binary attack label")
    ax.set_title(f"Top {top_k} features by absolute correlation with attack label",
                 fontsize=13, fontweight="bold")
    out = eda_dir / "05_top_features_by_correlation.png"
    _save(fig, out)
    return out, signed


def plot_feature_distributions(df: pd.DataFrame, top_features: list, eda_dir: Path):
    """Per-class boxplots for the most discriminative features (log-scale where helpful)."""
    n = min(6, len(top_features))
    fig, axes = plt.subplots(2, 3, figsize=(15, 9))
    axes = axes.flatten()

    categories = df["Category"].value_counts().head(7).index.tolist()  # cap for readability
    df_plot = df[df["Category"].isin(categories)].copy()
    palette = sns.color_palette("Set2", n_colors=len(categories))

    for i, feat in enumerate(top_features[:n]):
        ax = axes[i]
        data = []
        labels = []
        for cat in categories:
            vals = df_plot.loc[df_plot["Category"] == cat, feat].dropna()
            # Clip extreme tails so the boxplot is readable without dominating outliers
            vals = vals[(vals >= vals.quantile(0.001)) & (vals <= vals.quantile(0.999))]
            data.append(vals.values)
            labels.append(cat)
        bp = ax.boxplot(data, tick_labels=labels, patch_artist=True, showfliers=False)
        for patch, color in zip(bp["boxes"], palette):
            patch.set_facecolor(color)
            patch.set_alpha(0.7)
        ax.set_title(feat, fontsize=10, fontweight="bold")
        ax.tick_params(axis="x", rotation=30, labelsize=8)
        ax.tick_params(axis="y", labelsize=8)

    fig.suptitle("Top discriminative features by attack category (boxplots, outliers hidden)",
                 fontsize=14, fontweight="bold", y=1.00)
    out = eda_dir / "06_feature_distributions.png"
    _save(fig, out)
    return out


def compute_outlier_summary(df: pd.DataFrame, eda_dir: Path):
    """IQR-based outlier counts and percentages per feature."""
    feature_cols = [c for c in df.columns if c not in ("Label", "Category")]
    feat = df[feature_cols].select_dtypes(include=[np.number])
    q1 = feat.quantile(0.25)
    q3 = feat.quantile(0.75)
    iqr = q3 - q1
    is_outlier = (feat < (q1 - 1.5 * iqr)) | (feat > (q3 + 1.5 * iqr))
    summary = pd.DataFrame({
        "outlier_count": is_outlier.sum(),
        "outlier_pct": (is_outlier.mean() * 100).round(2),
    }).sort_values("outlier_pct", ascending=False)
    out = eda_dir / "07_outlier_summary.csv"
    summary.to_csv(out)
    return out, summary


def compute_per_class_stats(df: pd.DataFrame, top_features: list, eda_dir: Path):
    """For each top feature, mean/median/std per attack category."""
    rows = []
    for feat in top_features[:10]:
        for cat, grp in df.groupby("Category"):
            vals = grp[feat].dropna()
            rows.append({
                "feature": feat,
                "category": cat,
                "n": len(vals),
                "mean": float(vals.mean()) if len(vals) else float("nan"),
                "median": float(vals.median()) if len(vals) else float("nan"),
                "std": float(vals.std()) if len(vals) else float("nan"),
            })
    out_df = pd.DataFrame(rows)
    out = eda_dir / "08_per_class_feature_stats.csv"
    out_df.to_csv(out, index=False)
    return out, out_df


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "00b_eda")

    eda_dir = project_path(cfg, "results_dir", "eda")
    eda_dir.mkdir(parents=True, exist_ok=True)

    prepared = project_path(cfg, "processed_data_dir", "prepared.parquet")
    if not prepared.exists():
        raise FileNotFoundError(
            f"Run 01_prepare_data.py first. Missing: {prepared}"
        )

    logger.info("Loading prepared parquet: %s", prepared)
    df = pd.read_parquet(prepared)
    logger.info("Loaded %d rows, %d columns", len(df), df.shape[1])

    # 1. Class distribution (linear and log scale)
    logger.info("Plotting class distribution")
    plot_class_distribution(df, eda_dir, log_scale=False)
    plot_class_distribution(df, eda_dir, log_scale=True)

    # 2. Missing-value audit
    logger.info("Plotting missing-value audit")
    plot_missing_summary(df, eda_dir)

    # 3. Correlation heatmap
    logger.info("Plotting correlation heatmap")
    plot_correlation_heatmap(df, eda_dir, max_features=30)

    # 4. Top features by correlation with attack label
    logger.info("Plotting top features by correlation")
    _, signed = plot_top_features_by_attack_correlation(df, eda_dir, top_k=15)
    top_features = list(signed.index)

    # 5. Feature distributions per class
    logger.info("Plotting per-class feature distributions")
    plot_feature_distributions(df, top_features, eda_dir)

    # 6. Outlier summary
    logger.info("Computing outlier summary")
    compute_outlier_summary(df, eda_dir)

    # 7. Per-class feature statistics
    logger.info("Computing per-class feature statistics")
    compute_per_class_stats(df, top_features, eda_dir)

    # 8. Text summary
    summary_path = eda_dir / "eda_summary.txt"
    with summary_path.open("w") as fh:
        fh.write("Exploratory Data Analysis Summary\n")
        fh.write("=" * 50 + "\n\n")
        fh.write(f"Total rows:       {len(df):,}\n")
        fh.write(f"Total columns:    {df.shape[1]}\n")
        fh.write(f"Attack ratio:     {(df['Category'] != 'BENIGN').mean():.4f}\n\n")
        fh.write("Category counts:\n")
        for cat, c in df["Category"].value_counts().items():
            pct = 100.0 * c / len(df)
            fh.write(f"  {cat:<14s}  {c:>10,d}  ({pct:5.2f}%)\n")
        fh.write("\nTop 15 features by absolute correlation with attack label:\n")
        for feat, val in signed.items():
            fh.write(f"  {feat:<35s}  {val:+.4f}\n")
    logger.info("Wrote %s", summary_path)
    logger.info("EDA artefacts written to %s", eda_dir)


if __name__ == "__main__":
    main()
