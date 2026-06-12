#!/usr/bin/env python3
"""Step 4: Evaluate all trained models on the held-out test set.

Produces:
  results/metrics_summary.csv
  results/per_category_recall.csv
  results/confusion_matrices.txt
  results/plots/reliability_hybrid.png
  results/plots/pr_curves.png
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from sklearn.metrics import confusion_matrix, precision_recall_curve

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402
from src import models as models_mod  # noqa: E402
from src import metrics as metrics_mod  # noqa: E402


def reliability_plot(y_true, y_prob, path: Path, title: str):
    mp, of, counts = metrics_mod.reliability_curve(y_true, y_prob, n_bins=10)
    fig, ax = plt.subplots(figsize=(6, 5))
    ax.plot([0, 1], [0, 1], "--", color="gray", label="Perfect calibration")
    valid = [(m, o) for m, o in zip(mp, of) if not (np.isnan(m) or np.isnan(o))]
    if valid:
        xs, ys = zip(*valid)
        ax.plot(xs, ys, "o-", label="Hybrid")
    ax.set_xlabel("Mean predicted probability")
    ax.set_ylabel("Empirical frequency")
    ax.set_title(title)
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def pr_plot(results: dict, path: Path):
    fig, ax = plt.subplots(figsize=(6, 5))
    for name, (y_true, y_prob) in results.items():
        p, r, _ = precision_recall_curve(y_true, y_prob)
        ax.plot(r, p, label=name)
    ax.set_xlabel("Recall")
    ax.set_ylabel("Precision")
    ax.set_title("Precision-Recall curves (test set)")
    ax.legend()
    ax.grid(True, alpha=0.3)
    fig.tight_layout()
    fig.savefig(path, dpi=120)
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "04_evaluate")

    splits_path = project_path(cfg, "processed_data_dir", "splits.npz")
    z = np.load(splits_path, allow_pickle=True)
    X_te = z["X_test"]
    yb_te = z["y_test_bin"].astype(int)
    yc_te = z["y_test_cat"].astype(str)

    lin_svc = joblib.load(project_path(cfg, "artifacts_dir", "linear_svc.joblib"))
    iforest = joblib.load(project_path(cfg, "artifacts_dir", "isolation_forest.joblib"))
    hybrid = joblib.load(project_path(cfg, "artifacts_dir", "hybrid.joblib"))

    # Predictions
    lin_prob = lin_svc.predict_proba(X_te)[:, 1]
    lin_pred = (lin_prob >= 0.5).astype(int)

    if_pred = models_mod.isolation_forest_predict(iforest, X_te)
    if_score = models_mod.isolation_forest_score(iforest, X_te)

    hyb_prob = hybrid.predict_proba(X_te)[:, 1]
    hyb_pred = (hyb_prob >= 0.5).astype(int)

    # Metrics
    rows = []
    for name, y_pred, y_prob in [
        ("LinearSVC", lin_pred, lin_prob),
        ("IsolationForest", if_pred, if_score),
        ("HybridStack", hyb_pred, hyb_prob),
    ]:
        m = metrics_mod.binary_metrics(yb_te, y_pred, y_prob)
        m["model"] = name
        m["ece"] = metrics_mod.expected_calibration_error(yb_te, y_prob, n_bins=10)
        rows.append(m)
        logger.info(metrics_mod.format_metrics_line(name, m))
        logger.info("  ECE (10-bin): %.4f", m["ece"])

    df = pd.DataFrame(rows)[
        ["model", "macro_f1", "mcc", "accuracy", "precision", "recall",
         "false_positive_rate", "false_negative_rate", "roc_auc", "ece",
         "tp", "fp", "tn", "fn"]
    ]
    out = project_path(cfg, "results_dir", "metrics_summary.csv")
    df.to_csv(out, index=False)
    logger.info("Wrote %s", out)

    # Per-category recall
    cat_rows = []
    for name, y_pred in [("LinearSVC", lin_pred), ("IsolationForest", if_pred), ("HybridStack", hyb_pred)]:
        rec = metrics_mod.per_category_recall(yc_te, y_pred)
        for cat, r in rec.items():
            cat_rows.append({"model": name, "category": cat, "recall": r})
    cat_df = pd.DataFrame(cat_rows).pivot(index="category", columns="model", values="recall")
    cat_out = project_path(cfg, "results_dir", "per_category_recall.csv")
    cat_df.to_csv(cat_out)
    logger.info("Wrote %s\n%s", cat_out, cat_df.round(4).to_string())

    # Confusion matrices
    cm_path = project_path(cfg, "results_dir", "confusion_matrices.txt")
    with cm_path.open("w") as fh:
        for name, y_pred in [("LinearSVC", lin_pred), ("IsolationForest", if_pred), ("HybridStack", hyb_pred)]:
            cm = confusion_matrix(yb_te, y_pred, labels=[0, 1])
            fh.write(f"\n{name}\n")
            fh.write("                pred_BENIGN  pred_ATTACK\n")
            fh.write(f"true_BENIGN       {cm[0, 0]:>10d}  {cm[0, 1]:>10d}\n")
            fh.write(f"true_ATTACK       {cm[1, 0]:>10d}  {cm[1, 1]:>10d}\n")
    logger.info("Wrote %s", cm_path)

    # Plots
    reliability_plot(
        yb_te, hyb_prob,
        project_path(cfg, "plots_dir", "reliability_hybrid.png"),
        "Reliability diagram: Hybrid stacked model",
    )
    pr_plot(
        {"LinearSVC": (yb_te, lin_prob),
         "IsolationForest": (yb_te, if_score),
         "HybridStack": (yb_te, hyb_prob)},
        project_path(cfg, "plots_dir", "pr_curves.png"),
    )
    logger.info("Wrote reliability_hybrid.png and pr_curves.png")


if __name__ == "__main__":
    main()
