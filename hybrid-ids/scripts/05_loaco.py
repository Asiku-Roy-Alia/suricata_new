#!/usr/bin/env python3
"""Step 5: Leave-One-Attack-Category-Out (LOACO) experiment.

For each attack category, remove it entirely from training (both train and
validation sets), retrain the hybrid model on the remaining categories, then
measure the detection rate on the held-out category. This directly tests the
claim that the system can detect novel attacks.

Output:
  results/loaco/loaco_results.csv
  results/loaco/loaco_plot.png
  results/loaco/loaco_detailed.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402
from src import models as models_mod  # noqa: E402
from src import metrics as metrics_mod  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "05_loaco")

    if not cfg["loaco"]["enabled"]:
        logger.info("LOACO disabled in config. Exiting.")
        return

    splits_path = project_path(cfg, "processed_data_dir", "splits.npz")
    z = np.load(splits_path, allow_pickle=True)
    X_tr, X_val, X_te = z["X_train"], z["X_val"], z["X_test"]
    yb_tr, yb_val, yb_te = z["y_train_bin"].astype(int), z["y_val_bin"].astype(int), z["y_test_bin"].astype(int)
    yc_tr, yc_val, yc_te = z["y_train_cat"].astype(str), z["y_val_cat"].astype(str), z["y_test_cat"].astype(str)

    categories_present = set(np.unique(yc_tr)) - {"BENIGN"}
    loaco_categories = [c for c in cfg["loaco"]["attack_categories"] if c in categories_present]
    missing = [c for c in cfg["loaco"]["attack_categories"] if c not in categories_present]
    if missing:
        logger.warning("Categories in config but not in data: %s", missing)
    logger.info("LOACO will iterate over: %s", loaco_categories)

    rows = []
    detailed_lines = []

    for held_out in loaco_categories:
        logger.info("=" * 70)
        logger.info("LOACO iteration: holding out '%s'", held_out)
        logger.info("=" * 70)

        # Remove the held-out category from train AND val.
        mask_tr = yc_tr != held_out
        mask_val = yc_val != held_out

        X_tr_loaco = X_tr[mask_tr]
        yb_tr_loaco = yb_tr[mask_tr]
        X_val_loaco = X_val[mask_val]
        yb_val_loaco = yb_val[mask_val]

        logger.info("Train without %s: %d rows (%d benign, %d attack)",
                    held_out, len(X_tr_loaco), int((yb_tr_loaco == 0).sum()), int((yb_tr_loaco == 1).sum()))
        logger.info("Val without %s:   %d rows", held_out, len(X_val_loaco))

        # Train hybrid on reduced data.
        hybrid = models_mod.HybridStackedClassifier(cfg, logger)
        hybrid.fit(X_tr_loaco, yb_tr_loaco, X_val_loaco, yb_val_loaco, cv=3)

        # Evaluate on full test set: report overall metrics plus detection rate
        # specifically on the held-out category's test instances.
        probs = hybrid.predict_proba(X_te)[:, 1]
        preds = (probs >= 0.5).astype(int)

        overall = metrics_mod.binary_metrics(yb_te, preds, probs)

        held_out_mask_te = (yc_te == held_out)
        if held_out_mask_te.sum() == 0:
            logger.warning("No test samples for held-out category %s", held_out)
            held_out_recall = float("nan")
        else:
            held_out_recall = float(np.mean(preds[held_out_mask_te] == 1))

        # Recall on categories still known to the model.
        known_mask = (yc_te != held_out) & (yc_te != "BENIGN")
        if known_mask.sum() == 0:
            known_recall = float("nan")
        else:
            known_recall = float(np.mean(preds[known_mask] == 1))

        benign_mask = (yc_te == "BENIGN")
        if benign_mask.sum() == 0:
            tnr = float("nan")
        else:
            tnr = float(np.mean(preds[benign_mask] == 0))

        rows.append({
            "held_out_category": held_out,
            "novel_recall": held_out_recall,
            "known_attack_recall": known_recall,
            "true_negative_rate": tnr,
            "overall_macro_f1": overall["macro_f1"],
            "overall_mcc": overall["mcc"],
            "overall_fpr": overall["false_positive_rate"],
        })

        line = (
            f"{held_out:<15s}  novel_recall={held_out_recall:.4f}  "
            f"known_recall={known_recall:.4f}  TNR={tnr:.4f}  "
            f"macroF1={overall['macro_f1']:.4f}  MCC={overall['mcc']:.4f}"
        )
        logger.info(line)
        detailed_lines.append(line)

    df = pd.DataFrame(rows)
    out = project_path(cfg, "loaco_dir", "loaco_results.csv")
    df.to_csv(out, index=False)
    logger.info("Wrote %s", out)
    logger.info("\n%s", df.round(4).to_string(index=False))

    detail = project_path(cfg, "loaco_dir", "loaco_detailed.txt")
    with detail.open("w") as fh:
        fh.write("Leave-One-Attack-Category-Out experiment\n")
        fh.write("=" * 70 + "\n")
        fh.write("\n".join(detailed_lines))
    logger.info("Wrote %s", detail)

    # Plot: novel vs known recall per held-out category
    fig, ax = plt.subplots(figsize=(9, 5))
    x = np.arange(len(df))
    width = 0.35
    ax.bar(x - width / 2, df["novel_recall"], width, label="Recall on held-out (novel)", color="#C0504D")
    ax.bar(x + width / 2, df["known_attack_recall"], width, label="Recall on remaining known attacks", color="#4F81BD")
    ax.set_xticks(x)
    ax.set_xticklabels(df["held_out_category"], rotation=30, ha="right")
    ax.set_ylabel("Recall on test set")
    ax.set_title("LOACO: detection of held-out (novel) vs remaining known attack categories")
    ax.set_ylim(0, 1.0)
    ax.legend()
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    plot_path = project_path(cfg, "loaco_dir", "loaco_plot.png")
    fig.savefig(plot_path, dpi=120)
    plt.close(fig)
    logger.info("Wrote %s", plot_path)


if __name__ == "__main__":
    main()
