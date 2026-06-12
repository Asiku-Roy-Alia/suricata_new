#!/usr/bin/env python3
"""Step 3: Train baseline models and the hybrid stacked classifier.

Output:
  artifacts/linear_svc.joblib
  artifacts/isolation_forest.joblib
  artifacts/hybrid.joblib
  results/training_summary.txt
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402
from src import models as models_mod  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "03_train_models")

    splits_path = project_path(cfg, "processed_data_dir", "splits.npz")
    if not splits_path.exists():
        raise FileNotFoundError(f"Missing {splits_path}. Run 02_preprocess.py first.")

    logger.info("Loading splits: %s", splits_path)
    z = np.load(splits_path, allow_pickle=True)
    X_tr, X_val, X_te = z["X_train"], z["X_val"], z["X_test"]
    yb_tr, yb_val = z["y_train_bin"].astype(int), z["y_val_bin"].astype(int)

    # ---------- Baselines ----------
    logger.info("=" * 70)
    logger.info("BASELINE 1: Linear SVC")
    logger.info("=" * 70)
    lin_svc = models_mod.fit_linear_svc_baseline(X_tr, yb_tr, cfg, logger)
    joblib.dump(lin_svc, project_path(cfg, "artifacts_dir", "linear_svc.joblib"))
    logger.info("Saved linear_svc.joblib")

    logger.info("=" * 70)
    logger.info("BASELINE 2: Isolation Forest")
    logger.info("=" * 70)
    iforest = models_mod.fit_isolation_forest_baseline(X_tr, yb_tr, cfg, logger)
    joblib.dump(iforest, project_path(cfg, "artifacts_dir", "isolation_forest.joblib"))
    logger.info("Saved isolation_forest.joblib")

    # ---------- Hybrid ----------
    logger.info("=" * 70)
    logger.info("HYBRID STACKED MODEL")
    logger.info("=" * 70)
    hybrid = models_mod.HybridStackedClassifier(cfg, logger)
    hybrid.fit(X_tr, yb_tr, X_val, yb_val, cv=3)
    joblib.dump(hybrid, project_path(cfg, "artifacts_dir", "hybrid.joblib"))
    logger.info("Saved hybrid.joblib")
    logger.info("Best hyperparameters: %s", hybrid.artifacts_.best_params)

    summary_path = project_path(cfg, "results_dir", "training_summary.txt")
    with summary_path.open("w") as fh:
        fh.write("Training summary\n================\n\n")
        fh.write(f"Train size:      {len(X_tr)}\n")
        fh.write(f"Val size:        {len(X_val)}\n")
        fh.write(f"Test size:       {len(X_te)}\n\n")
        fh.write(f"Hybrid best params: {hybrid.artifacts_.best_params}\n")
    logger.info("Wrote %s", summary_path)


if __name__ == "__main__":
    main()
