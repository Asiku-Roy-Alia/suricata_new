#!/usr/bin/env python3
"""Step 2: Fit the preprocessing pipeline and save train/val/test splits.

Output:
  data/processed/splits.npz       (X_train, X_val, X_test, y_* arrays)
  artifacts/feature_pipeline.joblib
  data/processed/feature_info.txt (RFE-retained feature list + PCA summary)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402
from src import data as data_mod  # noqa: E402
from src import features as feat_mod  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "02_preprocess")

    prepared_path = project_path(cfg, "processed_data_dir", "prepared.parquet")
    if not prepared_path.exists():
        raise FileNotFoundError(
            f"Missing {prepared_path}. Run scripts/01_prepare_data.py first."
        )

    logger.info("Loading prepared parquet: %s", prepared_path)
    df = pd.read_parquet(prepared_path)
    logger.info("Loaded %d rows, %d columns", len(df), df.shape[1])

    X, y_bin, y_cat = data_mod.split_features_labels(df)
    logger.info("Feature space: %d columns", X.shape[1])

    (X_tr, X_val, X_te,
     yb_tr, yb_val, yb_te,
     yc_tr, yc_val, yc_te) = feat_mod.split_train_test_val(
        X, y_bin.values, y_cat.values,
        test_size=cfg["preprocessing"]["test_size"],
        val_size=cfg["preprocessing"]["validation_size"],
        seed=cfg["seed"],
    )
    logger.info("Split sizes: train=%d val=%d test=%d", len(X_tr), len(X_val), len(X_te))

    fp = feat_mod.fit(
        X_tr, yb_tr,
        n_rfe_features=cfg["preprocessing"]["rfe_n_features"],
        pca_variance=cfg["preprocessing"]["pca_variance_retained"],
        seed=cfg["seed"],
        logger=logger,
    )

    Xtr = feat_mod.transform(fp.pipeline, X_tr).astype(np.float32)
    Xval = feat_mod.transform(fp.pipeline, X_val).astype(np.float32)
    Xte = feat_mod.transform(fp.pipeline, X_te).astype(np.float32)
    logger.info("Transformed shapes: train %s, val %s, test %s", Xtr.shape, Xval.shape, Xte.shape)

    # ---- Class balancing on the TRAINING SET only ----
    # Validation and test sets keep their natural distribution because they
    # are used to estimate real-world performance. Balancing follows the
    # notebook approach: cap each class at class_cap real samples, then
    # use SMOTE to synthesise minority samples up to the cap.
    if cfg["preprocessing"].get("enable_class_balancing", False):
        from collections import Counter
        cap = int(cfg["preprocessing"]["class_cap"])
        logger.info("Balancing training set (cap=%d, then SMOTE to equalise)", cap)

        # Step 1: cap each class at `cap` real samples
        rng = np.random.default_rng(cfg["seed"])
        keep_indices = []
        for cat in np.unique(yc_tr):
            cat_idx = np.where(yc_tr == cat)[0]
            if len(cat_idx) > cap:
                chosen = rng.choice(cat_idx, size=cap, replace=False)
            else:
                chosen = cat_idx
            keep_indices.extend(chosen.tolist())
        keep_indices = np.array(sorted(keep_indices))
        Xtr_capped = Xtr[keep_indices]
        yb_tr_capped = yb_tr[keep_indices]
        yc_tr_capped = yc_tr[keep_indices]
        logger.info("After capping: %d rows, distribution: %s",
                    len(Xtr_capped), dict(Counter(yc_tr_capped)))

        # Step 2: SMOTE on the capped set, using the multi-class label so
        # SMOTE can target each minority category. The k_neighbours parameter
        # automatically adjusts down for very small classes.
        try:
            from imblearn.over_sampling import SMOTE
            min_class_count = min(Counter(yc_tr_capped).values())
            k = max(1, min(5, min_class_count - 1))
            smote = SMOTE(random_state=cfg["seed"], k_neighbors=k)
            Xtr_bal, yc_tr_bal = smote.fit_resample(Xtr_capped, yc_tr_capped)
            yb_tr_bal = (yc_tr_bal != "BENIGN").astype(np.int8)
            logger.info("After SMOTE: %d rows, distribution: %s",
                        len(Xtr_bal), dict(Counter(yc_tr_bal)))
            Xtr, yb_tr, yc_tr = Xtr_bal.astype(np.float32), yb_tr_bal, yc_tr_bal
        except ImportError:
            logger.warning("imbalanced-learn not installed, skipping SMOTE. "
                           "Install with: pip install imbalanced-learn")
            Xtr, yb_tr, yc_tr = Xtr_capped, yb_tr_capped, yc_tr_capped

    splits_path = project_path(cfg, "processed_data_dir", "splits.npz")
    np.savez_compressed(
        splits_path,
        X_train=Xtr, X_val=Xval, X_test=Xte,
        y_train_bin=yb_tr.astype(np.int8), y_val_bin=yb_val.astype(np.int8), y_test_bin=yb_te.astype(np.int8),
        y_train_cat=yc_tr, y_val_cat=yc_val, y_test_cat=yc_te,
    )
    logger.info("Wrote splits: %s", splits_path)

    joblib.dump(fp.pipeline, project_path(cfg, "artifacts_dir", "feature_pipeline.joblib"))
    logger.info("Wrote feature pipeline artifact")

    info_path = project_path(cfg, "processed_data_dir", "feature_info.txt")
    with info_path.open("w") as fh:
        fh.write(f"Input features: {X.shape[1]}\n")
        fh.write(f"RFE retained:   {len(fp.selected_feature_names)}\n")
        fh.write(f"PCA components: {fp.n_components}\n")
        fh.write(f"PCA variance retained: {fp.explained_variance_ratio_sum:.4f}\n\n")
        fh.write("RFE-selected features:\n")
        fh.write("\n".join(fp.selected_feature_names))
    logger.info("Wrote feature_info.txt")


if __name__ == "__main__":
    main()
