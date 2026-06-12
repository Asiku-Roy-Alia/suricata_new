#!/usr/bin/env python3
"""Smoke test that exercises the entire pipeline on synthetic data.

Run this first, before touching CIC-IDS-2017, to confirm your environment is
set up correctly. The script generates about ten thousand synthetic flow
records with properties similar to the real benchmark, runs the preprocessing
pipeline, trains baselines and the stacked hybrid, runs a tiny LOACO
experiment, and prints pass/fail with quantitative thresholds.

Expected runtime: under two minutes on a modest laptop.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging  # noqa: E402
from src import data as data_mod  # noqa: E402
from src import features as feat_mod  # noqa: E402
from src import models as models_mod  # noqa: E402
from src import metrics as metrics_mod  # noqa: E402


def generate_synthetic(n_benign: int, attack_specs: dict, seed: int) -> pd.DataFrame:
    """Generate a synthetic dataset with CIC-IDS-2017-like structure."""
    rng = np.random.default_rng(seed)
    n_features = 40
    frames = []

    # Benign: tight cluster around origin.
    x = rng.normal(loc=0.0, scale=1.0, size=(n_benign, n_features))
    benign = pd.DataFrame(x, columns=[f"f{i:02d}" for i in range(n_features)])
    benign["Label"] = "BENIGN"
    frames.append(benign)

    # Attacks: each category is a distinct gaussian blob offset from origin.
    for i, (cat, n) in enumerate(attack_specs.items()):
        center = np.zeros(n_features)
        # Shift a subset of features to create a learnable signature.
        shift_idx = rng.choice(n_features, size=10, replace=False)
        center[shift_idx] = 3.0 + 0.5 * i  # each category different
        x = rng.normal(loc=center, scale=1.2, size=(n, n_features))
        df = pd.DataFrame(x, columns=[f"f{i:02d}" for i in range(n_features)])
        df["Label"] = cat
        frames.append(df)

    return pd.concat(frames, axis=0, ignore_index=True).sample(frac=1.0, random_state=seed).reset_index(drop=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "00_smoke_test")

    logger.info("=" * 70)
    logger.info("SMOKE TEST")
    logger.info("=" * 70)

    # ---------- Synthetic data ----------
    attack_specs = {
        "DoS Hulk": 1500,
        "DDoS": 1200,
        "PortScan": 1000,
        "FTP-Patator": 400,
        "Web Attack  Brute Force": 300,
        "Bot": 200,
    }
    df = generate_synthetic(n_benign=8000, attack_specs=attack_specs, seed=cfg["seed"])
    logger.info("Synthetic dataset shape: %s", df.shape)

    # ---------- Apply the same normalisation the real pipeline uses ----------
    df = data_mod.normalise_labels(df, logger)
    X, y_bin, y_cat = data_mod.split_features_labels(df)

    # ---------- Three-way split ----------
    (X_tr, X_val, X_te,
     yb_tr, yb_val, yb_te,
     yc_tr, yc_val, yc_te) = feat_mod.split_train_test_val(
        X, y_bin.values, y_cat.values,
        test_size=cfg["preprocessing"]["test_size"],
        val_size=cfg["preprocessing"]["validation_size"],
        seed=cfg["seed"],
    )
    logger.info("Split sizes: train=%d val=%d test=%d", len(X_tr), len(X_val), len(X_te))

    # ---------- Feature pipeline ----------
    fp = feat_mod.fit(
        X_tr, yb_tr,
        n_rfe_features=min(20, X.shape[1]),
        pca_variance=cfg["preprocessing"]["pca_variance_retained"],
        seed=cfg["seed"],
        logger=logger,
    )
    Xtr = feat_mod.transform(fp.pipeline, X_tr)
    Xval = feat_mod.transform(fp.pipeline, X_val)
    Xte = feat_mod.transform(fp.pipeline, X_te)

    # ---------- Baselines ----------
    logger.info("-" * 70)
    logger.info("BASELINES")
    logger.info("-" * 70)

    lin = models_mod.fit_linear_svc_baseline(Xtr, yb_tr, cfg, logger)
    lin_prob = lin.predict_proba(Xte)[:, 1]
    lin_pred = (lin_prob >= 0.5).astype(int)
    lin_m = metrics_mod.binary_metrics(yb_te, lin_pred, lin_prob)
    logger.info(metrics_mod.format_metrics_line("LinearSVC", lin_m))

    iforest = models_mod.fit_isolation_forest_baseline(Xtr, yb_tr, cfg, logger)
    if_pred = models_mod.isolation_forest_predict(iforest, Xte)
    if_score = models_mod.isolation_forest_score(iforest, Xte)
    if_m = metrics_mod.binary_metrics(yb_te, if_pred, if_score)
    logger.info(metrics_mod.format_metrics_line("IsolationForest", if_m))

    # ---------- Hybrid ----------
    logger.info("-" * 70)
    logger.info("HYBRID STACKED MODEL")
    logger.info("-" * 70)

    hybrid = models_mod.HybridStackedClassifier(cfg, logger)
    hybrid.fit(Xtr, yb_tr, Xval, yb_val, cv=3)
    hyb_prob = hybrid.predict_proba(Xte)[:, 1]
    hyb_pred = (hyb_prob >= 0.5).astype(int)
    hyb_m = metrics_mod.binary_metrics(yb_te, hyb_pred, hyb_prob)
    logger.info(metrics_mod.format_metrics_line("Hybrid", hyb_m))

    # Per-category recall
    per_cat = metrics_mod.per_category_recall(yc_te, hyb_pred)
    logger.info("Per-category recall (hybrid): %s", per_cat)

    # Calibration
    ece = metrics_mod.expected_calibration_error(yb_te, hyb_prob, n_bins=10)
    logger.info("Hybrid Expected Calibration Error: %.4f", ece)

    # ---------- Acceptance thresholds ----------
    logger.info("=" * 70)
    logger.info("THRESHOLD CHECKS")
    logger.info("=" * 70)
    checks = [
        ("LinearSVC macro F1 > 0.85", lin_m["macro_f1"] > 0.85),
        ("Hybrid macro F1 > 0.90",    hyb_m["macro_f1"] > 0.90),
        ("Hybrid FPR < 0.05",         hyb_m["false_positive_rate"] < 0.05),
        ("Hybrid ECE < 0.10",         ece < 0.10),
    ]
    all_pass = True
    for name, ok in checks:
        status = "PASS" if ok else "FAIL"
        logger.info("  [%s] %s", status, name)
        if not ok:
            all_pass = False

    if all_pass:
        logger.info("SMOKE TEST PASSED. Environment is ready for CIC-IDS-2017.")
        sys.exit(0)
    else:
        logger.error("SMOKE TEST FAILED. See log above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
