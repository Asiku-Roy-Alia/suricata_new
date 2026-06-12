"""Feature engineering pipeline.

The pipeline performs scaling first, then Recursive Feature Elimination using
a fast linear estimator, then Principal Component Analysis on the retained
features. This order is deliberate:

  1. Scaling first so that RFE and PCA are not dominated by columns with
     large raw magnitudes (flow durations and byte counts span many orders).
  2. RFE next so that uninformative noise columns are removed before we let
     PCA mix features linearly.
  3. PCA last to reduce dimensionality while preserving 95% of variance,
     which materially speeds up subsequent SVM training.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import List, Tuple

import numpy as np
import pandas as pd
from sklearn.decomposition import PCA
from sklearn.feature_selection import RFE
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler


@dataclass
class FeaturePipeline:
    """Container for the fitted preprocessing objects and diagnostic info."""

    pipeline: Pipeline
    selected_feature_names: List[str]
    n_components: int
    explained_variance_ratio_sum: float


def build(n_rfe_features: int, pca_variance: float, seed: int) -> Pipeline:
    """Construct the unfitted sklearn pipeline."""
    selector_estimator = LogisticRegression(
        solver="liblinear",
        max_iter=1000,
        random_state=seed,
    )
    pipe = Pipeline(
        steps=[
            ("scaler", StandardScaler()),
            (
                "rfe",
                RFE(
                    estimator=selector_estimator,
                    n_features_to_select=n_rfe_features,
                    step=0.1,
                ),
            ),
            ("pca", PCA(n_components=pca_variance, svd_solver="full", random_state=seed)),
        ]
    )
    return pipe


def fit(
    X: pd.DataFrame,
    y: np.ndarray,
    n_rfe_features: int,
    pca_variance: float,
    seed: int,
    logger: logging.Logger,
) -> FeaturePipeline:
    """Fit the preprocessing pipeline on (X, y) and return diagnostic metadata."""
    pipe = build(n_rfe_features, pca_variance, seed)

    n_rfe_features = min(n_rfe_features, X.shape[1])
    pipe.named_steps["rfe"].n_features_to_select = n_rfe_features

    logger.info(
        "Fitting feature pipeline (%d rows, %d input features, RFE keeps %d, PCA var %.2f)",
        len(X),
        X.shape[1],
        n_rfe_features,
        pca_variance,
    )

    pipe.fit(X, y)

    rfe = pipe.named_steps["rfe"]
    pca = pipe.named_steps["pca"]
    support_mask = rfe.support_
    feature_names = list(X.columns[support_mask])

    logger.info("RFE retained %d features", support_mask.sum())
    logger.info("PCA produced %d components (var retained: %.4f)",
                pca.n_components_, float(pca.explained_variance_ratio_.sum()))

    return FeaturePipeline(
        pipeline=pipe,
        selected_feature_names=feature_names,
        n_components=int(pca.n_components_),
        explained_variance_ratio_sum=float(pca.explained_variance_ratio_.sum()),
    )


def transform(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """Apply the fitted pipeline to new data."""
    return pipeline.transform(X)


def split_train_test_val(
    X: pd.DataFrame,
    y_binary: np.ndarray,
    y_category: np.ndarray,
    test_size: float,
    val_size: float,
    seed: int,
) -> Tuple[np.ndarray, ...]:
    """Three-way stratified split.

    Returns X_train, X_val, X_test, y_bin_*, y_cat_*.
    The val split is taken out of the remaining 1 - test_size portion and is
    used later for calibrating the anomaly detector.
    """
    from sklearn.model_selection import train_test_split

    X_tr_full, X_te, yb_tr_full, yb_te, yc_tr_full, yc_te = train_test_split(
        X, y_binary, y_category,
        test_size=test_size, stratify=y_category, random_state=seed,
    )
    # Take val out of the remaining training portion.
    relative_val = val_size / (1.0 - test_size)
    X_tr, X_val, yb_tr, yb_val, yc_tr, yc_val = train_test_split(
        X_tr_full, yb_tr_full, yc_tr_full,
        test_size=relative_val, stratify=yc_tr_full, random_state=seed,
    )

    return X_tr, X_val, X_te, yb_tr, yb_val, yb_te, yc_tr, yc_val, yc_te
