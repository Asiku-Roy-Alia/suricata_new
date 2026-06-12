"""Feature engineering pipeline.

The pipeline performs scaling first, then Recursive Feature Elimination using
a fast linear estimator, then Principal Component Analysis on the retained
features. This order is deliberate because CIC-IDS-2017 flow features have
very different numeric scales and a large number of correlated columns.

The helper functions in this module also normalise Pandas/Arrow-backed data
before splitting. This prevents compatibility errors in newer Python, Pandas
and Scikit-learn combinations where train_test_split tries to index Arrow
extension arrays directly.
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


def _normalise_feature_frame(X: pd.DataFrame) -> pd.DataFrame:
    """Return a clean NumPy-backed float32 dataframe.

    Some modern Pandas builds can keep parquet/CSV data in Arrow-backed
    extension arrays. Those arrays are good for storage, but they can break
    older Scikit-learn indexing paths during stratified splitting. Converting
    the feature matrix to a normal NumPy-backed dataframe at the pipeline
    boundary makes the rest of the code deterministic.
    """
    if isinstance(X, pd.DataFrame):
        columns = list(X.columns)
        frame = X.reset_index(drop=True)
    else:
        frame = pd.DataFrame(X)
        columns = list(frame.columns)

    try:
        arr = frame.to_numpy(dtype=np.float32, na_value=np.nan, copy=True)
    except TypeError:
        arr = frame.to_numpy(copy=True).astype(np.float32, copy=False)

    if not np.isfinite(arr).all():
        arr = np.nan_to_num(
            arr,
            nan=0.0,
            posinf=np.finfo(np.float32).max,
            neginf=np.finfo(np.float32).min,
        ).astype(np.float32, copy=False)

    return pd.DataFrame(arr, columns=columns)


def _normalise_binary_labels(y_binary: np.ndarray) -> np.ndarray:
    """Return binary labels as a compact one-dimensional integer array."""
    return np.asarray(pd.Series(y_binary).to_numpy(), dtype=np.int8).reshape(-1)


def _normalise_category_labels(y_category: np.ndarray) -> np.ndarray:
    """Return category labels as a compact one-dimensional string array."""
    return np.asarray(pd.Series(y_category).astype(str).to_numpy(), dtype=str).reshape(-1)


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
            (
                "pca",
                PCA(
                    n_components=pca_variance,
                    svd_solver="full",
                    random_state=seed,
                ),
            ),
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
    """Fit the preprocessing pipeline on X and y and return diagnostics."""
    X = _normalise_feature_frame(X)
    y = _normalise_binary_labels(y)

    pipe = build(n_rfe_features, pca_variance, seed)

    n_rfe_features = min(int(n_rfe_features), X.shape[1])
    if n_rfe_features < 1:
        raise ValueError("n_rfe_features must keep at least one feature.")

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

    logger.info("RFE retained %d features", int(support_mask.sum()))
    logger.info(
        "PCA produced %d components (var retained: %.4f)",
        int(pca.n_components_),
        float(pca.explained_variance_ratio_.sum()),
    )

    return FeaturePipeline(
        pipeline=pipe,
        selected_feature_names=feature_names,
        n_components=int(pca.n_components_),
        explained_variance_ratio_sum=float(pca.explained_variance_ratio_.sum()),
    )


def transform(pipeline: Pipeline, X: pd.DataFrame) -> np.ndarray:
    """Apply the fitted pipeline to new data."""
    X = _normalise_feature_frame(X)
    return pipeline.transform(X)


def split_train_test_val(
    X: pd.DataFrame,
    y_binary: np.ndarray,
    y_category: np.ndarray,
    test_size: float,
    val_size: float,
    seed: int,
) -> Tuple[np.ndarray, ...]:
    """Create train, validation and test splits with category stratification.

    The function splits indices first, then uses Pandas iloc. That avoids
    Scikit-learn directly indexing Pandas Arrow extension arrays, which is
    the failure you saw in the smoke test.
    """
    from sklearn.model_selection import train_test_split

    X = _normalise_feature_frame(X)
    y_binary = _normalise_binary_labels(y_binary)
    y_category = _normalise_category_labels(y_category)

    if len(X) != len(y_binary) or len(X) != len(y_category):
        raise ValueError(
            "X, y_binary and y_category must have the same number of rows. "
            f"Got X={len(X)}, y_binary={len(y_binary)}, y_category={len(y_category)}."
        )

    if not 0.0 < float(test_size) < 1.0:
        raise ValueError("test_size must be between 0 and 1.")

    if not 0.0 < float(val_size) < 1.0:
        raise ValueError("val_size must be between 0 and 1.")

    if float(test_size) + float(val_size) >= 1.0:
        raise ValueError("test_size + val_size must be less than 1.")

    indices = np.arange(len(X))

    idx_tr_full, idx_te = train_test_split(
        indices,
        test_size=test_size,
        stratify=y_category,
        random_state=seed,
    )

    relative_val = val_size / (1.0 - test_size)

    idx_tr, idx_val = train_test_split(
        idx_tr_full,
        test_size=relative_val,
        stratify=y_category[idx_tr_full],
        random_state=seed,
    )

    X_tr = X.iloc[idx_tr].reset_index(drop=True)
    X_val = X.iloc[idx_val].reset_index(drop=True)
    X_te = X.iloc[idx_te].reset_index(drop=True)

    yb_tr = y_binary[idx_tr]
    yb_val = y_binary[idx_val]
    yb_te = y_binary[idx_te]

    yc_tr = y_category[idx_tr]
    yc_val = y_category[idx_val]
    yc_te = y_category[idx_te]

    return X_tr, X_val, X_te, yb_tr, yb_val, yb_te, yc_tr, yc_val, yc_te 