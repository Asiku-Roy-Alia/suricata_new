"""Evaluation metrics tailored to a class-imbalanced security classifier.

On CIC-IDS-2017 the dominant class is BENIGN. Raw accuracy rewards a trivial
classifier that predicts BENIGN on everything, which is why the proposal
evaluation insisted on macro F1 and Matthews Correlation Coefficient as the
headline metrics. This module reports all of the above plus per-class recall
so individual attack categories are never hidden behind an aggregate.
"""

from __future__ import annotations

from typing import Dict, List, Tuple

import numpy as np
from sklearn.metrics import (
    accuracy_score,
    confusion_matrix,
    f1_score,
    matthews_corrcoef,
    precision_recall_curve,
    precision_score,
    recall_score,
    roc_auc_score,
)


def binary_metrics(y_true: np.ndarray, y_pred: np.ndarray, y_prob: np.ndarray) -> Dict[str, float]:
    """Compute the standard binary metric bundle."""
    cm = confusion_matrix(y_true, y_pred, labels=[0, 1])
    tn, fp, fn, tp = cm.ravel()
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    fnr = fn / (fn + tp) if (fn + tp) else 0.0

    return {
        "accuracy": float(accuracy_score(y_true, y_pred)),
        "precision": float(precision_score(y_true, y_pred, zero_division=0)),
        "recall": float(recall_score(y_true, y_pred, zero_division=0)),
        "macro_f1": float(f1_score(y_true, y_pred, average="macro", zero_division=0)),
        "mcc": float(matthews_corrcoef(y_true, y_pred)),
        "roc_auc": float(roc_auc_score(y_true, y_prob)) if len(np.unique(y_true)) > 1 else float("nan"),
        "false_positive_rate": float(fpr),
        "false_negative_rate": float(fnr),
        "tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn),
    }


def per_category_recall(
    y_true_category: np.ndarray, y_pred_binary: np.ndarray
) -> Dict[str, float]:
    """Recall per attack category. BENIGN is reported as true-negative rate."""
    result: Dict[str, float] = {}
    for cat in np.unique(y_true_category):
        mask = (y_true_category == cat)
        if mask.sum() == 0:
            continue
        if cat == "BENIGN":
            # For benign, we want the proportion correctly labelled 0 (TNR).
            result[cat] = float(np.mean(y_pred_binary[mask] == 0))
        else:
            # For attack categories, recall = proportion flagged as attack.
            result[cat] = float(np.mean(y_pred_binary[mask] == 1))
    return result


def reliability_curve(
    y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10
) -> Tuple[List[float], List[float], List[int]]:
    """Empirical reliability curve: mean predicted prob vs observed frequency."""
    bins = np.linspace(0, 1, n_bins + 1)
    bin_idx = np.clip(np.digitize(y_prob, bins) - 1, 0, n_bins - 1)
    mean_pred, obs_freq, counts = [], [], []
    for b in range(n_bins):
        mask = (bin_idx == b)
        count = int(mask.sum())
        counts.append(count)
        if count == 0:
            mean_pred.append(float("nan"))
            obs_freq.append(float("nan"))
        else:
            mean_pred.append(float(np.mean(y_prob[mask])))
            obs_freq.append(float(np.mean(y_true[mask])))
    return mean_pred, obs_freq, counts


def expected_calibration_error(
    y_true: np.ndarray, y_prob: np.ndarray, n_bins: int = 10
) -> float:
    """ECE: weighted average of |predicted - observed| across probability bins."""
    mean_pred, obs_freq, counts = reliability_curve(y_true, y_prob, n_bins)
    total = sum(counts)
    if total == 0:
        return float("nan")
    ece = 0.0
    for mp, of, c in zip(mean_pred, obs_freq, counts):
        if c == 0 or np.isnan(mp) or np.isnan(of):
            continue
        ece += (c / total) * abs(mp - of)
    return float(ece)


def format_metrics_line(name: str, metrics: Dict[str, float]) -> str:
    """One-line formatter suitable for log output."""
    return (
        f"{name:<24s}  "
        f"macroF1={metrics['macro_f1']:.4f}  "
        f"MCC={metrics['mcc']:.4f}  "
        f"acc={metrics['accuracy']:.4f}  "
        f"prec={metrics['precision']:.4f}  "
        f"rec={metrics['recall']:.4f}  "
        f"FPR={metrics['false_positive_rate']:.4f}  "
        f"ROC-AUC={metrics['roc_auc']:.4f}"
    )
