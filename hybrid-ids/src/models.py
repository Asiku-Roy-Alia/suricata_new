"""Model components for the hybrid IDS.

Architecture changes versus the original implementation:

* The supervised base learner is now a Random Forest. Tree ensembles dominate
  CIC-IDS-2017 leaderboards and natively output calibrated probabilities,
  which removes the need for an external Platt-scaling wrapper. Linear SVC
  remains available as a baseline for direct comparison.

* The anomaly base learner remains a calibrated Stochastic Gradient One-Class
  SVM. Its raw decision function is mapped to a probability via Platt scaling
  on a held-out validation set that contains both benign and attack samples,
  which addresses the heterogeneous-base-learner problem.

* The meta-learner remains Logistic Regression. It receives the supervised
  probability and the anomaly probability and produces the final fused output.

* The HybridStackedClassifier interface is unchanged: fit(X, y, X_val, y_val),
  predict(X), predict_proba(X). Existing scripts work without modification.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Dict, Optional

import numpy as np
from sklearn.base import BaseEstimator, ClassifierMixin, clone
from sklearn.calibration import CalibratedClassifierCV
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.isotonic import IsotonicRegression
from sklearn.linear_model import LogisticRegression, SGDOneClassSVM
from sklearn.metrics import roc_auc_score
from sklearn.model_selection import cross_val_score
from sklearn.svm import LinearSVC


# ---------------------------------------------------------------------------
# Calibrated One-Class SVM (anomaly base learner)
# ---------------------------------------------------------------------------
class CalibratedOneClassSVM(BaseEstimator, ClassifierMixin):
    """SGDOneClassSVM with a sigmoid calibrator fitted on a mixed validation set."""

    def __init__(self, nu: float = 0.1, random_state: int = 42, max_iter: int = 2000):
        self.nu = nu
        self.random_state = random_state
        self.max_iter = max_iter

    def fit(self, X_benign, y=None):
        self.detector_ = SGDOneClassSVM(
            nu=self.nu,
            random_state=self.random_state,
            max_iter=self.max_iter,
            tol=1e-4,
        )
        self.detector_.fit(X_benign)
        self.is_calibrated_ = False
        self.classes_ = np.array([0, 1])
        return self

    def raw_score(self, X) -> np.ndarray:
        return self.detector_.decision_function(X)

    def calibrate(self, X_val, y_val_binary, method: str = "sigmoid"):
        anomaly_score = -self.raw_score(X_val)
        if method == "sigmoid":
            self.calibrator_ = LogisticRegression(C=1.0, max_iter=1000)
            self.calibrator_.fit(anomaly_score.reshape(-1, 1), y_val_binary)
        elif method == "isotonic":
            self.calibrator_ = IsotonicRegression(out_of_bounds="clip")
            self.calibrator_.fit(anomaly_score, y_val_binary)
        else:
            raise ValueError(f"Unknown calibration method: {method}")
        self.calibration_method_ = method
        self.is_calibrated_ = True
        return self

    def predict_proba(self, X) -> np.ndarray:
        if not getattr(self, "is_calibrated_", False):
            raise RuntimeError("Call .calibrate(X_val, y_val_binary) before predict_proba().")
        anomaly_score = -self.raw_score(X)
        if self.calibration_method_ == "sigmoid":
            p_attack = self.calibrator_.predict_proba(anomaly_score.reshape(-1, 1))[:, 1]
        else:
            p_attack = self.calibrator_.predict(anomaly_score)
            p_attack = np.clip(p_attack, 1e-6, 1 - 1e-6)
        return np.column_stack([1.0 - p_attack, p_attack])

    def predict(self, X) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# ---------------------------------------------------------------------------
# Builders for supervised base learners
# ---------------------------------------------------------------------------
def build_random_forest(config: dict, seed: int) -> RandomForestClassifier:
    """Random Forest configured for CIC-IDS-2017 binary attack classification."""
    rf_cfg = config["models"]["supervised_rf"]
    return RandomForestClassifier(
        n_estimators=rf_cfg["n_estimators"],
        max_depth=rf_cfg.get("max_depth"),
        min_samples_split=rf_cfg.get("min_samples_split", 2),
        min_samples_leaf=rf_cfg.get("min_samples_leaf", 1),
        n_jobs=rf_cfg.get("n_jobs", -1),
        class_weight="balanced_subsample",
        random_state=seed,
    )


def build_calibrated_linear_svc(C: float, class_weight: str, max_iter: int,
                                 seed: int, cv: int = 3):
    """LinearSVC wrapped in CalibratedClassifierCV. Kept as a baseline."""
    base = LinearSVC(
        C=C,
        class_weight=class_weight,
        max_iter=max_iter,
        dual="auto",
        random_state=seed,
    )
    return CalibratedClassifierCV(base, method="sigmoid", cv=cv)


# ---------------------------------------------------------------------------
# Hybrid stacked classifier
# ---------------------------------------------------------------------------
@dataclass
class HybridArtifacts:
    """Trained components of the hybrid model."""

    supervised: object
    anomaly: CalibratedOneClassSVM
    meta: LogisticRegression
    best_params: Dict[str, object] = field(default_factory=dict)


class HybridStackedClassifier:
    """Random Forest + calibrated OCSVM + Logistic Regression meta-learner.

    Training proceeds in three steps. First, a Random Forest is fitted on the
    SMOTE-balanced training set with no grid search. Second, the calibrated
    anomaly detector is fitted on benign rows only and calibrated on the
    held-out validation set. Third, the Logistic Regression meta-learner is
    fitted on the two-column stack of supervised probability and anomaly
    probability for the validation set.
    """

    def __init__(self, config: dict, logger: logging.Logger):
        self.cfg = config
        self.logger = logger
        self.artifacts_: Optional[HybridArtifacts] = None

    def _train_supervised(self, X_train, y_train):
        rf_cfg = self.cfg["models"]["supervised_rf"]
        self.logger.info(
            "Training Random Forest (n_estimators=%d, max_depth=%s)",
            rf_cfg["n_estimators"], rf_cfg.get("max_depth"),
        )
        rf = build_random_forest(self.cfg, self.cfg["seed"])
        rf.fit(X_train, y_train)
        try:
            sample_size = min(20000, len(X_train))
            rng = np.random.default_rng(self.cfg["seed"])
            idx = rng.choice(len(X_train), size=sample_size, replace=False)
            cv_score = float(np.mean(cross_val_score(
                clone(rf), X_train[idx], y_train[idx],
                cv=3, scoring="f1_macro", n_jobs=-1,
            )))
            self.logger.info("  RF macro-F1 (3-fold CV on %d-row subsample): %.4f",
                             sample_size, cv_score)
        except Exception as e:
            self.logger.warning("CV scoring failed: %s", e)
        return rf

    def _search_anomaly(self, X_benign_train, X_val, y_val):
        best = None
        for nu in self.cfg["models"]["anomaly"]["nu_grid"]:
            detector = CalibratedOneClassSVM(nu=nu, random_state=self.cfg["seed"])
            detector.fit(X_benign_train)
            detector.calibrate(X_val, y_val, method="sigmoid")
            probs = detector.predict_proba(X_val)[:, 1]
            score = float(roc_auc_score(y_val, probs))
            self.logger.info("  anomaly nu=%.3f -> ROC-AUC %.4f", nu, score)
            if best is None or score > best[0]:
                best = (score, nu, detector)
        self.logger.info("Best anomaly nu: %.3f (ROC-AUC %.4f)", best[1], best[0])
        return best[2], best[1]

    def fit(self, X_train, y_train, X_val, y_val, cv: int = 3) -> HybridArtifacts:
        self.logger.info("Training supervised component")
        supervised = self._train_supervised(X_train, y_train)

        self.logger.info("Training anomaly component on benign rows only")
        benign_mask = (y_train == 0)
        X_benign = X_train[benign_mask]
        max_benign = self.cfg["models"]["anomaly"]["max_benign_rows"]
        if len(X_benign) > max_benign:
            rng = np.random.default_rng(self.cfg["seed"])
            idx = rng.choice(len(X_benign), size=max_benign, replace=False)
            X_benign = X_benign[idx]
            self.logger.info("Subsampled benign training set to %d rows", max_benign)

        anomaly, best_nu = self._search_anomaly(X_benign, X_val, y_val)

        self.logger.info("Training meta-learner on stacked validation features")
        sup_proba = supervised.predict_proba(X_val)[:, 1]
        ano_proba = anomaly.predict_proba(X_val)[:, 1]
        stack_val = np.column_stack([sup_proba, ano_proba])

        best_meta = None
        for C in self.cfg["models"]["meta_learner"]["C_grid"]:
            meta = LogisticRegression(
                C=C,
                max_iter=self.cfg["models"]["meta_learner"]["max_iter"],
                random_state=self.cfg["seed"],
            )
            scores = cross_val_score(meta, stack_val, y_val, cv=3, scoring="f1_macro")
            score = float(np.mean(scores))
            self.logger.info("  meta C=%.2f -> macro F1 %.4f", C, score)
            if best_meta is None or score > best_meta[0]:
                best_meta = (score, C)

        self.logger.info("Best meta C: %.2f (macro F1 %.4f)", best_meta[1], best_meta[0])
        meta_final = LogisticRegression(
            C=best_meta[1],
            max_iter=self.cfg["models"]["meta_learner"]["max_iter"],
            random_state=self.cfg["seed"],
        )
        meta_final.fit(stack_val, y_val)

        self.artifacts_ = HybridArtifacts(
            supervised=supervised,
            anomaly=anomaly,
            meta=meta_final,
            best_params={
                "supervised_type": "RandomForest",
                "n_estimators": self.cfg["models"]["supervised_rf"]["n_estimators"],
                "max_depth": self.cfg["models"]["supervised_rf"].get("max_depth"),
                "nu_anomaly": best_nu,
                "C_meta": best_meta[1],
            },
        )
        return self.artifacts_

    def predict_proba(self, X) -> np.ndarray:
        if self.artifacts_ is None:
            raise RuntimeError("Call fit() first.")
        sup = self.artifacts_.supervised.predict_proba(X)[:, 1]
        ano = self.artifacts_.anomaly.predict_proba(X)[:, 1]
        stack = np.column_stack([sup, ano])
        return self.artifacts_.meta.predict_proba(stack)

    def predict(self, X) -> np.ndarray:
        return (self.predict_proba(X)[:, 1] >= 0.5).astype(int)


# ---------------------------------------------------------------------------
# Baseline models
# ---------------------------------------------------------------------------
def fit_linear_svc_baseline(X_train, y_train, config: dict, logger: logging.Logger):
    logger.info("Fitting Linear SVC baseline")
    svc_cfg = config["models"]["supervised_svc"]
    model = build_calibrated_linear_svc(
        C=1.0,
        class_weight=svc_cfg["class_weight"],
        max_iter=svc_cfg["max_iter"],
        seed=config["seed"],
    )
    model.fit(X_train, y_train)
    return model


def fit_random_forest_baseline(X_train, y_train, config: dict, logger: logging.Logger):
    logger.info("Fitting Random Forest baseline")
    rf = build_random_forest(config, config["seed"])
    rf.fit(X_train, y_train)
    return rf


def fit_isolation_forest_baseline(X_train, y_train, config: dict, logger: logging.Logger):
    logger.info("Fitting Isolation Forest baseline on benign rows only")
    benign = X_train[y_train == 0]
    max_rows = min(100_000, len(benign))
    if len(benign) > max_rows:
        rng = np.random.default_rng(config["seed"])
        idx = rng.choice(len(benign), size=max_rows, replace=False)
        benign = benign[idx]
    model = IsolationForest(
        n_estimators=config["models"]["isolation_forest"]["n_estimators"],
        contamination=config["models"]["isolation_forest"]["contamination"],
        random_state=config["seed"],
        n_jobs=-1,
    )
    model.fit(benign)
    return model


def isolation_forest_predict(model, X) -> np.ndarray:
    raw = model.predict(X)
    return (raw == -1).astype(int)


def isolation_forest_score(model, X) -> np.ndarray:
    s = -model.score_samples(X)
    s_min, s_max = float(s.min()), float(s.max())
    if s_max - s_min < 1e-9:
        return np.zeros_like(s)
    return (s - s_min) / (s_max - s_min)
