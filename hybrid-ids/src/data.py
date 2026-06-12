"""Data loading and cleaning for CIC-IDS-2017.

The published CSVs have several well-documented issues that must be repaired
before the data is usable for modelling. This module centralises those fixes
so every downstream step sees a consistent dataset.

Known issues addressed:
  1. Column names contain leading whitespace.
  2. Some flow-rate columns contain positive and negative infinity.
  3. A non-trivial number of rows are exact duplicates.
  4. The Label column uses slightly different spellings across files, so we
     normalise everything to a small set of canonical attack categories.
  5. Unnamed columns and any column Flow_ID/Destination_IP/Source_IP must be
     dropped because they are identifiers, not features.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import List, Tuple

import numpy as np
import pandas as pd


# Canonical category mapping. Keys are regex-style prefixes that match the
# various label spellings used across the eight CIC-IDS-2017 CSVs.
LABEL_TO_CATEGORY = {
    "BENIGN": "BENIGN",
    "DoS Hulk": "DoS",
    "DoS GoldenEye": "DoS",
    "DoS slowloris": "DoS",
    "DoS Slowhttptest": "DoS",
    "Heartbleed": "DoS",
    "DDoS": "DDoS",
    "PortScan": "PortScan",
    "FTP-Patator": "Brute Force",
    "SSH-Patator": "Brute Force",
    "Web Attack  Brute Force": "Web Attack",
    "Web Attack  XSS": "Web Attack",
    "Web Attack  Sql Injection": "Web Attack",
    # The CIC files sometimes use a weird double-space, sometimes a single en-
    # dash character. We handle both by prefix matching in normalise_labels.
    "Web Attack": "Web Attack",
    "Infiltration": "Infiltration",
    "Bot": "Bot",
}


# Columns that must always be dropped because they are identifiers or have
# no predictive value.
NON_FEATURE_COLUMNS = {
    "Flow ID",
    "Source IP",
    "Source Port",
    "Destination IP",
    "Destination Port",
    "Timestamp",
    "SimillarHTTP",
    "Inbound",
    "Unnamed: 0",
}


def discover_csv_files(raw_dir: Path, pattern: str) -> List[Path]:
    """Find every CSV under the raw directory."""
    files = sorted(raw_dir.rglob(pattern))
    return [f for f in files if f.suffix.lower() == ".csv"]


def load_raw(files: List[Path], logger: logging.Logger) -> pd.DataFrame:
    """Concatenate every raw CSV into a single dataframe."""
    frames = []
    for i, f in enumerate(files, 1):
        logger.info("Reading (%d/%d) %s", i, len(files), f.name)
        try:
            df = pd.read_csv(f, low_memory=False, encoding="utf-8")
        except UnicodeDecodeError:
            df = pd.read_csv(f, low_memory=False, encoding="latin-1")
        df.columns = [c.strip() for c in df.columns]
        frames.append(df)
    data = pd.concat(frames, axis=0, ignore_index=True, sort=False)
    logger.info("Concatenated rows: %d, columns: %d", len(data), data.shape[1])
    return data


def drop_identifier_columns(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Remove identifier and non-feature columns if present."""
    to_drop = [c for c in df.columns if c in NON_FEATURE_COLUMNS]
    if to_drop:
        logger.info("Dropping identifier columns: %s", to_drop)
        df = df.drop(columns=to_drop)
    return df


def coerce_numeric(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Ensure every non-label column is numeric, replace inf with NaN."""
    label_col = "Label"
    feature_cols = [c for c in df.columns if c != label_col]

    for col in feature_cols:
        if df[col].dtype == object:
            df[col] = pd.to_numeric(df[col], errors="coerce")

    n_inf = int(np.isinf(df[feature_cols].values).sum())
    if n_inf:
        logger.info("Replacing %d infinity values with NaN", n_inf)
        df[feature_cols] = df[feature_cols].replace([np.inf, -np.inf], np.nan)
    return df


def drop_missing(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Drop rows with any NaN in feature space."""
    before = len(df)
    df = df.dropna(axis=0, how="any").reset_index(drop=True)
    logger.info("Dropped %d rows with missing values", before - len(df))
    return df


def drop_duplicates(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Remove exact duplicate rows, a known defect in CIC-IDS-2017."""
    before = len(df)
    df = df.drop_duplicates().reset_index(drop=True)
    logger.info("Dropped %d duplicate rows", before - len(df))
    return df


def normalise_labels(df: pd.DataFrame, logger: logging.Logger) -> pd.DataFrame:
    """Map the raw Label column to a small set of canonical categories."""
    if "Label" not in df.columns:
        raise KeyError("Expected a 'Label' column in the data.")

    def to_category(raw: str) -> str:
        raw = str(raw).strip()
        if raw == "BENIGN":
            return "BENIGN"
        if raw.startswith("Web Attack"):
            return "Web Attack"
        if raw.startswith("DoS") or raw == "Heartbleed":
            return "DoS"
        if raw == "DDoS":
            return "DDoS"
        if raw in ("FTP-Patator", "SSH-Patator"):
            return "Brute Force"
        if raw == "PortScan":
            return "PortScan"
        if raw == "Infiltration":
            return "Infiltration"
        if raw == "Bot":
            return "Bot"
        return raw

    df["Category"] = df["Label"].apply(to_category)
    logger.info("Category distribution:\n%s", df["Category"].value_counts().to_string())
    return df


def drop_rare_categories(
    df: pd.DataFrame, min_samples: int, logger: logging.Logger
) -> pd.DataFrame:
    """Drop attack categories with fewer than min_samples rows.

    Such categories are too rare for SMOTE to upsample meaningfully and
    contaminate the test set with classes the model will never learn. The
    notebook excludes Infiltration on these grounds.
    """
    counts = df["Category"].value_counts()
    rare = counts[counts < min_samples].index.tolist()
    rare = [c for c in rare if c != "BENIGN"]
    if not rare:
        return df
    before = len(df)
    df = df[~df["Category"].isin(rare)].reset_index(drop=True)
    logger.info(
        "Dropped %d rare categories (< %d samples): %s. Removed %d rows.",
        len(rare), min_samples, rare, before - len(df),
    )
    return df


def stratified_sample(
    df: pd.DataFrame, fraction: float, seed: int, logger: logging.Logger
) -> pd.DataFrame:
    """Stratified sample on the Category column using the modern pandas API."""
    if fraction >= 1.0:
        logger.info("Skipping subsampling (fraction >= 1.0)")
        return df.reset_index(drop=True).copy()

    if "Category" not in df.columns:
        raise KeyError(
            "Column 'Category' not found before stratified sampling. "
            "normalise_labels() must have failed."
        )

    logger.info("Performing stratified sampling with fraction=%.4f", fraction)


    out = (
        df.groupby("Category", group_keys=False)
        .sample(frac=fraction, random_state=seed)
        .reset_index(drop=True)
    )

    logger.info("Stratified sample: %d rows kept (from %d)", len(out), len(df))
    logger.info(
        "Post-sample category distribution:\n%s",
        out["Category"].value_counts().sort_index().to_string(),
    )

    return out

def prepare(
    raw_dir: Path,
    file_glob: str,
    fraction: float,
    seed: int,
    logger: logging.Logger,
    dedup: bool = True,
    min_category_samples: int = 0,
) -> pd.DataFrame:
    """Run the full raw-to-clean pipeline and return the resulting dataframe."""
    files = discover_csv_files(raw_dir, file_glob)
    if not files:
        raise FileNotFoundError(
            f"No CSV files found under {raw_dir}. See README section 'Data' "
            "for download instructions."
        )
    logger.info("Discovered %d raw CSV files", len(files))

    df = load_raw(files, logger)
    df = drop_identifier_columns(df, logger)
    df = coerce_numeric(df, logger)
    df = drop_missing(df, logger)
    if dedup:
        df = drop_duplicates(df, logger)
    df = normalise_labels(df, logger)
    if min_category_samples > 0:
        df = drop_rare_categories(df, min_category_samples, logger)
    df = stratified_sample(df, fraction, seed, logger)
    return df


def split_features_labels(df: pd.DataFrame) -> Tuple[pd.DataFrame, pd.Series, pd.Series]:
    """Return (X, y_binary, y_category). y_binary is 1 for attack, 0 for BENIGN."""
    y_category = df["Category"].astype(str)
    y_binary = (y_category != "BENIGN").astype(int)
    X = df.drop(columns=["Label", "Category"])
    return X, y_binary, y_category
