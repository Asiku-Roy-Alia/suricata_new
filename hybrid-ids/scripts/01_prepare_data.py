#!/usr/bin/env python3
"""Step 1: Load raw CIC-IDS-2017 CSVs, clean them, and write a processed parquet.

Output:
  data/processed/prepared.parquet   (cleaned, stratified-sampled data)
  data/processed/prepared_summary.txt (row/column counts, category distribution)
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from src.utils import load_config, set_seed, setup_logging, project_path  # noqa: E402
from src import data as data_mod  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=str, default=None)
    parser.add_argument(
        "--fraction",
        type=float,
        default=None,
        help="Override sampling fraction (useful for quick test runs).",
    )
    args = parser.parse_args()

    cfg = load_config(args.config)
    set_seed(cfg["seed"])
    logger = setup_logging(cfg, "01_prepare_data")

    fraction = args.fraction if args.fraction is not None else cfg["data"]["stratified_sample_fraction"]

    raw_dir = Path(cfg["paths"]["raw_data_dir"])
    logger.info("Reading raw CSVs from %s", raw_dir)

    df = data_mod.prepare(
        raw_dir=raw_dir,
        file_glob=cfg["data"]["file_glob"],
        fraction=fraction,
        seed=cfg["seed"],
        logger=logger,
        dedup=cfg["data"]["drop_duplicates"],
        min_category_samples=cfg["data"].get("min_category_samples", 0),
    )

    out_path = project_path(cfg, "processed_data_dir", "prepared.parquet")
    df.to_parquet(out_path, index=False)
    logger.info("Wrote %s (%d rows, %d columns)", out_path, len(df), df.shape[1])

    summary = project_path(cfg, "processed_data_dir", "prepared_summary.txt")
    with summary.open("w") as fh:
        fh.write(f"rows: {len(df)}\ncolumns: {df.shape[1]}\n\n")
        fh.write("Category distribution:\n")
        fh.write(df["Category"].value_counts().to_string())
        fh.write("\n\nColumn list:\n")
        fh.write("\n".join(df.columns.tolist()))
    logger.info("Wrote summary: %s", summary)


if __name__ == "__main__":
    main()
