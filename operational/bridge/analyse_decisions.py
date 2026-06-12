#!/usr/bin/env python3
"""
analyse_decisions.py
====================

Reads the decisions.csv produced by hybrid_bridge.py and prints a comparison
table of Suricata-only, ML-only, and fused detection. Intended for inclusion
in the dissertation results section.

Usage:
    python analyse_decisions.py decisions.csv
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

import pandas as pd


def main():
    p = argparse.ArgumentParser()
    p.add_argument("csv", type=Path)
    p.add_argument("--ground-truth", type=Path, default=None,
                   help="Optional CSV with columns flow_id,is_attack to compute precision/recall")
    args = p.parse_args()

    df = pd.read_csv(args.csv)
    n = len(df)

    print(f"\nTotal flows analysed: {n}\n")
    print("Detection counts")
    print("-" * 40)
    print(f"  Suricata only:        {(df['suricata_alert'] == 1).sum()}")
    print(f"  ML only:              {(df['ml_decision'] == 1).sum()}")
    print(f"  Both engines agree:   {((df['suricata_alert'] == 1) & (df['ml_decision'] == 1)).sum()}")
    print(f"  Suricata XOR ML:      {(df['suricata_alert'] != df['ml_decision']).sum()}")
    print(f"  Fused (OR):           {(df['fused_decision'] == 1).sum()}")
    print()

    print("Top 10 ML-flagged flows by probability")
    print("-" * 40)
    cols = ["timestamp", "src_ip", "dst_ip", "dst_port",
            "ml_proba", "suricata_alert", "fusion_reason"]
    cols = [c for c in cols if c in df.columns]
    print(df.nlargest(10, "ml_proba")[cols].to_string(index=False))
    print()

    sigs = df[df["suricata_alert"] == 1]["suricata_signature"].value_counts()
    if len(sigs) > 0:
        print("Suricata signature breakdown")
        print("-" * 40)
        for sig, count in sigs.items():
            print(f"  {count:>6d}  {sig}")
        print()

    if args.ground_truth and args.ground_truth.exists():
        # Optional accuracy assessment if user provides labelled flows
        gt = pd.read_csv(args.ground_truth)
        merged = df.merge(gt, left_on="src_ip", right_on="src_ip", how="inner")
        if len(merged):
            for engine, col in [("Suricata", "suricata_alert"),
                                ("ML",       "ml_decision"),
                                ("Fused",    "fused_decision")]:
                tp = ((merged[col] == 1) & (merged["is_attack"] == 1)).sum()
                fp = ((merged[col] == 1) & (merged["is_attack"] == 0)).sum()
                fn = ((merged[col] == 0) & (merged["is_attack"] == 1)).sum()
                prec = tp / (tp + fp) if (tp + fp) else 0
                rec = tp / (tp + fn) if (tp + fn) else 0
                print(f"  {engine:<10s}  precision={prec:.3f}  recall={rec:.3f}")


if __name__ == "__main__":
    main()
