#!/usr/bin/env python3
"""Write a small synthetic CIC-IDS-2017-lookalike CSV into data/raw so the
numbered pipeline scripts can be exercised without downloading the real
dataset. This file is a developer-only convenience; production runs should
download the real CIC-IDS-2017 CSVs.
"""

from pathlib import Path
import numpy as np
import pandas as pd

OUT = Path(__file__).resolve().parent.parent / "data" / "raw" / "synthetic_ciclike.csv"
OUT.parent.mkdir(parents=True, exist_ok=True)

rng = np.random.default_rng(42)
n_benign = 6000
specs = {
    "DoS Hulk": 1200,
    "DDoS": 1000,
    "PortScan": 900,
    "FTP-Patator": 400,
    "SSH-Patator": 300,
    "Web Attack  Brute Force": 250,
    "Bot": 180,
    "Infiltration": 80,
}

# Use realistic-looking CIC-IDS-2017 column names (with the typical leading
# whitespace quirk on a few columns for authenticity).
feature_names = [
    " Destination Port", " Flow Duration", " Total Fwd Packets", " Total Backward Packets",
    "Total Length of Fwd Packets", " Total Length of Bwd Packets", " Fwd Packet Length Max",
    " Fwd Packet Length Min", " Fwd Packet Length Mean", " Fwd Packet Length Std",
    "Bwd Packet Length Max", " Bwd Packet Length Min", " Bwd Packet Length Mean",
    " Bwd Packet Length Std", "Flow Bytes/s", " Flow Packets/s", " Flow IAT Mean",
    " Flow IAT Std", " Flow IAT Max", " Flow IAT Min", "Fwd IAT Total", " Fwd IAT Mean",
    " Fwd IAT Std", " Fwd IAT Max", " Fwd IAT Min", "Bwd IAT Total", " Bwd IAT Mean",
    " Bwd IAT Std", " Bwd IAT Max", " Bwd IAT Min", "Fwd PSH Flags", " Bwd PSH Flags",
    " Fwd URG Flags", " Bwd URG Flags", " Fwd Header Length", " Bwd Header Length",
    "Fwd Packets/s", " Bwd Packets/s", " Min Packet Length", " Max Packet Length",
]
n_features = len(feature_names)

frames = []

# Benign: low-magnitude, tight distribution
x = rng.lognormal(mean=1.0, sigma=0.5, size=(n_benign, n_features)) - 2.5
df = pd.DataFrame(x, columns=feature_names)
df["Label"] = "BENIGN"
frames.append(df)

for i, (cat, n) in enumerate(specs.items()):
    # Each attack category has a distinct shift across a subset of features.
    shift = np.zeros(n_features)
    shift_idx = rng.choice(n_features, size=12, replace=False)
    shift[shift_idx] = 4.0 + 0.6 * i
    x = rng.lognormal(mean=1.0, sigma=0.7, size=(n, n_features)) + shift
    df = pd.DataFrame(x, columns=feature_names)
    df["Label"] = cat
    frames.append(df)

full = pd.concat(frames, axis=0, ignore_index=True).sample(frac=1.0, random_state=42).reset_index(drop=True)
# Sprinkle a few infinities to emulate the known CIC-IDS defect.
inf_idx = rng.choice(len(full), size=20, replace=False)
full.loc[inf_idx, "Flow Bytes/s"] = np.inf
# And a few duplicates to emulate that defect too.
full = pd.concat([full, full.iloc[:50]], ignore_index=True)

full.to_csv(OUT, index=False)
print(f"Wrote {len(full)} rows to {OUT}")
