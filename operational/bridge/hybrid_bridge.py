#!/usr/bin/env python3
"""
hybrid_bridge.py
================

Consumes Suricata's EVE JSON output and runs the trained hybrid IDS model on
flow records. Produces a unified decision stream that combines what Suricata
detected via signatures with what the ML model detected via its calibrated
hybrid classifier.

Why this exists
---------------
Suricata catches attacks that match its rule set but misses anything not
covered by a rule. The hybrid ML model catches attacks based on flow-level
statistical patterns. Combining them is the operational point of the entire
project.

Modes
-----
1. tail   : Continuously tails eve.json (production-like). Use during a live
            replay or live capture.
2. batch  : Reads a complete eve.json once and writes a CSV of decisions.
            Recommended for the dissertation evaluation because it is
            reproducible.

Inputs
------
* Suricata EVE JSON file (with flow records present).
* The trained feature pipeline saved as artifacts/feature_pipeline.joblib.
* The trained hybrid model saved as artifacts/hybrid.joblib.

Outputs
-------
* logs/decisions.csv with one row per flow:
    timestamp, src_ip, dst_ip, dst_port, proto, bytes_total,
    suricata_alert (0/1), suricata_signature, ml_proba, ml_decision (0/1),
    fused_decision (0/1), fusion_reason

Decision-fusion rule
--------------------
The fused_decision is 1 (attack) if EITHER:
  * Suricata raised an alert on this flow, OR
  * The ML model's calibrated probability >= threshold (default 0.5).
This OR-fusion is the standard recommendation in the literature for
combining signature and anomaly engines.

Usage examples
--------------
  # Batch mode (recommended for the dissertation evaluation)
  python hybrid_bridge.py batch \
      --eve  ../suricata/logs/eve.json \
      --pipeline ../../hybrid-ids/artifacts/feature_pipeline.joblib \
      --model    ../../hybrid-ids/artifacts/hybrid.joblib \
      --out      ./logs/decisions.csv

  # Tail mode (for a live demonstration)
  python hybrid_bridge.py tail \
      --eve ../suricata/logs/eve.json \
      --pipeline ... --model ... --out ./logs/decisions.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, Optional

import joblib
import numpy as np


# The hybrid model was pickled with class definitions located in the
# hybrid-ids/src package. Make that package importable BEFORE we joblib.load.
# We try several plausible locations and also honour an env override.
_BRIDGE_DIR = Path(__file__).resolve().parent
_CANDIDATE_ROOTS = [
    _BRIDGE_DIR / ".." / ".." / "hybrid-ids",   # operational/bridge -> sibling hybrid-ids
    _BRIDGE_DIR / ".." / "hybrid-ids",          # operational/ -> child hybrid-ids
    _BRIDGE_DIR.parent.parent.parent / "hybrid-ids",  # one level higher
    Path.home() / "hybrid-ids",                 # user home
]
_extra = os.environ.get("HYBRID_IDS_ROOT")
if _extra:
    _CANDIDATE_ROOTS.insert(0, Path(_extra))

for _root in _CANDIDATE_ROOTS:
    _root = _root.resolve() if _root.exists() else _root
    if _root.exists() and (_root / "src").exists():
        sys.path.insert(0, str(_root))
        break


LOG = logging.getLogger("hybrid_bridge")


# ============================================================================
# Feature mapping: Suricata flow -> model input
# ============================================================================
# The trained model expects the 77 raw CIC-IDS-2017 features after going
# through the saved scikit-learn pipeline. Suricata's flow record contains a
# subset of these directly and we approximate the rest from packet/byte
# counters. Fields that we cannot derive are set to zero, which the model
# tolerates because PCA projects to a low-dimensional space.
#
# This mapping is deliberately conservative: only fields that Suricata
# computes natively are mapped. The function returns a dict keyed by the
# original CIC-IDS-2017 column names.

CIC_FEATURE_NAMES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
    "Flow Bytes/s", "Flow Packets/s",
    "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
    "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
    "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
    "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
    "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s",
    "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance",
    "FIN Flag Count", "SYN Flag Count", "RST Flag Count", "PSH Flag Count",
    "ACK Flag Count", "URG Flag Count", "CWE Flag Count", "ECE Flag Count",
    "Down/Up Ratio", "Average Packet Size",
    "Avg Fwd Segment Size", "Avg Bwd Segment Size", "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets", "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min",
    "Idle Mean", "Idle Std", "Idle Max", "Idle Min",
]


def suricata_flow_to_features(flow: dict) -> Dict[str, float]:
    """Convert a Suricata 'flow' EVE record into the CIC feature dict.

    Suricata flow records contain pkts_toserver / pkts_toclient and
    bytes_toserver / bytes_toclient as primary counters, plus 'start' and
    'end' timestamps from which the duration is derived. We compute the
    simplest CIC-equivalent fields and leave the rest at zero.
    """
    f = {name: 0.0 for name in CIC_FEATURE_NAMES}

    flow_obj = flow.get("flow", flow)
    pkts_to = float(flow_obj.get("pkts_toserver", 0))
    pkts_from = float(flow_obj.get("pkts_toclient", 0))
    bytes_to = float(flow_obj.get("bytes_toserver", 0))
    bytes_from = float(flow_obj.get("bytes_toclient", 0))

    # Duration in microseconds (CIC uses microseconds).
    start = flow_obj.get("start")
    end = flow_obj.get("end")
    duration_us = 0.0
    if start and end:
        try:
            from datetime import datetime
            t0 = datetime.fromisoformat(start.replace("Z", "+00:00"))
            t1 = datetime.fromisoformat(end.replace("Z", "+00:00"))
            duration_us = max(0.0, (t1 - t0).total_seconds() * 1_000_000)
        except Exception:
            duration_us = 0.0

    f["Flow Duration"] = duration_us
    f["Total Fwd Packets"] = pkts_to
    f["Total Backward Packets"] = pkts_from
    f["Total Length of Fwd Packets"] = bytes_to
    f["Total Length of Bwd Packets"] = bytes_from

    total_pkts = pkts_to + pkts_from
    total_bytes = bytes_to + bytes_from
    duration_s = duration_us / 1_000_000.0 if duration_us > 0 else 0.0

    if duration_s > 0:
        f["Flow Bytes/s"] = total_bytes / duration_s
        f["Flow Packets/s"] = total_pkts / duration_s
        f["Fwd Packets/s"] = pkts_to / duration_s
        f["Bwd Packets/s"] = pkts_from / duration_s

    if total_pkts > 0:
        avg_size = total_bytes / total_pkts
        f["Average Packet Size"] = avg_size
        f["Packet Length Mean"] = avg_size

    if pkts_to > 0:
        f["Avg Fwd Segment Size"] = bytes_to / pkts_to
    if pkts_from > 0:
        f["Avg Bwd Segment Size"] = bytes_from / pkts_from

    if pkts_to > 0:
        f["Down/Up Ratio"] = pkts_from / pkts_to

    f["Subflow Fwd Packets"] = pkts_to
    f["Subflow Fwd Bytes"] = bytes_to
    f["Subflow Bwd Packets"] = pkts_from
    f["Subflow Bwd Bytes"] = bytes_from

    # TCP flag aggregates from Suricata's tcp object if present.
    tcp = flow.get("tcp", {})
    if tcp:
        f["SYN Flag Count"] = float(tcp.get("syn", 0))
        f["ACK Flag Count"] = float(tcp.get("ack", 0))
        f["FIN Flag Count"] = float(tcp.get("fin", 0))
        f["RST Flag Count"] = float(tcp.get("rst", 0))
        f["PSH Flag Count"] = float(tcp.get("psh", 0))
        f["URG Flag Count"] = float(tcp.get("urg", 0))

    return f


# ============================================================================
# EVE JSON consumer
# ============================================================================
@dataclass
class FlowDecision:
    timestamp: str
    src_ip: str
    dst_ip: str
    dst_port: int
    proto: str
    bytes_total: float
    suricata_alert: int
    suricata_signature: str
    ml_proba: float
    ml_decision: int
    fused_decision: int
    fusion_reason: str


def iter_eve_records(path: Path, follow: bool, batch_grace: float = 0.5) -> Iterable[dict]:
    """Yield JSON records from an eve.json file.

    follow=True: tail the file forever (production mode).
    follow=False: read once then stop (batch mode).
    """
    with path.open("r") as fh:
        while True:
            line = fh.readline()
            if not line:
                if follow:
                    time.sleep(0.5)
                    continue
                else:
                    return
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                LOG.warning("Skipping malformed line in %s", path)


def build_alert_index(eve_path: Path) -> Dict[str, str]:
    """First pass: build a flow_id -> signature index from alert events.

    Suricata emits alert events separately from flow events but every event
    carries a flow_id when available. We use the index in a second pass to
    join alerts back to their flow records.
    """
    idx: Dict[str, str] = {}
    with eve_path.open("r") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if rec.get("event_type") == "alert":
                fid = rec.get("flow_id")
                sig = rec.get("alert", {}).get("signature", "")
                if fid is not None:
                    idx[str(fid)] = sig
    return idx


# ============================================================================
# Main inference loop
# ============================================================================
def run(
    mode: str,
    eve_path: Path,
    pipeline_path: Path,
    model_path: Path,
    out_path: Path,
    threshold: float,
):
    LOG.info("Loading feature pipeline: %s", pipeline_path)
    pipeline = joblib.load(pipeline_path)
    LOG.info("Loading hybrid model: %s", model_path)
    model = joblib.load(model_path)

    # The pipeline was fitted on a specific set of feature names. We must
    # provide exactly those, in exactly that order. Discover them from the
    # first step (StandardScaler) and use them to subset our 77-element
    # CIC mapping. This makes the bridge robust to pipelines fitted on
    # different feature subsets (e.g. dropped 'Destination Port').
    expected_features = None
    try:
        first_step = list(pipeline.named_steps.values())[0]
        if hasattr(first_step, "feature_names_in_"):
            expected_features = list(first_step.feature_names_in_)
            LOG.info("Pipeline expects %d features", len(expected_features))
    except Exception as e:
        LOG.warning("Could not inspect pipeline feature names: %s", e)
    if expected_features is None:
        expected_features = CIC_FEATURE_NAMES
        LOG.warning("Falling back to default 77 CIC feature names")

    follow = (mode == "tail")
    if not follow:
        LOG.info("Building alert index (first pass)")
        alert_idx = build_alert_index(eve_path)
        LOG.info("Indexed %d alert-flow mappings", len(alert_idx))
    else:
        alert_idx = {}

    out_path.parent.mkdir(parents=True, exist_ok=True)
    csv_fields = [
        "timestamp", "src_ip", "dst_ip", "dst_port", "proto", "bytes_total",
        "suricata_alert", "suricata_signature",
        "ml_proba", "ml_decision", "fused_decision", "fusion_reason",
    ]

    counts = {"flows": 0, "ml_attack": 0, "suri_alert": 0,
              "fused_attack": 0, "agreement": 0}

    with out_path.open("w", newline="") as csvfh:
        writer = csv.DictWriter(csvfh, fieldnames=csv_fields)
        writer.writeheader()

        for rec in iter_eve_records(eve_path, follow=follow):
            if rec.get("event_type") != "flow":
                continue

            counts["flows"] += 1
            fid = str(rec.get("flow_id", ""))

            # Suricata signal
            if follow:
                suri_sig = ""
                suri_alert = 0
            else:
                suri_sig = alert_idx.get(fid, "")
                suri_alert = 1 if suri_sig else 0
            if suri_alert:
                counts["suri_alert"] += 1

            # Build feature vector and run the model
            try:
                feats = suricata_flow_to_features(rec)
                # Build a single-row DataFrame so feature names match what
                # the pipeline expects. This avoids sklearn warnings and
                # handles missing features gracefully (defaults to 0.0).
                import pandas as _pd
                row_dict = {name: feats.get(name, 0.0) for name in expected_features}
                X_df = _pd.DataFrame([row_dict])
                X_df = X_df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
                X = pipeline.transform(X_df)
                proba = float(model.predict_proba(X)[0, 1])
                ml_decision = int(proba >= threshold)
            except Exception as e:
                LOG.warning("Inference failed for flow %s: %s", fid, e)
                proba = 0.0
                ml_decision = 0

            if ml_decision:
                counts["ml_attack"] += 1

            # Fusion: OR rule
            fused = 1 if (suri_alert or ml_decision) else 0
            if fused:
                counts["fused_attack"] += 1
            if (suri_alert == ml_decision):
                counts["agreement"] += 1

            reason = []
            if suri_alert:
                reason.append("suricata")
            if ml_decision:
                reason.append("ml")
            if not reason:
                reason.append("none")

            flow_obj = rec.get("flow", rec)
            writer.writerow({
                "timestamp": rec.get("timestamp", ""),
                "src_ip": rec.get("src_ip", ""),
                "dst_ip": rec.get("dest_ip", ""),
                "dst_port": rec.get("dest_port", ""),
                "proto": rec.get("proto", ""),
                "bytes_total": float(flow_obj.get("bytes_toserver", 0)) + float(flow_obj.get("bytes_toclient", 0)),
                "suricata_alert": suri_alert,
                "suricata_signature": suri_sig,
                "ml_proba": round(proba, 6),
                "ml_decision": ml_decision,
                "fused_decision": fused,
                "fusion_reason": "+".join(reason),
            })

            if counts["flows"] % 5000 == 0:
                LOG.info("Processed %d flows", counts["flows"])

    LOG.info("=" * 60)
    LOG.info("Run complete")
    LOG.info("Total flows processed:        %d", counts["flows"])
    LOG.info("Flagged by Suricata:          %d", counts["suri_alert"])
    LOG.info("Flagged by ML model:          %d", counts["ml_attack"])
    LOG.info("Flagged by fused decision:    %d", counts["fused_attack"])
    if counts["flows"]:
        LOG.info("Engine agreement (both same): %d (%.1f%%)",
                 counts["agreement"], 100 * counts["agreement"] / counts["flows"])
    LOG.info("Decisions written to %s", out_path)


def main():
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("mode", choices=["batch", "tail"], help="batch reads once; tail follows the file")
    p.add_argument("--eve", type=Path, required=True, help="Path to Suricata eve.json")
    p.add_argument("--pipeline", type=Path, required=True, help="Path to feature_pipeline.joblib")
    p.add_argument("--model", type=Path, required=True, help="Path to hybrid.joblib")
    p.add_argument("--out", type=Path, required=True, help="Output CSV path")
    p.add_argument("--threshold", type=float, default=0.5, help="ML decision threshold")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.eve.exists():
        LOG.error("EVE JSON file not found: %s", args.eve)
        sys.exit(1)
    if not args.pipeline.exists():
        LOG.error("Pipeline artifact not found: %s", args.pipeline)
        sys.exit(1)
    if not args.model.exists():
        LOG.error("Model artifact not found: %s", args.model)
        sys.exit(1)

    run(args.mode, args.eve, args.pipeline, args.model, args.out, args.threshold)


if __name__ == "__main__":
    main()
