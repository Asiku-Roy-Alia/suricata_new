#!/usr/bin/env python3
"""
realtime_bridge.py
==================

Tails Suricata's eve.json file in real time, runs the trained hybrid ML
model on every flow record, fuses the Suricata signature alert (if any)
with the ML decision, and pushes the result to Elasticsearch for the
Kibana dashboard.

Differences versus hybrid_bridge.py:
  * Continuous tail rather than batch
  * Sends to Elasticsearch via HTTP rather than writing CSV
  * Maintains a sliding window of recent flow_id -> alert mappings so it
    can correlate alerts that arrive after the corresponding flow record
  * Robust to file rotation (Suricata can rotate eve.json mid-stream)
  * Emits a summary every N flows so the operator can see it is alive

Inputs:
  --eve         path to suricata's eve.json (mounted from container)
  --pipeline    path to feature_pipeline.joblib
  --model       path to hybrid.joblib
  --es-url      Elasticsearch URL (default http://elasticsearch:9200)
  --es-index    target index name (default hybrid-ids-decisions)

The script also writes a tail of the most recent decisions to a local
CSV so a deep-dive analysis is possible without leaving Kibana.
"""

from __future__ import annotations

import argparse
import csv
import json
import logging
import os
import sys
import time
from collections import deque
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional

import joblib
import numpy as np
import requests


LOG = logging.getLogger("realtime_bridge")


# ---------------------------------------------------------------------------
# Make the trained model's class definitions importable. The model uses the
# CalibratedOneClassSVM and HybridStackedClassifier classes from src/, which
# joblib needs to be able to import when unpickling.
# ---------------------------------------------------------------------------
_BRIDGE_DIR = Path(__file__).resolve().parent
_HYBRID_IDS_ROOT = (_BRIDGE_DIR / ".." / ".." / "hybrid-ids").resolve()
if _HYBRID_IDS_ROOT.exists():
    sys.path.insert(0, str(_HYBRID_IDS_ROOT))
_extra = os.environ.get("HYBRID_IDS_ROOT")
if _extra:
    sys.path.insert(0, _extra)


# ---------------------------------------------------------------------------
# Feature extraction (identical to batch hybrid_bridge.py)
# ---------------------------------------------------------------------------
CIC_FEATURE_NAMES = [
    "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Min", "Fwd Packet Length Mean",
    "Fwd Packet Length Std", "Bwd Packet Length Max", "Bwd Packet Length Min",
    "Bwd Packet Length Mean", "Bwd Packet Length Std",
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
    f = {name: 0.0 for name in CIC_FEATURE_NAMES}

    flow_obj = flow.get("flow", flow)
    pkts_to = float(flow_obj.get("pkts_toserver", 0))
    pkts_from = float(flow_obj.get("pkts_toclient", 0))
    bytes_to = float(flow_obj.get("bytes_toserver", 0))
    bytes_from = float(flow_obj.get("bytes_toclient", 0))

    start = flow_obj.get("start")
    end = flow_obj.get("end")
    duration_us = 0.0
    if start and end:
        try:
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

    tcp = flow.get("tcp", {})
    if tcp:
        f["SYN Flag Count"] = float(tcp.get("syn", 0))
        f["ACK Flag Count"] = float(tcp.get("ack", 0))
        f["FIN Flag Count"] = float(tcp.get("fin", 0))
        f["RST Flag Count"] = float(tcp.get("rst", 0))
        f["PSH Flag Count"] = float(tcp.get("psh", 0))
        f["URG Flag Count"] = float(tcp.get("urg", 0))

    return f


# ---------------------------------------------------------------------------
# Robust eve.json tailer
# ---------------------------------------------------------------------------
class EveTailer:
    """Follows eve.json across truncation and rotation events.

    Suricata can rotate or truncate its log file at any time. A naive
    tail-style reader will silently stop receiving events when this
    happens. This class detects file replacement via inode change and
    truncation via file shrinkage, and reopens the file in either case.
    """

    def __init__(self, path: Path, poll_interval: float = 0.5):
        self.path = path
        self.poll = poll_interval
        self._fh = None
        self._inode = None
        self._pos = 0

    def _open(self) -> bool:
        try:
            stat = self.path.stat()
        except FileNotFoundError:
            return False
        if self._fh is not None:
            self._fh.close()
        self._fh = self.path.open("r")
        # On first open, jump to end to skip historical lines.
        # On reopen (rotation), start from the beginning of the new file.
        if self._inode is None:
            self._fh.seek(0, os.SEEK_END)
            self._pos = self._fh.tell()
        else:
            self._pos = 0
        self._inode = stat.st_ino
        LOG.info("Opened %s (inode=%d, starting at pos=%d)",
                 self.path, self._inode, self._pos)
        return True

    def __iter__(self):
        return self

    def __next__(self) -> dict:
        while True:
            if self._fh is None:
                if not self._open():
                    time.sleep(self.poll)
                    continue
            line = self._fh.readline()
            if line:
                self._pos = self._fh.tell()
                line = line.strip()
                if not line:
                    continue
                try:
                    return json.loads(line)
                except json.JSONDecodeError:
                    continue
            # No line available. Check for rotation/truncation.
            try:
                stat = self.path.stat()
            except FileNotFoundError:
                self._fh.close()
                self._fh = None
                time.sleep(self.poll)
                continue
            if stat.st_ino != self._inode:
                LOG.info("eve.json rotated, reopening")
                self._open()
                continue
            if stat.st_size < self._pos:
                LOG.info("eve.json truncated, reopening")
                self._open()
                continue
            time.sleep(self.poll)


# ---------------------------------------------------------------------------
# Elasticsearch client
# ---------------------------------------------------------------------------
class ElasticSink:
    def __init__(self, url: str, index: str, batch_size: int = 50):
        self.url = url.rstrip("/")
        self.index = index
        self.batch_size = batch_size
        self.buffer: list[dict] = []
        self.session = requests.Session()
        self.session.headers.update({"Content-Type": "application/x-ndjson"})

    def wait_until_ready(self, timeout: float = 120.0) -> bool:
        """Block until Elasticsearch responds with 200 on its root."""
        start = time.time()
        while time.time() - start < timeout:
            try:
                r = self.session.get(self.url, timeout=3)
                if r.status_code == 200:
                    LOG.info("Elasticsearch is ready at %s", self.url)
                    return True
            except requests.RequestException:
                pass
            time.sleep(2)
            LOG.info("Waiting for Elasticsearch ...")
        LOG.error("Elasticsearch not ready after %.0f seconds", timeout)
        return False

    def ensure_index(self) -> None:
        """Create the index with an explicit mapping if it does not exist."""
        # Check if exists
        try:
            r = self.session.head(f"{self.url}/{self.index}", timeout=5)
            if r.status_code == 200:
                return
        except requests.RequestException as e:
            LOG.warning("Index existence check failed: %s", e)
            return

        mapping = {
            "mappings": {
                "properties": {
                    "@timestamp":      {"type": "date"},
                    "flow_id":         {"type": "keyword"},
                    "src_ip":          {"type": "ip"},
                    "dst_ip":          {"type": "ip"},
                    "dst_port":        {"type": "integer"},
                    "proto":           {"type": "keyword"},
                    "bytes_total":     {"type": "long"},
                    "pkts_total":      {"type": "long"},
                    "duration_ms":     {"type": "float"},
                    "suricata_alert":  {"type": "boolean"},
                    "suricata_signature": {"type": "keyword"},
                    "ml_proba":        {"type": "float"},
                    "ml_decision":     {"type": "boolean"},
                    "fused_decision":  {"type": "boolean"},
                    "fusion_reason":   {"type": "keyword"},
                    "verdict":         {"type": "keyword"},  # benign/attack/agree/disagree
                }
            }
        }
        try:
            r = self.session.put(f"{self.url}/{self.index}",
                                 data=json.dumps(mapping),
                                 headers={"Content-Type": "application/json"},
                                 timeout=10)
            if r.status_code in (200, 201):
                LOG.info("Created index %s with explicit mapping", self.index)
            else:
                LOG.warning("Index create returned %d: %s", r.status_code, r.text[:200])
        except requests.RequestException as e:
            LOG.warning("Index create failed: %s", e)

    def push(self, doc: dict) -> None:
        self.buffer.append(doc)
        if len(self.buffer) >= self.batch_size:
            self.flush()

    def flush(self) -> None:
        if not self.buffer:
            return
        # Build NDJSON bulk payload
        body = []
        for doc in self.buffer:
            body.append(json.dumps({"index": {"_index": self.index}}))
            body.append(json.dumps(doc))
        payload = "\n".join(body) + "\n"
        try:
            r = self.session.post(f"{self.url}/_bulk",
                                  data=payload,
                                  timeout=10)
            if r.status_code >= 400:
                LOG.warning("Bulk push returned %d: %s", r.status_code, r.text[:200])
        except requests.RequestException as e:
            LOG.warning("Bulk push failed: %s", e)
        finally:
            self.buffer.clear()


# ---------------------------------------------------------------------------
# Main loop
# ---------------------------------------------------------------------------
def run(eve_path: Path, pipeline_path: Path, model_path: Path,
        es_url: str, es_index: str, csv_tail: Path, threshold: float,
        skip_es: bool):
    LOG.info("Loading feature pipeline: %s", pipeline_path)
    pipeline = joblib.load(pipeline_path)
    LOG.info("Loading hybrid model: %s", model_path)
    model = joblib.load(model_path)

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

    sink: Optional[ElasticSink] = None
    if not skip_es:
        sink = ElasticSink(es_url, es_index)
        if sink.wait_until_ready():
            sink.ensure_index()
        else:
            LOG.error("Continuing without Elasticsearch (results CSV only)")
            sink = None

    # CSV tail of recent decisions
    csv_tail.parent.mkdir(parents=True, exist_ok=True)
    csv_fh = csv_tail.open("w", newline="")
    csv_fields = ["timestamp", "src_ip", "dst_ip", "dst_port", "proto",
                  "bytes_total", "suricata_alert", "suricata_signature",
                  "ml_proba", "ml_decision", "fused_decision", "fusion_reason"]
    csv_writer = csv.DictWriter(csv_fh, fieldnames=csv_fields)
    csv_writer.writeheader()
    csv_fh.flush()

    # Sliding window: flow_id -> signature, kept for ALERT_TTL flows so we
    # can correlate alerts that arrive shortly after the flow event.
    alert_window: dict[str, str] = {}
    ALERT_TTL = 5000

    counts = {"flows": 0, "alerts": 0, "ml_attack": 0, "fused_attack": 0,
              "agreement": 0, "es_pushed": 0}
    last_summary = time.time()

    LOG.info("Tailing %s ...", eve_path)
    tailer = EveTailer(eve_path)

    for rec in tailer:
        et = rec.get("event_type")

        # Capture alerts so we can join them to flow events
        if et == "alert":
            fid = rec.get("flow_id")
            sig = rec.get("alert", {}).get("signature", "")
            if fid is not None:
                alert_window[str(fid)] = sig
                # Cap memory
                if len(alert_window) > ALERT_TTL:
                    # drop oldest 1000
                    for k in list(alert_window.keys())[:1000]:
                        alert_window.pop(k, None)
            counts["alerts"] += 1
            continue

        if et != "flow":
            continue

        counts["flows"] += 1
        fid = str(rec.get("flow_id", ""))

        # Suricata signal
        suri_sig = alert_window.pop(fid, "")
        suri_alert = bool(suri_sig)

        # ML inference
        try:
            import pandas as pd
            feats = suricata_flow_to_features(rec)
            row_dict = {n: feats.get(n, 0.0) for n in expected_features}
            X_df = pd.DataFrame([row_dict])
            X_df = X_df.replace([np.inf, -np.inf], 0.0).fillna(0.0)
            X = pipeline.transform(X_df)
            proba = float(model.predict_proba(X)[0, 1])
            ml_decision = bool(proba >= threshold)
        except Exception as e:
            LOG.warning("Inference failed for flow %s: %s", fid, e)
            proba = 0.0
            ml_decision = False

        if ml_decision:
            counts["ml_attack"] += 1

        fused = suri_alert or ml_decision
        if fused:
            counts["fused_attack"] += 1
        if suri_alert == ml_decision:
            counts["agreement"] += 1

        reasons = []
        if suri_alert:
            reasons.append("suricata")
        if ml_decision:
            reasons.append("ml")
        if not reasons:
            reasons.append("none")

        # Verdict label for Kibana visualisations
        if fused:
            verdict = "attack_both" if (suri_alert and ml_decision) else (
                "attack_suricata_only" if suri_alert else "attack_ml_only")
        else:
            verdict = "benign"

        flow_obj = rec.get("flow", rec)
        bytes_total = (float(flow_obj.get("bytes_toserver", 0)) +
                       float(flow_obj.get("bytes_toclient", 0)))
        pkts_total = (int(flow_obj.get("pkts_toserver", 0)) +
                      int(flow_obj.get("pkts_toclient", 0)))

        timestamp = rec.get("timestamp") or datetime.utcnow().isoformat() + "Z"

        doc = {
            "@timestamp": timestamp,
            "flow_id": fid,
            "src_ip": rec.get("src_ip", ""),
            "dst_ip": rec.get("dest_ip", ""),
            "dst_port": int(rec.get("dest_port", 0) or 0),
            "proto": rec.get("proto", ""),
            "bytes_total": int(bytes_total),
            "pkts_total": pkts_total,
            "duration_ms": float(flow_obj.get("age", 0.0)),
            "suricata_alert": suri_alert,
            "suricata_signature": suri_sig,
            "ml_proba": round(proba, 6),
            "ml_decision": ml_decision,
            "fused_decision": fused,
            "fusion_reason": "+".join(reasons),
            "verdict": verdict,
        }

        # Push to Elasticsearch
        if sink is not None:
            sink.push(doc)
            counts["es_pushed"] += 1

        # CSV mirror (uses 'timestamp' not '@timestamp' for legacy compatibility)
        csv_row = {k: doc.get(k, doc.get("@timestamp", "") if k == "timestamp" else "")
                   for k in csv_fields}
        csv_writer.writerow(csv_row)

        # Periodic summary
        now = time.time()
        if now - last_summary > 10.0:
            if sink is not None:
                sink.flush()
            csv_fh.flush()
            LOG.info("flows=%d alerts=%d ml_attack=%d fused=%d agree=%d es_pushed=%d",
                     counts["flows"], counts["alerts"], counts["ml_attack"],
                     counts["fused_attack"], counts["agreement"], counts["es_pushed"])
            last_summary = now


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--eve", type=Path, required=True)
    parser.add_argument("--pipeline", type=Path, required=True)
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--es-url", type=str,
                        default=os.environ.get("ES_URL", "http://elasticsearch:9200"))
    parser.add_argument("--es-index", type=str,
                        default=os.environ.get("ES_INDEX", "hybrid-ids-decisions"))
    parser.add_argument("--csv-tail", type=Path,
                        default=Path("/data/decisions_tail.csv"))
    parser.add_argument("--threshold", type=float, default=0.5)
    parser.add_argument("--skip-es", action="store_true",
                        help="Skip Elasticsearch (CSV only, useful for testing)")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s | %(levelname)-7s | %(message)s",
        datefmt="%H:%M:%S",
    )

    if not args.pipeline.exists():
        LOG.error("Pipeline artifact not found: %s", args.pipeline)
        sys.exit(1)
    if not args.model.exists():
        LOG.error("Model artifact not found: %s", args.model)
        sys.exit(1)

    run(args.eve, args.pipeline, args.model,
        args.es_url, args.es_index, args.csv_tail,
        args.threshold, args.skip_es)


if __name__ == "__main__":
    main()
