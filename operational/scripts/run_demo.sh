#!/usr/bin/env bash
# End-to-end runner for the Suricata + hybrid bridge demonstration.
#
# Usage: ./scripts/run_demo.sh [path/to/your.pcap]
#
# If a PCAP is supplied as the first argument, it overrides the synthetic one.
# Otherwise the docker-compose pcap-gen service generates a Friday-working-
# hours-style synthetic PCAP automatically on first run.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

# If user supplied a PCAP, copy it into the pcaps directory so the
# pcap-gen service detects it and skips generation.
if [[ $# -ge 1 ]]; then
    mkdir -p suricata/pcaps
    cp "$1" suricata/pcaps/sample.pcap
    echo "Copied $1 -> suricata/pcaps/sample.pcap (will be used as input)"
fi

mkdir -p suricata/logs suricata/pcaps
rm -f suricata/logs/eve.json

echo
echo "=========================================="
echo "Step 1: Generate PCAP (if needed) + run Suricata"
echo "=========================================="
( cd suricata && docker compose up --abort-on-container-exit )

if [[ ! -s suricata/logs/eve.json ]]; then
    echo "ERROR: Suricata produced no eve.json output. Check 'docker compose logs'."
    exit 1
fi

echo
echo "=========================================="
echo "Step 2: Run the hybrid bridge"
echo "=========================================="
cd bridge
if [[ ! -d .venv ]]; then
    python3 -m venv .venv
    source .venv/bin/activate
    pip install --quiet --upgrade pip
    pip install --quiet joblib numpy pandas scikit-learn
else
    source .venv/bin/activate
fi

mkdir -p logs
python hybrid_bridge.py batch \
  --eve      ../suricata/logs/eve.json \
  --pipeline ../../hybrid-ids/artifacts/feature_pipeline.joblib \
  --model    ../../hybrid-ids/artifacts/hybrid.joblib \
  --out      ./logs/decisions.csv

echo
echo "=========================================="
echo "Step 3: Comparison report"
echo "=========================================="
python analyse_decisions.py logs/decisions.csv
