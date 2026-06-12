#!/usr/bin/env bash
set -euo pipefail
DATASET_DIR="${1:-/dataset/MachineLearningCVE}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
if [ ! -d "$DATASET_DIR" ]; then
  echo "Dataset directory not found: $DATASET_DIR" >&2
  exit 1
fi
COUNT=$(find "$DATASET_DIR" -maxdepth 1 -name '*.csv' | wc -l)
if [ "$COUNT" -lt 8 ]; then
  echo "Expected at least 8 CIC-IDS-2017 CSV files in $DATASET_DIR, found $COUNT" >&2
  exit 1
fi
rm -rf "$ROOT/hybrid-ids/data/raw"
mkdir -p "$ROOT/hybrid-ids/data"
ln -s "$DATASET_DIR" "$ROOT/hybrid-ids/data/raw"
echo "Linked $DATASET_DIR -> $ROOT/hybrid-ids/data/raw"
ls -lh "$ROOT/hybrid-ids/data/raw"/*.csv
