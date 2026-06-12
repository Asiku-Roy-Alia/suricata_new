#!/usr/bin/env bash
# Runs the whole pipeline end-to-end. Stops on first error.
set -euo pipefail

PYTHON="${PYTHON:-python}"
ROOT="$(cd "$(dirname "$0")" && pwd)"
cd "$ROOT"

echo "=============================================================="
echo "Hybrid IDS: full pipeline"
echo "Project root: $ROOT"
echo "=============================================================="

$PYTHON scripts/00_smoke_test.py
echo
$PYTHON scripts/01_prepare_data.py
echo
$PYTHON scripts/00b_eda.py
echo
$PYTHON scripts/02_preprocess.py
echo
$PYTHON scripts/03_train_models.py
echo
$PYTHON scripts/04_evaluate.py
echo
$PYTHON scripts/05_loaco.py
echo
$PYTHON scripts/06_report.py

echo
echo "=============================================================="
echo "DONE. See results/final_report.md for the consolidated report."
echo "=============================================================="
