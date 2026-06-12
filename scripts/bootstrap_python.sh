#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r hybrid-ids/requirements.txt
echo "Python environment ready. Activate with: source $ROOT/.venv/bin/activate"
