# Hybrid Intrusion Detection System

This repository contains the complete BSc demonstration stack for a hybrid intrusion detection system:

- `hybrid-ids/` trains and evaluates the machine learning model on CIC-IDS-2017 flow CSVs.
- `operational/` runs a reproducible one-shot Suricata plus ML bridge demonstration from a generated PCAP.
- `realtime/` runs the live defence demo with PCAP generation, Suricata, the ML bridge, Elasticsearch, Kibana, and the React Node dashboard.

The Streamlit experiment has deliberately been left out. The live interface is Kibana on port `5601` plus the React dashboard on port `3000`.

## Recommended workflow

Use JupyterLab or the Ubuntu terminal for the ML training stage, then use Docker Compose for the Suricata, Elasticsearch, Kibana and dashboard stage.

The target VM shown in the setup already contains the CIC-IDS-2017 CSVs under `/dataset/MachineLearningCVE`. The cleanest setup is to symlink that directory into `hybrid-ids/data/raw` rather than committing dataset files into Git.

## First setup on Ubuntu

```bash
cd ~
git clone https://github.com/Asiku-Roy-Alia/suricata_new.git Hybrid-IDS-Project
cd Hybrid-IDS-Project

python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r hybrid-ids/requirements.txt
```

If the dataset already exists at `/dataset/MachineLearningCVE`, link it into the training project:

```bash
rm -rf hybrid-ids/data/raw
mkdir -p hybrid-ids/data
ln -s /dataset/MachineLearningCVE hybrid-ids/data/raw
ls hybrid-ids/data/raw/*.csv
```

If the dataset is somewhere else, replace `/dataset/MachineLearningCVE` with the correct directory containing the eight CIC-IDS-2017 `*_ISCX.csv` files.

## Training and evaluation

```bash
cd ~/Hybrid-IDS-Project
source .venv/bin/activate
cd hybrid-ids
python scripts/00_smoke_test.py
./run_all.sh
```

A full run produces the model artifacts in `hybrid-ids/artifacts/` and the evaluation outputs in `hybrid-ids/results/`. The realtime stack needs at least these two files:

```text
hybrid-ids/artifacts/feature_pipeline.joblib
hybrid-ids/artifacts/hybrid.joblib
```

The repository already includes trained artifacts for demonstration, so the realtime demo can run before retraining, but for a defence you should run the pipeline once on the VM so the artifacts and results match that machine.

## One-shot operational demonstration

This validates that Suricata can read a generated PCAP, produce `eve.json`, and that the trained ML model can consume the resulting flows.

```bash
cd ~/Hybrid-IDS-Project/operational/suricata
docker compose up --abort-on-container-exit

cd ../bridge
source ../../.venv/bin/activate
python hybrid_bridge.py batch \
  --eve ../suricata/logs/eve.json \
  --pipeline ../../hybrid-ids/artifacts/feature_pipeline.joblib \
  --model ../../hybrid-ids/artifacts/hybrid.joblib \
  --out logs/decisions.csv

python analyse_decisions.py logs/decisions.csv
```

## Realtime demo with Kibana and React dashboard

```bash
cd ~/Hybrid-IDS-Project/realtime
./scripts/preflight.sh
docker compose up -d
./scripts/healthcheck.sh
```

Open these in the Ubuntu browser:

```text
Kibana:          http://localhost:5601/app/dashboards
React dashboard: http://localhost:3000
Elasticsearch:  http://localhost:9200
```

Useful live logs:

```bash
docker compose logs -f pcap-generator
docker compose logs -f suricata
docker compose logs -f realtime-bridge
docker compose logs -f node-dashboard
```

To stop the realtime stack:

```bash
docker compose down
```

To reset the Elasticsearch index and start fresh:

```bash
docker compose down -v
docker compose up -d
```

## Important limitation

The trained ML model was fitted on CICFlowMeter-style CIC-IDS-2017 flow features. Suricata exposes only a smaller flow feature subset. The bridge maps what Suricata provides and fills missing CIC features with zero. This is acceptable for an end-to-end operational demonstration, but the quantitative scientific claims should come from the offline CIC-IDS-2017 evaluation and LOACO experiment in `hybrid-ids/results/`.
