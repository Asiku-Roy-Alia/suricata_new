# Ubuntu VM Setup Guide

## 1. Confirm the VM has the expected project tools

```bash
python3 --version
git --version
jupyter lab --version || true
docker --version || true
docker compose version || true
node --version || true
npm --version || true
```

If Docker is missing, install it before running the realtime stack. The simplest Ubuntu path is Docker Engine plus the Docker Compose plugin.

```bash
sudo apt update
sudo apt install -y ca-certificates curl gnupg lsb-release git python3-venv python3-pip
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg
. /etc/os-release
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu ${VERSION_CODENAME} stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update
sudo apt install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Log out of the Ubuntu session and log back in, or reboot the VM, so group membership applies. Then test:

```bash
docker run --rm hello-world
docker compose version
```

## 2. Prepare Elasticsearch kernel setting

Set the map-count value high enough for Elasticsearch:

```bash
sudo sysctl -w vm.max_map_count=1048576
echo 'vm.max_map_count=1048576' | sudo tee /etc/sysctl.d/99-elasticsearch.conf
sudo sysctl --system
```

## 3. Clone the repository

```bash
cd ~
git clone https://github.com/Asiku-Roy-Alia/suricata_new.git Hybrid-IDS-Project
cd Hybrid-IDS-Project
```

If the repository is private, configure GitHub credentials or use a temporary personal access token.

## 4. Create the Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r hybrid-ids/requirements.txt
```

## 5. Connect the dataset already visible in JupyterLab

Your screenshot shows CIC-IDS-2017 files under `/dataset/MachineLearningCVE`. Link them into the project:

```bash
rm -rf hybrid-ids/data/raw
mkdir -p hybrid-ids/data
ln -s /dataset/MachineLearningCVE hybrid-ids/data/raw
ls -lh hybrid-ids/data/raw/*.csv
```

You should see the eight files: Monday, Tuesday, Wednesday, Thursday morning, Thursday afternoon, Friday morning, Friday afternoon PortScan and Friday afternoon DDoS.

## 6. Run the ML pipeline

For a quick environment check:

```bash
cd ~/Hybrid-IDS-Project/hybrid-ids
source ../.venv/bin/activate
python scripts/00_smoke_test.py
```

For the full training and report generation:

```bash
./run_all.sh
```

## 7. Run the realtime stack

```bash
cd ~/Hybrid-IDS-Project/realtime
./scripts/preflight.sh
docker compose up -d
./scripts/healthcheck.sh
```

Open:

```text
http://localhost:5601/app/dashboards
http://localhost:3000
```

## 8. Common fixes

If `docker compose up` says port `5601`, `9200`, or `3000` is already used:

```bash
docker ps
sudo ss -tulpn | grep -E ':5601|:9200|:3000'
```

If Elasticsearch fails with `vm.max_map_count`:

```bash
sudo sysctl -w vm.max_map_count=1048576
docker compose restart elasticsearch
```

If the bridge cannot load `hybrid.joblib`, confirm the artifacts exist:

```bash
ls -lh ~/Hybrid-IDS-Project/hybrid-ids/artifacts/
```

If the React dashboard opens but shows no records, check whether the bridge has written to Elasticsearch:

```bash
curl http://localhost:9200/hybrid-ids-decisions/_count
```
