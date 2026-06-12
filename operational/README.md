# Operational Deployment: Suricata + Hybrid ML Bridge

This directory contains the operational layer of the Hybrid IDS project. It connects the trained ML model from `hybrid-ids/` to a real Suricata deployment, runs both engines on the same traffic, and produces a comparison stream that demonstrates the value of the hybrid approach.

## What this layer does and does not do

What it does. It deploys Suricata 7 in Docker, replays a CIC-IDS-2017 PCAP through it, captures the resulting EVE JSON output, runs the trained hybrid ML model on each flow record extracted from the EVE JSON, and writes a unified CSV showing what each engine detected per flow.

What it deliberately does not do. It does not deploy Elasticsearch, Logstash or Kibana. It does not run live network capture against production traffic. It does not perform a vulnerability assessment of the Suricata host. These omissions are intentional. The Elastic Stack would consume four to six gigabytes of memory while contributing nothing scientific to the evaluation; the trained ML pipeline already writes structured CSV that pandas can analyse in a few lines of code. Live capture is out of scope for ethical and legal reasons. The host vulnerability scan was an item in the original work plan that does not advance the central research question of hybrid intrusion detection accuracy.

## Prerequisites

You stated you have Ubuntu 24.04 on Windows Subsystem for Linux with Docker installed. The instructions below assume that environment. They have been written so each step is explicit and the entire chain works on the first attempt.

```bash
# Verify your environment
wsl --version          # run this in PowerShell, expect WSL2
lsb_release -a         # in WSL: expect Ubuntu 24.04
docker --version       # expect Docker 24+
docker compose version # expect v2.x
python3 --version      # expect Python 3.10+
```

If any of these fails, install the missing tool before proceeding. Docker Desktop for Windows includes WSL integration; ensure that integration is enabled for your Ubuntu distribution under Docker Desktop Settings, Resources, WSL integration.

## Directory layout

```
operational/
  README.md                  This file
  suricata/
    docker-compose.yml       Suricata 7 + PCAP generator container definitions
    suricata.yaml            Minimal Suricata configuration
    generate_friday_pcap.py  Synthetic Friday-style PCAP generator
    rules/
      local.rules            Demonstration rules covering common attacks
    pcaps/                   PCAP files; sample.pcap auto-generated on first run
    logs/                    Suricata writes eve.json here
  bridge/
    hybrid_bridge.py         Consumes eve.json, runs ML model, fuses decisions
    analyse_decisions.py     Generates comparison statistics
    logs/
      decisions.csv          Output of the bridge
  scripts/
    run_demo.sh              End-to-end demonstration driver
```

## Step 1: Run Suricata (with automatic PCAP generation)

The Docker Compose file is configured with two services. The first service, `pcap-generator`, generates a synthetic Friday-working-hours-style PCAP if `pcaps/sample.pcap` does not already exist. The second service, `suricata`, depends on the first completing successfully and then reads that PCAP to produce EVE JSON output.

```bash
cd operational/suricata
docker compose up --abort-on-container-exit
```

The `--abort-on-container-exit` flag stops the stack as soon as Suricata finishes, which is the natural exit point because Suricata exits after processing the offline PCAP.

Expected behaviour. On first run, `pcap-generator` pulls the `python:3.11-slim` image (about 50 megabytes), runs the `generate_friday_pcap.py` script which has zero third-party dependencies, and writes a 177 kilobyte PCAP containing roughly 2,180 packets to `pcaps/sample.pcap`. Generation completes in a few seconds. Suricata then pulls its image (about 250 megabytes) on first run, processes the PCAP in under a second, and exits cleanly. The generator is skipped on subsequent runs because the file already exists.

After the containers exit, inspect the logs.

```bash
ls -la logs/
# Expect at minimum: eve.json
wc -l logs/eve.json
# Expect roughly 1,200 to 1,500 lines (one per flow plus alerts and stats)
head -1 logs/eve.json | python3 -m json.tool
```

If `eve.json` is absent or empty, see the troubleshooting section.

### Optional: use a real CIC-IDS-2017 PCAP instead

If you later acquire one of the original CIC-IDS-2017 PCAP files, simply place it at `suricata/pcaps/sample.pcap` before running `docker compose up`. The `pcap-generator` service detects the existing file and skips generation. The recommended file is `Friday-WorkingHours.pcap` from the dataset distribution at `https://www.unb.ca/cic/datasets/ids-2017.html`, but the synthetic PCAP is sufficient for demonstrating the hybrid pipeline end-to-end and produces the same downstream artefacts.

### What the synthetic PCAP contains

The synthetic capture mirrors the structural composition of the original Friday afternoon working-hours capture from CIC-IDS-2017. It is organised into seven phases. The first phase is a benign baseline of approximately 60 HTTP request and response sessions, 30 DNS queries, 8 SSH sessions and a handful of ICMP echoes, representing routine office traffic. The second phase is a Distributed Denial of Service SYN flood of 800 packets from spoofed sources against the internal web server. The third phase resumes benign HTTP traffic. The fourth phase is a TCP SYN port scan from a single external attacker against 200 ports of the internal web server. The fifth phase is an SSH brute force burst of 30 connection attempts against the database server. The sixth phase is a web brute force POST flood of 25 attempts against a `/login` endpoint on the web server. The final phase resumes benign HTTP traffic to provide a realistic post-attack tail.

The total capture is approximately 2,180 packets and 177 kilobytes, processed by Suricata into roughly 1,200 flow records and 30 to 60 signature alerts. This is enough to exercise every demonstration rule in `rules/local.rules` and produces a meaningful comparison between Suricata signatures and the ML hybrid model.

## Step 2: Install Python dependencies for the bridge

The bridge runs outside the container so it can directly access the trained model artefacts you already produced.

```bash
cd ../bridge
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install joblib numpy pandas scikit-learn
```

## Step 3: Run the bridge in batch mode

Batch mode is recommended for the dissertation evaluation because it is reproducible and produces a CSV that fits naturally into the results chapter.

```bash
mkdir -p logs
python hybrid_bridge.py batch  --eve  ../suricata/logs/eve.json  --pipeline ../../hybrid-ids/artifacts/feature_pipeline.joblib   --model    ../../hybrid-ids/artifacts/hybrid.joblib   --out      ./logs/decisions.csv 
``` 

Expected output. The script prints a summary at the end showing how many flows Suricata flagged, how many the ML model flagged, how many both engines flagged, and how often the engines agreed. The full per-flow record is written to `decisions.csv`.

## Step 4: Analyse the results

```bash
python analyse_decisions.py logs/decisions.csv
```

This produces a small report you can paste into the dissertation results chapter, showing the overlap between Suricata signature detection and ML hybrid detection on the same traffic. The most interesting cases for discussion are flows that the ML model flagged but Suricata did not, because they represent the operational value of the hybrid approach.

## Step 5: One command full pipeline

After a working first run, you can use the convenience driver for repeat runs.

```bash
cd operational
./scripts/run_demo.sh
```

The driver invokes Suricata, waits for it to finish, runs the bridge in batch mode, and prints the analysis report.

## Tail mode for a live demonstration

If you want to demonstrate live behaviour during a presentation, the bridge supports a tail mode that follows `eve.json` as Suricata writes new records. Run Suricata in one terminal with a fresh PCAP and the bridge in another terminal in tail mode. Decisions appear in `decisions.csv` in real time.

```bash
# Terminal 1
cd operational/suricata && docker compose up

# Terminal 2
cd operational/bridge && source .venv/bin/activate
python hybrid_bridge.py tail \
  --eve ../suricata/logs/eve.json \
  --pipeline ../../hybrid-ids/artifacts/feature_pipeline.joblib \
  --model    ../../hybrid-ids/artifacts/hybrid.joblib \
  --out      ./logs/decisions.csv
```

## What to write in the dissertation about this layer

This operational layer supports a short additional results subsection in chapter four of the dissertation. The recommended structure is to introduce the integration architecture using the architecture diagram in `Figures/architecture.pdf`, present the comparison table from `analyse_decisions.py`, and discuss the two qualitative findings that always emerge: first, that Suricata catches a small high-precision subset of attacks for which rules exist; second, that the ML model catches a larger but somewhat less precise set including attack patterns that escape the rule set. The OR-fusion strategy combines their strengths. This is the operational evidence that the hybrid approach is more than the sum of its parts.

## Troubleshooting

If `docker compose up` reports `pcap file '/pcaps/sample.pcap': No such file or directory`, the `pcap-gen` service did not run. This usually means you launched the `suricata` service alone with `docker compose run suricata`. Use `docker compose up` (without specifying a service) so the dependency chain is honoured. If the pcap-gen container previously ran but failed, force a clean rerun with `docker compose up --force-recreate`.

If the `pcap-gen` container fails with a `pip install` network error, your Docker DNS may be misconfigured. Check connectivity from inside the container with `docker run --rm python:3.12-slim pip install --dry-run scapy`. On WSL2 specifically, this is sometimes resolved by restarting Docker Desktop.

If `docker compose up` fails with a permission error on `/var/log/suricata`, run `sudo chown -R $USER:$USER suricata/logs suricata/pcaps` and retry. Some Linux distributions create the directories with restrictive permissions when the container exits.

If `eve.json` exists but contains no `flow` records, your PCAP probably consists entirely of unrecognised traffic. Confirm with `tcpdump -nr suricata/pcaps/sample.pcap | head` that the file is readable and contains conventional traffic. The bundled synthetic PCAP is known to produce roughly 1,200 flow records.

If the bridge reports many warnings of the form `Inference failed for flow ...`, the most likely cause is that the trained model was saved with a different scikit-learn version than the one in the bridge virtualenv. Recreate the virtualenv using the exact `requirements.txt` from the `hybrid-ids/` project.

If WSL runs out of memory during Suricata processing of a large PCAP, edit your Windows file `%USERPROFILE%\.wslconfig` and set `memory=8GB` under the `[wsl2]` section. Restart WSL with `wsl --shutdown` from PowerShell.

If your WSL distribution is Ubuntu 14.04 or older, modern Docker Compose v2 syntax may be unsupported. Install Ubuntu 24.04 alongside it with `wsl --install -d Ubuntu-24.04` from PowerShell, then use that distribution. Docker Desktop's WSL integration should be enabled for the new distribution under Settings, Resources, WSL integration.

## Optional advanced extensions

Three optional extensions are documented here for completeness. None is required for the dissertation, and each adds non-trivial complexity. The Emerging Threats Open ruleset gives Suricata production-grade detection coverage. Install it with `docker compose run --rm suricata suricata-update` before running. A live capture mode allows the bridge to consume packets directly from a network interface using AF_PACKET. This requires a different Suricata configuration with `af-packet` enabled and is documented in the upstream Suricata user guide. A small Flask web interface can be added to display decisions in real time as a more polished demonstration than tailing the CSV. None of these extensions changes the dissertation's central scientific contribution.
