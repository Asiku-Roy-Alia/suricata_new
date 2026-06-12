# Hybrid IDS — Real-Time Defence Demo

This directory adds a real-time pipeline on top of the trained hybrid model. It is intended for a live demonstration during the dissertation viva. The stack runs entirely inside Docker so it works the same on Linux, on macOS, and on Windows Subsystem for Linux 2.

## What it does

A continuous PCAP generator writes a fresh 15,000-packet capture every minute to a shared volume, containing a realistic mix of benign and attack traffic. A small loader service copies the latest PCAP into a watch directory every twenty seconds, with a unique filename per drop. A Suricata 7 service runs in a wrapper loop: each iteration finds the oldest unprocessed PCAP, runs Suricata against it once, appends the per-iteration EVE JSON to a master log file, and deletes the processed PCAP. A real-time Python bridge tails the master EVE JSON file, runs the trained hybrid model on every flow record, fuses the Suricata signature alert with the ML decision, and pushes the result to Elasticsearch. Kibana provides a live dashboard refreshing every five seconds.

This pipeline avoids the complications of network injection inside containers (virtual interfaces, link-layer replay, kernel privileges) by running Suricata in offline file mode under a wrapper loop. Functionally, the result is identical from the operator's perspective: fresh packet data flows through the entire pipeline continuously and shows up in Kibana within seconds of being generated.

## What this is not, and what to expect during the demo

This is not live network capture from your physical machine. The generator produces synthetic but realistic flow patterns inside the container network. It is suitable for a demonstration, not for production deployment.

The Suricata signature engine works exactly as it would in production. Brute force attempts, port scans, and web attack patterns will fire signature alerts that appear in the dashboard verdict pie and the recent alerts table. This is genuine signature-based detection on synthetic-but-valid TCP and HTTP traffic.

The machine learning branch is intentionally illustrative rather than quantitatively rigorous in the live demo. The trained hybrid model was fitted on the seventy-seven flow features that CICFlowMeter computes from raw packet captures, including features such as Flow Inter-Arrival Time Standard Deviation, Active Mean, Idle Standard Deviation, and Initial Forward Window Bytes. Suricata's flow records expose only a small subset of these features, on the order of eight: packet and byte counts per direction, flow duration, and TCP flag counts. The bridge fills missing features with zero so the model can still produce a probability, which means the live ML output is dominated by these zero-filled inputs and tends toward a near-constant probability across flows. This is documented honestly in chapter five of the dissertation as a known limitation of bridging high-level flow telemetry to feature-rich ML models.

The rigorous quantitative evaluation of the ML model lives in chapter four of the dissertation, which uses the actual CIC-IDS-2017 labelled flow records with all seventy-seven features intact. The live demo here is the operational architecture that proves the pipeline works end-to-end; the numbers that matter scientifically come from the offline experiments. A future-work item, scoped beyond this dissertation, is to integrate a CICFlowMeter sidecar service that recomputes the full feature set from packets so the ML branch can produce quantitatively meaningful predictions in real time.

## System requirements

A recent Docker installation with Compose v2. Allocate at least eight gigabytes of memory to Docker Desktop (Settings -> Resources -> Memory). On WSL2, additionally edit `%USERPROFILE%\.wslconfig` to ensure your distribution has at least eight gigabytes available, then restart with `wsl --shutdown` from PowerShell. About ten gigabytes of free disk space is needed for the Elasticsearch image plus index data.

The trained model artifacts must exist at `../hybrid-ids/artifacts/hybrid.joblib` and `../hybrid-ids/artifacts/feature_pipeline.joblib`. These are produced by the main pipeline. Verify before starting:

```bash
ls -la ../hybrid-ids/artifacts/hybrid.joblib ../hybrid-ids/artifacts/feature_pipeline.joblib
```

## Starting the stack

Before the very first run, execute the pre-flight check to verify your machine is properly configured:

```bash
cd realtime
./scripts/preflight.sh
```

This script verifies Docker is installed, that kernel parameters required by Elasticsearch are set, that enough memory is available, and that the trained model artifacts exist. Address any issues it reports before continuing.

Then start the stack:

```bash
docker compose up -d
```

The first run downloads four images: Python 3.11 slim, Alpine 3.19, jasonish/suricata:7.0, Elasticsearch 8.11.4, and Kibana 8.11.4. Total download is approximately 1.5 gigabytes. Subsequent starts reuse the local images.

After `docker compose up -d` returns, the stack takes about ninety seconds to fully initialise. Elasticsearch needs roughly thirty seconds to become healthy and Kibana needs another thirty to forty seconds on top of that. The dashboard import runs once Kibana is ready.

Once initialisation should be complete, verify all services are healthy:

```bash
./scripts/healthcheck.sh
```

This produces a green-and-red checklist of every service in the stack. If anything is red, the script prints the docker logs command you need to investigate further.

## Watching the demo

Open three terminals.

In the first terminal, watch the generator:
```bash
docker compose logs -f pcap-generator
```

In the second terminal, watch the bridge process flows:
```bash
docker compose logs -f realtime-bridge
```

In a browser, open Kibana at `http://localhost:5601`. Click "Dashboards" in the left menu, then open "Hybrid IDS — Live Decisions". The dashboard auto-refreshes every five seconds. Set the time range to "Last 15 minutes" and you should see verdicts streaming in.

## Stopping

```bash
docker compose down            # stop and remove containers, keep data
docker compose down -v         # also wipe Elasticsearch index data
```

## What the dashboard shows

Six panels arranged in a six-row grid. The verdict pie chart in the top left breaks down decisions by category: benign, attack flagged by both engines, attack flagged by Suricata only, and attack flagged by the ML model only. The flow rate over time chart in the top right shows total flow throughput stacked by verdict, so the operator can see traffic surge during attack phases. The top attacker source IPs panel shows which sources triggered the most flagged flows, filtered to attack flows only. The Suricata signature hits panel shows which rules fired and how often. The ML probability distribution histogram shows whether the model is making confident decisions or sitting near 0.5. The recent alerts table at the bottom shows the most recent flagged flows with their full metadata, sorted by timestamp descending.

## Troubleshooting

If the bridge container exits immediately with an `ImportError`, the model artefacts are using a different version of scikit-learn than the one in the bridge environment. The compose file pins recent versions; if you see this, re-train the model on the same Python environment.

If `docker compose logs suricata` shows "0 packets" or no flow events, check that the pcap-loader is feeding files: `docker compose logs pcap-loader` should show "dropped feed_N.pcap" lines. If it does not, the generator volume may be empty; verify with `docker compose logs pcap-generator`.

If Kibana shows "Unable to load saved objects" or the dashboard appears empty, run `docker compose restart kibana-setup` to retry the import. Then refresh Kibana in your browser.

If Elasticsearch fails to start with a `vm.max_map_count` error, run `sudo sysctl -w vm.max_map_count=262144` on the host. On WSL2 this needs to be done in the WSL distro itself, then restart Docker Desktop.

If the stack starts but no decisions appear in Kibana, check the bridge logs first (`docker compose logs realtime-bridge`). The bridge logs a summary every ten seconds showing flow throughput; if those summaries are not appearing, Suricata is not producing flow events.

If the bridge keeps logging `Inference failed for flow ...`, the feature pipeline expects column names that the EVE JSON does not supply. The bridge is designed to fill missing features with zero, so this should not happen with the bundled artifacts. If it does, run with `--verbose` and check the actual error.

## How this maps to the dissertation

This stack is for the live defence demonstration. Its presence in the repository should be mentioned in chapter five (conclusion and future work) as the operational deployment artefact. The numbers reported in the results chapter still come from the batch experiments described in the main pipeline, because those use the labelled CIC-IDS-2017 ground truth and the Leave-One-Attack-Category-Out protocol. The real-time stack runs against synthesised traffic and is qualitative rather than quantitative.
