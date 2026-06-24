# Hybrid IDS Real-Time Defence Demo

This directory adds a real-time pipeline on top of the trained hybrid model. It is intended for a live demonstration during the dissertation viva. The stack runs entirely inside Docker so it works the same on Linux, on macOS, and on Windows Subsystem for Linux 2.

## Architecture

The stack comprises eight Docker services that form a continuous pipeline from packet generation through to visual presentation.

A continuous PCAP generator writes a fresh 15,000-packet capture every minute to a shared volume, containing a realistic mix of benign and attack traffic. A small loader service copies the latest PCAP into a watch directory every twenty seconds, with a unique filename per drop. A Suricata 7 service runs in a wrapper loop: each iteration finds the oldest unprocessed PCAP, runs Suricata against it once, appends the per-iteration EVE JSON to a master log file, and deletes the processed PCAP. A real-time Python bridge tails the master EVE JSON file, runs the trained hybrid model on every flow record, fuses the Suricata signature alert with the ML decision, and pushes the result to Elasticsearch.

Two presentation layers are provided for the demonstration:

**Kibana** at `http://localhost:5601` shows real data flowing through the pipeline. The `kibana-setup` service automatically creates an Elasticsearch index template with explicit keyword mappings for the fields the Kibana visualizations aggregate on, and then imports a pre-built six-panel dashboard. This dashboard auto-refreshes every five seconds and shows verdict distribution, flow rate over time, top attacker IPs, Suricata signature hits, ML probability distribution, and a recent alerts table.

**React Node dashboard** at `http://localhost:3000` is a self-contained React application with a built-in traffic simulation engine. It does not depend on Elasticsearch or any backend services, which means it starts instantly and is always visually active with scrolling logs, updating charts, and accumulating metrics. This is the recommended primary presentation tool for the viva because it is zero-latency and always alive, regardless of whether the backend pipeline has finished warming up.

## System requirements

A recent Docker installation with Compose v2. Allocate at least eight gigabytes of memory to Docker Desktop. On WSL2, edit `%USERPROFILE%\.wslconfig` to set at least eight gigabytes, then restart with `wsl --shutdown`. About ten gigabytes of free disk space is needed for the images and Elasticsearch index data.

The trained model artifacts must exist at `../hybrid-ids/artifacts/hybrid.joblib` and `../hybrid-ids/artifacts/feature_pipeline.joblib`. Verify before starting:

```bash
ls -la ../hybrid-ids/artifacts/hybrid.joblib ../hybrid-ids/artifacts/feature_pipeline.joblib
```

## Starting the stack

Run the pre-flight check first:

```bash
cd realtime
./scripts/preflight.sh
```

Then start the stack:

```bash
docker compose up -d
```

The first run downloads images and builds the React dashboard. The React dashboard is available almost immediately on port 3000. Elasticsearch needs roughly 30 seconds to become healthy, and Kibana needs another 30 to 40 seconds after that. The `kibana-setup` service runs once both are ready: it creates the ES index template and imports the dashboard.

After about 90 seconds, verify all services:

```bash
./scripts/healthcheck.sh
```

## Watching the demo

Open in the browser:

```text
React dashboard: http://localhost:3000
Kibana:          http://localhost:5601/app/dashboards
```

The React dashboard is live immediately with simulated traffic. In Kibana, open "Hybrid IDS -- Live Decisions" and set the time range to "Last 15 minutes". Data appears once the bridge starts pushing decisions to Elasticsearch.

Useful log commands:

```bash
docker compose logs -f pcap-generator
docker compose logs -f suricata
docker compose logs -f realtime-bridge
docker compose logs -f node-dashboard
docker compose logs -f kibana-setup
```

## Stopping

```bash
docker compose down            # stop and remove containers, keep data
docker compose down -v         # also wipe Elasticsearch index data
```

## How Kibana was fixed

Previous versions of this stack had three issues that prevented Kibana from working:

1. The Elasticsearch environment section in docker-compose.yml used invalid YAML syntax for the CORS configuration lines, which caused Docker Compose to fail at parse time before any container could start.

2. Without an explicit index template, Elasticsearch auto-mapped string fields as `text` type with a `.keyword` sub-field. The Kibana visualizations referenced these fields directly for terms aggregations, which requires `keyword` type. The `kibana-setup` service now creates an index template that maps `verdict`, `src_ip`, `dst_ip`, `proto`, `suricata_signature`, and `fusion_reason` as `keyword` explicitly.

3. If the index already existed with incorrect `text` mappings from a previous run, the template would not retroactively fix it. The setup script now detects this condition and deletes the index so it recreates correctly under the new template.

## Important limitation

The trained ML model was fitted on CICFlowMeter-style CIC-IDS-2017 flow features. Suricata exposes only a smaller flow feature subset. The bridge maps what Suricata provides and fills missing CIC features with zero. This is acceptable for an end-to-end operational demonstration, but the quantitative scientific claims come from the offline CIC-IDS-2017 evaluation and LOACO experiment in `hybrid-ids/results/`.

## Troubleshooting

If the bridge container exits with an `ImportError`, the model artifacts use a different scikit-learn version. Re-train the model on the same Python environment or update the pip install line in docker-compose.yml.

If `docker compose logs suricata` shows zero packets or no flow events, verify the pcap-loader is feeding files: `docker compose logs pcap-loader` should show "dropped feed_N.pcap" lines.

If Kibana shows empty panels or "Unable to load saved objects", run `docker compose restart kibana-setup` to retry the import. If the index already has documents with wrong mappings, run `docker compose down -v` to wipe everything and start fresh.

If the React dashboard shows a blank page, check `docker compose logs node-dashboard` for npm or build errors. The first build may take 30 to 60 seconds as npm installs dependencies.

If Elasticsearch fails with a `vm.max_map_count` error, run `sudo sysctl -w vm.max_map_count=262144` on the host. On WSL2 this must be done in the WSL distro itself.
