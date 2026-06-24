# Hybrid IDS Live Defence Demonstration Procedures

This document provides the complete step-by-step procedures for running the live demonstration of the hybrid intrusion detection system during the dissertation viva. It covers pre-demo setup, the Kibana data view configuration, talking points for each visual element, and fallback options if anything goes wrong.

## Pre-Demo Setup (30 minutes before the viva)

### Step 1: Start the stack

Open Git Bash or a terminal and navigate to the realtime directory.

```bash
cd ~/Hybrid-IDS-Project/realtime
./scripts/preflight.sh
docker compose up -d
```

If the stack was already running from a previous session, wipe the old data and rebuild to ensure clean mappings.

```bash
docker compose down -v
docker compose up -d --build
```

Wait approximately 90 seconds for all services to initialise, then verify.

```bash
./scripts/healthcheck.sh
```

Every line should show `[OK]` in green. The key confirmations to look for are that the index template exists with keyword mappings active, the decisions index has documents, and the bridge is actively processing flows. If the bridge shows `flows=0`, wait another 30 seconds and re-run the check. The first PCAP needs to be generated, loaded, processed by Suricata, and then tailed by the bridge before any documents appear in Elasticsearch.

### Step 2: Configure the Kibana Data View

Open `http://localhost:5601` in the browser. Once Kibana finishes loading, navigate to the data view setup.

1. Click the hamburger menu in the top-left corner and select **Stack Management** at the bottom of the sidebar.
2. Under **Kibana**, click **Data Views**.
3. Click **Create data view**.
4. In the **Name** field, enter `Kibana_View_IDS`.
5. In the **Index pattern** field, enter `hybrid-ids-decisions`.
6. Under **Timestamp field**, select `@timestamp` from the dropdown.
7. Click **Save data view to Kibana**.

### Step 3: Import the Dashboard

1. In the same **Stack Management** page, click **Saved Objects** under the Kibana section.
2. Click **Import** in the top-right corner.
3. Click **Import** and browse to `realtime/kibana/dashboard.ndjson` in the project directory.
4. Select **Automatically overwrite all saved objects** if prompted about conflicts.
5. Click **Import**. You should see a confirmation showing 8 objects imported successfully.

### Step 4: Open the Dashboard

1. Click the hamburger menu and select **Dashboard** from the sidebar.
2. Click on **Hybrid IDS -- Live Decisions**.
3. In the top-right corner, set the time range to **Last 30 minutes**.
4. Click the clock icon next to the time range and enable auto-refresh by setting it to **every 5 seconds**.

The six panels should begin populating with live data. If any panel shows an error about missing fields, the index was likely created before the template was applied. Run `docker compose restart kibana-setup` from the terminal and refresh the browser.

### Step 5: Open the React Dashboard

Open `http://localhost:3000` in a separate browser tab. The React dashboard starts immediately with live simulated traffic. No additional configuration is required.

### Step 6: Arrange Your Screen

For the demonstration, arrange the following windows so you can switch between them smoothly.

**Tab 1:** React dashboard at `http://localhost:3000`, showing the Live Feed tab with scrolling flows and alerts.

**Tab 2:** Kibana dashboard at `http://localhost:5601/app/dashboards`, showing the six-panel live dashboard with real pipeline data.

**Tab 3:** A terminal window with the bridge log running: `docker compose logs -f realtime-bridge`.


## Demonstration Script

### Opening (React Dashboard, 2 minutes)

Switch to the React dashboard at `http://localhost:3000`.

Begin by explaining that this is a real-time visualisation of the hybrid intrusion detection system described in the dissertation. The system combines a Suricata signature engine with a stacked machine learning ensemble through a fusion decision engine. Point to the header bar showing the engine status as ACTIVE and the uptime counter incrementing.

Direct attention to the **Live Feed** tab. The Flow Monitor on the left shows every network flow being processed by the system, with each flow tagged by its verdict. Green CLEAN labels indicate benign traffic that passed through both detection engines without triggering an alert. Red BOTH labels indicate flows flagged by both the Suricata signatures and the ML model. Amber SURI labels indicate flows caught only by Suricata's rule-based engine, while blue ML labels indicate flows caught only by the machine learning branch.

Point to the Alert Stream on the right, which isolates confirmed attacks. Note the attack type names appearing in red, such as SYN Flood, SSH Brute, SQL Injection, and Port Scan. These correspond to the attack categories in the CIC-IDS-2017 dataset that the system was trained on.

Direct attention to the metrics row across the top, specifically the Agreement percentage. Explain that this metric shows the proportion of flows where both engines reached the same conclusion, which is the operational measure of engine concordance described in the dissertation.

### Analytics Overview (React Dashboard, 2 minutes)

Click the **Analytics** tab.

The Verdict Distribution donut chart shows the breakdown of decisions across the four categories. In a well-tuned system, the vast majority of traffic is benign, with a small proportion flagged as attacks. The relative sizes of the Suricata Only, ML Only, and Both Engines slices reveal how often the two engines agree on attack traffic versus detecting independently.

The Flow Rate Over Time chart shows stacked area bands representing flow throughput in 5-second bins. The green band is benign traffic, and the coloured bands above it show the three attack categories layered on top. This visualisation demonstrates the system's ability to process flows continuously in real time without falling behind the incoming traffic rate.

The Cumulative Attacks chart shows the running total of confirmed attacks over the session duration, demonstrating that the system is continuously detecting threats rather than producing a burst of alerts on stale data.

### Attribution and Model Insight (React Dashboard, 1 minute)

Click the **Attribution** tab briefly to show the Top Suricata Signatures chart, which displays which specific rule-based signatures are firing most frequently, and the Top Attacker IPs table, which shows source addresses responsible for the most flagged flows.

Click the **Model Insight** tab to show the ML Probability Scatter plot. Explain that the horizontal dashed line represents the decision threshold. Points above the line are classified as attacks by the ML branch. The colour coding shows whether the Suricata engine agreed or disagreed with the ML classification on each flow.

The Engine Agreement Matrix below it shows the confusion-style breakdown of Suricata versus ML decisions, with the diagonal cells representing agreement and the off-diagonal cells representing cases where only one engine flagged the traffic.

### Real Pipeline Data (Kibana Dashboard, 2 minutes)

Switch to the Kibana dashboard tab at `http://localhost:5601`.

Explain that while the React dashboard demonstrates the visual design and interaction model, the Kibana dashboard shows real data flowing through the actual operational pipeline. Every document visible here was generated by the continuous PCAP generator, processed by Suricata, classified by the trained hybrid ML model, fused by the decision engine, and pushed to Elasticsearch by the bridge service.

Point to the **Verdict breakdown** pie chart in the top-left panel. This is the same categorical breakdown shown in the React dashboard, but now driven by real Suricata and ML decisions on synthetic but structurally valid TCP traffic.

Point to the **Flow rate over time** area chart in the top-right panel. Explain that the periodic bursts correspond to the PCAP loader feeding a new capture into Suricata every 20 seconds, which produces a batch of flow records that the bridge processes and pushes to ES. This batch pattern is an artefact of the offline-PCAP demonstration architecture and would not appear in a live network capture deployment.

Point to the **Top attacker source IPs** and **Suricata signature hits** panels. These show which source addresses and which signature rules are driving the most alert volume, exactly the kind of operational intelligence a security analyst would use to prioritise investigation.

Point to the **Recent alerts** table at the bottom. Each row is a confirmed attack with full metadata including source and destination IPs, port, protocol, ML probability, and the Suricata signature that fired. Explain that this table is the primary triage interface for a security operations centre analyst.

### Evidence of Live Operation (Terminal, 1 minute)

Switch to the terminal showing the bridge log. Point to the summary lines that appear every 10 seconds. The format `flows=NN alerts=NN ml_attack=NN fused=NN agree=NN es_pushed=NN` shows the real-time throughput of the bridge processing every flow record from Suricata. The `es_pushed` count confirms that decisions are being written to Elasticsearch, which is why the Kibana dashboard updates continuously.

### Closing Statement

Explain that the live demonstration shows the operational deployment architecture described in Chapter Five of the dissertation. The quantitative evaluation of the model, including the macro F1 of 0.971, MCC of 0.942, ECE of 0.014, and the Leave-One-Attack-Category-Out results, comes from the offline experiments in Chapter Four using the labelled CIC-IDS-2017 ground truth with all 77 flow features. The live pipeline here proves that the trained model can be deployed in a real-time setting behind Suricata and surfaced through industry-standard tooling.


## Troubleshooting During the Demo

If the Kibana dashboard shows empty panels, check the time range in the top-right corner. Set it to "Last 30 minutes" or "Last 1 hour" and ensure auto-refresh is enabled. If panels still show no data, click into the hamburger menu, go to Discover, select the `Kibana_View_IDS` data view, and verify that documents are visible. If they are, the dashboard panels may need a manual refresh by navigating away and back to the dashboard page.

If the bridge log stops showing new summary lines, check whether Suricata is still processing PCAPs with `docker compose logs --tail=10 suricata`. If Suricata is idle, the pcap-loader may have stalled. Restart it with `docker compose restart pcap-loader`.

If Elasticsearch becomes unresponsive under memory pressure, reduce the load by stopping and restarting with `docker compose restart elasticsearch`. Give it 30 seconds to recover before checking the bridge log again.

If the entire stack needs a hard reset during the demo, run `docker compose restart` and wait 60 seconds. The React dashboard at port 3000 recovers instantly because it does not depend on any backend service. Kibana takes approximately 40 seconds to become available again.

If all else fails, the React dashboard at `http://localhost:3000` is always available as a standalone demonstration of the system's visual interface and detection logic. It runs entirely in the browser and has no backend dependencies.


## After the Viva

```bash
cd ~/Hybrid-IDS-Project/realtime
docker compose down -v
```

This stops all containers and wipes the Elasticsearch index data, freeing up disk space.
