# Demo Day Cheatsheet

Quick reference for running the live demo during the dissertation viva.

## Before the room

About thirty minutes before the viva, start the stack and verify it is healthy. Do this from your laptop with reliable internet on the off chance Docker needs to pull a missing image.

```bash
cd realtime
./scripts/preflight.sh    # confirm everything is in order
docker compose up -d      # launch all services
sleep 90                  # give the stack time to settle
./scripts/healthcheck.sh  # verify every service is green
```

If `healthcheck.sh` shows everything green, open the React dashboard at `http://localhost:3000` and Kibana at `http://localhost:5601` in your browser. The React dashboard is live immediately with simulated traffic. In Kibana, navigate to Dashboards, then "Hybrid IDS - Live Decisions". Confirm verdicts are appearing. Set the time picker to "Last 15 minutes" with auto-refresh every 5 seconds.

If anything is red, address it before the viva starts.

## During the demo

Have three windows arranged on screen.

The first window is the React dashboard at `http://localhost:3000`. This is the primary presentation tool because it is always live with simulated traffic, regardless of whether the backend pipeline has finished warming up. Point out the scrolling flow monitor and alert stream in the Live Feed tab, the updating charts in the Analytics tab, and the ML probability scatter in the Model Insight tab. The simulation engine is configurable from the sidebar: adjust the attack rate, ML threshold, and refresh speed to show how the system responds to changing threat conditions.

The second window is the Kibana dashboard at `http://localhost:5601/app/dashboards`. This shows real data from the pipeline, proving that the trained model is running against Suricata output. Point out the verdict pie chart, the flow rate timeline, and the recent alerts table with live data from the bridge.

The third window is a terminal showing the bridge log. This is the evidence that the ML model is actively running on every flow:

```bash
docker compose logs -f realtime-bridge
```

The summary lines reading `flows=NN alerts=NN ml_attack=NN fused=NN` appear every ten seconds and prove the bridge is processing flows live.

The third window is a terminal showing Suricata processing PCAPs:

```bash
docker compose logs -f suricata
```

The lines reading `[suricata] processing /pcap-watch/feed_NN.pcap` and `[suricata] appended NNNN events to master eve.json` show that fresh data is flowing through the pipeline every twenty seconds.

## What to say while the demo runs

The React dashboard is showing a live simulation of the hybrid intrusion detection system with realistic network traffic patterns. The flow monitor shows individual packet decisions streaming through the fusion engine, with each flow classified by both the Suricata signature engine and the stacked ML model. The alert stream isolates confirmed attacks.

Switching to the Kibana dashboard, this shows real decisions from the actual pipeline running inside Docker. The Suricata signature engine fires alerts on actual attack patterns including brute force, port scans, and web attacks. These are the same signatures you would see in a production Suricata deployment. The ML model on the other branch produces probability scores on every flow record. The fused decision combines both engines, so a flow flagged by either is treated as suspicious.

The rigorous quantitative evaluation of the model is in chapter four, using the labelled CIC-IDS-2017 ground truth. What you are seeing now is the operational architecture: how the trained model would be deployed in a live SOC environment.

## If something goes wrong

If Kibana shows no data, open the bridge log window first. If the bridge is producing summary lines, the issue is between the bridge and Kibana, which usually means Elasticsearch is overloaded; just give it a minute. If the bridge is silent, check the Suricata log; if Suricata is silent, check the generator log:

```bash
docker compose logs --tail=20 pcap-generator
docker compose logs --tail=20 pcap-loader
docker compose logs --tail=20 suricata
docker compose logs --tail=20 realtime-bridge
```

If the entire stack has crashed, restart it:

```bash
docker compose restart
sleep 60
./scripts/healthcheck.sh
```

If you have time pressure and the backend pipeline is not cooperating, the React dashboard at `http://localhost:3000` is always available as a standalone presentation tool with its built-in simulation engine. It does not depend on Elasticsearch or any backend service. The dissertation does not depend on the live demo.

## After the viva

```bash
docker compose down -v   # stop everything and wipe the Elasticsearch data
```

This frees up the disk space and ensures that if you restart later you get a clean dashboard.
