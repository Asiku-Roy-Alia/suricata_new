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

If `healthcheck.sh` shows everything green, open Kibana at `http://localhost:5601` in your browser and navigate to Dashboards, then "Hybrid IDS - Live Decisions". Confirm verdicts are appearing. Set the time picker to "Last 15 minutes" with auto-refresh every 5 seconds.

If anything is red, address it before the viva starts.

## During the demo

Have three windows arranged on screen.

The first window is the Kibana dashboard at `http://localhost:5601/app/dashboards`. This is the centrepiece. Point out the verdict pie chart updating in real time, the flow rate timeline showing benign and attack traffic, and the recent alerts table populating with new flagged flows.

The second window is a terminal showing the bridge log. This is your evidence that the ML model is actively running on every flow:

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

The dashboard is showing live decisions on traffic generated inside the container. The Suricata signature engine on the right side of the verdict pie shows alerts firing on actual attack patterns: brute force, port scans, web attacks. These are the signature-based detections you would get from a production Suricata deployment. The ML model on the other branch of the verdict pie shows the hybrid stacked classifier from chapter four producing probability scores on every flow record. The fused decision combines both engines, so a flow flagged by either is treated as suspicious.

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

If you have time pressure and the live stack is not cooperating, you can fall back to the static screenshots of the dashboard saved in `dissertation/figures/` and present those instead. The dissertation does not depend on the live demo.

## After the viva

```bash
docker compose down -v   # stop everything and wipe the Elasticsearch data
```

This frees up the disk space and ensures that if you restart later you get a clean dashboard.
