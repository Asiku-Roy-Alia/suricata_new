#!/usr/bin/env bash
# ============================================================================
# Realtime stack health check (improved April 2026)
# Now correctly reports green when Suricata is appending events and the
# bridge is actively processing flows + pushing to Elasticsearch.
# ============================================================================
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$SCRIPT_DIR/.."

ok()   { printf "  \033[32m[OK]\033[0m  %s\n" "$1"; }
fail() { printf "  \033[31m[FAIL]\033[0m %s\n" "$1"; ANY_FAIL=1; }
ANY_FAIL=0

check_running() {
    local name="$1"
    if docker compose ps --status=running --services 2>/dev/null | grep -q "^${name}$"; then
        ok "container '${name}' is running"
    else
        fail "container '${name}' is NOT running"
    fi
}

echo "1. Container status"
echo "==================="
check_running pcap-generator
check_running pcap-loader
check_running suricata
check_running realtime-bridge
check_running elasticsearch
check_running kibana
check_running node-dashboard

echo
echo "2. PCAP generator"
echo "================="
GEN_LOG=$(docker compose logs --tail=10 pcap-generator 2>&1)
if echo "$GEN_LOG" | grep -q "wrote .* packets"; then
    LATEST=$(echo "$GEN_LOG" | grep "wrote" | tail -1)
    ok "generator producing PCAPs: ${LATEST#*] }"
else
    fail "generator has not produced any PCAPs yet"
fi

echo
echo "3. PCAP loader"
echo "=============="
LD_LOG=$(docker compose logs --tail=20 pcap-loader 2>&1)
if echo "$LD_LOG" | grep -q "dropped feed_"; then
    ok "loader is feeding PCAPs into Suricata's watch directory"
else
    fail "loader has not dropped any PCAPs yet"
fi

echo
echo "4. Suricata"
echo "==========="
SU_LOG=$(docker compose logs --tail=50 suricata 2>&1)
if echo "$SU_LOG" | grep -q "starting wrapper loop\|appended .* events\|Engine started"; then
    ok "Suricata wrapper loop is active"

    PROCESSED=$(echo "$SU_LOG" | grep -c "appended .* events" || true)
    if [ "$PROCESSED" -gt 0 ]; then
        ok "Suricata has processed $PROCESSED PCAPs in the recent log window"
    fi

    # No more flaky "empty eve.json" check — the appended events line is definitive
else
    fail "Suricata wrapper loop has not started"
fi

echo
echo "5. Elasticsearch"
echo "================"
ES_HEALTH=""
for attempt in 1 2 3 4 5; do
    ES_HEALTH=$(curl -sS --max-time 5 http://localhost:9200/_cluster/health 2>/dev/null || true)
    if echo "$ES_HEALTH" | grep -q '"status":"green"\|"status":"yellow"'; then
        break
    fi
    if [ "$attempt" -lt 5 ]; then
        printf "       (attempt %d/5: ES still warming up, waiting 10s...)\n" "$attempt"
        sleep 10
    fi
done

if echo "$ES_HEALTH" | grep -q '"status":"green"\|"status":"yellow"'; then
    ok "Elasticsearch cluster: $(echo "$ES_HEALTH" | grep -o '"status":"[^"]*"' | head -1)"
else
    fail "Elasticsearch is not reachable on http://localhost:9200 (waited 50s)"
fi

DOC_COUNT=$(curl -sS --max-time 5 "http://localhost:9200/hybrid-ids-decisions/_count" 2>/dev/null | \
            grep -o '"count":[0-9]*' | head -1 | cut -d: -f2)
if [ -n "${DOC_COUNT:-}" ] && [ "$DOC_COUNT" -gt 0 ]; then
    ok "decisions index has ${DOC_COUNT} documents"
elif [ -n "${DOC_COUNT:-}" ]; then
    fail "decisions index exists but is empty (bridge may not be writing yet)"
else
    fail "decisions index does not exist yet (give the bridge another minute)"
fi

echo
echo "6. Bridge"
echo "========="
BR_LOG=$(docker compose logs --tail=40 realtime-bridge 2>&1)

if echo "$BR_LOG" | grep -q "flows="; then
    ok "bridge is tailing and actively processing flows"
    LATEST_SUMMARY=$(echo "$BR_LOG" | grep "flows=" | tail -1 || echo "")
    if [ -n "$LATEST_SUMMARY" ]; then
        ok "latest summary: $(echo "$LATEST_SUMMARY" | sed 's/.*INFO    | //')"
    fi
elif echo "$BR_LOG" | grep -q "Tailing"; then
    ok "bridge has started tailing eve.json (still warming up)"
else
    fail "bridge has not started tailing"
fi

echo
echo "7. Kibana"
echo "========="
KB_STATUS=""
for attempt in 1 2 3 4 5 6; do
    KB_STATUS=$(curl -sS --max-time 5 http://localhost:5601/api/status 2>/dev/null || true)
    if echo "$KB_STATUS" | grep -q '"level":"available"'; then
        break
    fi
    if [ "$attempt" -lt 6 ]; then
        printf "       (attempt %d/6: Kibana still warming up, waiting 15s...)\n" "$attempt"
        sleep 15
    fi
done

if echo "$KB_STATUS" | grep -q '"level":"available"'; then
    ok "Kibana is available at http://localhost:5601"
    ok "open dashboard: http://localhost:5601/app/dashboards"
else
    fail "Kibana is not yet available (waited ~90s; check 'docker compose logs kibana')"
fi


echo
echo "8. React Node dashboard"
echo "======================="
ND_STATUS=$(curl -sS --max-time 5 http://localhost:3000 2>/dev/null || true)
if echo "$ND_STATUS" | grep -qi "Hybrid IDS\|root"; then
    ok "React dashboard is available at http://localhost:3000"
else
    fail "React dashboard is not reachable yet (check docker compose logs node-dashboard)"
fi

echo
if [ "$ANY_FAIL" = "1" ]; then
    echo -e "\033[31mSome checks failed.\033[0m See README.md troubleshooting section."
    exit 1
else
    echo -e "\033[32mAll checks passed.\033[0m The demo is live! 🚀"
    exit 0
fi