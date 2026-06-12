#!/bin/sh
# ============================================================================
# Wait for Kibana to be ready, then import the saved-objects dashboard.
# This script runs once and exits.
# ============================================================================
set -e

KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
DASHBOARD_FILE="/dashboard/dashboard.ndjson"

echo "[kibana-setup] Waiting for Kibana at $KIBANA_URL ..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$ATTEMPT" -gt 60 ]; then
        echo "[kibana-setup] Kibana did not become ready in 5 minutes. Aborting."
        exit 1
    fi
    if curl -fsS "$KIBANA_URL/api/status" >/dev/null 2>&1; then
        STATE=$(curl -fsS "$KIBANA_URL/api/status" | grep -o '"level":"[^"]*"' | head -1 || echo "")
        if echo "$STATE" | grep -q "available"; then
            echo "[kibana-setup] Kibana is ready (attempt $ATTEMPT)"
            break
        fi
    fi
    sleep 5
done

# Give Kibana a few extra seconds to fully initialise the saved-objects API.
sleep 5

echo "[kibana-setup] Importing dashboard from $DASHBOARD_FILE"
RESPONSE=$(curl -sS -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form "file=@$DASHBOARD_FILE" || echo "ERROR")

echo "[kibana-setup] Import response:"
echo "$RESPONSE" | head -c 2000
echo

if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "[kibana-setup] Dashboard imported successfully"
    echo "[kibana-setup] Open http://localhost:5601/app/dashboards"
elif echo "$RESPONSE" | grep -q '"successCount"'; then
    echo "[kibana-setup] Import completed (some objects may have been skipped)"
else
    echo "[kibana-setup] WARNING: import may have failed. Check the response above."
fi

# Set the dashboard as the default landing page
echo "[kibana-setup] Setting default index pattern"
curl -sS -X POST "$KIBANA_URL/api/kibana/settings" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{"changes":{"defaultIndex":"hybrid-ids-decisions-pattern"}}' \
    || true
echo

echo "[kibana-setup] Done."
