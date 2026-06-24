#!/bin/sh
# ============================================================================
# Hybrid IDS Kibana Setup
#
# 1. Waits for Elasticsearch to be healthy.
# 2. Creates an index template with explicit keyword mappings so that
#    Kibana visualizations can run terms aggregations on string fields.
# 3. Waits for Kibana to be fully available.
# 4. Imports the saved-objects dashboard via the Kibana API.
# 5. Sets the default index pattern.
#
# Without step 2, ES auto-maps string fields as "text" type. Terms
# aggregations require "keyword" type, so every Kibana panel that
# groups by verdict, src_ip, or suricata_signature would fail silently.
# ============================================================================
set -e

ES_URL="${ES_URL:-http://elasticsearch:9200}"
KIBANA_URL="${KIBANA_URL:-http://kibana:5601}"
DASHBOARD_FILE="/dashboard/dashboard.ndjson"

# -------------------------------------------------------------------
# Step 1: Wait for Elasticsearch
# -------------------------------------------------------------------
echo "[setup] Waiting for Elasticsearch at $ES_URL ..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$ATTEMPT" -gt 40 ]; then
        echo "[setup] ERROR: Elasticsearch did not become ready in 200s."
        exit 1
    fi
    HEALTH=$(curl -sS --max-time 5 "$ES_URL/_cluster/health" 2>/dev/null || echo "")
    if echo "$HEALTH" | grep -q '"status":"green"\|"status":"yellow"'; then
        echo "[setup] Elasticsearch is healthy (attempt $ATTEMPT)"
        break
    fi
    sleep 5
done

# -------------------------------------------------------------------
# Step 2: Create index template with explicit field mappings
#
# This ensures that string fields the Kibana visualizations aggregate
# on are mapped as "keyword" rather than the default "text".
# The template matches the index name "hybrid-ids-decisions" that the
# bridge writes to.
# -------------------------------------------------------------------
echo "[setup] Creating index template 'hybrid-ids-template' ..."

TEMPLATE='{
  "index_patterns": ["hybrid-ids-decisions*"],
  "priority": 100,
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "refresh_interval": "2s"
    },
    "mappings": {
      "properties": {
        "@timestamp":         { "type": "date" },
        "src_ip":             { "type": "keyword" },
        "dst_ip":             { "type": "keyword" },
        "dst_port":           { "type": "integer" },
        "proto":              { "type": "keyword" },
        "verdict":            { "type": "keyword" },
        "ml_proba":           { "type": "float" },
        "ml_decision":        { "type": "boolean" },
        "suricata_alert":     { "type": "boolean" },
        "suricata_signature": { "type": "keyword" },
        "fused_decision":     { "type": "boolean" },
        "fusion_reason":      { "type": "keyword" },
        "bytes_total":        { "type": "long" },
        "pkts_total":         { "type": "long" },
        "duration_ms":        { "type": "float" },
        "flow_id":            { "type": "keyword" }
      }
    }
  }
}'

TMPL_RESP=$(curl -sS -X PUT "$ES_URL/_index_template/hybrid-ids-template" \
    -H "Content-Type: application/json" \
    -d "$TEMPLATE" 2>&1 || echo "ERROR")

if echo "$TMPL_RESP" | grep -q '"acknowledged":true'; then
    echo "[setup] Index template created successfully"
else
    echo "[setup] WARNING: template creation response: $TMPL_RESP"
fi

# If the index already exists with wrong mappings, delete it so the
# bridge recreates it under the new template on next write.
EXISTING=$(curl -sS --max-time 5 "$ES_URL/hybrid-ids-decisions" 2>/dev/null || echo "")
if echo "$EXISTING" | grep -q '"hybrid-ids-decisions"'; then
    # Check whether verdict is already keyword
    MAPPING_TYPE=$(curl -sS "$ES_URL/hybrid-ids-decisions/_mapping" 2>/dev/null | \
                   grep -o '"verdict":{[^}]*}' | head -1 || echo "")
    if echo "$MAPPING_TYPE" | grep -q '"text"'; then
        echo "[setup] Existing index has 'text' mappings. Deleting so it recreates with keyword."
        curl -sS -X DELETE "$ES_URL/hybrid-ids-decisions" > /dev/null 2>&1 || true
    else
        echo "[setup] Existing index already has correct mappings. Keeping data."
    fi
fi

# -------------------------------------------------------------------
# Step 3: Wait for Kibana
# -------------------------------------------------------------------
echo "[setup] Waiting for Kibana at $KIBANA_URL ..."
ATTEMPT=0
while true; do
    ATTEMPT=$((ATTEMPT + 1))
    if [ "$ATTEMPT" -gt 60 ]; then
        echo "[setup] ERROR: Kibana did not become ready in 5 minutes."
        exit 1
    fi
    if curl -fsS "$KIBANA_URL/api/status" >/dev/null 2>&1; then
        STATE=$(curl -fsS "$KIBANA_URL/api/status" | grep -o '"level":"[^"]*"' | head -1 || echo "")
        if echo "$STATE" | grep -q "available"; then
            echo "[setup] Kibana is ready (attempt $ATTEMPT)"
            break
        fi
    fi
    sleep 5
done

# Extra buffer for Kibana's saved-objects API to initialise.
sleep 8

# -------------------------------------------------------------------
# Step 4: Import the dashboard
# -------------------------------------------------------------------
echo "[setup] Importing dashboard from $DASHBOARD_FILE ..."
RESPONSE=$(curl -sS -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
    -H "kbn-xsrf: true" \
    --form "file=@$DASHBOARD_FILE" 2>&1 || echo "ERROR")

echo "[setup] Import response (first 2000 chars):"
echo "$RESPONSE" | head -c 2000
echo

if echo "$RESPONSE" | grep -q '"success":true'; then
    echo "[setup] Dashboard imported successfully"
elif echo "$RESPONSE" | grep -q '"successCount"'; then
    echo "[setup] Import completed (some objects may have been skipped)"
else
    echo "[setup] WARNING: import may have failed. Retrying in 15s ..."
    sleep 15
    RESPONSE2=$(curl -sS -X POST "$KIBANA_URL/api/saved_objects/_import?overwrite=true" \
        -H "kbn-xsrf: true" \
        --form "file=@$DASHBOARD_FILE" 2>&1 || echo "ERROR")
    echo "$RESPONSE2" | head -c 1000
    echo
fi

# -------------------------------------------------------------------
# Step 5: Set the default index pattern
# -------------------------------------------------------------------
echo "[setup] Setting default index pattern ..."
curl -sS -X POST "$KIBANA_URL/api/kibana/settings" \
    -H "kbn-xsrf: true" \
    -H "Content-Type: application/json" \
    -d '{"changes":{"defaultIndex":"hybrid-ids-decisions-pattern"}}' \
    > /dev/null 2>&1 || true

echo
echo "[setup] Done. Open http://localhost:5601/app/dashboards"
