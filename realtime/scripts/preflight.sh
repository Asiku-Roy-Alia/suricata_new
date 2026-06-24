#!/usr/bin/env bash
# ============================================================================
# Pre-flight check before starting the realtime stack.
# Run this once before `docker compose up -d`.
#
# Verifies kernel parameters required by Elasticsearch and prints
# guidance if any are missing.
# ============================================================================
set -u

ok()   { printf "  \033[32m[OK]\033[0m  %s\n" "$1"; }
warn() { printf "  \033[33m[WARN]\033[0m %s\n" "$1"; }
fail() { printf "  \033[31m[FAIL]\033[0m %s\n" "$1"; ANY_FAIL=1; }
ANY_FAIL=0

echo "Pre-flight check for hybrid IDS realtime stack"
echo "==============================================="
echo

echo "1. Docker availability"
echo "----------------------"
if command -v docker >/dev/null 2>&1; then
    DOCKER_VER=$(docker --version 2>&1 | head -1)
    ok "Docker installed: $DOCKER_VER"
else
    fail "Docker is not installed or not on PATH"
fi

if docker compose version >/dev/null 2>&1; then
    COMPOSE_VER=$(docker compose version 2>&1 | head -1)
    ok "Docker Compose v2 available: $COMPOSE_VER"
else
    fail "Docker Compose v2 is not available. Install Docker Desktop or 'docker-compose-plugin'."
fi

echo
echo "2. Kernel parameters (required by Elasticsearch)"
echo "-------------------------------------------------"
# On Linux, sysctl reads kernel parameters directly. On Windows Git Bash
# the host kernel is invisible to us; what matters is the WSL2 kernel
# that Docker Desktop uses, which has its own settings. We detect the
# environment and emit appropriate guidance.
case "$(uname -s)" in
    Linux*)
        CURRENT_MMC=$(sysctl -n vm.max_map_count 2>/dev/null || echo "0")
        if [ "$CURRENT_MMC" -ge 1048576 ]; then
            ok "vm.max_map_count = $CURRENT_MMC (OK, must be >= 1048576)"
        else
            warn "vm.max_map_count = $CURRENT_MMC (Elasticsearch needs >= 1048576)"
            echo "       To fix temporarily for this boot:"
            echo "         sudo sysctl -w vm.max_map_count=1048576"
            echo "       To make permanent, add this line to /etc/sysctl.conf:"
            echo "         vm.max_map_count=1048576"
            echo "       Then run: sudo sysctl -p"
            ANY_FAIL=1
        fi
        ;;
    MINGW*|MSYS*|CYGWIN*)
        warn "Cannot check vm.max_map_count from Git Bash on Windows."
        echo "       Docker Desktop on Windows uses WSL2 internally, which has"
        echo "       its own kernel parameters. If Elasticsearch fails to start,"
        echo "       run this in PowerShell as Administrator:"
        echo "         wsl -d docker-desktop -- sysctl -w vm.max_map_count=1048576"
        echo "       Or if you have your own Ubuntu WSL distro:"
        echo "         wsl -d Ubuntu -- sudo sysctl -w vm.max_map_count=1048576"
        echo "       Most modern Docker Desktop installs set this automatically."
        echo "       Skip this warning and try docker compose up; if Elasticsearch"
        echo "       complains, then come back and run the command above."
        ;;
    *)
        warn "Unknown OS '$(uname -s)'. Skipping vm.max_map_count check."
        ;;
esac

echo
echo "3. Memory available to Docker"
echo "-----------------------------"
if [ -r /proc/meminfo ]; then
    MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
    MEM_GB=$((MEM_KB / 1024 / 1024))
    if [ "$MEM_GB" -ge 8 ]; then
        ok "Total memory: ${MEM_GB} GB (>= 8 GB recommended)"
    else
        warn "Total memory: ${MEM_GB} GB (Elasticsearch + Kibana need at least 8 GB)"
        echo "       On Windows WSL2, edit %USERPROFILE%\\.wslconfig:"
        echo "         [wsl2]"
        echo "         memory=8GB"
        echo "       Then run from PowerShell: wsl --shutdown"
    fi
fi

echo
echo "4. Trained model artifacts"
echo "--------------------------"
HYBRID_DIR="$(dirname $(realpath $0))/../../hybrid-ids/artifacts"
PIPELINE="$HYBRID_DIR/feature_pipeline.joblib"
MODEL="$HYBRID_DIR/hybrid.joblib"

if [ -f "$PIPELINE" ]; then
    SIZE=$(du -h "$PIPELINE" | cut -f1)
    ok "feature_pipeline.joblib found ($SIZE) at $PIPELINE"
else
    fail "feature_pipeline.joblib NOT FOUND at $PIPELINE"
    echo "       Run the main hybrid-ids pipeline first to produce it:"
    echo "         cd ../hybrid-ids && python scripts/02_preprocess.py"
fi

if [ -f "$MODEL" ]; then
    SIZE=$(du -h "$MODEL" | cut -f1)
    ok "hybrid.joblib found ($SIZE) at $MODEL"
else
    fail "hybrid.joblib NOT FOUND at $MODEL"
    echo "       Run the main hybrid-ids pipeline first to produce it:"
    echo "         cd ../hybrid-ids && python scripts/03_train_models.py"
fi

echo
echo "5. Port availability"
echo "--------------------"
# Different OSes have different ways to check listening ports.
for PORT in 9200 5601 3000; do
    IN_USE=""
    if command -v ss >/dev/null 2>&1; then
        if ss -tln 2>/dev/null | grep -q ":${PORT} "; then
            IN_USE=1
        fi
    elif command -v netstat >/dev/null 2>&1; then
        if netstat -an 2>/dev/null | grep -E "LISTEN|LISTENING" | grep -q ":${PORT}\b"; then
            IN_USE=1
        fi
    fi
    if [ -n "$IN_USE" ]; then
        warn "port $PORT may already be in use (will conflict with the stack)"
    else
        ok "port $PORT appears free"
    fi
done

echo
if [ "$ANY_FAIL" = "1" ]; then
    echo -e "\033[31mPre-flight check FAILED.\033[0m Address the issues above before starting."
    echo "Once fixed, re-run this script. When all checks pass, run:"
    echo "  docker compose up -d"
    exit 1
else
    echo -e "\033[32mPre-flight check PASSED.\033[0m You can now start the stack:"
    echo "  docker compose up -d"
    echo "After about 90 seconds, run scripts/healthcheck.sh to verify all services."
    exit 0
fi
