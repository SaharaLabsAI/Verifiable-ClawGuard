#!/bin/bash
# ec2_cleanup.sh - Stop all EC2 parent instance services
#
# This script stops all services started by ec2_setup.sh:
# 1. HTTP forwarder
# 2. Vsock proxies (OpenClaw gateway, optional guardrail/experiment proxies)
# 3. Nitro enclave
#
# Usage:
#   ./ec2_cleanup.sh

set -e

TARGET_ENCLAVE_CID=""

stop_pid_tree() {
    local root_pid="$1"

    if [ -z "$root_pid" ] || ! ps -p "$root_pid" > /dev/null 2>&1; then
        return 0
    fi

    local child_pid
    for child_pid in $(pgrep -P "$root_pid" 2>/dev/null || true); do
        stop_pid_tree "$child_pid"
    done

    kill "$root_pid" 2>/dev/null || true
    sleep 0.2
    if ps -p "$root_pid" > /dev/null 2>&1; then
        kill -9 "$root_pid" 2>/dev/null || true
    fi
}

wait_for_pid_exit() {
    local pid="$1"
    local attempts="${2:-15}"
    local delay="${3:-0.2}"
    local i

    for ((i=0; i<attempts; i++)); do
        if ! ps -p "$pid" > /dev/null 2>&1; then
            return 0
        fi
        sleep "$delay"
    done

    return 1
}

stop_pid_verified() {
    local pid="$1"
    local label="$2"

    if [ -z "$pid" ] || ! ps -p "$pid" > /dev/null 2>&1; then
        echo "  $label not running"
        return 0
    fi

    echo "  Stopping $label (PID: $pid)..."
    kill "$pid" 2>/dev/null || true

    if wait_for_pid_exit "$pid"; then
        echo "  ✓ Stopped"
        return 0
    fi

    echo "  Escalating $label to SIGKILL (PID: $pid)..."
    kill -9 "$pid" 2>/dev/null || true

    if wait_for_pid_exit "$pid" 10 0.1; then
        echo "  ✓ Stopped"
        return 0
    fi

    echo "  ✗ Failed to stop $label (PID: $pid)"
    return 1
}

echo "============================================================"
echo "  Cleaning up EC2 Parent Instance Services"
echo "============================================================"
echo ""

# ============================================================================
# Stop Vsock Proxies
# ============================================================================

if [ -f ".vsock_proxy_pids" ]; then
    echo "[1/3] Stopping vsock proxies..."

    source .vsock_proxy_pids
    TARGET_ENCLAVE_CID="${ENCLAVE_CID:-}"

    # Backward compatibility: older PID files used MOLTBOT_PROXY_PID
    OPENCLAW_PROXY_PID="${OPENCLAW_PROXY_PID:-${MOLTBOT_PROXY_PID:-}}"

    if [ -n "$OPENCLAW_PROXY_PID" ] && ps -p "$OPENCLAW_PROXY_PID" > /dev/null 2>&1; then
        stop_pid_verified "$OPENCLAW_PROXY_PID" "OpenClaw proxy"
    else
        echo "  OpenClaw proxy not running"
    fi

    if [ -n "$GUARDRAIL_PROXY_PID" ] && ps -p "$GUARDRAIL_PROXY_PID" > /dev/null 2>&1; then
        stop_pid_verified "$GUARDRAIL_PROXY_PID" "Guardrail proxy"
    fi

    if [ -n "$EXPERIMENT_PROXY_PID" ] && ps -p "$EXPERIMENT_PROXY_PID" > /dev/null 2>&1; then
        stop_pid_verified "$EXPERIMENT_PROXY_PID" "Experiment proxy"
    fi

    rm -f .vsock_proxy_pids
    echo ""
else
    echo "[1/3] Vsock proxies: No PID file found"
    echo ""
fi

# ============================================================================
# Stop HTTP Forwarder
# ============================================================================

echo "[2/3] Stopping HTTP forwarder..."

HTTP_FORWARDER_STOP_ATTEMPTED=false

# Try PID file first
if [ -f ".http_forwarder_pid" ]; then
    HTTP_FORWARDER_PID=$(cat .http_forwarder_pid)
    if ps -p "$HTTP_FORWARDER_PID" > /dev/null 2>&1; then
        echo "  Stopping HTTP forwarder process tree (PID: $HTTP_FORWARDER_PID)..."
        HTTP_FORWARDER_STOP_ATTEMPTED=true
        stop_pid_tree "$HTTP_FORWARDER_PID"
        echo "  ✓ Stopped"
    else
        echo "  HTTP forwarder not running (stale PID)"
    fi
    rm -f .http_forwarder_pid
fi

# Sweep any leftover forwarder processes (python child and/or wrapper shell)
HTTP_FORWARDER_PIDS=$(pgrep -f '[v]sock_http_forwarder\.py|[s]tart_http_forwarder\.sh|[v]sock_http_forwarder' || true)
if [ -n "$HTTP_FORWARDER_PIDS" ]; then
    echo "  Stopping leftover HTTP forwarder processes: $HTTP_FORWARDER_PIDS"
    HTTP_FORWARDER_STOP_ATTEMPTED=true
    pkill -TERM -f '[v]sock_http_forwarder\.py' 2>/dev/null || true
    pkill -TERM -f '[s]tart_http_forwarder\.sh' 2>/dev/null || true
    sleep 1

    REMAINING_FORWARDER_PIDS=$(pgrep -f '[v]sock_http_forwarder\.py|[s]tart_http_forwarder\.sh|[v]sock_http_forwarder' || true)
    if [ -n "$REMAINING_FORWARDER_PIDS" ]; then
        echo "  Escalating leftover forwarder processes to SIGKILL: $REMAINING_FORWARDER_PIDS"
        pkill -KILL -f '[v]sock_http_forwarder\.py' 2>/dev/null || true
        pkill -KILL -f '[s]tart_http_forwarder\.sh' 2>/dev/null || true
        sleep 0.5
    fi

    FINAL_FORWARDER_PIDS=$(pgrep -f '[v]sock_http_forwarder\.py|[s]tart_http_forwarder\.sh|[v]sock_http_forwarder' || true)
    if [ -n "$FINAL_FORWARDER_PIDS" ]; then
        echo "  ✗ Failed to stop HTTP forwarder processes: $FINAL_FORWARDER_PIDS"
    else
        echo "  ✓ Stopped"
    fi
elif [ "$HTTP_FORWARDER_STOP_ATTEMPTED" = false ]; then
    echo "  HTTP forwarder not running"
fi

echo ""

# ============================================================================
# Terminate Enclave
# ============================================================================

echo "[3/3] Terminating enclave..."

if ! command -v nitro-cli > /dev/null 2>&1; then
    echo "  nitro-cli not found; skipping enclave termination"
    echo ""
else
    TARGET_ENCLAVE_ID=""

    if [ -n "$TARGET_ENCLAVE_CID" ]; then
        TARGET_ENCLAVE_ID=$(nitro-cli describe-enclaves 2>/dev/null | jq -r --arg cid "$TARGET_ENCLAVE_CID" '.[] | select((.EnclaveCID|tostring) == $cid) | .EnclaveID' | head -n 1)
    fi

    if [ -z "$TARGET_ENCLAVE_ID" ]; then
        RUNNING_ENCLAVE_IDS=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[] | select(.State == "RUNNING") | .EnclaveID')
        RUNNING_COUNT=$(echo "$RUNNING_ENCLAVE_IDS" | sed '/^$/d' | wc -l | tr -d ' ')

        if [ "$RUNNING_COUNT" = "1" ]; then
            TARGET_ENCLAVE_ID="$RUNNING_ENCLAVE_IDS"
        elif [ "$RUNNING_COUNT" -gt 1 ]; then
            echo "  Multiple running enclaves found; skipping automatic termination"
            echo "  Terminate manually with: nitro-cli terminate-enclave --enclave-id <id>"
            echo ""
        fi
    fi

    if [ -n "$TARGET_ENCLAVE_ID" ]; then
        echo "  Terminating enclave (ID: $TARGET_ENCLAVE_ID)..."
        nitro-cli terminate-enclave --enclave-id "$TARGET_ENCLAVE_ID" > /dev/null
        echo "  ✓ Enclave terminated"
        echo ""
    elif [ -z "$TARGET_ENCLAVE_CID" ]; then
        echo "  No running enclave found"
        echo ""
    fi
fi

# ============================================================================
# Summary
# ============================================================================

echo "============================================================"
echo " ✓ Cleanup Complete!"
echo "============================================================"
echo ""
echo "All services stopped."
echo ""
echo "To restart:"
echo "  ./ec2_setup.sh --api-key <key>"
echo ""
