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
        echo "  Stopping OpenClaw proxy (PID: $OPENCLAW_PROXY_PID)..."
        kill "$OPENCLAW_PROXY_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
    else
        echo "  OpenClaw proxy not running"
    fi

    if [ -n "$GUARDRAIL_PROXY_PID" ] && ps -p "$GUARDRAIL_PROXY_PID" > /dev/null 2>&1; then
        echo "  Stopping Guardrail proxy (PID: $GUARDRAIL_PROXY_PID)..."
        kill "$GUARDRAIL_PROXY_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
    fi

    if [ -n "$EXPERIMENT_PROXY_PID" ] && ps -p "$EXPERIMENT_PROXY_PID" > /dev/null 2>&1; then
        echo "  Stopping Experiment proxy (PID: $EXPERIMENT_PROXY_PID)..."
        kill "$EXPERIMENT_PROXY_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
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

# Try PID file first
if [ -f ".http_forwarder_pid" ]; then
    HTTP_FORWARDER_PID=$(cat .http_forwarder_pid)
    if ps -p "$HTTP_FORWARDER_PID" > /dev/null 2>&1; then
        echo "  Stopping HTTP forwarder (PID: $HTTP_FORWARDER_PID)..."
        kill "$HTTP_FORWARDER_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
    else
        echo "  HTTP forwarder not running (stale PID)"
    fi
    rm -f .http_forwarder_pid
else
    # Fallback: kill by process name
    HTTP_FORWARDER_PIDS=$(pgrep -f vsock_http_forwarder || true)
    if [ -n "$HTTP_FORWARDER_PIDS" ]; then
        echo "  Stopping HTTP forwarder processes: $HTTP_FORWARDER_PIDS"
        pkill -f vsock_http_forwarder || true
        echo "  ✓ Stopped"
    else
        echo "  HTTP forwarder not running"
    fi
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
