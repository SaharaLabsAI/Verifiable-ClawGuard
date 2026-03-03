#!/bin/bash
# start_vsock_proxy.sh - Start vsock proxies for enclave services
#
# This script runs on the PARENT EC2 INSTANCE to expose enclave services:
# 1. MoltBot WebSocket gateway (port 18789)
# 2. Guardrail proxy (port 8080) - optional, for debugging
# 3. Latency experiment server (port 8770) - optional
#
# Usage:
#   ./start_vsock_proxy.sh [enclave-cid]
#
# Example:
#   ./start_vsock_proxy.sh 16

set -e

ENCLAVE_CID="${1:-16}"

echo "=========================================="
echo "  Starting Vsock Proxies"
echo "=========================================="
echo ""
echo "Enclave CID: $ENCLAVE_CID"
echo ""

# Verify enclave is running
if ! nitro-cli describe-enclaves | jq -e ".[] | select(.EnclaveCID == $ENCLAVE_CID)" > /dev/null 2>&1; then
    echo "ERROR: No enclave found with CID $ENCLAVE_CID"
    echo ""
    echo "Available enclaves:"
    nitro-cli describe-enclaves | jq -r '.[] | "  CID \(.EnclaveCID): \(.State)"'
    exit 1
fi

echo "✓ Enclave CID $ENCLAVE_CID is running"
echo ""

# Check if vsock_proxy.py exists
if [ ! -f "vsock_proxy.py" ]; then
    echo "ERROR: vsock_proxy.py not found"
    echo "Make sure you're in the src directory"
    exit 1
fi

chmod +x vsock_proxy.py

# Create log directory
mkdir -p logs

echo "Starting proxies..."
echo ""

# Start MoltBot WebSocket proxy
echo "[1/3] Starting MoltBot WebSocket proxy..."
echo "  Local:  ws://127.0.0.1:18789"
echo "  Enclave: CID $ENCLAVE_CID:18789"

nohup python3 vsock_proxy.py \
    --tcp-host 0.0.0.0 \
    --tcp-port 18789 \
    --vsock-cid $ENCLAVE_CID \
    --vsock-port 18789 \
    > logs/moltbot_proxy.log 2>&1 &

MOLTBOT_PROXY_PID=$!
echo "  PID: $MOLTBOT_PROXY_PID"
sleep 2

if ! ps -p $MOLTBOT_PROXY_PID > /dev/null 2>&1; then
    echo "  ✗ Failed to start MoltBot proxy"
    echo "  Check logs/moltbot_proxy.log for errors"
    exit 1
fi

echo "  ✓ MoltBot proxy started"
echo ""

# Optionally start guardrail proxy (for debugging)
START_GUARDRAIL_PROXY="${START_GUARDRAIL_PROXY:-false}"

if [ "$START_GUARDRAIL_PROXY" = "true" ]; then
    echo "[2/3] Starting Guardrail proxy (debug mode)..."
    echo "  Local:  http://127.0.0.1:8080"
    echo "  Enclave: CID $ENCLAVE_CID:8080"

    nohup python3 vsock_proxy.py \
        --tcp-host 127.0.0.1 \
        --tcp-port 8080 \
        --vsock-cid $ENCLAVE_CID \
        --vsock-port 8080 \
        > logs/guardrail_proxy.log 2>&1 &

    GUARDRAIL_PROXY_PID=$!
    echo "  PID: $GUARDRAIL_PROXY_PID"
    sleep 2

    if ! ps -p $GUARDRAIL_PROXY_PID > /dev/null 2>&1; then
        echo "  ✗ Failed to start Guardrail proxy"
        echo "  Check logs/guardrail_proxy.log for errors"
        kill $MOLTBOT_PROXY_PID 2>/dev/null || true
        exit 1
    fi

    echo "  ✓ Guardrail proxy started"
else
    echo "[2/3] Guardrail proxy: Skipped (set START_GUARDRAIL_PROXY=true to enable)"
fi

# Optionally start latency experiment proxy
START_EXPERIMENT_PROXY="${START_EXPERIMENT_PROXY:-false}"
EXPERIMENT_PROXY_BIND="${EXPERIMENT_PROXY_BIND:-127.0.0.1}"

if [ "$START_EXPERIMENT_PROXY" = "true" ]; then
    echo "[3/3] Starting Latency Experiment proxy..."
    echo "  Local:  http://$EXPERIMENT_PROXY_BIND:8770"
    echo "  Enclave: CID $ENCLAVE_CID:8770"

    nohup python3 vsock_proxy.py \
        --tcp-host $EXPERIMENT_PROXY_BIND \
        --tcp-port 8770 \
        --vsock-cid $ENCLAVE_CID \
        --vsock-port 8770 \
        > logs/experiment_proxy.log 2>&1 &

    EXPERIMENT_PROXY_PID=$!
    echo "  PID: $EXPERIMENT_PROXY_PID"
    sleep 2

    if ! ps -p $EXPERIMENT_PROXY_PID > /dev/null 2>&1; then
        echo "  ✗ Failed to start Latency Experiment proxy"
        echo "  Check logs/experiment_proxy.log for errors"
        kill $MOLTBOT_PROXY_PID ${GUARDRAIL_PROXY_PID:-} 2>/dev/null || true
        exit 1
    fi

    echo "  ✓ Latency Experiment proxy started"
else
    echo "[3/3] Latency Experiment proxy: Skipped (set START_EXPERIMENT_PROXY=true to enable)"
fi

echo ""

# Save PIDs for later cleanup
cat > .vsock_proxy_pids <<EOF
MOLTBOT_PROXY_PID=$MOLTBOT_PROXY_PID
GUARDRAIL_PROXY_PID=${GUARDRAIL_PROXY_PID:-}
EXPERIMENT_PROXY_PID=${EXPERIMENT_PROXY_PID:-}
ENCLAVE_CID=$ENCLAVE_CID
EOF

echo "=========================================="
echo "  ✓ Proxies Started"
echo "=========================================="
echo ""
echo "MoltBot WebSocket gateway:"
echo "  ws://$(curl -s ifconfig.me):18789"
echo "  or ws://127.0.0.1:18789 (if on EC2)"
echo ""

if [ "$START_GUARDRAIL_PROXY" = "true" ]; then
    echo "Guardrail proxy (debug):"
    echo "  http://127.0.0.1:8080"
    echo ""
fi

if [ "$START_EXPERIMENT_PROXY" = "true" ]; then
    echo "Latency experiment API:"
    echo "  http://$EXPERIMENT_PROXY_BIND:8770/experiment/latency"
    echo ""
fi
