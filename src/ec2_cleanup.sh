#!/bin/bash
# ec2_cleanup.sh - Stop all EC2 parent instance services
#
# This script stops all services started by ec2_setup.sh:
# 1. HTTP forwarder
# 2. Vsock proxies (MoltBot gateway, optional guardrail proxy)
#
# Usage:
#   ./ec2_cleanup.sh

set -e

echo "============================================================"
echo "  Cleaning up EC2 Parent Instance Services"
echo "============================================================"
echo ""

# ============================================================================
# Stop Vsock Proxies
# ============================================================================

if [ -f ".vsock_proxy_pids" ]; then
    echo "[1/2] Stopping vsock proxies..."

    source .vsock_proxy_pids

    if [ -n "$MOLTBOT_PROXY_PID" ] && ps -p "$MOLTBOT_PROXY_PID" > /dev/null 2>&1; then
        echo "  Stopping MoltBot proxy (PID: $MOLTBOT_PROXY_PID)..."
        kill "$MOLTBOT_PROXY_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
    else
        echo "  MoltBot proxy not running"
    fi

    if [ -n "$GUARDRAIL_PROXY_PID" ] && ps -p "$GUARDRAIL_PROXY_PID" > /dev/null 2>&1; then
        echo "  Stopping Guardrail proxy (PID: $GUARDRAIL_PROXY_PID)..."
        kill "$GUARDRAIL_PROXY_PID" 2>/dev/null || true
        echo "  ✓ Stopped"
    fi

    rm -f .vsock_proxy_pids
    echo ""
else
    echo "[1/2] Vsock proxies: No PID file found"
    echo ""
fi

# ============================================================================
# Stop HTTP Forwarder
# ============================================================================

echo "[2/2] Stopping HTTP forwarder..."

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
