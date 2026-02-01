#!/bin/bash
# stop_vsock_proxy.sh - Stop vsock proxies

set -e

echo "Stopping vsock proxies..."

if [ ! -f .vsock_proxy_pids ]; then
    echo "No running proxies found (.vsock_proxy_pids not found)"
    exit 1
fi

source .vsock_proxy_pids

if [ -n "$MOLTBOT_PROXY_PID" ]; then
    if ps -p $MOLTBOT_PROXY_PID > /dev/null 2>&1; then
        echo "  Stopping MoltBot proxy (PID: $MOLTBOT_PROXY_PID)..."
        kill $MOLTBOT_PROXY_PID
        echo "  ✓ Stopped"
    else
        echo "  MoltBot proxy not running"
    fi
fi

if [ -n "$GUARDRAIL_PROXY_PID" ]; then
    if ps -p $GUARDRAIL_PROXY_PID > /dev/null 2>&1; then
        echo "  Stopping Guardrail proxy (PID: $GUARDRAIL_PROXY_PID)..."
        kill $GUARDRAIL_PROXY_PID
        echo "  ✓ Stopped"
    else
        echo "  Guardrail proxy not running"
    fi
fi

rm .vsock_proxy_pids

echo ""
echo "✓ All proxies stopped"
