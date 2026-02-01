#!/bin/bash

# ============================================================================
# Stop Test Services
# ============================================================================

echo "Stopping test services..."

# Stop MoltBot gateway
pkill -f "clawdbot gateway"

# Stop guardrail proxy
pkill -f "proxy_server.py"

echo "✓ Services stopped"
