#!/bin/bash
# boot_vsock.sh - Enclave boot script with vsock agent injection
#
# This script runs inside the Nitro Enclave and:
# 1. Starts the guardrail proxy
# 2. Receives MoltBot package from parent via vsock
# 3. Installs and configures MoltBot
# 4. Starts MoltBot gateway
#
# PCR2 includes this script, but NOT the MoltBot package!

set -e

echo "=========================================="
echo "  Guardrail + MoltBot Enclave Bootstrap"
echo "=========================================="
echo ""

# ============================================================================
# Step 0: Configure loopback interface
# ============================================================================

echo "[0/5] Configuring loopback interface..."

# Bring up loopback interface (required for localhost communication)
if ip link set lo up 2>&1; then
    echo "  ✓ Loopback interface configured"
else
    echo "  ⚠ WARNING: Failed to bring up loopback interface"
fi

# Verify it's actually up
if ip addr show lo 2>/dev/null | grep -q "inet 127.0.0.1"; then
    echo "  ✓ Loopback interface has IP address"
else
    echo "  ⚠ WARNING: Loopback interface may not have IP configured"
fi

echo ""

# ============================================================================
# Step 0.5: Remount /tmp with exec permissions
# ============================================================================

echo "[0.5/5] Remounting /tmp with exec permissions..."

# Try to remount /tmp without noexec (needed for loading native .node modules)
set +e  # Don't exit on error
if mount -o remount,exec /tmp 2>&1; then
    echo "  ✓ /tmp remounted with exec permissions"
    mount | grep " /tmp " | head -1
else
    echo "  ✗ FAILED: Cannot remount /tmp in enclave environment"
    echo "  This will cause native module loading to fail"
fi
set -e

echo ""

# ============================================================================
# Step 1: Configure network isolation (CRITICAL!)
# ============================================================================

echo "[1/5] Configuring network isolation..."

# Block all outbound network except localhost
# This prevents MoltBot from bypassing the guardrail proxy
# Note: iptables may fail in some enclave environments, but we continue anyway
set +e  # Don't exit on iptables failure
if iptables -A OUTPUT -o lo -j ACCEPT 2>/dev/null && \
   iptables -A OUTPUT -j DROP 2>/dev/null; then
    echo "  ✓ iptables configured successfully"
    IPTABLES_CONFIGURED=true
else
    echo "  ⚠ WARNING: iptables configuration failed"
    echo "    Network isolation cannot be enforced via iptables"
    echo "    Continuing anyway - network isolation will rely on enclave environment"
    IPTABLES_CONFIGURED=false
fi
set -e  # Re-enable exit on error

# Verify isolation (only if iptables worked)
if [ "$IPTABLES_CONFIGURED" = true ]; then
    echo "  Testing network isolation..."
    if timeout 2 curl -s https://api.openai.com > /dev/null 2>&1; then
        echo "  ERROR: Network isolation failed! Can reach external hosts."
        exit 1
    fi
    echo "  ✓ Network isolation verified"
else
    echo "  ⚠ Skipping network isolation test (iptables not configured)"
fi

echo ""

# ============================================================================
# Step 1.5: Start local HTTP proxy (for outbound internet access)
# ============================================================================

echo "[1.5/5] Starting local HTTP proxy..."
cd /guardrail

# Start local HTTP proxy that forwards to parent via vsock
# This allows the guardrail proxy to reach OpenAI API through the parent EC2
python3 local_http_proxy.py \
    --listen-port 8888 \
    --parent-cid 3 \
    --vsock-port 8001 &
LOCAL_PROXY_PID=$!

echo "  ✓ Local HTTP proxy started (PID: $LOCAL_PROXY_PID)"
echo "    Listening on localhost:8888"
echo "    Forwarding to parent CID 3 via vsock:8001"

echo ""

# ============================================================================
# Step 2: Start guardrail proxy
# ============================================================================

echo "[2/5] Starting guardrail proxy server..."
cd /guardrail

# Configure HTTP proxy for outbound requests
export HTTP_PROXY="http://localhost:8888"
export HTTPS_PROXY="http://localhost:8888"

# Start proxy in background
# Note: NeMo Guardrails will fail to initialize (no API key yet)
# This is expected - proxy will run in audit-only mode until first request
python3 proxy_server.py &
PROXY_PID=$!

# Wait for proxy to be ready
echo "  Waiting for proxy to be ready..."

# Give server a few seconds to start before checking
sleep 5

# Simple check - try both localhost and 127.0.0.1
for i in {1..10}; do
    # Try 127.0.0.1 first (more reliable in containers/enclaves)
    if curl -sf http://127.0.0.1:8080/health > /dev/null 2>&1; then
        echo "  ✓ Guardrail proxy is ready (PID: $PROXY_PID)"
        break
    fi

    if [ $i -eq 10 ]; then
        echo "  ERROR: Proxy health check failed after 15 seconds"
        echo "  Server appears to have started but health endpoint not responding"
        echo "  Trying one more manual check:"
        curl -v http://127.0.0.1:8080/health 2>&1 || true
        kill $PROXY_PID 2>/dev/null || true
        exit 1
    fi

    sleep 1
done

echo ""

# ============================================================================
# Step 2.5: Start attestation server
# ============================================================================

echo "[2.5/5] Starting attestation server..."

# Start attestation server in background (keep output visible for debugging)
python3 /guardrail/attestation_server.py &
ATTESTATION_PID=$!
echo "  Attestation server started (PID: $ATTESTATION_PID)"

# Wait for server to be ready
for i in {1..30}; do
    # Check if process is still alive
    if ! kill -0 $ATTESTATION_PID 2>/dev/null; then
        echo "  ERROR: Attestation server process died (PID: $ATTESTATION_PID)"
        echo "  Check output above for error messages"
        kill $PROXY_PID $LOCAL_PROXY_PID 2>/dev/null || true
        exit 1
    fi
    
    if curl -s http://localhost:8765/health > /dev/null 2>&1; then
        echo "  ✓ Attestation server is healthy"
        break
    fi
    
    if [ $i -eq 30 ]; then
        echo "  ERROR: Attestation server failed to respond after 30 seconds"
        echo "  Process is running but not responding to health checks"
        kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID 2>/dev/null || true
        exit 1
    fi
    
    sleep 1
done

echo ""

# ============================================================================
# Step 3: Receive MoltBot package via vsock
# ============================================================================

echo "[3/5] Receiving MoltBot package from parent instance..."
echo "  Waiting for injection... (no timeout, will wait indefinitely)"

# Run vsock receiver
# Note: This will BLOCK indefinitely until inject_moltbot.sh is run from parent
python3 /guardrail/vsock_receiver.py \
    --port 9000 \
    --output /tmp/moltbot.tgz \
    --metadata-output /tmp/agent_metadata.json

if [ ! -f /tmp/moltbot.tgz ]; then
    echo "  ERROR: Failed to receive MoltBot tarball"
    kill $PROXY_PID
    exit 1
fi

if [ ! -f /tmp/agent_metadata.json ]; then
    echo "  ERROR: Agent metadata not saved"
    kill $PROXY_PID
    exit 1
fi

# Display received metadata
echo ""
echo "  Received package metadata:"
cat /tmp/agent_metadata.json | jq '.'
echo ""

# ============================================================================
# Step 4: Install MoltBot
# ============================================================================

echo "[4/5] Installing MoltBot from received tarball..."

# Extract bundled tarball (contains node_modules with all dependencies)
echo "  Extracting bundled package..."
# Extract to /tmp (we attempted to remount with exec in step 0.5)
INSTALL_DIR="/tmp/node_modules"
mkdir -p "$INSTALL_DIR"
tar xzf /tmp/moltbot.tgz -C "$INSTALL_DIR"

# Find and create wrapper for clawdbot binary
CLAWDBOT_ENTRY=""
if [ -f "$INSTALL_DIR/clawdbot/dist/entry.js" ]; then
    CLAWDBOT_ENTRY="$INSTALL_DIR/clawdbot/dist/entry.js"
    echo "  ✓ Found binary: dist/entry.js"
elif [ -f "$INSTALL_DIR/clawdbot/bin/clawdbot.js" ]; then
    CLAWDBOT_ENTRY="$INSTALL_DIR/clawdbot/bin/clawdbot.js"
    echo "  ✓ Found binary: bin/clawdbot.js"
elif [ -f "$INSTALL_DIR/clawdbot/bin/index.js" ]; then
    CLAWDBOT_ENTRY="$INSTALL_DIR/clawdbot/bin/index.js"
    echo "  ✓ Found binary: bin/index.js"
else
    echo "  ERROR: Could not find clawdbot binary"
    echo "  Searched for:"
    echo "    - $INSTALL_DIR/clawdbot/dist/entry.js"
    echo "    - $INSTALL_DIR/clawdbot/bin/clawdbot.js"
    echo "    - $INSTALL_DIR/clawdbot/bin/index.js"
    kill $PROXY_PID
    exit 1
fi

# Create wrapper script (avoids /tmp execute permission issues)
cat > /usr/local/bin/clawdbot <<WRAPPER_EOF
#!/bin/bash
exec node "$CLAWDBOT_ENTRY" "\$@"
WRAPPER_EOF

chmod +x /usr/local/bin/clawdbot
echo "  ✓ Wrapper script created: /usr/local/bin/clawdbot"

# Verify installation
if ! command -v clawdbot &> /dev/null; then
    echo "  ERROR: MoltBot installation failed (clawdbot command not found)"
    kill $PROXY_PID
    exit 1
fi

INSTALLED_VERSION=$(clawdbot --version 2>/dev/null || echo "unknown")
echo "  ✓ MoltBot installed: $INSTALLED_VERSION"

# Set NODE_PATH so Node.js can find modules in /tmp/node_modules
export NODE_PATH="$INSTALL_DIR:$NODE_PATH"
echo "  ✓ NODE_PATH configured: $NODE_PATH"
echo ""

# ============================================================================
# Step 5: Configure and start MoltBot
# ============================================================================

echo "[5/5] Configuring MoltBot to use guardrail proxy..."

# Create MoltBot config directory
mkdir -p ~/.clawdbot

# Register attestation skill
echo "  Registering attestation skill..."
mkdir -p ~/.clawdbot/skills/attestation-skill
cp /attestation-skill/SKILL.md ~/.clawdbot/skills/attestation-skill/SKILL.md
echo "  ✓ Attestation skill registered at ~/.clawdbot/skills/attestation-skill/SKILL.md"

# Read API key from vsock-injected file
if [ -f /tmp/api_key ]; then
    API_KEY=$(cat /tmp/api_key)
    echo "  ✓ API key loaded from vsock injection"
else
    echo "  ⚠ No API key provided - using placeholder"
    API_KEY="sk-proj-dummy"
fi

# Read gateway token from vsock-injected file
if [ -f /tmp/gateway_token ]; then
    GATEWAY_TOKEN=$(cat /tmp/gateway_token)
    echo "  ✓ Gateway token loaded from vsock injection"
else
    echo "  ⚠ No gateway token provided - generating random token"
    GATEWAY_TOKEN=$(openssl rand -hex 32)
    echo "  Generated token: $GATEWAY_TOKEN"
fi

# Create config that routes all LLM calls through the guardrail proxy
# Note: Using correct config path: ~/.clawdbot/clawdbot.json
cat > ~/.clawdbot/clawdbot.json <<EOF
{
  "models": {
    "mode": "merge",
    "providers": {
      "guardrail-proxy-openai": {
        "baseUrl": "http://localhost:8080/v1/",
        "apiKey": "$API_KEY",
        "api": "openai-completions",
        "models": [
          {
            "id": "gpt-5.1",
            "name": "GPT-5.1 (via Guardrail)",
            "input": ["text"],
            "contextWindow": 128000,
            "maxTokens": 4096
          }
        ]
      }
    }
  },
  "agents": {
    "defaults": {
      "model": {
        "primary": "guardrail-proxy-openai/gpt-5.1"
      }
    }
  },
  "gateway": {
    "port": 18789,
    "mode": "local",
    "bind": "lan",
    "auth": {
      "mode": "token",
      "token": "$GATEWAY_TOKEN"
    }
  }
}
EOF

# Securely delete API key and gateway token files
rm -f /tmp/api_key /tmp/gateway_token

echo "  ✓ MoltBot configured:"
echo "    - Config: ~/.clawdbot/clawdbot.json"
echo "    - Proxy: http://localhost:8080/v1"
echo "    - All LLM calls will be routed through guardrail"
echo "    - API key and gateway token securely loaded and original files deleted"
echo ""

# ============================================================================
# Step 5.5: Start vsock-to-TCP bridge for gateway access
# ============================================================================

echo "[5.5/6] Starting vsock-to-TCP bridge..."

# Start bridge to forward vsock connections to gateway
python3 /guardrail/vsock_to_tcp_bridge.py \
    --vsock-port 18789 \
    --tcp-port 18789 \
    >/dev/null 2>&1 &

BRIDGE_PID=$!
echo "  ✓ Vsock-to-TCP bridge started (PID: $BRIDGE_PID)"
echo "    Vsock :18789 → TCP localhost:18789"

echo ""

# ============================================================================
# Final: Start MoltBot Gateway
# ============================================================================

echo "=========================================="
echo "  Starting MoltBot Gateway"
echo "=========================================="
echo ""

# Trap SIGTERM to cleanup
trap "echo 'Shutting down...'; kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID $BRIDGE_PID 2>/dev/null || true; exit 0" SIGTERM SIGINT

# Start MoltBot gateway (blocks)
# Gateway is configured in ~/.clawdbot/clawdbot.json (mode: "local", port: 18789)
# Use xvfb-run to provide virtual display for clipboard module
echo "Starting gateway with virtual display (xvfb)..."

# Try to start gateway, but run diagnostics on error
if ! xvfb-run -a clawdbot gateway; then
    echo ""
    echo "=========================================="
    echo "  ERROR: MoltBot Gateway Failed to Start"
    echo "=========================================="
    echo ""

    # Run automatic diagnostics
    echo "Running diagnostics..."
    echo ""

    echo "0. Checking /tmp mount flags:"
    mount | grep " /tmp " || mount | grep "tmpfs"
    echo ""

    echo "1. Checking installed X11 libraries:"
    dpkg -l | grep -E 'libx11|libxcb|libxext|xvfb' || echo "   No X11 libraries found"
    echo ""

    echo "2. Checking clipboard native module:"
    CLIPBOARD_NODE="/tmp/node_modules/@mariozechner/clipboard-linux-x64-gnu/clipboard.linux-x64-gnu.node"
    if [ -f "$CLIPBOARD_NODE" ]; then
        echo "   File info:"
        ls -lh "$CLIPBOARD_NODE"
        echo "   Dependencies:"
        ldd "$CLIPBOARD_NODE" 2>&1 | head -20
    else
        echo "   Native module not found at expected location: $CLIPBOARD_NODE"
        echo "   Searching for .node files:"
        find /tmp/node_modules -name "*.node" 2>/dev/null | head -10 || echo "   No .node files found"
    fi
    echo ""

    echo "3. Checking DISPLAY variable:"
    xvfb-run -a env | grep DISPLAY || echo "   DISPLAY not set"
    echo ""

    echo "4. Checking clawdbot version:"
    clawdbot --version 2>&1 || echo "   Failed to get version"
    echo ""

    echo "=========================================="
    echo "  Diagnostics complete. Keeping enclave alive..."
    echo "  Background services still running:"
    echo "    - Guardrail proxy (PID: $PROXY_PID)"
    echo "    - Local HTTP proxy (PID: $LOCAL_PROXY_PID)"
    echo "=========================================="

    # Sleep forever to keep enclave running
    tail -f /dev/null
fi

# If MoltBot exits normally, cleanup
echo "MoltBot gateway exited"
kill $PROXY_PID $LOCAL_PROXY_PID $BRIDGE_PID 2>/dev/null || true
exit 0
