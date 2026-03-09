#!/bin/bash
# boot_vsock.sh - Enclave boot script with vsock agent injection
#
# This script runs inside the Nitro Enclave and:
# 1. Starts the guardrail proxy
# 2. Receives OpenClaw package from parent via vsock
# 3. Installs and configures OpenClaw
# 4. Starts OpenClaw gateway
#
# PCR2 includes this script, but NOT the OpenClaw package!

set -e

echo "=========================================="
echo "  Guardrail + OpenClaw Enclave Bootstrap"
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
# This prevents OpenClaw from bypassing the guardrail proxy
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
# Step 2: Receive OpenClaw package via vsock
# ============================================================================

echo "[2/6] Receiving OpenClaw package from parent instance..."
echo "  Waiting for injection... (no timeout, will wait indefinitely)"

# Run vsock receiver
# Note: This will BLOCK indefinitely until inject_openclaw.sh is run from parent
python3 /guardrail/vsock_receiver.py \
    --port 9000 \
    --output /tmp/openclaw.tgz \
    --metadata-output /tmp/agent_metadata.json \
    --apikey-output /tmp/api_key \
    --openai-apikey-output /tmp/openai_api_key \
    --openrouter-apikey-output /tmp/openrouter_api_key \
    --serper-apikey-output /tmp/serper_api_key \
    --gateway-token-output /tmp/gateway_token

if [ ! -f /tmp/openclaw.tgz ]; then
    echo "  ERROR: Failed to receive OpenClaw tarball"
    kill $LOCAL_PROXY_PID 2>/dev/null || true
    exit 1
fi

if [ ! -f /tmp/agent_metadata.json ]; then
    echo "  ERROR: Agent metadata not saved"
    kill $LOCAL_PROXY_PID 2>/dev/null || true
    exit 1
fi

# Display received metadata
echo ""
echo "  Received package metadata:"
cat /tmp/agent_metadata.json | jq '.'
echo ""

# Validate tarball integrity against injected metadata hash
echo "[2.1/6] Validating received tarball SHA256..."
EXPECTED_SHA256="dddd008a818a569cf70bb43665fda8eb13e8e8b28368ba73a7b916beaeb4996c"

if command -v sha256sum >/dev/null 2>&1; then
    ACTUAL_SHA256=$(sha256sum /tmp/openclaw.tgz | cut -d' ' -f1)
elif command -v shasum >/dev/null 2>&1; then
    ACTUAL_SHA256=$(shasum -a 256 /tmp/openclaw.tgz | cut -d' ' -f1)
else
    echo "  ERROR: No SHA256 utility found (need sha256sum or shasum)"
    kill $LOCAL_PROXY_PID 2>/dev/null || true
    exit 1
fi

if [ "$ACTUAL_SHA256" != "$EXPECTED_SHA256" ]; then
    echo "  ERROR: SHA256 mismatch for received tarball"
    echo "    Expected: $EXPECTED_SHA256"
    echo "    Actual:   $ACTUAL_SHA256"
    kill $LOCAL_PROXY_PID 2>/dev/null || true
    exit 1
fi
echo "  ✓ SHA256 verified"
echo ""

# ============================================================================
# Step 2.5: Load and export injected API keys
# ============================================================================

echo "[2.5/6] Loading injected API keys..."

# OPENAI_API_KEY (prefer dedicated file, fallback to legacy /tmp/api_key)
if [ -f /tmp/openai_api_key ]; then
    export OPENAI_API_KEY=$(cat /tmp/openai_api_key)
    echo "  ✓ OPENAI_API_KEY loaded"
elif [ -f /tmp/api_key ]; then
    export OPENAI_API_KEY=$(cat /tmp/api_key)
    echo "  ✓ OPENAI_API_KEY loaded from legacy api_key"
else
    echo "  ⚠ No OPENAI_API_KEY provided"
fi

# OPENROUTER_API_KEY
if [ -f /tmp/openrouter_api_key ]; then
    export OPENROUTER_API_KEY=$(cat /tmp/openrouter_api_key)
    echo "  ✓ OPENROUTER_API_KEY loaded"
else
    echo "  ⚠ No OPENROUTER_API_KEY provided"
fi

# SERPER_API_KEY
if [ -f /tmp/serper_api_key ]; then
    export SERPER_API_KEY=$(cat /tmp/serper_api_key)
    echo "  ✓ SERPER_API_KEY loaded"
else
    echo "  ⚠ No SERPER_API_KEY provided"
fi

echo ""

# ============================================================================
# Step 3: Start guardrail proxy
# ============================================================================

echo "[3/6] Starting guardrail proxy server..."
cd /guardrail

# Configure HTTP proxy for outbound requests
export HTTP_PROXY="http://localhost:8888"
export HTTPS_PROXY="http://localhost:8888"
# Exclude localhost and 127.0.0.1 from proxying (so guardrail proxy works)
export NO_PROXY="localhost,127.0.0.1"

# Start proxy in background
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
# Step 3.5: Start attestation server
# ============================================================================

echo "[3.5/6] Starting attestation server..."

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
# Step 3.6: Start latency experiment server
# ============================================================================

echo "[3.6/6] Starting latency experiment server..."

# Start experiment server in background (inherits exported API keys)
python3 /guardrail/guardrail_server.py &
EXPERIMENT_SERVER_PID=$!
echo "  Latency experiment server started (PID: $EXPERIMENT_SERVER_PID)"

# Wait for server to be ready
for i in {1..30}; do
    if ! kill -0 $EXPERIMENT_SERVER_PID 2>/dev/null; then
        echo "  ERROR: Latency experiment server process died (PID: $EXPERIMENT_SERVER_PID)"
        kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID 2>/dev/null || true
        exit 1
    fi

    if curl -s http://localhost:8770/health > /dev/null 2>&1; then
        echo "  ✓ Latency experiment server is healthy"
        break
    fi

    if [ $i -eq 30 ]; then
        echo "  ERROR: Latency experiment server failed to respond after 30 seconds"
        kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID $EXPERIMENT_SERVER_PID 2>/dev/null || true
        exit 1
    fi

    sleep 1
done

echo ""

# ============================================================================
# Step 3.8: Prepare unprivileged OpenClaw runtime user
# ============================================================================

echo "[3.8/6] Preparing unprivileged OpenClaw runtime user..."

OPENCLAW_USER="openclaw"
OPENCLAW_HOME="/var/lib/openclaw"
OPENCLAW_CONFIG_DIR="/etc/openclaw"
OPENCLAW_CONFIG_PATH="$OPENCLAW_CONFIG_DIR/openclaw.json"
OPENCLAW_SKILLS_DIR="$OPENCLAW_HOME/.openclaw/skills/attestation-skill"

if id -u "$OPENCLAW_USER" >/dev/null 2>&1; then
    echo "  ✓ User '$OPENCLAW_USER' already exists"
else
    if useradd -r -m -d "$OPENCLAW_HOME" -s /usr/sbin/nologin "$OPENCLAW_USER" 2>/dev/null; then
        echo "  ✓ Created system user '$OPENCLAW_USER'"
    elif useradd -m -d "$OPENCLAW_HOME" -s /bin/bash "$OPENCLAW_USER" 2>/dev/null; then
        echo "  ✓ Created user '$OPENCLAW_USER'"
    else
        echo "  ERROR: Failed to create user '$OPENCLAW_USER'"
        kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID $EXPERIMENT_SERVER_PID 2>/dev/null || true
        exit 1
    fi
fi

mkdir -p "$OPENCLAW_HOME/.openclaw" "$OPENCLAW_CONFIG_DIR"
chown -R "$OPENCLAW_USER":"$OPENCLAW_USER" "$OPENCLAW_HOME"
chmod 700 "$OPENCLAW_HOME/.openclaw"
echo "  ✓ Runtime directories prepared"
echo ""

# ============================================================================
# Step 4: Install OpenClaw
# ============================================================================

echo "[4/5] Installing OpenClaw from received tarball..."

# Extract bundled tarball (contains node_modules with all dependencies)
echo "  Extracting bundled package..."
# Extract to /tmp (we attempted to remount with exec in step 0.5)
INSTALL_DIR="/tmp/node_modules"
mkdir -p "$INSTALL_DIR"
tar xzf /tmp/openclaw.tgz -C "$INSTALL_DIR"

# Find and create wrapper for openclaw binary
OPENCLAW_ENTRY=""
if [ -f "$INSTALL_DIR/openclaw/dist/entry.js" ]; then
    OPENCLAW_ENTRY="$INSTALL_DIR/openclaw/dist/entry.js"
    echo "  ✓ Found binary: dist/entry.js"
elif [ -f "$INSTALL_DIR/openclaw/bin/openclaw.js" ]; then
    OPENCLAW_ENTRY="$INSTALL_DIR/openclaw/bin/openclaw.js"
    echo "  ✓ Found binary: bin/openclaw.js"
elif [ -f "$INSTALL_DIR/openclaw/bin/index.js" ]; then
    OPENCLAW_ENTRY="$INSTALL_DIR/openclaw/bin/index.js"
    echo "  ✓ Found binary: bin/index.js"
else
    echo "  ERROR: Could not find openclaw binary"
    echo "  Searched for:"
    echo "    - $INSTALL_DIR/openclaw/dist/entry.js"
    echo "    - $INSTALL_DIR/openclaw/bin/openclaw.js"
    echo "    - $INSTALL_DIR/openclaw/bin/index.js"
    kill $PROXY_PID
    exit 1
fi

# Create wrapper script (avoids /tmp execute permission issues)
cat > /usr/local/bin/openclaw <<WRAPPER_EOF
#!/bin/bash
exec node "$OPENCLAW_ENTRY" "\$@"
WRAPPER_EOF

chmod +x /usr/local/bin/openclaw
echo "  ✓ Wrapper script created: /usr/local/bin/openclaw"

# Verify installation
if ! command -v openclaw &> /dev/null; then
    echo "  ERROR: OpenClaw installation failed (openclaw command not found)"
    kill $PROXY_PID
    exit 1
fi

INSTALLED_VERSION=$(openclaw --version 2>/dev/null || echo "unknown")
echo "  ✓ OpenClaw installed: $INSTALLED_VERSION"

# Set NODE_PATH so Node.js can find modules in /tmp/node_modules

# Ensure NO_PROXY is set for OpenClaw as well (exclude localhost from HTTP proxy)
export NO_PROXY="localhost,127.0.0.1"
echo "  ✓ NO_PROXY configured to exclude localhost from HTTP proxy"
export NODE_PATH="$INSTALL_DIR:$NODE_PATH"
echo "  ✓ NODE_PATH configured: $NODE_PATH"
echo ""

# ============================================================================
# Step 5: Configure and start OpenClaw
# ============================================================================

echo "[5/5] Configuring OpenClaw to use guardrail proxy..."

# Register attestation skill
echo "  Registering attestation skill..."
mkdir -p "$OPENCLAW_SKILLS_DIR"
cp /attestation-skill/SKILL.md "$OPENCLAW_SKILLS_DIR/SKILL.md"
chown -R "$OPENCLAW_USER":"$OPENCLAW_USER" "$OPENCLAW_HOME/.openclaw/skills"
echo "  ✓ Attestation skill registered at $OPENCLAW_SKILLS_DIR/SKILL.md"

# Read API key from vsock-injected file
if [ -n "${OPENAI_API_KEY:-}" ]; then
    API_KEY="$OPENAI_API_KEY"
    echo "  ✓ OpenAI API key loaded from exported OPENAI_API_KEY"
elif [ -f /tmp/api_key ]; then
    API_KEY=$(cat /tmp/api_key)
    echo "  ✓ API key loaded from legacy /tmp/api_key"
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
cat > "$OPENCLAW_CONFIG_PATH" <<EOF
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
            "maxTokens": 10000
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
  },
  "channels": {
    "telegram": {
      "enabled": false,
      "dmPolicy": "pairing",
      "groupPolicy": "allowlist",
      "streamMode": "partial",
      "proxy": "http://localhost:8888"
    }
  }
}
EOF

# Keep config immutable to the unprivileged OpenClaw runtime user.
chown root:root "$OPENCLAW_CONFIG_PATH"
chmod 0444 "$OPENCLAW_CONFIG_PATH"

# Securely delete API key and gateway token files
rm -f /tmp/api_key /tmp/openai_api_key /tmp/openrouter_api_key /tmp/serper_api_key /tmp/gateway_token

echo "  ✓ OpenClaw configured:"
echo "    - Config: $OPENCLAW_CONFIG_PATH (read-only)"
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

# Start bridge to forward vsock connections to latency experiment server
python3 /guardrail/vsock_to_tcp_bridge.py \
    --vsock-port 8770 \
    --tcp-port 8770 \
    >/dev/null 2>&1 &

EXPERIMENT_BRIDGE_PID=$!
echo "  ✓ Latency experiment bridge started (PID: $EXPERIMENT_BRIDGE_PID)"
echo "    Vsock :8770 → TCP localhost:8770"

echo ""

# ============================================================================
# Final: Start OpenClaw Gateway
# ============================================================================

echo "=========================================="
echo "  Starting OpenClaw Gateway"
echo "=========================================="
echo ""

# Trap SIGTERM to cleanup
trap "echo 'Shutting down...'; kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID $EXPERIMENT_SERVER_PID $BRIDGE_PID $EXPERIMENT_BRIDGE_PID 2>/dev/null || true; exit 0" SIGTERM SIGINT

# Start OpenClaw gateway (blocks)
# Gateway is configured in $OPENCLAW_CONFIG_PATH (mode: "local", port: 18789)
# Use xvfb-run to provide virtual display for clipboard module
echo "Starting gateway with virtual display (xvfb)..."

# Ensure HTTP proxy environment variables are set for OpenClaw
# (Node.js/undici needs these for fetch to work through proxy)
export HTTP_PROXY="http://localhost:8888"
export HTTPS_PROXY="http://localhost:8888"
export NO_PROXY="localhost,127.0.0.1"

# Force Node.js to use environment HTTP proxy for undici/fetch
# This works with Node.js 18+ built-in fetch
export NODE_OPTIONS="--dns-result-order=ipv4first ${NODE_OPTIONS:-}"

OPENCLAW_GATEWAY_CMD="export HTTP_PROXY='$HTTP_PROXY' HTTPS_PROXY='$HTTPS_PROXY' NO_PROXY='$NO_PROXY' NODE_OPTIONS='$NODE_OPTIONS' NODE_PATH='$NODE_PATH' OPENCLAW_CONFIG_PATH='$OPENCLAW_CONFIG_PATH'; xvfb-run -a openclaw gateway"

echo "  HTTP proxy environment:"
echo "    HTTP_PROXY=$HTTP_PROXY"
echo "    HTTPS_PROXY=$HTTPS_PROXY"
echo "    NO_PROXY=$NO_PROXY"
echo "    NODE_OPTIONS=$NODE_OPTIONS"
echo "    OPENCLAW_CONFIG_PATH=$OPENCLAW_CONFIG_PATH"
echo "    RUN_AS_USER=$OPENCLAW_USER"
echo ""

# Try to start gateway, but run diagnostics on error
if ! su -s /bin/bash -c "$OPENCLAW_GATEWAY_CMD" "$OPENCLAW_USER"; then
    echo ""
    echo "=========================================="
    echo "  ERROR: OpenClaw Gateway Failed to Start"
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

    echo "4. Checking openclaw version:"
    openclaw --version 2>&1 || echo "   Failed to get version"
    echo ""

    echo "=========================================="
    echo "  Diagnostics complete. Keeping enclave alive..."
    echo "  Background services still running:"
    echo "    - Guardrail proxy (PID: $PROXY_PID)"
    echo "    - Local HTTP proxy (PID: $LOCAL_PROXY_PID)"
    echo "    - Attestation server (PID: $ATTESTATION_PID)"
    echo "    - Latency experiment server (PID: $EXPERIMENT_SERVER_PID)"
    echo "    - Gateway bridge (PID: $BRIDGE_PID)"
    echo "    - Experiment bridge (PID: $EXPERIMENT_BRIDGE_PID)"
    echo "=========================================="

    # Sleep forever to keep enclave running
    tail -f /dev/null
fi

# If OpenClaw exits normally, cleanup
echo "OpenClaw gateway exited"
kill $PROXY_PID $LOCAL_PROXY_PID $ATTESTATION_PID $EXPERIMENT_SERVER_PID $BRIDGE_PID $EXPERIMENT_BRIDGE_PID 2>/dev/null || true
exit 0
