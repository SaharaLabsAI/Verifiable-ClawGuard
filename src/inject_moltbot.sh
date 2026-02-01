#!/bin/bash
# inject_moltbot.sh - Send MoltBot package + API key to enclave via vsock
#
# This script runs on the PARENT EC2 INSTANCE (not inside enclave)
# It downloads MoltBot from npm and injects it into the enclave via vsock.
#
# Usage:
#   ./inject_moltbot.sh [version] [enclave-cid] [api-key]
#
# Example:
#   ./inject_moltbot.sh 1.2.3 16 sk-proj-YOUR-API-KEY
#
# Note: API key is injected at runtime, so it doesn't affect PCR2 measurement

set -e

# ============================================================================
# Configuration
# ============================================================================

MOLTBOT_VERSION="${1:-latest}"
ENCLAVE_CID="${2:-16}"
API_KEY="${3:-}"
VSOCK_PORT=9000

WORK_DIR="/tmp/moltbot_injection_$$"
CACHE_DIR="$HOME/.cache/moltbot_injection"
TARBALL_PATH="$WORK_DIR/moltbot.tgz"

echo "=========================================="
echo "  MoltBot Injection to Enclave"
echo "=========================================="
echo ""
echo "Configuration:"
echo "  MoltBot Version: $MOLTBOT_VERSION"
echo "  Enclave CID:     $ENCLAVE_CID"
echo "  Vsock Port:      $VSOCK_PORT"
echo "  API Key:         ${API_KEY:+provided}"

if [ -z "$API_KEY" ]; then
    echo ""
    echo "⚠ WARNING: No API key provided!"
    echo "  MoltBot will be configured but may not work without an API key."
    echo "  Usage: $0 <version> <cid> <api-key>"
    echo ""
fi

echo ""

# ============================================================================
# Step 1: Create working directory
# ============================================================================

echo "[1/4] Creating working directory..."
mkdir -p "$WORK_DIR"
cd "$WORK_DIR"
echo "  Working directory: $WORK_DIR"
echo ""

# ============================================================================
# Step 2: Download MoltBot from npm (or use cache)
# ============================================================================

echo "[2/4] Preparing MoltBot v${MOLTBOT_VERSION}..."

# First, resolve "latest" to actual version if needed
if [ "$MOLTBOT_VERSION" = "latest" ]; then
    echo "  Resolving 'latest' version from npm..."
    MOLTBOT_VERSION=$(npm view clawdbot version 2>/dev/null || echo "latest")
    echo "  Latest version: $MOLTBOT_VERSION"
fi

# Check cache first
mkdir -p "$CACHE_DIR"
CACHED_TARBALL="$CACHE_DIR/clawdbot-${MOLTBOT_VERSION}.tgz"

if [ -f "$CACHED_TARBALL" ]; then
    echo "  ✓ Found cached tarball: $CACHED_TARBALL"
    echo "    Copying from cache (skipping npm install)..."
    cp "$CACHED_TARBALL" "$TARBALL_PATH"
    TARBALL_SIZE=$(stat -c%s "$TARBALL_PATH" 2>/dev/null || stat -f%z "$TARBALL_PATH")
    echo "    Size: $TARBALL_SIZE bytes ($(echo "scale=2; $TARBALL_SIZE / 1024 / 1024" | bc) MB)"
else
    echo "  No cached tarball found. Downloading from npm..."

    # Install clawdbot locally with all dependencies
    mkdir -p package_bundle
    cd package_bundle

    if [ "$MOLTBOT_VERSION" = "latest" ]; then
        npm install clawdbot --production --no-save
    else
        npm install clawdbot@${MOLTBOT_VERSION} --production --no-save
    fi

    # Extract actual version from node_modules (in case version was "latest")
    ACTUAL_VERSION=$(node -p "require('./node_modules/clawdbot/package.json').version")
    echo "  Installed version: $ACTUAL_VERSION"
    MOLTBOT_VERSION="$ACTUAL_VERSION"

    # Create bundled tarball with all dependencies
    cd ..
    tar czf "$TARBALL_PATH" -C package_bundle/node_modules .

    # Verify tarball was created
    if [ ! -f "$TARBALL_PATH" ]; then
        echo "  ERROR: Failed to create bundled tarball"
        rm -rf "$WORK_DIR"
        exit 1
    fi

    TARBALL_SIZE=$(stat -c%s "$TARBALL_PATH" 2>/dev/null || stat -f%z "$TARBALL_PATH")
    echo "  ✓ Downloaded: $TARBALL_PATH"
    echo "    Size: $TARBALL_SIZE bytes ($(echo "scale=2; $TARBALL_SIZE / 1024 / 1024" | bc) MB)"

    # Save to cache for future use
    CACHED_TARBALL="$CACHE_DIR/clawdbot-${MOLTBOT_VERSION}.tgz"
    cp "$TARBALL_PATH" "$CACHED_TARBALL"
    echo "  ✓ Saved to cache: $CACHED_TARBALL"
fi

echo ""

# ============================================================================
# Step 3: Compute SHA256 hash
# ============================================================================

echo "[3/4] Computing SHA256 hash..."

# Compute hash (compatible with Linux and macOS)
if command -v sha256sum &> /dev/null; then
    HASH=$(sha256sum "$TARBALL_PATH" | cut -d' ' -f1)
elif command -v shasum &> /dev/null; then
    HASH=$(shasum -a 256 "$TARBALL_PATH" | cut -d' ' -f1)
else
    echo "  ERROR: No SHA256 utility found (need sha256sum or shasum)"
    rm -rf "$WORK_DIR"
    exit 1
fi

echo "  ✓ SHA256: $HASH"
echo ""

# ============================================================================
# Step 4: Send to enclave via vsock
# ============================================================================

echo "[4/4] Sending package to enclave (CID $ENCLAVE_CID)..."

# Create metadata JSON (including API key if provided)
if [ -n "$API_KEY" ]; then
    METADATA=$(cat <<EOF
{
  "package": "clawdbot",
  "version": "$MOLTBOT_VERSION",
  "sha256": "$HASH",
  "size_bytes": $TARBALL_SIZE,
  "api_key": "$API_KEY"
}
EOF
)
else
    METADATA=$(cat <<EOF
{
  "package": "clawdbot",
  "version": "$MOLTBOT_VERSION",
  "sha256": "$HASH",
  "size_bytes": $TARBALL_SIZE
}
EOF
)
fi

echo "  Metadata:"
echo "$METADATA" | jq '.'
echo ""

# Send via vsock using Python
python3 << PYTHON_SCRIPT
import socket
import json
import sys
import time

# Metadata
metadata = '''$METADATA'''

# Connect to enclave
print(f"  Connecting to enclave CID $ENCLAVE_CID on port $VSOCK_PORT...")
try:
    sock = socket.socket(socket.AF_VSOCK, socket.SOCK_STREAM)
    sock.connect(($ENCLAVE_CID, $VSOCK_PORT))

    # Optimize socket buffers for large transfers
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 2 * 1024 * 1024)  # 2MB send buffer

    print(f"  ✓ Connected to enclave")
except Exception as e:
    print(f"  ERROR: Failed to connect: {e}", file=sys.stderr)
    sys.exit(1)

# Send metadata length and metadata
try:
    metadata_bytes = metadata.encode('utf-8')
    metadata_len = len(metadata_bytes)

    print(f"  Sending metadata ({metadata_len} bytes)...")
    sock.sendall(metadata_len.to_bytes(4, 'big'))  # Use sendall!
    sock.sendall(metadata_bytes)  # Use sendall!

    # Send tarball
    print(f"  Sending tarball...")
    start_time = time.time()

    with open('$TARBALL_PATH', 'rb') as f:
        data = f.read()
        total_bytes = len(data)
        sent_bytes = 0
        chunk_size = 256 * 1024  # 256KB chunks (larger for better performance)

        while sent_bytes < total_bytes:
            chunk = data[sent_bytes:sent_bytes + chunk_size]
            sock.sendall(chunk)  # CRITICAL: Use sendall() not send()!
            sent_bytes += len(chunk)

            # Progress indicator every 50MB with speed
            if sent_bytes % (50 * 1024 * 1024) == 0 or sent_bytes == total_bytes:
                elapsed = time.time() - start_time
                progress = (sent_bytes / total_bytes) * 100
                mb_sent = sent_bytes / 1024 / 1024
                speed_mbps = (sent_bytes / 1024 / 1024) / elapsed if elapsed > 0 else 0
                print(f"    Progress: {progress:.1f}% ({mb_sent:.1f} MB) - {speed_mbps:.1f} MB/s")

        elapsed = time.time() - start_time
        speed_mbps = (total_bytes / 1024 / 1024) / elapsed if elapsed > 0 else 0
        print(f"  ✓ Sent complete tarball ({total_bytes} bytes in {elapsed:.1f}s - {speed_mbps:.1f} MB/s)")

    sock.close()
    print(f"  ✓ Connection closed")

except Exception as e:
    print(f"  ERROR: Transfer failed: {e}", file=sys.stderr)
    sock.close()
    sys.exit(1)

PYTHON_SCRIPT

if [ $? -ne 0 ]; then
    echo ""
    echo "ERROR: Failed to send package to enclave"
    rm -rf "$WORK_DIR"
    exit 1
fi

echo ""

# ============================================================================
# Cleanup
# ============================================================================

echo "Cleaning up..."
rm -rf "$WORK_DIR"

echo ""
echo "=========================================="
echo "  ✓ Injection Complete!"
echo "=========================================="
echo ""
echo "The enclave should now be:"
echo "  1. Installing MoltBot v${MOLTBOT_VERSION}"
echo "  2. Configuring it to use the guardrail proxy"
echo "  3. Starting the MoltBot gateway"
echo ""
echo "Package details:"
echo "  Version: $MOLTBOT_VERSION"
echo "  SHA256:  $HASH"
echo ""
echo "Cache info:"
echo "  Cached tarball: $CACHE_DIR/clawdbot-${MOLTBOT_VERSION}.tgz"
echo "  To clear cache: rm -rf $CACHE_DIR"
echo ""
echo "To verify, check the enclave console:"
echo "  nitro-cli console --enclave-id <enclave-id>"
echo ""
