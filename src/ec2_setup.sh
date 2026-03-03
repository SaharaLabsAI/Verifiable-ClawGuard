#!/bin/bash
# ec2_setup.sh - Complete EC2 parent instance setup for verifiable guardrail
#
# This script performs all required EC2-side operations by calling:
# 1. start_http_forwarder.sh - Enable enclave internet access
# 2. inject_openclaw.sh - Inject agent into enclave
# 3. start_vsock_proxy.sh - Expose agent to external clients
#
# Usage:
#   ./ec2_setup.sh --api-key <key> [options]
#
# Options:
#   --api-key KEY              OpenAI API key (required)
#   --gateway-token TOKEN      OpenClaw gateway token (optional)
#   --openrouter-api-key KEY   OpenRouter API key (optional)
#   --serper-api-key KEY       Serper API key (optional)
#   --agent-version VERSION    OpenClaw version (default: 2026.2.1)
#   --enclave-cid CID          Enclave CID (default: auto-detect)
#   --skip-http-forwarder      Skip starting HTTP forwarder
#   --skip-agent-injection     Skip agent injection
#   --skip-vsock-proxy         Skip vsock proxy setup
#   --enable-guardrail-proxy   Enable guardrail debug proxy on 8080
#   --enable-experiment-proxy  Enable latency experiment proxy on 8770
#   --experiment-bind HOST     Bind host for experiment proxy (default: 127.0.0.1)
#   --help                     Show this help message

set -e

# ============================================================================
# Configuration & Defaults
# ============================================================================

AGENT_VERSION="2026.2.1"
ENCLAVE_CID=""
API_KEY="${OPENAI_API_KEY:-}"
GATEWAY_TOKEN="${GATEWAY_TOKEN:-}"
OPENROUTER_API_KEY="${OPENROUTER_API_KEY:-}"
SERPER_API_KEY="${SERPER_API_KEY:-}"
SKIP_HTTP_FORWARDER=false
SKIP_AGENT_INJECTION=false
SKIP_VSOCK_PROXY=false
ENABLE_GUARDRAIL_PROXY=false
ENABLE_EXPERIMENT_PROXY=false
EXPERIMENT_PROXY_BIND="127.0.0.1"

# ============================================================================
# Parse Arguments
# ============================================================================

while [[ $# -gt 0 ]]; do
    case $1 in
        --agent-version)
            AGENT_VERSION="$2"
            shift 2
            ;;
        --enclave-cid)
            ENCLAVE_CID="$2"
            shift 2
            ;;
        --api-key)
            API_KEY="$2"
            shift 2
            ;;
        --gateway-token)
            GATEWAY_TOKEN="$2"
            shift 2
            ;;
        --openrouter-api-key)
            OPENROUTER_API_KEY="$2"
            shift 2
            ;;
        --serper-api-key)
            SERPER_API_KEY="$2"
            shift 2
            ;;
        --skip-http-forwarder)
            SKIP_HTTP_FORWARDER=true
            shift
            ;;
        --skip-agent-injection)
            SKIP_AGENT_INJECTION=true
            shift
            ;;
        --skip-vsock-proxy)
            SKIP_VSOCK_PROXY=true
            shift
            ;;
        --enable-guardrail-proxy)
            ENABLE_GUARDRAIL_PROXY=true
            shift
            ;;
        --enable-experiment-proxy)
            ENABLE_EXPERIMENT_PROXY=true
            shift
            ;;
        --experiment-bind)
            EXPERIMENT_PROXY_BIND="$2"
            shift 2
            ;;
        --help)
            awk 'NR==1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"
            exit 0
            ;;
        *)
            echo "ERROR: Unknown option: $1"
            echo "Use --help for usage information"
            exit 1
            ;;
    esac
done

# ============================================================================
# Validation & Auto-Detection
# ============================================================================

# Auto-detect enclave CID if not provided
if [ -z "$ENCLAVE_CID" ]; then
    echo "Auto-detecting enclave CID..."

    # Get all running enclaves
    RUNNING_ENCLAVES=$(nitro-cli describe-enclaves 2>/dev/null | jq -r '.[] | select(.State == "RUNNING") | .EnclaveCID' || echo "")

    if [ -z "$RUNNING_ENCLAVES" ]; then
        echo "ERROR: No running enclaves found"
        echo ""
        echo "Available enclaves:"
        nitro-cli describe-enclaves | jq -r '.[] | "  CID \(.EnclaveCID): \(.State)"'
        exit 1
    fi

    # Count how many running enclaves
    ENCLAVE_COUNT=$(echo "$RUNNING_ENCLAVES" | wc -l | tr -d ' ')

    if [ "$ENCLAVE_COUNT" -gt 1 ]; then
        echo "ERROR: Multiple running enclaves found. Please specify --enclave-cid"
        echo ""
        echo "Running enclaves:"
        nitro-cli describe-enclaves | jq -r '.[] | select(.State == "RUNNING") | "  CID \(.EnclaveCID)"'
        exit 1
    fi

    ENCLAVE_CID="$RUNNING_ENCLAVES"
    echo "  ✓ Detected enclave CID: $ENCLAVE_CID"
    echo ""
fi

# Validate API key
if [ "$SKIP_AGENT_INJECTION" = false ] && [ -z "$API_KEY" ]; then
    echo "ERROR: --api-key is required (unless using --skip-agent-injection)"
    echo ""
    echo "Usage: $0 --api-key sk-proj-YOUR-KEY"
    echo "Use --help for more options"
    exit 1
fi

# Check scripts exist
if [ "$SKIP_HTTP_FORWARDER" = false ] && [ ! -f "start_http_forwarder.sh" ]; then
    echo "ERROR: start_http_forwarder.sh not found"
    echo "Make sure you're in the src directory"
    exit 1
fi

if [ "$SKIP_AGENT_INJECTION" = false ] && [ ! -f "inject_openclaw.sh" ]; then
    echo "ERROR: inject_openclaw.sh not found"
    echo "Make sure you're in the src directory"
    exit 1
fi

if [ "$SKIP_VSOCK_PROXY" = false ] && [ ! -f "start_vsock_proxy.sh" ]; then
    echo "ERROR: start_vsock_proxy.sh not found"
    echo "Make sure you're in the src directory"
    exit 1
fi

# ============================================================================
# Header
# ============================================================================

echo "============================================================"
echo "  EC2 Parent Instance Setup for Verifiable Guardrail"
echo "============================================================"
echo ""
echo "Configuration:"
echo "  Agent Version:        $AGENT_VERSION"
echo "  Enclave CID:          $ENCLAVE_CID"
echo "  API Key:              ${API_KEY:+provided}"
echo "  Gateway Token:        ${GATEWAY_TOKEN:+provided}"
echo "  OpenRouter API Key:   ${OPENROUTER_API_KEY:+provided}"
echo "  Serper API Key:       ${SERPER_API_KEY:+provided}"
echo "  HTTP Forwarder:       $([ "$SKIP_HTTP_FORWARDER" = true ] && echo "SKIP" || echo "START")"
echo "  Agent Injection:      $([ "$SKIP_AGENT_INJECTION" = true ] && echo "SKIP" || echo "RUN")"
echo "  Vsock Proxy:          $([ "$SKIP_VSOCK_PROXY" = true ] && echo "SKIP" || echo "START")"
echo "  Guardrail Proxy:      $([ "$ENABLE_GUARDRAIL_PROXY" = true ] && echo "ENABLED" || echo "DISABLED")"
echo "  Experiment Proxy:     $([ "$ENABLE_EXPERIMENT_PROXY" = true ] && echo "ENABLED" || echo "DISABLED")"
echo "  Experiment Bind:      $EXPERIMENT_PROXY_BIND"
echo ""

# Create logs directory
mkdir -p logs

# ============================================================================
# Step 1: Start HTTP Forwarder
# ============================================================================

if [ "$SKIP_HTTP_FORWARDER" = false ]; then
    echo "============================================================"
    echo " [1/3] Starting HTTP Forwarder"
    echo "============================================================"
    echo ""

    # Run in background
    nohup bash start_http_forwarder.sh > logs/http_forwarder_setup.log 2>&1 &
    HTTP_FORWARDER_PID=$!
    echo "  Started in background (PID: $HTTP_FORWARDER_PID)"
    echo "  Log: logs/http_forwarder_setup.log"

    # Give it a moment to start
    sleep 3

    if ! ps -p "$HTTP_FORWARDER_PID" > /dev/null 2>&1; then
        echo "  ✗ Failed to start HTTP forwarder"
        echo "  Check logs/http_forwarder_setup.log for errors"
        exit 1
    fi

    echo "$HTTP_FORWARDER_PID" > .http_forwarder_pid

    echo "  ✓ HTTP forwarder started successfully"
    echo ""
else
    echo "[1/3] HTTP Forwarder: SKIPPED"
    echo ""
fi

# ============================================================================
# Step 2: Inject Agent
# ============================================================================

if [ "$SKIP_AGENT_INJECTION" = false ]; then
    echo "============================================================"
    echo " [2/3] Injecting Agent into Enclave"
    echo "============================================================"
    echo ""

    # Wait a bit for HTTP forwarder to be ready
    if [ "$SKIP_HTTP_FORWARDER" = false ]; then
        echo "  Waiting for HTTP forwarder to be ready..."
        sleep 1
        echo ""
    fi

    bash inject_openclaw.sh "$AGENT_VERSION" "$ENCLAVE_CID" "$API_KEY" "$GATEWAY_TOKEN" "$OPENROUTER_API_KEY" "$SERPER_API_KEY"

    if [ $? -ne 0 ]; then
        echo ""
        echo "  ✗ Agent injection failed"
        exit 1
    fi

    echo "  ✓ Agent injection complete"
    echo ""

    # Wait for agent to install
    echo "  Waiting for agent to install in enclave..."
    sleep 1
    echo ""
else
    echo "[2/3] Agent Injection: SKIPPED"
    echo ""
fi

# ============================================================================
# Step 3: Start Vsock Proxies
# ============================================================================

if [ "$SKIP_VSOCK_PROXY" = false ]; then
    echo "============================================================"
    echo " [3/3] Starting Vsock Proxies"
    echo "============================================================"
    echo ""

    if [ "$ENABLE_GUARDRAIL_PROXY" = true ]; then
        export START_GUARDRAIL_PROXY=true
    fi
    if [ "$ENABLE_EXPERIMENT_PROXY" = true ]; then
        export START_EXPERIMENT_PROXY=true
        export EXPERIMENT_PROXY_BIND="$EXPERIMENT_PROXY_BIND"
    fi

    bash start_vsock_proxy.sh "$ENCLAVE_CID"

    if [ $? -ne 0 ]; then
        echo ""
        echo "  ✗ Vsock proxy setup failed"
        exit 1
    fi

    echo "  ✓ Vsock proxies started"
    echo ""
else
    echo "[3/3] Vsock Proxies: SKIPPED"
    echo ""
fi

# ============================================================================
# Summary
# ============================================================================

echo "============================================================"
echo " ✓ Setup Complete!"
echo "============================================================"
echo ""

if [ "$SKIP_HTTP_FORWARDER" = false ]; then
    echo "HTTP Forwarder:"
    echo "  Running in background"
    echo "  Log: logs/http_forwarder_setup.log"
    echo ""
fi

if [ "$SKIP_AGENT_INJECTION" = false ]; then
    echo "Agent Injection:"
    echo "  Agent: OpenClaw v$AGENT_VERSION"
    echo "  Check enclave console for installation status:"
    echo "    nitro-cli console --enclave-id \$(nitro-cli describe-enclaves | jq -r '.[0].EnclaveID')"
    echo ""
fi

if [ "$SKIP_VSOCK_PROXY" = false ]; then
    echo "Vsock Proxies:"
    PUBLIC_IP=$(curl -s ifconfig.me 2>/dev/null || echo "YOUR-IP")
    echo "  OpenClaw Gateway: ws://$PUBLIC_IP:18789"
    echo "                   or ws://127.0.0.1:18789 (local)"

    if [ "$ENABLE_GUARDRAIL_PROXY" = true ]; then
        echo "  Guardrail Proxy: http://127.0.0.1:8080"
    fi
    if [ "$ENABLE_EXPERIMENT_PROXY" = true ]; then
        echo "  Experiment Proxy: http://$EXPERIMENT_PROXY_BIND:8770/experiment/latency"
    fi
    echo ""

fi

echo "To cleanup:"
echo "  ./ec2_cleanup.sh"
echo ""
