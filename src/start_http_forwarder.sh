#!/bin/bash
# start_http_forwarder.sh - Start the HTTP forwarder on parent EC2
#
# This script runs the vsock HTTP forwarder that allows the enclave
# to access the internet (specifically OpenAI API) through the parent EC2.
#
# Usage:
#   ./start_http_forwarder.sh
#
# Run this BEFORE starting the enclave.

set -e

echo "Starting Vsock HTTP Forwarder..."
echo ""
echo "This allows the enclave to access the internet via the parent EC2."
echo "The forwarder listens on vsock port 8001 and forwards HTTP/HTTPS"
echo "requests from the enclave to the internet."
echo ""

# Check if Python 3 is available
if ! command -v python3 &> /dev/null; then
    echo "ERROR: python3 not found"
    exit 1
fi

# Start the forwarder
echo "Starting forwarder on vsock port 8001..."
python3 vsock_http_forwarder.py --vsock-port 8001

