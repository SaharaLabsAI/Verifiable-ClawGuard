#!/bin/bash
# build_and_deploy.sh - One-command build and deployment
#
# This script automates the entire process:
# 1. Build Docker image
# 2. Convert to EIF (Enclave Image Format)
# 3. Display PCR values
# 4. Optionally deploy to EC2

set -e

echo "=========================================="
echo "  Guardrail Enclave Builder"
echo "=========================================="
echo ""

# Configuration
IMAGE_NAME="guardrail-enclave"
IMAGE_TAG="latest"
EIF_FILE="guardrail-vsock.eif"

# Parse arguments
SKIP_BUILD=false
DEPLOY_TO_EC2=false
EC2_HOST=""

while [[ $# -gt 0 ]]; do
    case $1 in
        --skip-build)
            SKIP_BUILD=true
            shift
            ;;
        --deploy)
            DEPLOY_TO_EC2=true
            EC2_HOST="$2"
            shift 2
            ;;
        *)
            echo "Unknown option: $1"
            echo "Usage: $0 [--skip-build] [--deploy ec2-user@host]"
            exit 1
            ;;
    esac
done

# ============================================================================
# Step 1: Build Docker image
# ============================================================================

if [ "$SKIP_BUILD" = false ]; then
    echo "[1/2] Building Docker image..."
    echo ""

    docker build \
        -f Dockerfile.vsock \
        -t ${IMAGE_NAME}:${IMAGE_TAG} \
        .

    echo ""
    echo "✓ Docker image built: ${IMAGE_NAME}:${IMAGE_TAG}"
    echo ""
else
    echo "[1/3] Skipping Docker build (--skip-build flag)"
    echo ""
fi

# ============================================================================
# Step 2: Convert to EIF
# ============================================================================

echo "[2/2] Converting to Enclave Image Format (EIF)..."
echo ""

# Check if nitro-cli is installed
if ! command -v nitro-cli &> /dev/null; then
    echo "ERROR: nitro-cli not found"
    echo ""
    echo "Install AWS Nitro CLI:"
    echo "  Amazon Linux 2: sudo amazon-linux-extras install aws-nitro-enclaves-cli"
    echo "  Ubuntu: Follow https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave-cli-install.html"
    exit 1
fi

# Build enclave image and capture output
BUILD_OUTPUT=$(nitro-cli build-enclave \
    --docker-uri ${IMAGE_NAME}:${IMAGE_TAG} \
    --output-file ${EIF_FILE} 2>&1)

# Save output for debugging
echo "$BUILD_OUTPUT" > build_output.txt
echo "$BUILD_OUTPUT"

echo ""
echo "✓ Enclave image created: ${EIF_FILE}"
echo ""
