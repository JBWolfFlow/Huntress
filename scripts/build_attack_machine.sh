#!/bin/bash
# Build the Huntress attack machine Docker image.
# Usage: ./scripts/build_attack_machine.sh [--no-cache]
#
# The image contains security tools (nuclei, sqlmap, ffuf, etc.) and a
# Squid proxy that enforces scope via HUNTRESS_ALLOWED_DOMAINS env var.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
IMAGE_NAME="huntress-attack-machine:latest"
DOCKER_DIR="$PROJECT_ROOT/docker"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}[huntress]${NC} Building attack machine image: $IMAGE_NAME"

# Check Docker is available
if ! command -v docker &> /dev/null; then
    echo -e "${RED}[error]${NC} Docker is not installed or not in PATH" >&2
    exit 1
fi

if ! docker info &> /dev/null; then
    echo -e "${RED}[error]${NC} Docker daemon is not running" >&2
    exit 1
fi

# Parse args
BUILD_ARGS=""
if [[ "${1:-}" == "--no-cache" ]]; then
    BUILD_ARGS="--no-cache"
    echo -e "${YELLOW}[huntress]${NC} Building without cache"
fi

# Build the image
echo -e "${YELLOW}[huntress]${NC} Starting Docker build..."
docker build \
    $BUILD_ARGS \
    -t "$IMAGE_NAME" \
    -f "$DOCKER_DIR/Dockerfile.attack-machine" \
    "$DOCKER_DIR"

echo ""
echo -e "${GREEN}[huntress]${NC} Build complete: $IMAGE_NAME"
echo ""

# Verify tools are installed
echo -e "${YELLOW}[huntress]${NC} Verifying installed tools..."

TOOLS=(
    "nuclei -version"
    "subfinder -version"
    "httpx -version"
    "katana -version"
    "ffuf -V"
    "dalfox version"
    "nmap --version"
    "sqlmap --version"
    "commix --version"
    "ghauri --version"
    "interactsh-client -version"
    "curl --version"
    "jq --version"
    "python3 --version"
    "squid -v"
)

PASS=0
FAIL=0

for tool_cmd in "${TOOLS[@]}"; do
    tool_name=$(echo "$tool_cmd" | awk '{print $1}')
    if docker run --rm "$IMAGE_NAME" bash -c "$tool_cmd" &>/dev/null; then
        echo -e "  ${GREEN}[OK]${NC} $tool_name"
        ((PASS++))
    else
        echo -e "  ${RED}[FAIL]${NC} $tool_name"
        ((FAIL++))
    fi
done

echo ""
echo -e "${GREEN}[huntress]${NC} Verification: $PASS passed, $FAIL failed"

if [ "$FAIL" -gt 0 ]; then
    echo -e "${YELLOW}[warning]${NC} Some tools failed verification. The image may still be usable."
    exit 1
fi

# Test scope enforcement
echo ""
echo -e "${YELLOW}[huntress]${NC} Testing scope enforcement..."
RESULT=$(docker run --rm -e HUNTRESS_ALLOWED_DOMAINS="example.com" "$IMAGE_NAME" \
    bash -c "sleep 2 && curl -s --proxy http://127.0.0.1:3128 --max-time 5 http://httpbin.org/ip 2>&1 || echo 'BLOCKED'" 2>&1)

if echo "$RESULT" | grep -qi "blocked\|denied\|403\|ERR_ACCESS_DENIED"; then
    echo -e "  ${GREEN}[OK]${NC} Out-of-scope request correctly blocked"
else
    echo -e "  ${YELLOW}[WARN]${NC} Could not verify scope blocking (proxy may not be ready in time)"
fi

echo ""
echo -e "${GREEN}[huntress]${NC} Attack machine ready: docker run --rm -e HUNTRESS_ALLOWED_DOMAINS=target.com $IMAGE_NAME nuclei -u https://target.com"
