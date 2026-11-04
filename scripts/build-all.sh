#!/bin/bash
# Build all OHTTP components (gateway, relay-simulator)
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

build_component() {
    local component=$1
    log_info "Building $component..."

    if [ ! -d "$REPO_ROOT/$component" ]; then
        log_error "Component directory not found: $component"
        return 1
    fi

    cd "$REPO_ROOT/$component"

    if [ ! -f "Dockerfile" ]; then
        log_error "No Dockerfile found in $component"
        return 1
    fi

    docker build -t "ohttp-$component:latest" .
    log_info "✓ Built ohttp-$component:latest"
}

# Parse arguments
if [ $# -eq 0 ]; then
    # Build all components
    COMPONENTS=("gateway" "relay-simulator")
else
    # Build specific component
    COMPONENTS=("$@")
fi

# Build each component
for component in "${COMPONENTS[@]}"; do
    build_component "$component"
done

log_info "Build complete!"
log_info "Images:"
docker images | grep "ohttp-" | head -10
