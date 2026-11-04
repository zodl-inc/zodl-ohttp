#!/bin/bash
# Push OHTTP images to container registry
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Configure your registry URL here or via environment variable
REGISTRY="${REGISTRY_URL:-your-registry.example.com}"

if [ "$REGISTRY" == "your-registry.example.com" ]; then
    echo "ERROR: Set REGISTRY_URL environment variable to your container registry"
    echo "Example: export REGISTRY_URL=registry.example/ohttp"
    exit 1
fi

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

log_info() {
    echo -e "${GREEN}[INFO]${NC} $*"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $*"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $*"
}

# Parse arguments
TAG="latest"
while [[ $# -gt 0 ]]; do
    case $1 in
        --tag)
            TAG="$2"
            shift 2
            ;;
        *)
            log_error "Unknown argument: $1"
            echo "Usage: $0 [--tag TAG]"
            exit 1
            ;;
    esac
done

# Registry login
# This script does not log in: it assumes docker is already authenticated to $REGISTRY
# (for example `docker login --password-stdin "$REGISTRY"` or your registry's credential helper).
log_info "Logging into registry..."

push_image() {
    local component=$1
    local local_tag="ohttp-$component:latest"
    local registry_repo="$REGISTRY/ohttp-$component"
    local registry_tag="$registry_repo:$TAG"

    log_info "Pushing $component..."

    # Check if local image exists
    if ! docker image inspect "$local_tag" &> /dev/null; then
        log_warn "Local image $local_tag not found. Building first..."
        cd "$REPO_ROOT/$component"
        docker build -t "$local_tag" .
    fi

    # Tag for registry
    docker tag "$local_tag" "$registry_tag"

    # Push to registry
    docker push "$registry_tag"
    log_info "✓ Pushed $registry_tag"

    # Also push :latest if not already
    if [ "$TAG" != "latest" ]; then
        docker tag "$local_tag" "$registry_repo:latest"
        docker push "$registry_repo:latest"
        log_info "✓ Pushed $registry_repo:latest"
    fi
}

# Push both components
push_image "gateway"
push_image "relay-simulator"

log_info "Deploy complete!"
log_info ""
log_info "Images pushed:"
log_info "  - $REGISTRY/ohttp-gateway:$TAG"
log_info "  - $REGISTRY/ohttp-relay-simulator:$TAG"
