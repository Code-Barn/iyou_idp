#!/bin/bash
set -euo pipefail

# build-image.sh — compile the iyou-idp container image locally
# Ensures the FFI/maturin bridge layer fits the Python interpreter path.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

cd "$PROJECT_ROOT"

# Tag and build
IMAGE_TAG="${IMAGE_TAG:-iyou-idp:latest}"

echo "==> Building ${IMAGE_TAG} ..."
docker build \
    --tag "${IMAGE_TAG}" \
    --file Dockerfile \
    --progress=plain \
    .

echo "==> Build complete: ${IMAGE_TAG}"
docker image inspect "${IMAGE_TAG}" --format '{{.Size}}' | \
    awk '{printf "==> Image size: %.2f MB\n", $1 / 1024 / 1024}'
