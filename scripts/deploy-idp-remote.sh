#!/bin/bash
# Wrapper delegating to canonical deploy-idp-remote.sh in k3s_vm
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
K3S_DEPLOY="$REPO_ROOT/../k3s_vm/scripts/deploy-idp-remote.sh"

if [ ! -f "$K3S_DEPLOY" ]; then
    echo "ERROR: Canonical deploy script not found at $K3S_DEPLOY"
    exit 1
fi

LOCAL_IDP_PATH="${LOCAL_IDP_PATH:-$REPO_ROOT}" exec "$K3S_DEPLOY" "$@"
