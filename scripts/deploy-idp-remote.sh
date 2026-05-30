#!/bin/bash
# Deploy iyou-idp via cross-VM pipeline (local stream -> dc13 build -> K3s import -> Helm release)
# Usage: LOCAL_IDP_PATH=/path/to/iyou_idp ./scripts/deploy-idp-remote.sh
#
# Prerequisites:
#   - SSH host aliases: 'dc13' (build VM, 100.64.0.7) and 'k3s' (K3s node, 192.168.1.6) in ~/.ssh/config
#   - LOCAL_IDP_PATH points to local iyou_idp checkout with a valid Dockerfile
#   - dc13: Docker daemon running, /home/dc13/builds/ directory writable
#   - Local: k3s-kubeconfig.yaml in current working directory
#   - Passwordless sudo for k3s ctr on K3s node
#   - Helm chart present at $REPO_ROOT/apps/iyou-idp/

set -euo pipefail

LOCAL_IDP_PATH="${LOCAL_IDP_PATH:-}"
IMAGE_TAR="iyou-idp-latest.tar"
REMOTE_BUILDS_DIR="/home/dc13/builds"
KUBECONFIG_FILE="$(pwd)/k3s-kubeconfig.yaml"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "╔══════════════════════════════════════════════════════╗"
echo "║   iyou-idp Cross-VM Deployment Pipeline            ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""

# ── Preflight ──────────────────────────────────────────────
if [ ! -f "$KUBECONFIG_FILE" ]; then
    echo "ERROR: k3s-kubeconfig.yaml not found at $KUBECONFIG_FILE"
    echo "  Run this script from the directory containing k3s-kubeconfig.yaml"
    exit 1
fi

if [ -z "$LOCAL_IDP_PATH" ]; then
    echo "ERROR: LOCAL_IDP_PATH must be set to the local iyou_idp checkout"
    echo "  Usage: LOCAL_IDP_PATH=/path/to/iyou_idp $0"
    exit 1
fi

if [ ! -d "$LOCAL_IDP_PATH" ]; then
    echo "ERROR: LOCAL_IDP_PATH '$LOCAL_IDP_PATH' does not exist"
    exit 1
fi

if [ ! -f "$LOCAL_IDP_PATH/Dockerfile" ]; then
    echo "ERROR: No Dockerfile found in $LOCAL_IDP_PATH"
    exit 1
fi

# ── Stage 1: Seed Vault Secrets ────────────────────────────
echo "▸ STAGE 1/6 — Seed Vault secrets"
VAULT_PATH="secret/mesh-infra/iyou-idp"
VAULT_FULL="secret/data/mesh-infra/iyou-idp"
if KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- vault kv get "$VAULT_FULL" &>/dev/null; then
    echo "  └─ Vault secret exists, ensuring all fields"
    KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- \
        vault kv patch "$VAULT_PATH" secret_key="$(openssl rand -hex 32)" 2>/dev/null || true
    KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- \
        vault kv patch "$VAULT_PATH" database_url="postgres://iyou_idp:$(openssl rand -hex 32)@postgres.identity.svc.cluster.local:5432/iyou_idp" 2>/dev/null || true
else
    echo "  └─ Generating and injecting all secrets into Vault"
    DB_PASS="$(openssl rand -hex 32)"
    KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- vault kv put "$VAULT_PATH" \
        secret_key="$(openssl rand -hex 32)" \
        database_url="postgres://iyou_idp:${DB_PASS}@postgres.identity.svc.cluster.local:5432/iyou_idp"
    echo "  ✓ Secrets injected: $VAULT_FULL"
fi

# Force ExternalSecret to sync immediately
echo "  └─ Syncing ExternalSecret from Vault"
KUBECONFIG="$KUBECONFIG_FILE" kubectl describe externalsecret -n identity iyou-idp-es &>/dev/null && \
  KUBECONFIG="$KUBECONFIG_FILE" kubectl create secret generic -n identity iyou-idp-secret \
    --from-literal=IDP_SECRET_KEY="$(KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- vault kv get -field=secret_key "$VAULT_PATH" 2>/dev/null)" \
    --from-literal=DATABASE_URL="$(KUBECONFIG="$KUBECONFIG_FILE" kubectl exec -n vault vault-0 -- vault kv get -field=database_url "$VAULT_PATH" 2>/dev/null)" \
    --dry-run=client -o yaml | KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f - 2>/dev/null || true
echo ""

# ── Stage 2: Stream local repo -> dc13 Docker build ───────
echo "▸ STAGE 2/6 — Stream local repo -> dc13 Docker build"
echo "  └─ tar -czf - . | ssh dc13 \"docker build --no-cache --tag iyou-idp:latest -\""
cd "$LOCAL_IDP_PATH" && tar -czf - . | ssh dc13 "docker build --no-cache --tag iyou-idp:latest -"
echo "  ✓ Image built natively on dc13 (x86_64)"
echo ""

# ── Stage 3: Export image to tarball on dc13 ───────────────
echo "▸ STAGE 3/6 — Export image to tarball on dc13"
echo "  └─ docker save -> $REMOTE_BUILDS_DIR/$IMAGE_TAR"
ssh dc13 "mkdir -p '$REMOTE_BUILDS_DIR' && docker save iyou-idp:latest -o '$REMOTE_BUILDS_DIR/$IMAGE_TAR'"
echo "  ✓ Image exported: $REMOTE_BUILDS_DIR/$IMAGE_TAR"
echo ""

# ── Stage 4: Encrypted transit dc13 -> K3s node ────────────
echo "▸ STAGE 4/6 — Secure transit dc13 -> k3s"
echo "  └─ Streaming tarball through encrypted SSH tunnel"
ssh dc13 "cat '$REMOTE_BUILDS_DIR/$IMAGE_TAR'" | ssh k3s "cat > /tmp/$IMAGE_TAR"
echo "  ✓ Tarball delivered to k3s:/tmp/$IMAGE_TAR"
echo ""

# ── Stage 5: Remove stale image, then import fresh ─────────
echo "▸ STAGE 5/6 — Replace image in k3s container runtime"
echo "  └─ Removing stale image (avoids kubelet caching stale manifest)"
ssh k3s "sudo ctr image rm docker.io/library/iyou-idp:latest 2>/dev/null; echo '(stale removed or absent)'"
echo "  └─ Importing fresh image from tarball"
ssh k3s "sudo k3s ctr images import /tmp/$IMAGE_TAR"
echo "  ✓ Fresh image imported into k3s runtime"
echo ""

# ── Stage 6: Helm Release Upgrade ──────────────────────────
echo "▸ STAGE 6/6 — Helm upgrade --install iyou-idp + rollout restart"
echo "  └─ Creating identity namespace (if absent)"
KUBECONFIG="$KUBECONFIG_FILE" kubectl create namespace identity --dry-run=client -o yaml | \
    KUBECONFIG="$KUBECONFIG_FILE" kubectl apply -f -
echo "  └─ KUBECONFIG=$KUBECONFIG_FILE helm upgrade ..."
KUBECONFIG="$KUBECONFIG_FILE" helm upgrade --install iyou-idp "$REPO_ROOT/apps/iyou-idp" \
    --namespace identity \
    --create-namespace \
    --wait \
    --timeout 5m
echo "  ✓ Helm release upgraded"
echo ""
echo "  └─ Forcing rollout restart (kubelet re-resolves image tag)"
KUBECONFIG="$KUBECONFIG_FILE" kubectl rollout restart deployment -n identity iyou-idp
echo "  ✓ Pod restart triggered"
echo ""

# ── Cleanup: purge tarballs from both hosts ────────────────
echo "▸ Cleanup — removing staging tarballs"
ssh dc13 "rm -f '$REMOTE_BUILDS_DIR/$IMAGE_TAR'" && echo "  ✓ dc13: $IMAGE_TAR removed"
ssh k3s "sudo rm -f /tmp/$IMAGE_TAR" && echo "  ✓ k3s: /tmp/$IMAGE_TAR removed"
echo ""

# ── Summary ─────────────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════╗"
echo "║   Deployment Complete                               ║"
echo "╚══════════════════════════════════════════════════════╝"
echo ""
echo "  Pipeline summary:"
echo "    STAGE 1  Seed Vault secrets                    ── local      ✓"
echo "    STAGE 2  tar stream -> dc13 docker build       ── local>dc13 ✓"
echo "    STAGE 3  docker save -> tarball                ── dc13       ✓"
echo "    STAGE 4  SSH tunnel transfer                   ── dc13>k3s   ✓"
echo "    STAGE 5  ctr rm + import fresh                 ── k3s        ✓"
echo "    STAGE 6  helm upgrade + rollout restart        ── local      ✓"
echo "    CLEANUP  tarballs purged                       ── dc13+k3s   ✓"
echo ""
echo "  Access: https://id.iyou.me"
echo ""
echo "  Status check:"
echo "    KUBECONFIG=$KUBECONFIG_FILE kubectl get pods -n identity"
echo "    KUBECONFIG=$KUBECONFIG_FILE kubectl get ingress -n identity"
echo ""
echo "  Satellite callback URLs (cluster-internal):"
echo "    IDP_BASE_URL=http://iyou-idp.identity.svc.cluster.local:8000"
echo "    IDP_WUN_URL=http://iyou-wun.satellite.svc.cluster.local:8001"
echo "    IDP_HOME_URL=http://iyou-home.user.svc.cluster.local:9000"
echo "    IDP_HOME_WS_URL=ws://iyou-home.user.svc.cluster.local:9001"
