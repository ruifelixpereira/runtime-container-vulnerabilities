#!/usr/bin/env bash
# Arc-enable a k3s cluster running on a remote VM
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Arc-enable a k3s cluster running on an Azure VM.

Options:
    --vm-ip IP              Public IP of the VM (required)
    --admin-user USER       VM admin username (default: azureuser)
    --resource-group RG     Resource group for the Arc resource (required)
    --cluster-name NAME     Name for the Arc-enabled cluster (required)
    --location LOC          Azure location (default: westeurope)
    --help                  Show this help message

EOF
    exit 0
}

VM_IP=""
ADMIN_USER="azureuser"
RG=""
CLUSTER_NAME=""
LOCATION="westeurope"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vm-ip) VM_IP="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --resource-group) RG="$2"; shift 2 ;;
        --cluster-name) CLUSTER_NAME="$2"; shift 2 ;;
        --location) LOCATION="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$VM_IP" || -z "$RG" || -z "$CLUSTER_NAME" ]]; then
    log_error "Missing required parameters"
    usage
fi

SUBSCRIPTION_ID=$(az account show --query id -o tsv)

log_info "Arc-enabling k3s cluster on $VM_IP as '$CLUSTER_NAME'..."
log_info "Running locally with SSH tunnel to VM's k3s API server (no az login on VM needed)"

# Ensure connectedk8s extension is installed locally
az extension add --name connectedk8s --yes 2>/dev/null || true

# Fetch kubeconfig from the VM
LOCAL_KUBECONFIG="/tmp/arc-enable-k3s-kubeconfig-$$"
log_info "Fetching kubeconfig from VM..."
scp -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}:/etc/rancher/k3s/k3s.yaml" "$LOCAL_KUBECONFIG"

# Set up SSH tunnel: forward a local port to the k3s API server on the VM (port 6443)
LOCAL_PORT=$((RANDOM % 10000 + 40000))
log_info "Opening SSH tunnel on local port $LOCAL_PORT -> ${VM_IP}:6443..."
ssh -o StrictHostKeyChecking=no -N -L "${LOCAL_PORT}:127.0.0.1:6443" "${ADMIN_USER}@${VM_IP}" &
TUNNEL_PID=$!

cleanup_tunnel() {
    kill "$TUNNEL_PID" 2>/dev/null || true
    rm -f "$LOCAL_KUBECONFIG" 2>/dev/null || true
}
trap cleanup_tunnel EXIT

# Wait for tunnel to be ready
sleep 3

# Rewrite kubeconfig to point to the local tunnel
sed -i "s|server: https://127.0.0.1:6443|server: https://127.0.0.1:${LOCAL_PORT}|g" "$LOCAL_KUBECONFIG"

# Verify connectivity through the tunnel
log_info "Verifying k3s connectivity through tunnel..."
if ! kubectl --kubeconfig "$LOCAL_KUBECONFIG" --insecure-skip-tls-verify get nodes; then
    log_error "Cannot reach k3s API through SSH tunnel"
    exit 2
fi

# Run az connectedk8s connect locally (uses local az session, no login on VM needed)
log_info "Connecting cluster to Azure Arc..."
az connectedk8s connect \
    --name "$CLUSTER_NAME" \
    --resource-group "$RG" \
    --location "$LOCATION" \
    --subscription "$SUBSCRIPTION_ID" \
    --kube-config "$LOCAL_KUBECONFIG" \
    --distribution k3s \
    --infrastructure generic

log_info "Verifying Arc pods on the VM..."
ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" \
    "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl get pods -n azure-arc"

# Create ClusterRoleBinding so the AAD user can access the cluster through Arc proxy
AAD_USER=$(az ad signed-in-user show --query userPrincipalName -o tsv 2>/dev/null || true)
if [[ -n "$AAD_USER" ]]; then
    log_info "Creating ClusterRoleBinding for AAD user '$AAD_USER'..."
    ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" \
        "KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl create clusterrolebinding arc-aad-admin --clusterrole=cluster-admin --user='${AAD_USER}' 2>/dev/null || true"
    log_success "AAD user '$AAD_USER' granted cluster-admin via Arc proxy"
fi

# Verify from Azure side
log_info "Verifying Arc cluster from Azure..."
MAX_WAIT=60
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    STATUS=$(az connectedk8s show \
        --name "$CLUSTER_NAME" \
        --resource-group "$RG" \
        --query "properties.connectivityStatus" -o tsv 2>/dev/null || echo "NotFound")
    if [[ "$STATUS" == "Connected" ]]; then
        break
    fi
    sleep 10
    WAITED=$((WAITED + 10))
done

if [[ "$STATUS" == "Connected" ]]; then
    log_success "Arc cluster '$CLUSTER_NAME' is connected"
else
    log_error "Arc cluster status: $STATUS (may take a few more minutes)"
fi
