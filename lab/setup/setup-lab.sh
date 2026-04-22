#!/usr/bin/env bash
# Orchestrator: deploy the full testing lab
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LAB_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Deploy the container vulnerabilities testing lab.

Options:
    --location LOC          Azure region (default: westeurope)
    --base-name NAME        Base name for resources (default: cvulnlab)
    --ssh-key FILE          Path to SSH public key (default: ~/.ssh/id_rsa.pub)
    --admin-user USER       VM admin username (default: azureuser)
    --skip-infra            Skip Bicep deployment (use existing infra)
    --skip-arc              Skip Arc-enabling the cluster
    --skip-images           Skip pushing images to ACR
    --skip-deploy           Skip deploying workloads to k3s
    --docker-hub-user USER  Docker Hub username (avoids rate limits)
    --docker-hub-pass PASS  Docker Hub password or PAT
    --help                  Show this help message

EOF
    exit 0
}

LOCATION="westeurope"
BASE_NAME="cvulnlab"
SSH_KEY_FILE="$HOME/.ssh/id_rsa.pub"
ADMIN_USER="azureuser"
SKIP_INFRA=false
SKIP_ARC=false
SKIP_IMAGES=false
SKIP_DEPLOY=false
DOCKER_HUB_USER=""
DOCKER_HUB_PASS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --location) LOCATION="$2"; shift 2 ;;
        --base-name) BASE_NAME="$2"; shift 2 ;;
        --ssh-key) SSH_KEY_FILE="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --skip-infra) SKIP_INFRA=true; shift ;;
        --skip-arc) SKIP_ARC=true; shift ;;
        --skip-images) SKIP_IMAGES=true; shift ;;
        --skip-deploy) SKIP_DEPLOY=true; shift ;;
        --docker-hub-user) DOCKER_HUB_USER="$2"; shift 2 ;;
        --docker-hub-pass) DOCKER_HUB_PASS="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

RG_NAME="${BASE_NAME}-rg"

log_header "Container Vulnerabilities Testing Lab Setup"

# Validate prerequisites
for cmd in az jq ssh; do
    if ! command -v "$cmd" &>/dev/null; then
        log_error "Missing required tool: $cmd"
        exit 2
    fi
done

if ! az account show &>/dev/null; then
    log_error "Not logged in to Azure. Run 'az login' first."
    exit 2
fi

if [[ ! -f "$SSH_KEY_FILE" ]]; then
    log_error "SSH public key not found: $SSH_KEY_FILE"
    log_error "Generate one with: ssh-keygen -t rsa -b 4096"
    exit 2
fi

SSH_PUBLIC_KEY=$(cat "$SSH_KEY_FILE")
SUBSCRIPTION_ID=$(az account show --query id -o tsv)
log_info "Subscription: $SUBSCRIPTION_ID"
log_info "Location:     $LOCATION"
log_info "Base name:    $BASE_NAME"

# ── Step 1: Deploy infrastructure ──────────────────────────────────────
if [[ "$SKIP_INFRA" == false ]]; then
    log_header "Step 1: Deploying Infrastructure (Bicep)"

    az deployment sub create \
        --name "${BASE_NAME}-lab-$(date +%s)" \
        --location "$LOCATION" \
        --template-file "$LAB_DIR/infra/main.bicep" \
        --parameters \
            location="$LOCATION" \
            baseName="$BASE_NAME" \
            adminUsername="$ADMIN_USER" \
            sshPublicKey="$SSH_PUBLIC_KEY" \
        --output table

    log_success "Infrastructure deployed"
else
    log_info "Skipping infrastructure deployment"
fi

# Get deployment outputs
VM_IP=$(az deployment sub show \
    --name "$(az deployment sub list --query "[?starts_with(name, '${BASE_NAME}-lab-')] | sort_by(@, &properties.timestamp) | [-1].name" -o tsv)" \
    --query "properties.outputs.vmPublicIp.value" -o tsv 2>/dev/null || \
    az network public-ip show --resource-group "$RG_NAME" --name "${BASE_NAME}-pip" --query ipAddress -o tsv)

ACR_NAME=$(az acr list --resource-group "$RG_NAME" --query "[0].name" -o tsv)
ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)

log_info "VM Public IP:    $VM_IP"
log_info "ACR Name:        $ACR_NAME"
log_info "ACR Login Server: $ACR_LOGIN_SERVER"

# ── Step 2: Wait for VM cloud-init to finish ───────────────────────────
log_header "Step 2: Waiting for VM Setup (k3s installation)"

MAX_WAIT=300
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${ADMIN_USER}@${VM_IP}" \
        "test -f /home/${ADMIN_USER}/.lab-setup-complete" 2>/dev/null; then
        break
    fi
    echo -n "."
    sleep 10
    WAITED=$((WAITED + 10))
done
echo ""

if [[ $WAITED -ge $MAX_WAIT ]]; then
    log_error "VM setup did not complete within ${MAX_WAIT}s"
    log_error "SSH in and check: ssh ${ADMIN_USER}@${VM_IP}"
    exit 2
fi

log_success "VM is ready with k3s installed"

# Verify k3s
ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" "kubectl get nodes"

# ── Step 3: Arc-enable the k3s cluster ─────────────────────────────────
if [[ "$SKIP_ARC" == false ]]; then
    log_header "Step 3: Arc-enabling the k3s Cluster"
    "$SCRIPT_DIR/arc-enable.sh" \
        --vm-ip "$VM_IP" \
        --admin-user "$ADMIN_USER" \
        --resource-group "$RG_NAME" \
        --cluster-name "${BASE_NAME}-k3s" \
        --location "$LOCATION"
else
    log_info "Skipping Arc enablement"
fi

# ── Step 4: Push images to ACR ─────────────────────────────────────────
if [[ "$SKIP_IMAGES" == false ]]; then
    log_header "Step 4: Pushing Container Images to ACR"
    push_args=(--acr-name "$ACR_NAME")
    [[ -n "$DOCKER_HUB_USER" ]] && push_args+=(--docker-hub-user "$DOCKER_HUB_USER")
    [[ -n "$DOCKER_HUB_PASS" ]] && push_args+=(--docker-hub-pass "$DOCKER_HUB_PASS")
    "$SCRIPT_DIR/push-images.sh" "${push_args[@]}"
else
    log_info "Skipping image push"
fi

# ── Step 5: Deploy workloads to k3s ───────────────────────────────────
if [[ "$SKIP_DEPLOY" == false ]]; then
    log_header "Step 5: Deploying Workloads to k3s"

    # Create ACR pull secret on the cluster
    ACR_PASSWORD=$(az acr credential show --name "$ACR_NAME" --query "passwords[0].value" -o tsv)

    ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" bash <<REMOTE
set -euo pipefail
kubectl create namespace vuln-test 2>/dev/null || true
kubectl create secret docker-registry acr-secret \
    --namespace vuln-test \
    --docker-server="${ACR_LOGIN_SERVER}" \
    --docker-username="${ACR_NAME}" \
    --docker-password="${ACR_PASSWORD}" \
    2>/dev/null || true
REMOTE

    # Copy and apply manifests
    scp -o StrictHostKeyChecking=no \
        "$LAB_DIR/manifests/vulnerable-deployments.yaml" \
        "$LAB_DIR/manifests/clean-deployments.yaml" \
        "${ADMIN_USER}@${VM_IP}:/tmp/"

    ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" bash <<REMOTE
set -euo pipefail
# Replace ACR_LOGIN_SERVER placeholder in manifests
sed -i "s|__ACR_LOGIN_SERVER__|${ACR_LOGIN_SERVER}|g" /tmp/vulnerable-deployments.yaml
sed -i "s|__ACR_LOGIN_SERVER__|${ACR_LOGIN_SERVER}|g" /tmp/clean-deployments.yaml

kubectl apply -f /tmp/vulnerable-deployments.yaml
kubectl apply -f /tmp/clean-deployments.yaml

echo "Waiting for pods to be ready..."
kubectl wait --namespace vuln-test --for=condition=available --timeout=120s deployment --all || true
kubectl get pods -n vuln-test
REMOTE

    log_success "Workloads deployed"
else
    log_info "Skipping workload deployment"
fi

# ── Done ───────────────────────────────────────────────────────────────
log_header "Lab Setup Complete"
echo ""
log_info "VM SSH:          ssh ${ADMIN_USER}@${VM_IP}"
log_info "Resource Group:  $RG_NAME"
log_info "ACR:             $ACR_LOGIN_SERVER"
log_info "Arc Cluster:     ${BASE_NAME}-k3s"
echo ""
log_info "Wait ~15 min for Defender to scan ACR images, then run:"
log_info "  ./lab/test/validate.sh --resource-group $RG_NAME --cluster-name ${BASE_NAME}-k3s"
echo ""
log_info "To run the vulnerability check:"
log_info "  ./scripts/check-vulnerabilities.sh --resource-group $RG_NAME"
echo ""
log_info "To tear down the lab:"
log_info "  az group delete --name $RG_NAME --yes --no-wait"
