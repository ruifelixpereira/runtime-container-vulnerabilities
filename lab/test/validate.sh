#!/usr/bin/env bash
# Validate that the lab is working: running containers have known vulnerabilities
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[PASS]${NC} $*"; }
log_fail()    { echo -e "${RED}[FAIL]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Validate that the testing lab is set up correctly and that Defender has
found vulnerabilities in the running containers.

Options:
    --resource-group RG     Resource group (required)
    --cluster-name NAME     Arc cluster name (required)
    --vm-ip IP              VM public IP (auto-detected if not set)
    --admin-user USER       VM admin username (default: azureuser)
    --acr-name NAME         ACR name (auto-detected if not set)
    --help                  Show this help message

EOF
    exit 0
}

RG=""
CLUSTER_NAME=""
VM_IP=""
ADMIN_USER="azureuser"
ACR_NAME=""
PASS_COUNT=0
FAIL_COUNT=0
WARN_COUNT=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --resource-group) RG="$2"; shift 2 ;;
        --cluster-name) CLUSTER_NAME="$2"; shift 2 ;;
        --vm-ip) VM_IP="$2"; shift 2 ;;
        --admin-user) ADMIN_USER="$2"; shift 2 ;;
        --acr-name) ACR_NAME="$2"; shift 2 ;;
        --help) usage ;;
        *) log_fail "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$RG" || -z "$CLUSTER_NAME" ]]; then
    log_fail "Resource group and cluster name are required"
    usage
fi

assert_pass() { log_success "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
assert_fail() { log_fail "$1"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
assert_warn() { log_warn "$1"; WARN_COUNT=$((WARN_COUNT + 1)); }

log_header "Testing Lab Validation"

# ── Test 1: Resource group exists ──────────────────────────────────────
log_info "Test 1: Resource group exists"
if az group show --name "$RG" &>/dev/null; then
    assert_pass "Resource group '$RG' exists"
else
    assert_fail "Resource group '$RG' not found"
    exit 2
fi

# ── Test 2: ACR exists and has images ──────────────────────────────────
log_info "Test 2: ACR exists with images"
if [[ -z "$ACR_NAME" ]]; then
    ACR_NAME=$(az acr list --resource-group "$RG" --query "[0].name" -o tsv 2>/dev/null)
fi

if [[ -n "$ACR_NAME" ]]; then
    assert_pass "ACR '$ACR_NAME' exists"

    REPO_COUNT=$(az acr repository list --name "$ACR_NAME" -o tsv 2>/dev/null | wc -l)
    if [[ "$REPO_COUNT" -ge 5 ]]; then
        assert_pass "ACR has $REPO_COUNT repositories (expected >= 5 vulnerable)"
    else
        assert_fail "ACR has only $REPO_COUNT repositories (expected >= 5)"
    fi

    # Check vulnerable images exist
    for repo in vuln/nginx vuln/node vuln/httpd vuln/redis vuln/postgres; do
        if az acr repository show --name "$ACR_NAME" --repository "$repo" &>/dev/null; then
            assert_pass "ACR repository '$repo' exists"
        else
            assert_fail "ACR repository '$repo' missing"
        fi
    done
else
    assert_fail "No ACR found in resource group '$RG'"
fi

# ── Test 3: Arc cluster is connected ──────────────────────────────────
log_info "Test 3: Arc cluster is connected"
ARC_STATUS=$(az connectedk8s show \
    --name "$CLUSTER_NAME" \
    --resource-group "$RG" \
    --query "properties.connectivityStatus" -o tsv 2>/dev/null || echo "NotFound")

if [[ "$ARC_STATUS" == "Connected" ]]; then
    assert_pass "Arc cluster '$CLUSTER_NAME' is connected"
else
    assert_fail "Arc cluster status: $ARC_STATUS (expected: Connected)"
fi

# ── Test 4: VM is reachable and k3s is running ─────────────────────────
log_info "Test 4: VM and k3s health"
if [[ -z "$VM_IP" ]]; then
    VM_IP=$(az network public-ip list --resource-group "$RG" --query "[0].ipAddress" -o tsv 2>/dev/null)
fi

if [[ -n "$VM_IP" ]]; then
    if ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "${ADMIN_USER}@${VM_IP}" "kubectl get nodes" &>/dev/null; then
        assert_pass "VM reachable and k3s is running"

        # Check pods in vuln-test namespace
        POD_STATUS=$(ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" \
            "kubectl get pods -n vuln-test -o json" 2>/dev/null)

        TOTAL_PODS=$(echo "$POD_STATUS" | jq '.items | length')
        RUNNING_PODS=$(echo "$POD_STATUS" | jq '[.items[] | select(.status.phase == "Running")] | length')

        if [[ "$TOTAL_PODS" -ge 7 ]]; then
            assert_pass "Found $TOTAL_PODS pods in vuln-test namespace (expected >= 7)"
        else
            assert_fail "Only $TOTAL_PODS pods in vuln-test (expected >= 7: 5 vuln + 2 clean)"
        fi

        if [[ "$RUNNING_PODS" -ge 5 ]]; then
            assert_pass "$RUNNING_PODS pods are running"
        else
            assert_warn "Only $RUNNING_PODS/$TOTAL_PODS pods running"
        fi

        # Check vulnerable pods specifically
        VULN_PODS=$(echo "$POD_STATUS" | jq '[.items[] | select(.metadata.labels["test-type"] == "vulnerable")] | length')
        CLEAN_PODS=$(echo "$POD_STATUS" | jq '[.items[] | select(.metadata.labels["test-type"] == "clean")] | length')
        log_info "  Vulnerable pods: $VULN_PODS | Clean pods: $CLEAN_PODS"

        # Check that pods have image digests (needed for cross-referencing)
        PODS_WITH_DIGEST=$(echo "$POD_STATUS" | jq '
            [.items[] |
             .status.containerStatuses[]? |
             select(.imageID != null and (.imageID | test("sha256:")))
            ] | length')

        if [[ "$PODS_WITH_DIGEST" -ge 5 ]]; then
            assert_pass "$PODS_WITH_DIGEST containers have image digests (sha256)"
        else
            assert_warn "Only $PODS_WITH_DIGEST containers have image digests"
        fi
    else
        assert_fail "Cannot reach VM at $VM_IP or k3s not running"
    fi
else
    assert_fail "Could not determine VM IP"
fi

# ── Test 5: Defender for Containers is enabled ─────────────────────────
log_info "Test 5: Defender for Containers is enabled"
DEFENDER_TIER=$(az security pricing show --name Containers --query pricingTier -o tsv 2>/dev/null || echo "NotFound")

if [[ "$DEFENDER_TIER" == "Standard" ]]; then
    assert_pass "Defender for Containers is enabled (Standard tier)"
else
    assert_fail "Defender for Containers tier: $DEFENDER_TIER (expected: Standard)"
fi

# ── Test 6: Vulnerability findings exist in Resource Graph ─────────────
log_info "Test 6: Defender vulnerability findings in ACR"

if ! az extension show --name resource-graph &>/dev/null; then
    az extension add --name resource-graph --yes 2>/dev/null
fi

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv 2>/dev/null)

VULN_QUERY="securityresources
| where type == 'microsoft.security/assessments/subassessments'
| where properties.additionalData.assessedResourceType == 'AzureContainerRegistryVulnerability'
| where properties.additionalData.registryHost =~ '${ACR_LOGIN_SERVER}'
| summarize
    totalFindings = count(),
    uniqueImages = dcount(tostring(properties.additionalData.imageDigest)),
    critical = countif(properties.status.severity == 'Critical'),
    high = countif(properties.status.severity == 'High'),
    medium = countif(properties.status.severity == 'Medium'),
    low = countif(properties.status.severity == 'Low')"

VULN_RESULT=$(az graph query -q "$VULN_QUERY" --first 1 -o json 2>/dev/null | jq '.data[0]' 2>/dev/null || echo "{}")

TOTAL_FINDINGS=$(echo "$VULN_RESULT" | jq '.totalFindings // 0')
UNIQUE_VULN_IMAGES=$(echo "$VULN_RESULT" | jq '.uniqueImages // 0')
CRITICAL=$(echo "$VULN_RESULT" | jq '.critical // 0')
HIGH=$(echo "$VULN_RESULT" | jq '.high // 0')

if [[ "$TOTAL_FINDINGS" -gt 0 ]]; then
    assert_pass "Defender found $TOTAL_FINDINGS vulnerabilities across $UNIQUE_VULN_IMAGES images"
    log_info "  Critical: $CRITICAL | High: $HIGH | Medium: $(echo "$VULN_RESULT" | jq '.medium // 0') | Low: $(echo "$VULN_RESULT" | jq '.low // 0')"
else
    assert_warn "No vulnerability findings yet — Defender may still be scanning (wait 5-15 min)"
fi

# ── Test 7: Cross-reference check ─────────────────────────────────────
log_info "Test 7: Cross-reference running images with vulnerabilities"

if [[ "$TOTAL_FINDINGS" -gt 0 && -n "$VM_IP" ]]; then
    # Get digests from running pods
    RUNNING_DIGESTS=$(ssh -o StrictHostKeyChecking=no "${ADMIN_USER}@${VM_IP}" \
        "kubectl get pods -n vuln-test -o json" 2>/dev/null | jq -r '
        [.items[] |
         .status.containerStatuses[]? |
         .imageID |
         select(. != null) |
         capture("(?<digest>sha256:[a-f0-9]+)") |
         .digest
        ] | unique | .[]')

    # Get digests with vulnerabilities
    VULN_DIGEST_QUERY="securityresources
| where type == 'microsoft.security/assessments/subassessments'
| where properties.additionalData.assessedResourceType == 'AzureContainerRegistryVulnerability'
| where properties.additionalData.registryHost =~ '${ACR_LOGIN_SERVER}'
| distinct tostring(properties.additionalData.imageDigest)"

    VULN_DIGESTS=$(az graph query -q "$VULN_DIGEST_QUERY" --first 1000 -o json 2>/dev/null | \
        jq -r '.data[].Column1' 2>/dev/null || echo "")

    MATCH_COUNT=0
    for digest in $RUNNING_DIGESTS; do
        if echo "$VULN_DIGESTS" | grep -q "$digest"; then
            MATCH_COUNT=$((MATCH_COUNT + 1))
        fi
    done

    if [[ "$MATCH_COUNT" -gt 0 ]]; then
        assert_pass "Found $MATCH_COUNT running containers with known vulnerabilities"
    else
        assert_warn "No digest matches yet — Defender may still be processing"
    fi
else
    assert_warn "Skipping cross-reference (no findings or VM unreachable)"
fi

# ── Summary ────────────────────────────────────────────────────────────
log_header "Validation Summary"
echo -e "  ${GREEN}Passed:   $PASS_COUNT${NC}"
echo -e "  ${RED}Failed:   $FAIL_COUNT${NC}"
echo -e "  ${YELLOW}Warnings: $WARN_COUNT${NC}"
echo ""

if [[ $FAIL_COUNT -gt 0 ]]; then
    log_fail "Some tests failed. Review the output above."
    exit 1
elif [[ $WARN_COUNT -gt 0 ]]; then
    log_warn "All critical tests passed, but some checks need attention."
    log_info "If Defender hasn't scanned yet, wait 15 min and re-run this script."
    exit 0
else
    log_success "All tests passed! The lab is fully operational."
    exit 0
fi
