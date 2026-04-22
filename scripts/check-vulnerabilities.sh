#!/usr/bin/env bash
# Main orchestrator: check running containers for known vulnerabilities
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Check running containers on Arc-enabled K8s clusters for known vulnerabilities
detected by Microsoft Defender for Containers.

Options:
    --subscription ID       Azure subscription ID(s), comma-separated
    --resource-group RG     Resource group with Arc clusters (required)
    --clusters NAMES        Comma-separated cluster names (default: all in RG)
    --registries NAMES      Filter ACR registries (default: all)
    --exclude-ns NAMES      Namespaces to exclude (default: system namespaces)
    --severity LEVEL        Minimum severity: Critical, High, Medium, Low (default: Medium)
    --format FORMAT         Output: table, json, csv (default: table)
    --save                  Save report to output/ directory
    --help                  Show this help message

Examples:
    $(basename "$0") --resource-group myRG
    $(basename "$0") --resource-group myRG --clusters cluster1,cluster2 --severity High
    $(basename "$0") --resource-group myRG --format json --save

EOF
    exit 0
}

# Load env defaults
load_env

SUBSCRIPTION="${SUBSCRIPTION_ID:-}"
RG="${RESOURCE_GROUP:-}"
CLUSTERS="${CLUSTER_NAMES:-}"
REGISTRIES="${REGISTRY_NAMES:-}"
EXCLUDE_NS="${NAMESPACES_EXCLUDE:-kube-system,kube-public,kube-node-lease,gatekeeper-system,azure-arc}"
SEVERITY="${SEVERITY_THRESHOLD:-Medium}"
FORMAT="${OUTPUT_FORMAT:-table}"
SAVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscription) SUBSCRIPTION="$2"; shift 2 ;;
        --resource-group) RG="$2"; shift 2 ;;
        --clusters) CLUSTERS="$2"; shift 2 ;;
        --registries) REGISTRIES="$2"; shift 2 ;;
        --exclude-ns) EXCLUDE_NS="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        --save) SAVE=true; shift ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$RG" ]]; then
    log_error "Resource group is required. Set RESOURCE_GROUP in .env or use --resource-group"
    exit 2
fi

log_header "Container Runtime Vulnerability Check"
log_info "Configuration:"
log_info "  Resource Group:  $RG"
log_info "  Clusters:        ${CLUSTERS:-<all in RG>}"
log_info "  Registries:      ${REGISTRIES:-<all>}"
log_info "  Severity:        >= $SEVERITY"
log_info "  Format:          $FORMAT"
echo ""

# Step 1: Check prerequisites
log_header "Step 1: Checking Prerequisites"
check_prerequisites
log_success "All prerequisites met"

# Step 2: Query vulnerability findings
log_header "Step 2: Querying ACR Vulnerability Findings"
VULNS_FILE="${TMP_PREFIX}-vulns.json"

vuln_args=(--output "$VULNS_FILE" --severity "$SEVERITY")
[[ -n "$SUBSCRIPTION" ]] && vuln_args+=(--subscriptions "$SUBSCRIPTION")
[[ -n "$REGISTRIES" ]] && vuln_args+=(--registries "$REGISTRIES")

"$SCRIPT_DIR/query-acr-vulnerabilities.sh" "${vuln_args[@]}"

VULN_IMAGE_COUNT=$(jq 'length' "$VULNS_FILE")
if [[ "$VULN_IMAGE_COUNT" -eq 0 ]]; then
    log_success "No vulnerability findings in ACR. Nothing to cross-reference."
    exit 0
fi

# Step 3: Query running images from Arc clusters
log_header "Step 3: Querying Running Images from Arc Clusters"
IMAGES_FILE="${TMP_PREFIX}-images.json"

image_args=(--resource-group "$RG" --output "$IMAGES_FILE" --exclude-ns "$EXCLUDE_NS")
[[ -n "$CLUSTERS" ]] && image_args+=(--clusters "$CLUSTERS")

"$SCRIPT_DIR/query-running-images.sh" "${image_args[@]}"

IMAGE_COUNT=$(jq 'length' "$IMAGES_FILE")
if [[ "$IMAGE_COUNT" -eq 0 ]]; then
    log_warn "No running containers found. Nothing to cross-reference."
    exit 0
fi

# Step 4: Cross-reference and generate report
log_header "Step 4: Generating Vulnerability Report"

report_args=(--vulns "$VULNS_FILE" --images "$IMAGES_FILE" --severity "$SEVERITY" --format "$FORMAT")

if [[ "$SAVE" == true ]]; then
    ensure_output_dir
    TIMESTAMP=$(date +%Y%m%d-%H%M%S)
    REPORT_EXT="txt"
    [[ "$FORMAT" == "json" ]] && REPORT_EXT="json"
    [[ "$FORMAT" == "csv" ]] && REPORT_EXT="csv"
    REPORT_FILE="${OUTPUT_DIR}/vulnerability-report-${TIMESTAMP}.${REPORT_EXT}"
    report_args+=(--output "$REPORT_FILE")
fi

"$SCRIPT_DIR/cross-reference.sh" "${report_args[@]}"
EXIT_CODE=$?

exit $EXIT_CODE
