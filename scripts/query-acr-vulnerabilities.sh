#!/usr/bin/env bash
# Query ACR vulnerability findings from Defender for Containers via Azure Resource Graph
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Query vulnerability findings from Defender for Containers via Azure Resource Graph.

Options:
    --subscriptions ID      Subscription ID(s) to query (comma-separated)
    --registries NAMES      Filter by ACR registry names (comma-separated)
    --severity THRESHOLD    Minimum severity: Critical, High, Medium, Low (default: Medium)
    --output FILE           Write JSON output to file (default: stdout)
    --help                  Show this help message

EOF
    exit 0
}

SUBSCRIPTIONS="${SUBSCRIPTION_ID:-}"
REGISTRIES="${REGISTRY_NAMES:-}"
SEVERITY="${SEVERITY_THRESHOLD:-Medium}"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --subscriptions) SUBSCRIPTIONS="$2"; shift 2 ;;
        --registries) REGISTRIES="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

log_header "Querying ACR Vulnerability Findings"

# Read the KQL query
KQL_FILE="${PROJECT_DIR}/queries/acr-vulnerabilities.kql"
if [[ ! -f "$KQL_FILE" ]]; then
    log_error "KQL query file not found: $KQL_FILE"
    exit 2
fi
QUERY=$(cat "$KQL_FILE")

# Add registry filter if specified
if [[ -n "$REGISTRIES" ]]; then
    registry_filter=""
    IFS=',' read -ra REG_ARRAY <<< "$REGISTRIES"
    for reg in "${REG_ARRAY[@]}"; do
        reg=$(echo "$reg" | xargs) # trim whitespace
        if [[ -n "$registry_filter" ]]; then
            registry_filter="${registry_filter}, '${reg}', '${reg}.azurecr.io'"
        else
            registry_filter="'${reg}', '${reg}.azurecr.io'"
        fi
    done
    QUERY="${QUERY}
| where registry in~ (${registry_filter})"
fi

log_info "Querying Azure Resource Graph for vulnerability assessments..."
RESULT=$(run_arg_query "$QUERY" "$SUBSCRIPTIONS")

# Count and summarize
TOTAL=$(echo "$RESULT" | jq 'length')
if [[ "$TOTAL" -eq 0 ]]; then
    log_warn "No vulnerability findings found."
    echo "[]" > "${OUTPUT_FILE:-/dev/stdout}"
    exit 0
fi

# Filter by severity threshold
FILTERED=$(echo "$RESULT" | jq --arg threshold "$SEVERITY" '
    def severity_rank:
        if . == "Critical" then 1
        elif . == "High" then 2
        elif . == "Medium" then 3
        elif . == "Low" then 4
        else 99
        end;
    ($threshold | severity_rank) as $thr |
    [ .[] | select((.severity | severity_rank) <= $thr) ]
')

FILTERED_COUNT=$(echo "$FILTERED" | jq 'length')
UNIQUE_IMAGES=$(echo "$FILTERED" | jq '[.[].imageDigest] | unique | length')
UNIQUE_CVES=$(echo "$FILTERED" | jq '[.[].cveId] | unique | length')

# Severity breakdown
CRITICAL=$(echo "$FILTERED" | jq '[.[] | select(.severity == "Critical")] | length')
HIGH=$(echo "$FILTERED" | jq '[.[] | select(.severity == "High")] | length')
MEDIUM=$(echo "$FILTERED" | jq '[.[] | select(.severity == "Medium")] | length')
LOW=$(echo "$FILTERED" | jq '[.[] | select(.severity == "Low")] | length')

log_success "Found $FILTERED_COUNT findings (from $TOTAL total, filtered by severity >= $SEVERITY)"
log_info "  Unique images: $UNIQUE_IMAGES"
log_info "  Unique CVEs:   $UNIQUE_CVES"
log_info "  Critical: $CRITICAL | High: $HIGH | Medium: $MEDIUM | Low: $LOW"

# Group by image digest for easier cross-referencing
GROUPED=$(echo "$FILTERED" | jq '
    group_by(.imageDigest) |
    map({
        imageDigest: .[0].imageDigest,
        repositoryName: .[0].repositoryName,
        registry: .[0].registry,
        imageTag: (.[0].imageTag // ""),
        imageRef: (.[0].registry + "/" + .[0].repositoryName + (if .[0].imageTag != "" and .[0].imageTag != null then ":" + .[0].imageTag else "" end) + "@" + .[0].imageDigest),
        vulnerabilities: [.[] | {cveId, severity, patchable, description, cvss, publishedDate}],
        summary: {
            total: length,
            critical: [.[] | select(.severity == "Critical")] | length,
            high: [.[] | select(.severity == "High")] | length,
            medium: [.[] | select(.severity == "Medium")] | length,
            low: [.[] | select(.severity == "Low")] | length,
            patchable: [.[] | select(.patchable == true)] | length
        }
    })
')

if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$GROUPED" > "$OUTPUT_FILE"
    log_success "Vulnerability data written to $OUTPUT_FILE"
else
    echo "$GROUPED"
fi
