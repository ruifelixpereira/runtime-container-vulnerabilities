#!/usr/bin/env bash
# Query running container images from Arc-enabled Kubernetes clusters
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Query running container images from Arc-enabled Kubernetes clusters.

Options:
    --resource-group RG     Resource group containing the Arc clusters (required)
    --clusters NAMES        Comma-separated cluster names (default: all in RG)
    --exclude-ns NAMES      Comma-separated namespaces to exclude
    --output FILE           Write JSON output to file (default: stdout)
    --help                  Show this help message

EOF
    exit 0
}

RG="${RESOURCE_GROUP:-}"
CLUSTERS="${CLUSTER_NAMES:-}"
EXCLUDE_NS="${NAMESPACES_EXCLUDE:-kube-system,kube-public,kube-node-lease,gatekeeper-system,azure-arc}"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --resource-group) RG="$2"; shift 2 ;;
        --clusters) CLUSTERS="$2"; shift 2 ;;
        --exclude-ns) EXCLUDE_NS="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$RG" ]]; then
    log_error "Resource group is required. Set RESOURCE_GROUP in .env or use --resource-group"
    exit 2
fi

log_header "Querying Running Container Images from Arc Clusters"

# Discover clusters if not specified
if [[ -z "$CLUSTERS" ]]; then
    log_info "Discovering Arc-enabled K8s clusters in resource group '$RG'..."
    CLUSTERS_JSON=$(az connectedk8s list --resource-group "$RG" -o json 2>/dev/null || echo "[]")
    CLUSTER_LIST=$(echo "$CLUSTERS_JSON" | jq -r '.[].name')
    if [[ -z "$CLUSTER_LIST" ]]; then
        log_error "No Arc-enabled clusters found in resource group '$RG'"
        exit 2
    fi
    log_info "Found clusters: $(echo "$CLUSTER_LIST" | tr '\n' ', ' | sed 's/,$//')"
else
    CLUSTER_LIST=$(echo "$CLUSTERS" | tr ',' '\n')
fi

# Build jq namespace exclusion filter
EXCLUDE_FILTER=$(echo "$EXCLUDE_NS" | tr ',' '\n' | jq -R . | jq -s '.')

# jq filter to extract container image info from pod JSON
JQ_EXTRACT_IMAGES='
    [
        .items[] |
        select(.metadata.namespace as $ns | ($exclude | index($ns)) | not) |
        . as $pod |
        (
            (.status.containerStatuses // []) +
            (.status.initContainerStatuses // [])
        )[] |
        {
            cluster: $cluster,
            namespace: $pod.metadata.namespace,
            podName: $pod.metadata.name,
            containerName: .name,
            image: .image,
            imageID: .imageID,
            imageDigest: (
                if .imageID then
                    (.imageID | capture("(?<digest>sha256:[a-f0-9]+)") | .digest) // null
                else null end
            ),
            state: (
                if .state.running then "running"
                elif .state.waiting then "waiting"
                elif .state.terminated then "terminated"
                else "unknown" end
            ),
            ready: .ready
        }
    ]
'

ALL_IMAGES="[]"

for CLUSTER in $CLUSTER_LIST; do
    CLUSTER=$(echo "$CLUSTER" | xargs) # trim
    log_info "Processing cluster: $CLUSTER"

    PROXY_PORT=$((RANDOM % 10000 + 40000))
    KUBECONFIG_FILE="${TMP_PREFIX}-kubeconfig-${CLUSTER}"

    PROXY_LOG="${TMP_PREFIX}-proxy-${CLUSTER}.log"

    log_info "  Establishing Arc proxy on port $PROXY_PORT..."

    az connectedk8s proxy \
        --name "$CLUSTER" \
        --resource-group "$RG" \
        --port "$PROXY_PORT" \
        --file "$KUBECONFIG_FILE" &>"$PROXY_LOG" &
    PROXY_PID=$!

    # Wait for proxy to be ready (up to 90s — first connection can be slow)
    MAX_WAIT=90
    WAITED=0
    while [[ $WAITED -lt $MAX_WAIT ]]; do
        if [[ -f "$KUBECONFIG_FILE" ]] && kubectl --kubeconfig "$KUBECONFIG_FILE" get nodes &>/dev/null; then
            break
        fi
        sleep 5
        WAITED=$((WAITED + 5))
        if (( WAITED % 15 == 0 )); then
            log_info "  Still waiting for Arc proxy... (${WAITED}s/${MAX_WAIT}s)"
        fi
    done

    if [[ $WAITED -ge $MAX_WAIT ]]; then
        log_warn "  Failed to connect to cluster '$CLUSTER' after ${MAX_WAIT}s, skipping..."
        log_warn "  Arc proxy log:"
        cat "$PROXY_LOG" >&2
        kill "$PROXY_PID" 2>/dev/null || true
        rm -f "$KUBECONFIG_FILE" "$PROXY_LOG" 2>/dev/null || true
        continue
    fi

    log_success "  Connected to cluster '$CLUSTER'"

    # Get all pods with their container image info
    PODS_JSON=$(kubectl --kubeconfig "$KUBECONFIG_FILE" get pods \
        --all-namespaces \
        -o json 2>/dev/null || echo '{"items":[]}')

    # Kill proxy and clean up
    kill "$PROXY_PID" 2>/dev/null || true
    rm -f "$KUBECONFIG_FILE" "$PROXY_LOG" 2>/dev/null || true

    # Extract running container images with their digests
    CLUSTER_IMAGES=$(echo "$PODS_JSON" | jq --arg cluster "$CLUSTER" --argjson exclude "$EXCLUDE_FILTER" "$JQ_EXTRACT_IMAGES")

    CONTAINER_COUNT=$(echo "$CLUSTER_IMAGES" | jq 'length')
    UNIQUE_DIGESTS=$(echo "$CLUSTER_IMAGES" | jq '[.[].imageDigest | select(. != null)] | unique | length')
    log_info "  Found $CONTAINER_COUNT containers with $UNIQUE_DIGESTS unique image digests"

    # Merge into all images
    ALL_IMAGES=$(echo "$ALL_IMAGES" "$CLUSTER_IMAGES" | jq -s '.[0] + .[1]')
done

TOTAL=$(echo "$ALL_IMAGES" | jq 'length')
TOTAL_DIGESTS=$(echo "$ALL_IMAGES" | jq '[.[].imageDigest | select(. != null)] | unique | length')
log_success "Total: $TOTAL containers across all clusters, $TOTAL_DIGESTS unique image digests"

if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$ALL_IMAGES" > "$OUTPUT_FILE"
    log_success "Running images data written to $OUTPUT_FILE"
else
    echo "$ALL_IMAGES"
fi
