#!/usr/bin/env bash
# Cross-reference running container images with known vulnerabilities
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Cross-reference running container images with ACR vulnerability findings.

Options:
    --vulns FILE            JSON file with vulnerability findings (required)
    --images FILE           JSON file with running images (required)
    --severity THRESHOLD    Minimum severity: Critical, High, Medium, Low (default: Medium)
    --format FORMAT         Output format: table, json, csv (default: table)
    --output FILE           Write report to file (optional, also prints to stdout)
    --help                  Show this help message

EOF
    exit 0
}

VULNS_FILE=""
IMAGES_FILE=""
SEVERITY="${SEVERITY_THRESHOLD:-Medium}"
FORMAT="${OUTPUT_FORMAT:-table}"
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --vulns) VULNS_FILE="$2"; shift 2 ;;
        --images) IMAGES_FILE="$2"; shift 2 ;;
        --severity) SEVERITY="$2"; shift 2 ;;
        --format) FORMAT="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$VULNS_FILE" || -z "$IMAGES_FILE" ]]; then
    log_error "Both --vulns and --images files are required"
    usage
fi

if [[ ! -f "$VULNS_FILE" ]]; then
    log_error "Vulnerability file not found: $VULNS_FILE"
    exit 2
fi

if [[ ! -f "$IMAGES_FILE" ]]; then
    log_error "Running images file not found: $IMAGES_FILE"
    exit 2
fi

log_header "Cross-Referencing Runtime Images with Vulnerabilities"

# Perform the cross-reference using jq
REPORT=$(jq -n \
    --slurpfile vulns "$VULNS_FILE" \
    --slurpfile images "$IMAGES_FILE" \
    --arg severity "$SEVERITY" '
    def severity_rank:
        if . == "Critical" then 1
        elif . == "High" then 2
        elif . == "Medium" then 3
        elif . == "Low" then 4
        else 99
        end;

    ($severity | severity_rank) as $threshold |

    # Build lookup maps for vulnerability info
    # 1st priority: by manifestDigest (the Docker-Content-Digest from ACR — what Defender uses)
    # 2nd priority: by imageDigest from kubectl (image ID on the node)
    # 3rd priority: by configDigest (image config from ACR manifest)
    # 4th priority: by layer digest (matches if Defender digest is a layer in the image)
    ($vulns[0] | map({key: .imageDigest, value: .}) | from_entries) as $vuln_by_digest |

    # Build a set of all vulnerability digests for layer matching
    ($vulns[0] | [.[] | .imageDigest] | unique) as $all_vuln_digests |

    # Match running images against vulnerability findings
    [
        $images[0][] |
        . as $container |

        # Layer-based match: check if any vuln digest is in the container layer digests
        (
            if ($container.layerDigests // []) | length > 0 then
                ([$all_vuln_digests[] | . as $vd | select($container.layerDigests | index($vd))] | .[0] // null) as $matched_layer |
                if $matched_layer != null then $vuln_by_digest[$matched_layer] else null end
            else null end
        ) as $layer_match |

        # Check configDigest
        (
            if $container.configDigest != null then
                $vuln_by_digest[$container.configDigest] // null
            else null end
        ) as $config_match |

        # Check manifestDigest (from Docker-Content-Digest header — what Defender reports)
        (
            if $container.manifestDigest != null and $container.manifestDigest != "" then
                $vuln_by_digest[$container.manifestDigest] // null
            else null end
        ) as $manifest_match |

        # Try matching in priority order: manifest → image ID → config → layers
        (
            $manifest_match
        ) // (
            if $container.imageDigest != null then
                $vuln_by_digest[$container.imageDigest] // null
            else null end
        ) // (
            $config_match
        ) // (
            $layer_match
        ) |

        select(. != null) |
        . as $vuln_info |
        {
            cluster: $container.cluster,
            namespace: $container.namespace,
            podName: $container.podName,
            containerName: $container.containerName,
            image: $container.image,
            imageDigest: ($container.imageDigest // "N/A"),
            matchedBy: (
                if $manifest_match != null
                then "manifest"
                elif ($container.imageDigest != null and $vuln_by_digest[$container.imageDigest] != null)
                then "digest"
                elif $config_match != null
                then "config"
                else "layer"
                end
            ),
            containerState: $container.state,
            registry: $vuln_info.registry,
            repositoryName: $vuln_info.repositoryName,
            vulnerabilities: [
                $vuln_info.vulnerabilities[] |
                select((.severity | severity_rank) <= $threshold)
            ],
            summary: {
                total: [.vulnerabilities[] | select((.severity | severity_rank) <= $threshold)] | length,
                critical: [.vulnerabilities[] | select(.severity == "Critical")] | length,
                high: [.vulnerabilities[] | select(.severity == "High")] | length,
                medium: [.vulnerabilities[] | select(.severity == "Medium")] | length,
                low: [.vulnerabilities[] | select(.severity == "Low")] | length,
                patchable: [.vulnerabilities[] | select(.patchable == true) | select((.severity | severity_rank) <= $threshold)] | length
            }
        } |
        select(.summary.total > 0)
    ] |
    sort_by(.summary.critical, .summary.high, .summary.medium) | reverse |

    # Build final report
    {
        generatedAt: (now | todate),
        severityThreshold: $severity,
        summary: {
            totalRunningContainers: ($images[0] | length),
            containersWithDigest: [$images[0][] | select(.imageDigest != null)] | length,
            vulnerableContainers: length,
            uniqueVulnerableImages: ([.[].imageDigest] | unique | length),
            totalFindings: (([.[].summary.total] | add) // 0),
            bySeverity: {
                critical: (([.[].summary.critical] | add) // 0),
                high: (([.[].summary.high] | add) // 0),
                medium: (([.[].summary.medium] | add) // 0),
                low: (([.[].summary.low] | add) // 0)
            },
            totalPatchable: (([.[].summary.patchable] | add) // 0)
        },
        runningContainers: [
            $images[0][] |
            select(.imageDigest != null) |
            {namespace, podName, containerName, image, imageDigest, state}
        ] | sort_by(.namespace, .podName),
        vulnerableContainers: .
    }
')

# Output based on format
output_table() {
    local data="$1"

    echo ""
    echo -e "${BOLD}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BOLD}║       CONTAINER RUNTIME VULNERABILITY REPORT                ║${NC}"
    echo -e "${BOLD}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo ""

    # Summary
    echo -e "${BOLD}Summary${NC}"
    echo -e "  Generated:                $(echo "$data" | jq -r '.generatedAt')"
    echo -e "  Severity threshold:       $(echo "$data" | jq -r '.severityThreshold')"
    echo -e "  Running containers:       $(echo "$data" | jq -r '.summary.totalRunningContainers')"
    echo -e "  With image digest:        $(echo "$data" | jq -r '.summary.containersWithDigest')"
    echo -e "  ${RED}Vulnerable containers:  $(echo "$data" | jq -r '.summary.vulnerableContainers')${NC}"
    echo -e "  Unique vulnerable images: $(echo "$data" | jq -r '.summary.uniqueVulnerableImages')"
    echo ""
    echo -e "${BOLD}Findings by Severity${NC}"

    local crit high med low
    crit=$(echo "$data" | jq -r '.summary.bySeverity.critical')
    high=$(echo "$data" | jq -r '.summary.bySeverity.high')
    med=$(echo "$data" | jq -r '.summary.bySeverity.medium')
    low=$(echo "$data" | jq -r '.summary.bySeverity.low')
    echo -e "  ${RED}Critical: $crit${NC}  |  ${YELLOW}High: $high${NC}  |  Medium: $med  |  Low: $low"
    echo -e "  Patchable: $(echo "$data" | jq -r '.summary.totalPatchable')"
    echo ""

    # Running containers and digests
    echo -e "${BOLD}Running Containers & Image Digests${NC}"
    echo ""
    printf "%-18s %-30s %-15s %-45s %s\n" \
        "NAMESPACE" "POD" "CONTAINER" "IMAGE" "DIGEST"
    printf "%-18s %-30s %-15s %-45s %s\n" \
        "---------" "---" "---------" "-----" "------"

    echo "$data" | jq -r '
        .runningContainers[] |
        [.namespace, .podName, .containerName, .image, (.imageDigest // "N/A")] |
        @tsv' | while IFS=$'\t' read -r ns pod container image digest; do
        printf "%-18s %-30s %-15s %-45s %s\n" \
            "$ns" "${pod:0:30}" "$container" "${image:0:45}" "${digest:0:20}..."
    done
    echo ""

    # Vulnerable containers table
    local vuln_count
    vuln_count=$(echo "$data" | jq '.vulnerableContainers | length')

    if [[ "$vuln_count" -eq 0 ]]; then
        echo -e "${GREEN}No vulnerable containers found matching the severity threshold.${NC}"
        return
    fi

    echo -e "${BOLD}Vulnerable Containers${NC}"
    echo ""
    printf "%-18s %-28s %-14s %-6s %-6s %-6s %-6s %-10s\n" \
        "NAMESPACE" "POD" "CONTAINER" "CRIT" "HIGH" "MED" "PATCH" "MATCHED BY"
    printf "%-18s %-28s %-14s %-6s %-6s %-6s %-6s %-10s\n" \
        "---------" "---" "---------" "----" "----" "---" "-----" "----------"

    echo "$data" | jq -r '.vulnerableContainers[] |
        [.namespace, .podName, .containerName,
         (.summary.critical | tostring), (.summary.high | tostring),
         (.summary.medium | tostring), (.summary.patchable | tostring),
         .matchedBy] |
        @tsv' | while IFS=$'\t' read -r ns pod container crit_c high_c med_c patch_c matched; do
        printf "%-18s %-28s %-14s %-6s %-6s %-6s %-6s %-10s\n" \
            "$ns" "${pod:0:28}" "$container" "$crit_c" "$high_c" "$med_c" "$patch_c" "$matched"
    done

    echo ""
    echo -e "${BOLD}Top CVEs across all running containers${NC}"
    echo ""
    printf "%-18s %-10s %-8s %-6s %s\n" "CVE" "SEVERITY" "CVSS" "PATCH" "DESCRIPTION"
    printf "%-18s %-10s %-8s %-6s %s\n" "---" "--------" "----" "-----" "-----------"

    echo "$data" | jq -r '
        [.vulnerableContainers[].vulnerabilities[]] |
        group_by(.cveId) |
        map(.[0]) |
        sort_by(
            (if .severity == "Critical" then 0 elif .severity == "High" then 1
             elif .severity == "Medium" then 2 else 3 end),
            (-(.cvss // 0))
        ) |
        .[:20][] |
        [.cveId, .severity, (.cvss // 0 | tostring),
         (if .patchable then "Yes" else "No" end),
         (.description[:60] // "N/A")] |
        @tsv' | while IFS=$'\t' read -r cve sev cvss patch desc; do
        printf "%-18s %-10s %-8s %-6s %s\n" "$cve" "$sev" "$cvss" "$patch" "$desc"
    done
}

output_csv() {
    local data="$1"
    echo "cluster,namespace,pod,container,image,imageDigest,matchedBy,state,cveId,severity,cvss,patchable,description"
    echo "$data" | jq -r '.vulnerableContainers[] |
        . as $c |
        .vulnerabilities[] |
        [$c.cluster, $c.namespace, $c.podName, $c.containerName, $c.image,
         $c.imageDigest, $c.matchedBy, $c.containerState, .cveId, .severity,
         (.cvss // 0 | tostring), (.patchable | tostring),
         (.description // "" | gsub(","; ";"))] |
        @csv'
}

case "$FORMAT" in
    table)
        output_table "$REPORT"
        ;;
    json)
        echo "$REPORT" | jq .
        ;;
    csv)
        output_csv "$REPORT"
        ;;
    *)
        log_error "Unknown format: $FORMAT"
        exit 2
        ;;
esac

# Write to file if requested
if [[ -n "$OUTPUT_FILE" ]]; then
    ensure_output_dir
    case "$FORMAT" in
        table) output_table "$REPORT" > "$OUTPUT_FILE" ;;
        json) echo "$REPORT" | jq . > "$OUTPUT_FILE" ;;
        csv) output_csv "$REPORT" > "$OUTPUT_FILE" ;;
    esac
    log_success "Report written to $OUTPUT_FILE"
fi

# Exit code based on findings
VULN_COUNT=$(echo "$REPORT" | jq '.summary.vulnerableContainers')
if [[ "$VULN_COUNT" -gt 0 ]]; then
    log_warn "Found $VULN_COUNT vulnerable running containers."
    exit 1
else
    log_success "No vulnerable running containers found."
    exit 0
fi
