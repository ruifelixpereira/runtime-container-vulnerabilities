#!/usr/bin/env bash
# Resolve image layer digests from ACR for running container images
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Query ACR to resolve image manifests and layer digests for running container images.
This enriches the running images JSON with layer information from the registry,
enabling layer-level matching against Defender vulnerability findings.

Options:
    --images FILE           JSON file with running images (required)
    --output FILE           Write enriched JSON output to file (default: stdout)
    --help                  Show this help message

EOF
    exit 0
}

IMAGES_FILE=""
OUTPUT_FILE=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --images) IMAGES_FILE="$2"; shift 2 ;;
        --output) OUTPUT_FILE="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$IMAGES_FILE" ]]; then
    log_error "--images file is required"
    usage
fi

if [[ ! -f "$IMAGES_FILE" ]]; then
    log_error "Images file not found: $IMAGES_FILE"
    exit 2
fi

log_header "Resolving Image Layers from ACR"

# Extract unique ACR images (registry/repo:tag) from running images
# Only process images from *.azurecr.io registries
UNIQUE_IMAGES=$(jq -r '[.[].image] | unique | .[] | select(contains(".azurecr.io"))' "$IMAGES_FILE")

if [[ -z "$UNIQUE_IMAGES" ]]; then
    log_warn "No ACR images found in running containers. Skipping layer resolution."
    cp "$IMAGES_FILE" "${OUTPUT_FILE:-/dev/stdout}"
    exit 0
fi

IMAGE_COUNT=$(echo "$UNIQUE_IMAGES" | wc -l)
log_info "Found $IMAGE_COUNT unique ACR images to resolve"

# Build a JSON map: image_ref -> { manifestDigest, configDigest, layers: [digest, ...] }
LAYER_MAP="{}"
RESOLVED=0
FAILED=0
LAST_ACR_NAME=""
REFRESH_TOKEN=""

for IMAGE_REF in $UNIQUE_IMAGES; do
    # Parse registry, repo, and tag/digest from image reference
    # Format: registry.azurecr.io/repo/path:tag or registry.azurecr.io/repo/path@sha256:...
    REGISTRY=$(echo "$IMAGE_REF" | cut -d'/' -f1)
    ACR_NAME=$(echo "$REGISTRY" | cut -d'.' -f1)

    # Get repo and reference (tag or digest)
    REPO_AND_REF=$(echo "$IMAGE_REF" | cut -d'/' -f2-)

    if [[ "$REPO_AND_REF" == *"@sha256:"* ]]; then
        REPO=$(echo "$REPO_AND_REF" | cut -d'@' -f1)
        REF=$(echo "$REPO_AND_REF" | cut -d'@' -f2)
    elif [[ "$REPO_AND_REF" == *":"* ]]; then
        REPO=$(echo "$REPO_AND_REF" | rev | cut -d':' -f2- | rev)
        REF=$(echo "$REPO_AND_REF" | rev | cut -d':' -f1 | rev)
    else
        REPO="$REPO_AND_REF"
        REF="latest"
    fi

    log_info "  Resolving layers: ${ACR_NAME}/${REPO}:${REF}"

    # Get ACR refresh token (cache per ACR to avoid repeated logins)
    if [[ "$ACR_NAME" != "$LAST_ACR_NAME" ]]; then
        REFRESH_TOKEN=$(az acr login --name "$ACR_NAME" --expose-token --output tsv --query accessToken 2>/dev/null) || {
            log_warn "    Failed to get ACR refresh token for $ACR_NAME — skipping"
            FAILED=$((FAILED + 1))
            continue
        }
        LAST_ACR_NAME="$ACR_NAME"
    fi

    # Exchange refresh token for a repository-scoped access token
    TOKEN=$(curl -sS --max-time 10 \
        "https://${REGISTRY}/oauth2/token" \
        -d "grant_type=refresh_token&service=${REGISTRY}&scope=repository:${REPO}:pull&refresh_token=${REFRESH_TOKEN}" \
        2>/dev/null | jq -r '.access_token // empty') || true

    if [[ -z "$TOKEN" ]]; then
        log_warn "    Failed to exchange token for $REGISTRY/$REPO — skipping"
        FAILED=$((FAILED + 1))
        continue
    fi

    # Fetch the manifest (try Docker v2 manifest first, then OCI)
    MANIFEST=""
    LAST_RESPONSE=""
    MANIFEST_DIGEST=""
    for MEDIA_TYPE in \
        "application/vnd.docker.distribution.manifest.v2+json" \
        "application/vnd.oci.image.manifest.v1+json" \
        "application/vnd.docker.distribution.manifest.list.v2+json" \
        "application/vnd.oci.image.index.v1+json"; do

        MANIFEST_URL="https://${REGISTRY}/v2/${REPO}/manifests/${REF}"
        HTTP_CODE=$(curl -sS --max-time 10 \
            -o /tmp/acr-manifest-resp-$$.json \
            -D /tmp/acr-manifest-headers-$$.txt \
            -w "%{http_code}" \
            -H "Authorization: Bearer $TOKEN" \
            -H "Accept: $MEDIA_TYPE" \
            "$MANIFEST_URL" 2>/dev/null) || continue

        LAST_RESPONSE=$(cat /tmp/acr-manifest-resp-$$.json 2>/dev/null)

        if [[ "$HTTP_CODE" != "200" ]]; then
            continue
        fi

        # Check if we got a valid manifest (not an error response)
        if echo "$LAST_RESPONSE" | jq -e '.schemaVersion // .config // .layers' &>/dev/null; then
            MANIFEST="$LAST_RESPONSE"
            # Extract the Docker-Content-Digest header (this is the manifest digest Defender uses)
            MANIFEST_DIGEST=$(grep -i 'Docker-Content-Digest:' /tmp/acr-manifest-headers-$$.txt 2>/dev/null | sed 's/^[^:]*: *//;s/\r//' || true)
            break
        fi
    done
    rm -f /tmp/acr-manifest-resp-$$.json /tmp/acr-manifest-headers-$$.txt

    if [[ -z "$MANIFEST" ]]; then
        err_msg=$(echo "$LAST_RESPONSE" | jq -r '.errors[0].message // empty' 2>/dev/null || true)
        if [[ -n "$err_msg" ]]; then
            log_warn "    Failed to fetch manifest: $err_msg"
        else
            log_warn "    Failed to fetch manifest (URL: ${MANIFEST_URL}, last HTTP: ${HTTP_CODE:-N/A})"
        fi
        FAILED=$((FAILED + 1))
        continue
    fi

    # Check if this is a manifest list/index (multi-arch) — resolve to linux/amd64
    SCHEMA_VERSION=$(echo "$MANIFEST" | jq -r '.schemaVersion // 0')
    MEDIA_TYPE_RESP=$(echo "$MANIFEST" | jq -r '.mediaType // ""')

    if [[ "$MEDIA_TYPE_RESP" == *"manifest.list"* ]] || [[ "$MEDIA_TYPE_RESP" == *"image.index"* ]]; then
        # Multi-arch image — pick linux/amd64
        PLATFORM_DIGEST=$(echo "$MANIFEST" | jq -r '
            .manifests[] |
            select(.platform.architecture == "amd64" and .platform.os == "linux") |
            .digest' | head -1)

        if [[ -n "$PLATFORM_DIGEST" ]]; then
            log_info "    Multi-arch image, resolving linux/amd64: ${PLATFORM_DIGEST:0:20}..."
            # The platform digest itself is a manifest digest Defender may reference
            MANIFEST_DIGEST="$PLATFORM_DIGEST"
            MANIFEST=$(curl -sS --max-time 10 \
                -H "Authorization: Bearer $TOKEN" \
                -H "Accept: application/vnd.docker.distribution.manifest.v2+json, application/vnd.oci.image.manifest.v1+json" \
                "https://${REGISTRY}/v2/${REPO}/manifests/${PLATFORM_DIGEST}" 2>/dev/null) || {
                log_warn "    Failed to resolve platform manifest — skipping"
                FAILED=$((FAILED + 1))
                continue
            }
        else
            log_warn "    No linux/amd64 platform found in manifest list — skipping"
            FAILED=$((FAILED + 1))
            continue
        fi
    fi

    # Extract config digest and layer digests
    IMAGE_LAYERS=$(echo "$MANIFEST" | jq --arg md "$MANIFEST_DIGEST" '{
        manifestDigest: $md,
        configDigest: (.config.digest // null),
        layers: [(.layers // [])[] | .digest]
    }') || {
        log_warn "    Failed to parse manifest — skipping"
        FAILED=$((FAILED + 1))
        continue
    }

    LAYER_COUNT=$(echo "$IMAGE_LAYERS" | jq '.layers | length')
    CONFIG_DIGEST=$(echo "$IMAGE_LAYERS" | jq -r '.configDigest // "N/A"')
    log_info "    Found $LAYER_COUNT layers, manifest: ${MANIFEST_DIGEST:0:20}..., config: ${CONFIG_DIGEST:0:20}..."

    # Add to map
    LAYER_MAP=$(echo "$LAYER_MAP" | jq --arg key "$IMAGE_REF" --argjson layers "$IMAGE_LAYERS" \
        '. + {($key): $layers}')
    RESOLVED=$((RESOLVED + 1))
done

log_info "Resolved: $RESOLVED, Failed: $FAILED"

# Enrich running images with layer digests
ENRICHED=$(jq --argjson layerMap "$LAYER_MAP" '
    [.[] |
        . as $container |
        ($layerMap[$container.image] // null) as $layers |
        . + {
            manifestDigest: (if $layers then $layers.manifestDigest else null end),
            configDigest: (if $layers then $layers.configDigest else null end),
            layerDigests: (if $layers then $layers.layers else [] end)
        }
    ]
' "$IMAGES_FILE")

if [[ -n "$OUTPUT_FILE" ]]; then
    echo "$ENRICHED" > "$OUTPUT_FILE"
    log_success "Enriched images with layer data written to $OUTPUT_FILE"
else
    echo "$ENRICHED"
fi
