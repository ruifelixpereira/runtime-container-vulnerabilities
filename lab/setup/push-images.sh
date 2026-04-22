#!/usr/bin/env bash
# Push vulnerable and clean container images to ACR
set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Pull known-vulnerable and clean container images and push them to ACR.

Options:
    --acr-name NAME              ACR name (required)
    --docker-hub-user USERNAME   Docker Hub username (avoids rate limits)
    --docker-hub-pass PASSWORD   Docker Hub password or PAT
    --help                       Show this help message

Docker Hub rate-limits unauthenticated pulls. Create a free account at
https://hub.docker.com and pass your credentials to avoid errors.

EOF
    exit 0
}

ACR_NAME=""
DOCKER_HUB_USER=""
DOCKER_HUB_PASS=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --acr-name) ACR_NAME="$2"; shift 2 ;;
        --docker-hub-user) DOCKER_HUB_USER="$2"; shift 2 ;;
        --docker-hub-pass) DOCKER_HUB_PASS="$2"; shift 2 ;;
        --help) usage ;;
        *) log_error "Unknown option: $1"; usage ;;
    esac
done

if [[ -z "$ACR_NAME" ]]; then
    log_error "ACR name is required"
    usage
fi

ACR_LOGIN_SERVER=$(az acr show --name "$ACR_NAME" --query loginServer -o tsv)

log_info "Logging into ACR: $ACR_LOGIN_SERVER"
az acr login --name "$ACR_NAME"

# ── Vulnerable images (old versions with known CVEs) ───────────────────
# These are intentionally old versions that Defender will flag
VULNERABLE_IMAGES=(
    "docker.io/library/nginx:1.14.0"          # CVE-2019-9511, CVE-2019-9513, many OpenSSL CVEs
    "docker.io/library/node:12-alpine"         # EOL, multiple CVEs
    "docker.io/library/httpd:2.4.29"           # CVE-2018-1312, CVE-2018-1333
    "docker.io/library/redis:5.0.0"            # CVE-2021-32625, CVE-2021-32672
    "docker.io/library/postgres:9.6"           # EOL, many CVEs
)

# ── Clean images (latest, minimal CVEs) ────────────────────────────────
CLEAN_IMAGES=(
    "docker.io/library/nginx:stable-alpine"
    "docker.io/library/redis:alpine"
)

import_image() {
    local source="$1"
    local target_repo="$2"
    local target_tag="$3"
    local max_retries=2

    local auth_args=()
    if [[ -n "$DOCKER_HUB_USER" && -n "$DOCKER_HUB_PASS" ]]; then
        auth_args=(--username "$DOCKER_HUB_USER" --password "$DOCKER_HUB_PASS")
    fi

    log_info "Importing $source → ${ACR_LOGIN_SERVER}/${target_repo}:${target_tag}"
    for ((attempt = 1; attempt <= max_retries; attempt++)); do
        if az acr import \
            --name "$ACR_NAME" \
            --source "$source" \
            --image "${target_repo}:${target_tag}" \
            --force \
            "${auth_args[@]}" 2>&1; then
            log_success "  Imported ${target_repo}:${target_tag}"
            return 0
        fi
        if [[ $attempt -lt $max_retries ]]; then
            log_warn "  Retry $attempt/$max_retries..."
            sleep 10
        fi
    done
    log_warn "  Failed to import $source"
    return 1
}

log_info "Importing vulnerable images..."
# Using versions that are old enough to have known CVEs but still available on Docker Hub
import_image "docker.io/library/nginx:1.16.0"     "vuln/nginx"     "1.16.0"
import_image "docker.io/library/node:14-alpine"    "vuln/node"      "14-alpine"
import_image "docker.io/library/httpd:2.4.41"      "vuln/httpd"     "2.4.41"
import_image "docker.io/library/redis:6.0.0"       "vuln/redis"     "6.0.0"
import_image "docker.io/library/postgres:12.2"     "vuln/postgres"  "12.2"

log_info "Importing clean images..."
import_image "docker.io/library/nginx:stable-alpine"  "clean/nginx"  "stable-alpine"
import_image "docker.io/library/redis:alpine"         "clean/redis"  "alpine"

# List what's in the ACR
log_info "ACR repositories:"
az acr repository list --name "$ACR_NAME" -o table

log_success "All images pushed to ACR"
log_warn "Defender for Containers will scan these images automatically."
log_warn "Scanning typically takes 5-15 minutes for new images."
