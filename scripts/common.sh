#!/usr/bin/env bash
# Common utilities for container vulnerability scripts
# shellcheck disable=SC2034

set -euo pipefail

# Colors
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Severity ranking (lower = more severe)
declare -A SEVERITY_RANK=(
    [Critical]=1
    [High]=2
    [Medium]=3
    [Low]=4
)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
TMP_PREFIX="/tmp/container-vulns-$$"
OUTPUT_DIR="${PROJECT_DIR}/output"

log_info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
log_success() { echo -e "${GREEN}[OK]${NC} $*"; }
log_warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error()   { echo -e "${RED}[ERROR]${NC} $*" >&2; }
log_header()  { echo -e "\n${BOLD}${CYAN}═══ $* ═══${NC}\n"; }

cleanup() {
    rm -f "${TMP_PREFIX}"* 2>/dev/null || true
}
trap cleanup EXIT

check_prerequisites() {
    local missing=()
    for cmd in az kubectl jq; do
        if ! command -v "$cmd" &>/dev/null; then
            missing+=("$cmd")
        fi
    done
    if [[ ${#missing[@]} -gt 0 ]]; then
        log_error "Missing required tools: ${missing[*]}"
        log_error "Install them before running this script."
        exit 2
    fi

    # Check az login
    if ! az account show &>/dev/null; then
        log_error "Not logged in to Azure. Run 'az login' first."
        exit 2
    fi

    # Check resource-graph extension
    if ! az extension show --name resource-graph &>/dev/null; then
        log_info "Installing Azure Resource Graph extension..."
        az extension add --name resource-graph --yes
    fi

    # Check connectedk8s extension
    if ! az extension show --name connectedk8s &>/dev/null; then
        log_info "Installing Azure Connected K8s extension..."
        az extension add --name connectedk8s --yes
    fi
}

load_env() {
    local env_file="${PROJECT_DIR}/.env"
    if [[ -f "$env_file" ]]; then
        log_info "Loading configuration from .env"
        # shellcheck disable=SC1090
        set -a
        source "$env_file"
        set +a
    fi
}

# Run an Azure Resource Graph query with pagination and retry
run_arg_query() {
    local query="$1"
    local subscriptions="${2:-}"
    local max_retries=3
    local retry_delay=5

    local sub_args=()
    if [[ -n "$subscriptions" ]]; then
        sub_args=(--subscriptions "$subscriptions")
    fi

    for ((attempt = 1; attempt <= max_retries; attempt++)); do
        if result=$(az graph query -q "$query" "${sub_args[@]}" --first 1000 -o json 2>&1); then
            echo "$result" | jq -r '.data'
            return 0
        fi
        if [[ $attempt -lt $max_retries ]]; then
            log_warn "ARG query failed (attempt $attempt/$max_retries), retrying in ${retry_delay}s..."
            sleep "$retry_delay"
            retry_delay=$((retry_delay * 2))
        fi
    done
    log_error "ARG query failed after $max_retries attempts"
    log_error "$result"
    return 1
}

# Convert severity threshold to numeric rank
severity_meets_threshold() {
    local severity="$1"
    local threshold="$2"
    local sev_rank="${SEVERITY_RANK[$severity]:-99}"
    local thr_rank="${SEVERITY_RANK[$threshold]:-3}"
    [[ "$sev_rank" -le "$thr_rank" ]]
}

# Ensure output directory exists
ensure_output_dir() {
    mkdir -p "$OUTPUT_DIR"
}
