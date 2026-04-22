# Container Runtime Vulnerability Checker

Cross-references **running container images** on **Azure Arc-enabled Kubernetes clusters** with known vulnerabilities detected by **Microsoft Defender for Containers** in Azure Container Registry.

## How It Works

1. **Queries Defender for Containers** — Fetches vulnerability assessments from Azure Resource Graph for images scanned in ACR
2. **Queries Arc-enabled K8s clusters** — Connects to each cluster via `az connectedk8s proxy` and extracts running container image digests
3. **Cross-references** — Matches image digests (sha256) between running containers and known vulnerabilities
4. **Reports** — Generates a vulnerability report showing which running containers are affected

## Prerequisites

- **Azure CLI** (`az`) with extensions: `resource-graph`, `connectedk8s`
- **kubectl**
- **jq**
- Azure account with read access to:
  - Azure Resource Graph (for Defender findings)
  - Arc-enabled K8s clusters (for `connectedk8s proxy`)
- Defender for Containers enabled on your ACR

## Quick Start

```bash
# 1. Clone and configure
cp .env.example .env
# Edit .env with your subscription, resource group, etc.

# 2. Make scripts executable
chmod +x scripts/*.sh

# 3. Login to Azure
az login

# 4. Run the check
./scripts/check-vulnerabilities.sh --resource-group <your-rg>
```

## Usage

```bash
# Scan all Arc clusters in a resource group
./scripts/check-vulnerabilities.sh --resource-group myRG

# Scan specific clusters, only Critical/High
./scripts/check-vulnerabilities.sh \
    --resource-group myRG \
    --clusters cluster1,cluster2 \
    --severity High

# JSON output saved to file
./scripts/check-vulnerabilities.sh \
    --resource-group myRG \
    --format json \
    --save

# CSV output for spreadsheet import
./scripts/check-vulnerabilities.sh \
    --resource-group myRG \
    --format csv \
    --save
```

## Configuration

Copy `.env.example` to `.env` and fill in:

| Variable | Required | Description |
|---|---|---|
| `SUBSCRIPTION_ID` | No | Azure subscription(s), comma-separated |
| `RESOURCE_GROUP` | Yes | Resource group with Arc clusters |
| `CLUSTER_NAMES` | No | Specific clusters (default: all in RG) |
| `REGISTRY_NAMES` | No | Filter ACR registries |
| `NAMESPACES_EXCLUDE` | No | Namespaces to skip (default: system ns) |
| `SEVERITY_THRESHOLD` | No | Minimum severity (default: Medium) |
| `OUTPUT_FORMAT` | No | table, json, csv (default: table) |

## Scripts

| Script | Purpose |
|---|---|
| `check-vulnerabilities.sh` | Main orchestrator — run this |
| `query-acr-vulnerabilities.sh` | Queries Defender findings from ARG |
| `query-running-images.sh` | Gets running images from Arc K8s clusters |
| `cross-reference.sh` | Matches digests and generates report |
| `common.sh` | Shared utilities |

## Exit Codes

| Code | Meaning |
|---|---|
| 0 | No vulnerable running containers found |
| 1 | Vulnerable running containers detected |
| 2 | Error (missing prerequisites, auth failure, etc.) |

## Running Individual Scripts

```bash
# Just query vulnerabilities
./scripts/query-acr-vulnerabilities.sh \
    --subscriptions <sub-id> \
    --severity High \
    --output vulns.json

# Just get running images
./scripts/query-running-images.sh \
    --resource-group myRG \
    --clusters myCluster \
    --output images.json

# Cross-reference existing files
./scripts/cross-reference.sh \
    --vulns vulns.json \
    --images images.json \
    --format table
```

## KQL Query

The vulnerability data is sourced from Azure Resource Graph. The query is in [queries/acr-vulnerabilities.kql](queries/acr-vulnerabilities.kql) and can be tested directly in Azure Resource Graph Explorer.
