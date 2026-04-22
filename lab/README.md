# Container Vulnerabilities Testing Lab

Complete Azure testing environment for validating the container runtime vulnerability checker.

## What Gets Deployed

| Resource | Description |
|---|---|
| **Resource Group** | `cvulnlab-rg` (configurable) |
| **Azure VM** | Ubuntu 22.04 with k3s (lightweight K8s) |
| **Azure Container Registry** | Standard SKU with admin access |
| **Defender for Containers** | Enabled at subscription level |
| **Arc-enabled cluster** | k3s cluster connected to Azure Arc |

### Container Workloads

**Vulnerable images** (old versions with known CVEs):
- `nginx:1.14.0` — HTTP/2 DoS, OpenSSL CVEs
- `node:12-alpine` — EOL runtime, multiple CVEs
- `httpd:2.4.29` — auth bypass, DoS CVEs
- `redis:5.0.0` — integer overflow, Lua CVEs
- `postgres:9.6` — EOL, buffer overflow CVEs

**Clean images** (latest stable):
- `nginx:stable-alpine`
- `redis:alpine`

## Prerequisites

- Azure CLI (`az`) logged in
- SSH key pair (`~/.ssh/id_rsa.pub`)
- Sufficient Azure permissions (Contributor + Security Admin)

## Quick Start

```bash
# Deploy everything in one command
./lab/setup/setup-lab.sh --location swedencentral

# Wait ~15 minutes for Defender to scan ACR images

# Validate the lab
./lab/test/validate.sh --resource-group cvulnlab-rg --cluster-name cvulnlab-k3s

# Run the actual vulnerability check
./scripts/check-vulnerabilities.sh --resource-group cvulnlab-rg
```

## Step-by-Step Setup

### 1. Deploy infrastructure

```bash
./lab/setup/setup-lab.sh --location swedencentral --base-name cvulnlab
```

This deploys the Bicep templates, waits for k3s, Arc-enables the cluster, pushes images to ACR, and deploys workloads.

### 2. Skip individual steps if re-running

```bash
# Skip Bicep (infra already exists)
./lab/setup/setup-lab.sh --resource-group cvulnlab-rg --skip-infra

# Only re-deploy workloads
./lab/setup/setup-lab.sh --resource-group cvulnlab-rg --skip-infra --skip-arc --skip-images
```

### 3. Validate

```bash
./lab/test/validate.sh --resource-group cvulnlab-rg --cluster-name cvulnlab-k3s
```

The validation script checks:
1. Resource group exists
2. ACR has all expected repositories
3. Arc cluster is connected
4. VM is reachable with k3s running
5. Pods are running in `vuln-test` namespace
6. Defender for Containers is enabled
7. Vulnerability findings exist in Resource Graph
8. Running image digests match vulnerable image digests

### 4. Run the vulnerability checker

```bash
./scripts/check-vulnerabilities.sh --resource-group cvulnlab-rg
```

## Tear Down

```bash
az group delete --name cvulnlab-rg --yes --no-wait
```

## Estimated Cost

- VM (Standard_D2s_v3): ~$0.10/hr
- ACR (Standard): ~$0.67/day
- Defender for Containers: ~$7/month per cluster

Recommend tearing down when not in use.

## File Structure

```
lab/
├── infra/
│   ├── main.bicep                # Subscription-scoped deployment
│   ├── modules/
│   │   ├── network.bicep         # VNet, NSG, Public IP
│   │   ├── vm.bicep              # Ubuntu VM with k3s (cloud-init)
│   │   ├── acr.bicep             # Azure Container Registry
│   │   └── defender.bicep        # Defender for Containers pricing
│   └── scripts/
│       └── cloud-init.yaml       # VM bootstrap: k3s, az CLI, helm
├── setup/
│   ├── setup-lab.sh              # Full orchestrator
│   ├── arc-enable.sh             # Arc-enable k3s via SSH
│   └── push-images.sh            # Import vulnerable/clean images to ACR
├── manifests/
│   ├── vulnerable-deployments.yaml  # 5 deployments with old vulnerable images
│   └── clean-deployments.yaml       # 2 deployments with latest images
├── test/
│   └── validate.sh               # End-to-end lab validation
└── README.md                     # This file
```
