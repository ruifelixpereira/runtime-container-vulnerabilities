# Container Runtime Vulnerability Checker for Arc-enabled Kubernetes

## Goal

Build a bash-based solution that cross-references **running container images** on **Azure Arc-enabled Kubernetes clusters** with **known vulnerabilities** detected by **Microsoft Defender for Containers** on images stored in **Azure Container Registry (ACR)**.

## Architecture

```
┌─────────────────────────┐     ┌──────────────────────────────┐
│  Arc-enabled K8s Clusters│     │  Azure Container Registry    │
│  (running containers)    │     │  (Defender for Containers)   │
└──────────┬──────────────┘     └──────────────┬───────────────┘
           │                                    │
           │ kubectl / Azure Resource Graph     │ Azure Resource Graph
           │                                    │ (securityresources)
           ▼                                    ▼
     ┌─────────────────────────────────────────────┐
     │         Cross-Reference Engine              │
     │  Match image digests → Report vulnerable    │
     │  running containers                         │
     └─────────────────────────────────────────────┘
```

## Data Sources

### 1. Vulnerability Findings (Defender for Containers)

Query Azure Resource Graph table `securityresources` for container image vulnerability assessments:

```
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where properties.additionalData.assessedResourceType == "AzureContainerRegistryVulnerability"
| extend
    imageDigest = tostring(properties.additionalData.imageDigest),
    repositoryName = tostring(properties.additionalData.repositoryName),
    registry = tostring(properties.additionalData.registryHost),
    cveId = tostring(properties.id),
    severity = tostring(properties.status.severity),
    patchable = tobool(properties.additionalData.patchable),
    description = tostring(properties.description),
    displayName = tostring(properties.displayName)
```

### 2. Running Container Images (Arc-enabled K8s)

Two options (implement both, let user choose):

**Option A — kubectl via Arc proxy:** Use `az connectedk8s proxy` then `kubectl get pods` across all namespaces, extracting image references and their digests from `status.containerStatuses[].imageID`.

**Option B — Azure Resource Graph (if Defender sensor is deployed):**

```
kubernetesconfigurationresources
| where type == "microsoft.kubernetes/connectedclusters/providers/microsoft.security/defenderforcontainersettings"
```

Or use the Container Insights inventory:

```
resources
| where type == "microsoft.containerservice/managedclusters" or type == "microsoft.kubernetes/connectedclusters"
```

Combined with the Defender runtime data from `securityresources` where `assessedResourceType == "ServerVulnerabilityAssessment"`.

**Preferred approach for Arc:** Use `az connectedk8s proxy` + `kubectl` since it gives direct access to pod specs and running image digests.

## Solution Structure

```
container-vulnerabilities/
├── scripts/
│   ├── check-vulnerabilities.sh       # Main orchestrator script
│   ├── query-acr-vulnerabilities.sh   # Query Defender findings from ARG
│   ├── query-running-images.sh        # Get running images from Arc K8s
│   ├── cross-reference.sh             # Match and generate report
│   └── common.sh                      # Shared utilities, logging, colors
├── queries/
│   ├── acr-vulnerabilities.kql        # KQL query for ACR vulnerability findings
│   └── running-containers.kql         # KQL query for runtime containers (if ARG-based)
├── output/                            # Generated reports go here
├── .env.example                       # Template for environment variables
├── README.md
└── .github/
    └── prompts/
        └── container-vulnerabilities.prompt.md
```

## Implementation Details

### Environment Variables (.env)

```bash
# Required
SUBSCRIPTION_ID=""              # Azure subscription ID (or comma-separated list)
RESOURCE_GROUP=""               # Resource group containing the Arc clusters

# Optional
CLUSTER_NAMES=""                # Comma-separated Arc cluster names (empty = all in RG)
REGISTRY_NAMES=""               # Comma-separated ACR names to filter (empty = all)
NAMESPACES_EXCLUDE="kube-system,kube-public,kube-node-lease,gatekeeper-system"
SEVERITY_THRESHOLD="Medium"     # Minimum severity to report: Critical, High, Medium, Low
OUTPUT_FORMAT="table"           # table, json, csv
```

### Script Requirements

- **Bash 4+**, `az` CLI with `resource-graph` extension, `kubectl`, `jq`
- All scripts must be idempotent and safe to re-run
- Use `set -euo pipefail` in all scripts
- Provide clear colored terminal output with progress indicators
- Support `--help` flags on all scripts
- Exit codes: 0 = no vulnerabilities found, 1 = vulnerabilities found, 2 = error

### Main Script Flow (`check-vulnerabilities.sh`)

1. Validate prerequisites (`az`, `kubectl`, `jq` installed; user logged in)
2. Load configuration from `.env` or CLI arguments
3. Call `query-acr-vulnerabilities.sh` → produces `/tmp/acr-vulns.json`
4. For each Arc-enabled cluster:
   a. Establish `az connectedk8s proxy` (background process)
   b. Call `query-running-images.sh` → produces `/tmp/running-images-{cluster}.json`
   c. Kill the proxy
5. Call `cross-reference.sh` → matches image digests, produces final report
6. Output report to stdout and optionally to `output/` directory

### Image Matching Logic

Match by **image digest** (sha256 hash). The flow:

1. From Defender findings: extract `imageDigest` (format: `sha256:abc123...`)
2. From running pods: extract `status.containerStatuses[].imageID` which includes the digest
3. Parse the digest from the imageID field (format: `registry/repo@sha256:abc123...`)
4. Match digests → for each match, the running container is vulnerable

### Output Report Format

The report should include:
- **Summary**: total running images, total with vulnerabilities, breakdown by severity
- **Details per vulnerable container**:
  - Cluster name
  - Namespace
  - Pod name
  - Container name
  - Image reference (registry/repo:tag)
  - Image digest
  - List of CVEs (ID, severity, patchable, description)
- Sort by severity (Critical first), then by cluster/namespace/pod

### Edge Cases to Handle

- Images pulled by tag vs by digest (resolve via `imageID` in pod status)
- Same image in multiple clusters
- Pods in CrashLoopBackOff or Init state (still check)
- ACR images that have been rescanned (use latest assessment)
- Rate limiting on Azure Resource Graph queries (implement retry with backoff)
- `az connectedk8s proxy` connection failures (retry up to 3 times)
- Large clusters with >1000 pods (handle kubectl pagination)

### KQL Query for ACR Vulnerabilities (`queries/acr-vulnerabilities.kql`)

```kql
securityresources
| where type == "microsoft.security/assessments/subassessments"
| where properties.additionalData.assessedResourceType == "AzureContainerRegistryVulnerability"
| extend
    imageDigest = tostring(properties.additionalData.imageDigest),
    repositoryName = tostring(properties.additionalData.repositoryName),
    registry = tostring(properties.additionalData.registryHost),
    cveId = tostring(properties.displayName),
    severity = tostring(properties.status.severity),
    patchable = tobool(properties.additionalData.patchable),
    description = tostring(properties.description),
    cvss = toreal(properties.additionalData.cvss.base),
    publishedDate = todatetime(properties.additionalData.publishedDate),
    assessmentTime = todatetime(properties.timeGenerated)
| project imageDigest, repositoryName, registry, cveId, severity, patchable, description, cvss, publishedDate, assessmentTime
| where isnotempty(imageDigest)
| order by severity asc, cvss desc
```

### If TypeScript is Needed

If any part requires TypeScript (e.g., complex JSON processing, report generation), create a `src/` folder with:
- Use `tsx` for direct execution (no build step)
- Use `@azure/arm-resourcegraph` SDK for ARG queries
- Use `@azure/identity` for authentication (DefaultAzureCredential)
- Keep it minimal — only use TS for what bash can't do cleanly

## Constraints

- Do NOT store credentials in files; rely on `az` CLI logged-in session
- Do NOT require Helm or custom K8s operators
- Scripts must work on Linux and macOS (bash 4+)
- Minimize Azure API calls — batch where possible
- All temporary files in `/tmp/` with unique prefixes, cleaned up on exit
