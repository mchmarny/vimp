# User Guide

This guide walks you through the basic workflow of scanning container images for vulnerabilities, importing results, and querying the data.

## Prerequisites

- **vimp** installed ([installation instructions](../README.md#installation))
- At least one vulnerability scanner installed:
  - [Grype](https://github.com/anchore/grype) (recommended)
  - [Trivy](https://github.com/aquasecurity/trivy)
  - [Snyk](https://github.com/snyk/cli)
  - [OSV-Scanner](https://github.com/google/osv-scanner)

## Quick Demo

Run these commands to see vimp in action:

```bash
# 1. Scan an image with all available scanners
vimp scan --image docker.io/library/redis --yes

# 2. Query the results
vimp query --image docker.io/library/redis

# 3. Drill down to a specific digest
vimp query --image docker.io/library/redis --digest sha256:...

# 4. Compare findings across scanners
vimp query --image docker.io/library/redis --digest sha256:... --diff
```

## Workflow Overview

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   Scanner   │────▶│   Import    │────▶│   Query     │
│   (scan)    │     │  (import)   │     │  (query)    │
└─────────────┘     └─────────────┘     └─────────────┘
      │                   │                   │
      ▼                   ▼                   ▼
 JSON reports        SQLite/PG           JSON/SARIF
```

## Step 1: Scan an Image

The `scan` command discovers available scanners and runs them against a container image.

```bash
# Interactive mode (prompts for confirmation)
vimp scan --image nginx:1.25

# Non-interactive mode (auto-confirm)
vimp scan --image nginx:1.25 --yes

# Use specific scanners only
vimp scan --image nginx:1.25 --scanner grype --scanner trivy --yes
```

**Output:**
- JSON reports saved to `./reports/<image>/<scanner>.json`
- Results automatically imported to SQLite (`~/.vimp.db`)

### Scan Only (No Import)

To save reports without importing to a database:

```bash
vimp scan --image nginx:1.25 --yes --scan-only
```

### Custom Output Directory

```bash
vimp scan --image nginx:1.25 --yes --output ./my-reports
```

### Tag Discovery

Use `--disco` to automatically discover and scan recent tags from a registry. This is useful for scanning multiple versions of an image at once:

```bash
# Discover and scan the 5 most recent tags (default)
vimp scan --image alpine --disco --yes

# Scan the 3 most recent tags
vimp scan --image nginx --disco --tags 3 --yes

# Tag discovery with specific scanners
vimp scan --image redis --disco --tags 3 --scanner grype --scanner trivy --yes
```

Tags are sorted by semantic versioning (highest version first). All scans run concurrently (up to 10 parallel operations) for faster processing.

## Step 2: Import Results

The `import` command loads vulnerability data into a database for querying.

### Import from Scanner Output

If you have existing scanner reports:

```bash
# Auto-detect scanner format
vimp import --source docker.io/nginx:1.25 --file grype-report.json

# Import to PostgreSQL
vimp import --source docker.io/nginx:1.25 --file report.json \
  --target postgres://localhost:5432/vulns

# Import to BigQuery
vimp import --source docker.io/nginx:1.25 --file report.json \
  --target bq://myproject.dataset.vulnerabilities
```

### Auto-Scan and Import

If no `--file` is provided, vimp will scan the image automatically:

```bash
# Scan with all available scanners and import
vimp import --source docker.io/nginx:1.25

# Scan with specific scanners
vimp import --source docker.io/nginx:1.25 --scanners grype,trivy
```

## Step 3: Query Results

The `query` command provides hierarchical drill-down into vulnerability data.

### List All Images

```bash
vimp query
```

**Example output:**
```json
{
  "docker.io/library/nginx": {
    "versions": {
      "sha256:abc123...": {
        "exposures": 42,
        "sources": 2,
        "packages": 15,
        "high_score": 9.8
      }
    }
  }
}
```

### List Digests for an Image

```bash
vimp query --image docker.io/library/nginx
```

### List Vulnerabilities for a Digest

```bash
vimp query --image docker.io/library/nginx --digest sha256:abc123...
```

### Show Cross-Scanner Differences

Identify vulnerabilities where scanners disagree on severity:

```bash
vimp query --image docker.io/library/nginx --digest sha256:abc123... --diff
```

**Example output:**
```json
{
  "CVE-2023-1234": [
    {"source": "grype", "severity": "high", "score": 7.5},
    {"source": "trivy", "severity": "medium", "score": 5.3}
  ]
}
```

### Query Packages Affected by a CVE

```bash
vimp query --image docker.io/library/nginx --digest sha256:abc123... \
  --exposure CVE-2023-1234
```

### SARIF Output for GitHub

Generate SARIF format for GitHub Code Scanning integration:

```bash
vimp query --image docker.io/library/nginx --format sarif > results.sarif
```

## Complete Example

Here's a full end-to-end example you can copy and run:

```bash
# Install grype if not already installed
# brew install anchore/grype/grype

# Scan redis:7 with all available scanners
vimp scan --image redis:7 --yes

# List all scanned images
vimp query

# Get details for redis
vimp query --image docker.io/library/redis

# Show vulnerabilities for a specific digest (use the digest from previous output)
# vimp query --image docker.io/library/redis --digest sha256:...

# Export as SARIF for GitHub
vimp query --image docker.io/library/redis --format sarif > redis-vulns.sarif
```

## Storage Targets

vimp supports multiple storage backends:

| Target     | URI Format                          | Use Case                    |
|------------|-------------------------------------|-----------------------------|
| SQLite     | `sqlite://path/to/db.db`            | Local development (default) |
| PostgreSQL | `postgres://host:port/db`           | Team/production use         |
| BigQuery   | `bq://project.dataset.table`        | Large-scale analysis        |
| File       | `file://path/to/output.json`        | Export/archive              |
| Console    | `console://`                        | Debugging                   |

**Default:** `sqlite://~/.vimp.db`

Set a default target using the `VIMP_TARGET` environment variable:

```bash
export VIMP_TARGET="postgres://localhost:5432/vulns"
vimp import --source docker.io/nginx:1.25 --file report.json
```

## Next Steps

- See the [CLI Reference](cli-reference.md) for complete command documentation
- Check the [README](../README.md) for installation options and supported scanners
