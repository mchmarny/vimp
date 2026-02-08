# vimp

Compare data from multiple vulnerability scanners to get a more complete picture of potential exposures.

`vimp` normalizes output from common container image vulnerability scanners into a unified format, enabling cross-scanner comparison and trend analysis. Results can be stored in SQLite, PostgreSQL, or BigQuery, and exported as JSON or SARIF for GitHub Code Scanning integration.

## Supported Scanners

| Scanner | Detection | Notes |
|---------|-----------|-------|
| [Grype](https://github.com/anchore/grype) | `descriptor.name == "grype"` | Full CVSS support |
| [Trivy](https://github.com/aquasecurity/trivy) | `SchemaVersion` + `Results` | Full CVSS support |
| [Snyk](https://github.com/snyk/cli) | `vulnerabilities` + `applications` | Full CVSS support |
| [Clair](https://github.com/quay/clair) | `manifest_hash` + `vulnerabilities` | No CVSS scores |
| [OSV-Scanner](https://github.com/google/osv-scanner) | `results[*].packages[*].ecosystem` | SBOM-based |
| [Anchore Engine](https://github.com/anchore/anchore-engine) | `imageDigest` + `vulnerabilities` | Legacy support |

## Quick Start

```shell
# Scan an image (discovers installed scanners, saves reports, imports to SQLite)
vimp scan --image alpine:latest --yes

# Query results
vimp query --image docker.io/alpine:latest

# Or import from existing scanner output
vimp import --source docker.io/redis:latest --file grype-report.json
```

## Usage

### Scan

Scan container images for vulnerabilities using installed scanners:

```shell
# Discover scanners and scan (prompts for confirmation)
vimp scan --image alpine:latest

# Scan with specific scanners (no confirmation needed)
vimp scan --image alpine:latest --scanner grype --scanner trivy

# Skip confirmation prompt
vimp scan --image alpine:latest --yes

# Custom output directory
vimp scan --image alpine:latest --output ./my-reports

# Scan only (skip auto-import to database)
vimp scan --image alpine:latest --yes --scan-only
```

Results are saved to `./reports/<image>/<scanner>.json` and automatically imported into the default SQLite database unless `--scan-only` is specified.

### Import

Import vulnerability data from scanner output or automatically scan an image:

```shell
# Import from file (auto-detects scanner format)
vimp import --source docker.io/redis --file report.json

# Auto-scan with all installed scanners
vimp import --source docker.io/redis

# Import to PostgreSQL
vimp import --source docker.io/redis --file report.json --target postgres://localhost:5432/vulns

# Import to BigQuery
vimp import --source docker.io/redis --file report.json --target bq://project.dataset.table
```

### Query

Query stored vulnerability data with hierarchical drill-down:

```shell
# Summary of all images
vimp query

# Digests for an image
vimp query --image docker.io/redis

# Vulnerabilities for a specific digest
vimp query --image docker.io/redis --digest sha256:abc123...

# Show only cross-scanner differences
vimp query --image docker.io/redis --digest sha256:abc123... --diff

# Packages affected by a CVE
vimp query --image docker.io/redis --digest sha256:abc123... --exposure CVE-2021-44228

# SARIF output for GitHub Code Scanning
vimp query --image docker.io/redis --format sarif > results.sarif
```

### Example Output

Summary query:
```json
{
  "docker.io/redis": {
    "versions": {
      "sha256:7b83a0167532d4320a87246a815a134e19e31504d85e8e55f0bb5bb9edf70448": {
        "exposures": 240,
        "sources": 3,
        "packages": 73,
        "high_score": 10,
        "first_discovered": "2023-04-05T19:29:16Z",
        "last_discovered": "2023-04-05T19:41:11Z"
      }
    }
  }
}
```

Cross-scanner comparison (with `--diff`):
```json
{
  "CVE-2013-4392": [
    {"source": "grype", "severity": "low", "score": 3.3},
    {"source": "snyk", "severity": "medium", "score": 4.4},
    {"source": "trivy", "severity": "low", "score": 0}
  ]
}
```

## Storage Targets

| Target | URI Format | Query Support |
|--------|------------|---------------|
| SQLite | `sqlite://path/to/db.db` | Yes |
| PostgreSQL | `postgres://host:port/db` | Yes |
| BigQuery | `bq://project.dataset.table` | Import only |
| File | `file://path/to/output.json` | No |
| Console | `console://` | No |

Default: `sqlite://~/.vimp.db`

### Database Schema

```sql
CREATE TABLE vul (
    image      TEXT    NOT NULL,
    digest     TEXT    NOT NULL,
    source     TEXT    NOT NULL,
    processed  TEXT    NOT NULL,
    exposure   TEXT    NOT NULL,
    package    TEXT    NOT NULL,
    version    TEXT    NOT NULL,
    severity   TEXT    NOT NULL,
    score      REAL    NOT NULL,
    fixed      BOOLEAN NOT NULL,
    PRIMARY KEY (image, digest, source, exposure, package, version)
);
CREATE INDEX idx_image_processed ON vul(image, processed);
```

## Installation

### Go

```shell
go install github.com/mchmarny/vimp@latest
```

### Homebrew

```shell
brew tap mchmarny/vimp
brew install vimp
```

### Container Image

```shell
docker pull ghcr.io/mchmarny/vimp:latest
```

### Binary

Download from [releases](https://github.com/mchmarny/vimp/releases/latest). Releases include checksums, SBOMs, and SLSA provenance attestations.

### Linux Packages

**RHEL/CentOS:**
```shell
rpm -ivh https://github.com/mchmarny/vimp/releases/download/v$VERSION/vimp-$VERSION_Linux-amd64.rpm
```

**Debian/Ubuntu:**
```shell
wget https://github.com/mchmarny/vimp/releases/download/v$VERSION/vimp-$VERSION_Linux-amd64.deb
sudo dpkg -i vimp-$VERSION_Linux-amd64.deb
```

## Development

```shell
make build      # Build binary
make test       # Run tests with coverage
make lint       # Run linters
make qualify    # Full quality gate (test + lint + scan)
```

## License

Apache 2.0

## Disclaimer

This is my personal project and it does not represent my employer. While I do my best to ensure that everything works, I take no responsibility for issues caused by this code.
