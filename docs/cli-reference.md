# CLI Reference

Complete reference for all vimp commands and options.

## Global Options

These options are available for all commands:

| Option      | Description                |
|-------------|----------------------------|
| `--debug`   | Enable verbose output      |
| `--help`    | Show help                  |
| `--version` | Print version information  |

## Commands

- [scan](#scan) - Scan container images for vulnerabilities
- [import](#import) - Import vulnerability data from files
- [query](#query) - Query stored vulnerability data
- [server](#server) - Start web dashboard for vulnerability visualization

---

## scan

Scan a container image using available vulnerability scanners.

```
vimp scan [options]
```

### Description

Discovers available scanners on your system and runs them against a container image. Results are saved as JSON reports and automatically imported into a local SQLite database.

Use `--disco` to automatically discover recent tags from the registry and scan them all. Tags are sorted by semantic versioning (highest version first). All scan operations run concurrently with a maximum of 10 parallel operations.

**Supported scanners:** grype, trivy, snyk, osv

### Options

| Option | Shorthand | Description | Default |
|--------|-----------|-------------|---------|
| `--image` | `-i` | Container image to scan (required) | - |
| `--scanner` | `-s` | Scanner to use (can be repeated) | All available |
| `--output` | `-o` | Output directory for scan reports | `./reports` |
| `--target` | `-t` | Database target URI | `sqlite://~/.vimp.db` |
| `--yes` | `-y` | Skip confirmation prompt | `false` |
| `--scan-only` | - | Skip auto-import after scanning | `false` |
| `--disco` | - | Discover recent tags from registry | `false` |
| `--tags` | - | Number of tags to discover (1-20, requires `--disco`) | `5` |
| `--docker-mirror` | - | Docker Hub mirror URL (e.g., `mirror.gcr.io`) | - |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VIMP_TARGET` | Default target URI |
| `VIMP_DOCKER_MIRROR` | Docker Hub mirror URL |

### Examples

```bash
# Interactive scan (prompts for confirmation)
vimp scan --image alpine:latest

# Non-interactive scan
vimp scan --image alpine:latest --yes

# Scan with specific scanners
vimp scan --image alpine:latest --scanner grype --scanner trivy

# Custom output directory
vimp scan --image alpine:latest --output ./my-reports --yes

# Scan only (no database import)
vimp scan --image alpine:latest --yes --scan-only

# Import to PostgreSQL instead of SQLite
vimp scan --image alpine:latest --yes --target postgres://localhost:5432/vulns

# Discover and scan the 5 most recent tags
vimp scan --image alpine --disco --yes

# Discover and scan the 3 most recent tags
vimp scan --image nginx --disco --tags 3 --yes

# Tag discovery with specific scanners
vimp scan --image redis --disco --tags 3 --scanner grype --yes

# Use Docker Hub mirror
vimp scan --image alpine:latest --docker-mirror mirror.gcr.io --yes
```

### Output

Reports are saved to `<output>/<image>/<scanner>.json`:

```
./reports/
└── alpine_latest/
    ├── grype.json
    └── trivy.json
```

---

## import

Import vulnerability data from scanner output files or automatically scan an image.

```
vimp import [options]
```

### Description

Imports vulnerability data from scanner JSON output into a storage target. Supports auto-detection of scanner format. If no file is provided, automatically scans the image using available scanners.

**Supported formats:** grype, trivy, snyk, clair, osv-scanner, anchore

### Options

| Option | Shorthand | Description | Default |
|--------|-----------|-------------|---------|
| `--source` | `-s` | Image URI the report was generated from (required) | - |
| `--file` | `-f` | Path to vulnerability report file | - |
| `--target` | `-t` | Database target URI | `sqlite://~/.vimp.db` |
| `--scanners` | - | Comma-separated list of scanners (when no file) | All available |
| `--docker-mirror` | - | Docker Hub mirror URL (e.g., `mirror.gcr.io`) | - |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VIMP_TARGET` | Default target URI |
| `VIMP_DOCKER_MIRROR` | Docker Hub mirror URL |

### Target URI Formats

| Target | URI Format | Example |
|--------|------------|---------|
| SQLite | `sqlite://<path>` | `sqlite://data.db` |
| PostgreSQL | `postgres://<host>:<port>/<db>` | `postgres://localhost:5432/vulns` |
| BigQuery | `bq://<project>.<dataset>.<table>` | `bq://myproject.vulns.data` |
| File | `file://<path>` | `file://output.json` |
| Console | `console://` | `console://` |

### Examples

```bash
# Import from file (auto-detect format)
vimp import --source docker.io/redis:7 --file grype-report.json

# Auto-scan and import (no file)
vimp import --source docker.io/redis:7

# Auto-scan with specific scanners
vimp import --source docker.io/redis:7 --scanners grype,trivy

# Import to PostgreSQL
vimp import --source docker.io/redis:7 --file report.json \
  --target postgres://localhost:5432/vulns

# Import to BigQuery
vimp import --source docker.io/redis:7 --file report.json \
  --target bq://myproject.dataset.vulnerabilities

# Output to file
vimp import --source docker.io/redis:7 --file report.json \
  --target file://output.json

# Output to console (debugging)
vimp import --source docker.io/redis:7 --file report.json \
  --target console://
```

---

## query

Query stored vulnerability data with hierarchical drill-down.

```
vimp query [options]
```

### Description

Queries vulnerability data from a storage target. Supports hierarchical drill-down from images to digests to individual vulnerabilities. Can output as JSON or SARIF format.

### Options

| Option | Shorthand | Description | Default |
|--------|-----------|-------------|---------|
| `--target` | `-t` | Database target URI | `sqlite://~/.vimp.db` |
| `--image` | `--img` | Image URI (without tag/digest) | - |
| `--digest` | `--dig` | SHA256 digest of the image | - |
| `--exposure` | - | CVE ID to query | - |
| `--diff` | - | Only show cross-scanner differences | `false` |
| `--format` | - | Output format: `json` or `sarif` | `json` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VIMP_TARGET` | Default target URI |

### Query Hierarchy

1. **No options**: List all images with summary statistics
2. **`--image`**: List all digests for an image
3. **`--image --digest`**: List all vulnerabilities for a digest
4. **`--image --digest --exposure`**: List packages affected by a CVE
5. **`--image --digest --diff`**: Show cross-scanner differences

### Examples

```bash
# List all scanned images
vimp query

# List digests for an image
vimp query --image docker.io/library/nginx

# List vulnerabilities for a specific digest
vimp query --image docker.io/library/nginx --digest sha256:abc123...

# Show only cross-scanner differences
vimp query --image docker.io/library/nginx --digest sha256:abc123... --diff

# Query packages affected by a specific CVE
vimp query --image docker.io/library/nginx --digest sha256:abc123... \
  --exposure CVE-2021-44228

# Output as SARIF for GitHub Code Scanning
vimp query --image docker.io/library/nginx --format sarif > results.sarif

# Query from PostgreSQL
vimp query --target postgres://localhost:5432/vulns --image docker.io/library/nginx
```

### Output Formats

#### JSON (default)

Image summary:
```json
{
  "docker.io/library/nginx": {
    "versions": {
      "sha256:abc123...": {
        "exposures": 42,
        "sources": 2,
        "packages": 15,
        "high_score": 9.8,
        "first_discovered": "2024-01-15T10:30:00Z",
        "last_discovered": "2024-01-15T10:45:00Z"
      }
    }
  }
}
```

Cross-scanner diff:
```json
{
  "CVE-2023-1234": [
    {"source": "grype", "severity": "high", "score": 7.5},
    {"source": "trivy", "severity": "medium", "score": 5.3}
  ]
}
```

#### SARIF

SARIF 2.1.0 format for GitHub Code Scanning integration. Includes:
- Tool information
- Rules with severity mappings
- Results with locations

---

## server

Start a local HTTP server for the vulnerability dashboard.

```
vimp server [options]
```

### Description

Starts a local web server that provides a dashboard for visualizing vulnerability data. The dashboard includes:

- Overview statistics (images, exposures, severity distribution)
- Registry breakdown
- Recent scan results
- Image detail with time series charts
- Searchable image list
- Dark mode support

### Options

| Option | Shorthand | Description | Default |
|--------|-----------|-------------|---------|
| `--port` | `-p` | Port to listen on | `8080` |
| `--target` | `-t` | Database target URI | `sqlite://~/.vimp.db` |
| `--open` | - | Open browser automatically | `false` |

### Environment Variables

| Variable | Description |
|----------|-------------|
| `VIMP_TARGET` | Default target URI |

### Examples

```bash
# Start server with defaults
vimp server

# Start on custom port
vimp server --port 3000

# Start with PostgreSQL backend
vimp server --target postgres://localhost:5432/vulns

# Start and open browser automatically
vimp server --open

# Use a specific SQLite database
vimp server --target sqlite:///path/to/db.db --open
```

---

## Database Schema

vimp uses a single table for all storage targets:

```sql
CREATE TABLE vul (
    image      TEXT    NOT NULL,  -- Image URI (e.g., docker.io/library/nginx)
    digest     TEXT    NOT NULL,  -- SHA256 digest
    source     TEXT    NOT NULL,  -- Scanner name
    processed  TEXT    NOT NULL,  -- RFC3339 timestamp
    exposure   TEXT    NOT NULL,  -- CVE ID
    package    TEXT    NOT NULL,  -- Package name
    version    TEXT    NOT NULL,  -- Package version
    severity   TEXT    NOT NULL,  -- Severity level
    score      REAL    NOT NULL,  -- CVSS score
    fixed      BOOLEAN NOT NULL,  -- Fix available
    PRIMARY KEY (image, digest, source, exposure, package, version)
);

CREATE INDEX idx_image_processed ON vul(image, processed);
```

## Exit Codes

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |

## See Also

- [User Guide](user-guide.md) - Step-by-step workflow tutorial
- [README](../README.md) - Project overview and installation
