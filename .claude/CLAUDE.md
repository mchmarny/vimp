# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

`vimp` is a CLI tool that normalizes vulnerability data from multiple container image scanners, stores results in various backends, and provides unified querying capabilities.

**Supported scanners:** grype, trivy, snyk, clair, osv-scanner, anchore

**Storage backends:** SQLite, PostgreSQL, BigQuery, file, console

**Output formats:** JSON, SARIF (for GitHub Code Scanning)

## Non-Negotiable Rules

1. **Read before writing** — Never modify code you haven't read
2. **Tests must pass** — `make test` with race detector; never skip tests
3. **Use project patterns** — Learn existing code before inventing new approaches
4. **3-strike rule** — After 3 failed fix attempts, stop and reassess
5. **Context timeouts** — All I/O operations need context with timeout
6. **Check context in loops** — Always check `ctx.Done()` in long-running operations

## Git Configuration

- Commit to `main` branch (not `master`)
- Do use `-S` to cryptographically sign the commit
- Do NOT add `Co-Authored-By` lines (organization policy)
- Do not sign-off commits (no `-s` flag)

## Build and Development Commands

```bash
make build      # Build binary to ./bin/vimp
make test       # Run tests with race detection and coverage
make lint       # Run golangci-lint and yamllint
make tidy       # Format code and update go.mod
make cover      # Run tests and display coverage report
```

Run a single test:
```bash
go test -v -run TestGrypeConverter ./internal/converter/grype/
```

## Version Management

- **App version**: Determined from git tags (`git describe --tags`), injected at build time
- **Tool versions**: Centralized in `.versions.yaml`, used by GitHub Actions and local scripts

## Tools Scripts

```bash
tools/check-tools  # Verify installed tool versions match .versions.yaml
tools/setup-tools  # Install required tools at correct versions
tools/bump         # Version bumping with changelog generation
tools/e2e          # End-to-end integration tests
```

## Architecture

### Data Flow
```
Scanner Output (JSON) → Converter → Vulnerability → Target Importer → Storage
                                                  ↓
                                         Target Querier → Query Results (JSON/SARIF)
```

### Database Schema

Primary key (6-part): `(image, digest, source, exposure, package, version)`

### Key Packages

**`internal/cmd/`** - CLI commands using urfave/cli/v3
- `scan` - Scan container images using installed scanners (grype, trivy, snyk, osv). Supports `--disco` for tag discovery and concurrent execution.
- `import` - Import vulnerability reports from file or auto-scan image
- `query` - Query stored vulnerability data (supports JSON and SARIF output)

**`internal/converter/`** - Scanner-specific JSON parsers
- `grype/`, `trivy/`, `snyk/`, `clair/`, `osv/`, `anchore/` - 6 supported formats
- Registry pattern with auto-detection via `CanHandle()` method
- Uses gabs for JSON traversal

**`internal/scanner/`** - Scanner execution and registry
- Scanner interface with `Name()`, `IsAvailable()`, `Scan()`, `ConverterName()`
- Shells out to grype/trivy/snyk/osv if installed

**`internal/registry/`** - OCI registry operations
- `DiscoverTags()` - Discover recent tags from registry (sorted by semver)
- `BuildImageURIs()` - Build full image URIs from base ref and tags

**`internal/target/`** - Storage backends
- `sqlite/`, `postgres/`, `bq/` - Database targets with query support
- `file/`, `console/` - Output-only targets
- Each implements `Importer` and optionally `Querier` interfaces

**`internal/processor/`** - Core import/query orchestration
- Auto-detection of scanner format via converter registry
- Deduplication via SHA256 hash of exposure+package+version

**`pkg/data/`** - Shared data structures
- `Vulnerability` - Normalized vuln representation
- `ImageVulnerability` - Decorated with image/digest/source metadata

**`pkg/sarif/`** - SARIF 2.1.0 output format for GitHub Code Scanning

## Query Types

- `images` - List all scanned images
- `digests` - List digests for an image
- `exposure` - List vulnerabilities for image@digest
- `packages` - List affected packages for a CVE
- `timeseries` - Vulnerability counts over time
- `common` - Vulnerabilities shared across multiple images

## Target URI Schemes

Import targets use URI scheme prefix:
- `sqlite://path/to/db.db`
- `postgres://host:port/db`
- `bq://project.dataset.table`
- `file://path/to/output.json`
- `console://`

## Testing

Tests use `test.json` fixtures in each converter package. The `-short` flag skips integration tests requiring PostgreSQL.
