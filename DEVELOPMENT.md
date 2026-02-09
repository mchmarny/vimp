# Development Guide

This guide covers project setup, architecture, and development workflows for contributors working on vimp.

## Table of Contents

- [Quick Start](#quick-start)
- [Prerequisites](#prerequisites)
- [Project Architecture](#project-architecture)
- [Development Workflow](#development-workflow)
- [Make Targets Reference](#make-targets-reference)
- [Debugging](#debugging)

## Quick Start

```bash
# 1. Clone and setup
git clone https://github.com/mchmarny/vimp.git && cd vimp
make tidy           # Download dependencies

# 2. Develop
make test           # Run tests with race detector
make lint           # Run linters
make build          # Build binary to ./bin/vimp

# 3. Before submitting PR
make qualify        # Full check: test + lint
```

## Prerequisites

### Required Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| **Go 1.23+** | Language runtime | [golang.org/dl](https://golang.org/dl/) |
| **make** | Build automation | Pre-installed on macOS; `apt install make` on Ubuntu/Debian |
| **git** | Version control | Pre-installed on most systems |

### Development Tools

| Tool | Purpose | Installation |
|------|---------|--------------|
| golangci-lint | Go linting | `go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest` |
| yamllint | YAML linting | `pip install yamllint` or `brew install yamllint` |

### Version Management

Tool versions are centrally managed in `.versions.yaml`. This file is used by:
- `tools/check-tools` - Version verification
- `tools/setup-tools` - Local development setup
- GitHub Actions CI - Ensures CI uses identical versions

```bash
# Check installed tool versions
tools/check-tools

# Install required tools
tools/setup-tools
```

## Project Architecture

### Directory Structure

```
vimp/
├── cmd/vimp/           # CLI entry point
├── internal/
│   ├── cmd/            # CLI commands (urfave/cli v3)
│   ├── config/         # Configuration utilities
│   ├── converter/      # Scanner-specific JSON parsers
│   │   ├── grype/
│   │   ├── trivy/
│   │   ├── snyk/
│   │   ├── clair/
│   │   ├── osv/
│   │   └── anchore/
│   ├── parser/         # JSON parsing with gabs
│   ├── processor/      # Import/query orchestration
│   ├── scanner/        # Scanner execution
│   └── target/         # Storage backends
│       ├── sqlite/
│       ├── postgres/
│       ├── bq/
│       ├── file/
│       └── console/
├── pkg/
│   ├── data/           # Shared data structures
│   ├── errors/         # Structured error handling
│   ├── logging/        # CLI logging with colors
│   ├── query/          # Query types and results
│   └── sarif/          # SARIF output format
├── docs/               # User documentation
└── tools/              # Development scripts
```

### Key Components

#### CLI (`cmd/vimp`)
- **Framework**: [urfave/cli v3](https://github.com/urfave/cli)
- **Commands**: `scan`, `import`, `query`
- **Logging**: Custom slog handler with colored output

#### Converters (`internal/converter/`)
- **Pattern**: Registry-based with auto-detection
- **Interface**: `Name()`, `CanHandle(*gabs.Container)`, `Convert(ctx, *gabs.Container)`
- **Detection**: Each converter implements `CanHandle()` to detect its format
- **Supported**: grype, trivy, snyk, clair, osv, anchore

#### Scanners (`internal/scanner/`)
- **Pattern**: Registry-based with availability checking
- **Interface**: `Name()`, `IsAvailable()`, `Scan(ctx, image)`, `ConverterName()`
- **Execution**: Shells out to installed scanner binaries

#### Targets (`internal/target/`)
- **Pattern**: URI-based selection (`sqlite://`, `postgres://`, etc.)
- **Interfaces**: `Importer` for storing data, `Querier` for retrieving data
- **Query Support**: SQLite and PostgreSQL only

### Data Flow

```
Scanner Output (JSON) → Converter → Vulnerability → Target Importer → Storage
                                                  ↓
                                         Target Querier → Query Results (JSON/SARIF)
```

### Database Schema

Primary key (6-part): `(image, digest, source, exposure, package, version)`

Key columns:
- `image` - Container image URI (without tag/digest)
- `digest` - SHA256 digest
- `source` - Scanner name (grype, trivy, etc.)
- `processed` - RFC3339 timestamp
- `exposure` - CVE ID
- `package`, `version` - Affected package
- `severity`, `score` - CVSS info

## Development Workflow

### 1. Create a Branch

```bash
# For new features
git checkout -b feat/add-new-scanner

# For bug fixes
git checkout -b fix/query-timeout

# For documentation
git checkout -b docs/update-cli-reference
```

### 2. Make Changes

- **Small, focused commits**: Each commit should address one logical change
- **Clear commit messages**: Use imperative mood ("Add feature" not "Added feature")
- **Test as you go**: Write tests alongside your code

### 3. Run Tests

```bash
# Run unit tests with race detector
make test

# Run specific test
go test -v -run TestGrypeConverter ./internal/converter/grype/

# Run with coverage
make cover
```

### 4. Lint Your Code

```bash
# Run all linters
make lint

# Format code
make tidy
```

### 5. Full Qualification

Before submitting a PR:

```bash
make qualify
```

This runs: `tidy` → `test` → `lint`

### Adding a New Converter

1. Create package under `internal/converter/<name>/`
2. Implement `Converter` interface
3. Add `test.json` fixture file
4. Register in `internal/converter/converter.go` DefaultRegistry
5. Add tests

### Adding a New Scanner

1. Create package under `internal/scanner/<name>/`
2. Implement `Scanner` interface
3. Register in `internal/scanner/scanner.go` DefaultRegistry
4. Map to appropriate converter via `ConverterName()`

## Make Targets Reference

### Quality & Testing

| Target | Description |
|--------|-------------|
| `make test` | Unit tests with race detector and coverage |
| `make cover` | Tests with HTML coverage report |
| `make lint` | Lint Go and YAML files |
| `make qualify` | Full qualification (tidy + test + lint) |

### Build

| Target | Description |
|--------|-------------|
| `make build` | Build binary to `./bin/vimp` |
| `make tidy` | Format code and update go.mod |

### Release

| Target | Description |
|--------|-------------|
| `make bump-major` | Bump major version (1.2.3 → 2.0.0) |
| `make bump-minor` | Bump minor version (1.2.3 → 1.3.0) |
| `make bump-patch` | Bump patch version (1.2.3 → 1.2.4) |

### Utilities

| Target | Description |
|--------|-------------|
| `make clean` | Clean build artifacts |
| `make help` | Show all available targets |

## Debugging

### Common Issues

| Issue | Solution |
|-------|----------|
| Tests fail with race conditions | Ensure `ctx.Done()` is checked in loops |
| Import fails silently | Check `--debug` flag for detailed logging |
| Scanner not found | Verify scanner is installed and in PATH |
| Database locked (SQLite) | Close other connections; use PostgreSQL for concurrent access |

### Debugging Tests

```bash
# Run specific test with verbose output
go test -v ./internal/converter/grype/... -run TestConvert

# Run tests with race detector
go test -race ./...

# Generate coverage report
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Debugging CLI

```bash
# Enable debug logging
vimp --debug scan --image alpine:latest

# Check version
vimp --version
```

## Code Style

- Use existing patterns - read the code before adding new approaches
- Context timeouts on all I/O operations
- Check `ctx.Done()` in loops
- Structured errors with `pkg/errors`
- No unnecessary comments - code should be self-documenting

## Additional Resources

- [User Guide](docs/user-guide.md) - End-user documentation
- [CLI Reference](docs/cli-reference.md) - Complete command documentation
