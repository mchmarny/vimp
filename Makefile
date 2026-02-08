# Makefile for vimp
# Purpose: Build, lint, test, and manage releases

REPO_NAME          := vimp
VERSION            ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo "v0.0.0")
IMAGE_REGISTRY     ?= ghcr.io/mchmarny
IMAGE_TAG          ?= latest
YAML_FILES         := $(shell find . -type f \( -iname "*.yml" -o -iname "*.yaml" \) ! -path "./vendor/*")
COMMIT             := $(shell git rev-parse HEAD 2>/dev/null || echo "unknown")
BRANCH             := $(shell git rev-parse --abbrev-ref HEAD 2>/dev/null || echo "unknown")
GO_VERSION         := $(shell go env GOVERSION 2>/dev/null | sed 's/go//')
GOLINT_VERSION     := $(shell golangci-lint --version 2>/dev/null | awk '{print $$4}' || echo "not installed")
GORELEASER_VERSION := $(shell goreleaser --version 2>/dev/null | sed -n 's/^GitVersion:[[:space:]]*//p' || echo "not installed")
COVERAGE_THRESHOLD ?= 70

all: help

# =============================================================================
# Info
# =============================================================================

.PHONY: info
info: ## Prints project info
	@echo "version:     $(VERSION)"
	@echo "commit:      $(COMMIT)"
	@echo "branch:      $(BRANCH)"
	@echo "go:          $(GO_VERSION)"
	@echo "linter:      $(GOLINT_VERSION)"
	@echo "goreleaser:  $(GORELEASER_VERSION)"

# =============================================================================
# Code Formatting & Dependencies
# =============================================================================

.PHONY: tidy
tidy: ## Formats code and updates Go module dependencies
	@go fmt ./...
	@go mod tidy

.PHONY: fmt-check
fmt-check: ## Checks if code is formatted (CI-friendly)
	@test -z "$$(gofmt -l .)" || (echo "Code not formatted. Run 'make tidy':" && gofmt -l . && exit 1)
	@echo "Code formatting check passed"

.PHONY: upgrade
upgrade: ## Upgrades all dependencies to latest versions
	@go get -u ./...
	@go mod tidy

# =============================================================================
# Linting
# =============================================================================

.PHONY: lint
lint: lint-go lint-yaml ## Lints the entire project (Go and YAML)
	@echo "Completed Go and YAML lints"

.PHONY: lint-go
lint-go: ## Lints Go files with golangci-lint
	@echo "Running go vet..."
	@go vet ./...
	@echo "Running golangci-lint..."
	@golangci-lint run -c .golangci.yaml

.PHONY: lint-yaml
lint-yaml: ## Lints YAML files with yamllint
	@if [ -n "$(YAML_FILES)" ]; then \
		yamllint -c .yamllint $(YAML_FILES); \
	else \
		echo "No YAML files found to lint."; \
	fi

# =============================================================================
# Testing
# =============================================================================

.PHONY: test
test: ## Runs unit tests with race detector and coverage
	@mkdir -p tmp
	@echo "Running tests with race detector..."
	@go test -short -count=1 -race -covermode=atomic -coverprofile=coverage.out ./...
	@echo "Test coverage:"
	@go tool cover -func=coverage.out | tail -1

.PHONY: test-coverage
test-coverage: test ## Runs tests and enforces coverage threshold
	@coverage=$$(go tool cover -func=coverage.out | grep total | awk '{print $$3}' | sed 's/%//'); \
	echo "Coverage: $$coverage% (threshold: $(COVERAGE_THRESHOLD)%)"; \
	if [ $$(echo "$$coverage < $(COVERAGE_THRESHOLD)" | bc) -eq 1 ]; then \
		echo "ERROR: Coverage $$coverage% is below threshold $(COVERAGE_THRESHOLD)%"; \
		exit 1; \
	fi; \
	echo "Coverage check passed"

.PHONY: cover
cover: test ## Runs tests and displays coverage report
	@go tool cover -func=coverage.out

.PHONY: e2e
e2e: build ## Runs end-to-end integration tests
	@echo "Running e2e tests..."
	@tools/e2e

# =============================================================================
# Security
# =============================================================================

.PHONY: scan
scan: ## Scans for vulnerabilities with grype
	@echo "Running vulnerability scan..."
	@grype dir:. --fail-on high --quiet

# =============================================================================
# Build & Release
# =============================================================================

.PHONY: build
build: tidy ## Builds binaries for the current OS and architecture
	@KO_DOCKER_REPO=$(IMAGE_REGISTRY) goreleaser build --clean --single-target --snapshot --timeout 10m0s || exit 1
	@mkdir -p bin && find dist -name vimp -type f -perm +111 -exec cp {} bin/vimp \;

.PHONY: image
image: ## Builds and pushes container image
	@echo "Building image: $(IMAGE_REGISTRY)/vimp:$(IMAGE_TAG)"
	@KO_DOCKER_REPO=$(IMAGE_REGISTRY) ko build --bare --sbom=none --tags=$(IMAGE_TAG) .

.PHONY: release
release: ## Runs full release process with goreleaser
	@goreleaser release --clean --timeout 10m0s

# =============================================================================
# Quality Gate
# =============================================================================

.PHONY: qualify
qualify: test lint scan ## Qualifies the codebase (test, lint, scan)
	@echo "Codebase qualification completed"

# =============================================================================
# Cleanup
# =============================================================================

.PHONY: clean
clean: ## Cleans build artifacts
	@rm -rf ./dist ./bin ./coverage.out ./cover.out ./tmp
	@go clean ./...
	@echo "Cleaned build artifacts"

.PHONY: clean-all
clean-all: clean ## Deep cleans including module cache
	@go clean -modcache
	@echo "Deep clean completed"

# =============================================================================
# Version Management
# =============================================================================

.PHONY: version
version: ## Prints the current version
	@echo $(VERSION)

.PHONY: tag
tag: ## Creates release tag
	@git tag -s -m "release $(VERSION)" $(VERSION)
	@git push origin $(VERSION)

.PHONY: tagless
tagless: ## Deletes the current release tag
	@git tag -d $(VERSION)
	@git push --delete origin $(VERSION)

# =============================================================================
# Help
# =============================================================================

.PHONY: help
help: ## Displays available commands
	@echo "Available make targets:"
	@grep -E '^[a-zA-Z0-9_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk \
		'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-18s\033[0m %s\n", $$1, $$2}'
