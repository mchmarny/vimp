RELEASE_VERSION :=$(shell cat .version)
COMMIT          :=$(shell git rev-parse HEAD)
YAML_FILES      :=$(shell find . -type f -regex ".*yaml" -print)
CURRENT_DATE	:=$(shell date '+%Y-%m-%dT%H:%M:%SZ')

## Variable assertions
ifndef RELEASE_VERSION
	$(error RELEASE_VERSION is not set)
endif

ifndef COMMIT
	$(error COMMIT is not set)
endif

all: help

.PHONY: version
version: ## Prints the current version
	@echo $(RELEASE_VERSION)

.PHONY: tidy
tidy: ## Updates the go modules and vendors all dependancies 
	go mod tidy
	go mod vendor

.PHONY: upgrade
upgrade: ## Upgrades all dependancies 
	go get -d -u ./...
	go mod tidy
	go mod vendor

.PHONY: test
test: tidy ## Runs unit tests
	mkdir -p tmp
	go test -short -count=1 -race -covermode=atomic -coverprofile=cover.out ./...

.PHONY: cover
cover: test ## Runs unit tests and putputs coverage
	go tool cover -func=cover.out

.PHONY: lint
lint: lint-go lint-yaml ## Lints the entire project 
	@echo "Completed Go and YAML lints"

.PHONY: lint
lint-go: ## Lints the entire project using go 
	golangci-lint run -c .golangci.yaml

.PHONY: lint-yaml
lint-yaml: ## Runs yamllint on all yaml files (brew install yamllint)
	yamllint -c .yamllint $(YAML_FILES)

.PHONY: build
build: tidy ## Builds CLI binary
	mkdir -p ./bin
	CGO_ENABLED=0 go build -trimpath -ldflags="\
    -w -s -X main.version=$(RELEASE_VERSION) \
	-w -s -X main.commit=$(COMMIT) \
	-w -s -X main.date=$(CURRENT_DATE) \
	-extldflags '-static'" \
    -a -mod vendor -o bin/vulctl cmd/vulctl/main.go

.PHONY: image
image: ## Builds the docker image
	docker build \
		--build-arg VERSION=$(RELEASE_VERSION) \
		--build-arg COMMIT=$(COMMIT) \
		--build-arg DATE=$(CURRENT_DATE) \
		-t vulctl:$(RELEASE_VERSION) \
		.

.PHONY: setup
setup: ## Creates the GCP resources 
	terraform -chdir=./setup init
	terraform -chdir=./setup apply -auto-approve

.PHONY: apply
apply: ## Applies Terraform
	terraform -chdir=./setup apply -auto-approve

.PHONY: tag
tag: ## Creates release tag 
	git tag -s -m "release $(RELEASE_VERSION)" $(RELEASE_VERSION)
	git push origin $(RELEASE_VERSION)

.PHONY: tagless
tagless: ## Delete the current release tag 
	git tag -d $(RELEASE_VERSION)
	git push --delete origin $(RELEASE_VERSION)

.PHONY: clean
clean: ## Cleans bin and temp directories
	go clean
	rm -fr ./vendor
	rm -fr ./bin

.PHONY: help
help: ## Display available commands
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk \
		'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
