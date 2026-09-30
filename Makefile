BINARY := localiam
INSTALL_DIR := $(HOME)/.local/bin

# This repo sits under the tree's go.work without being a member.
GO := GOWORK=off go

.DEFAULT_GOAL := help

.PHONY: help
help: ## Display this help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_\/-]+:.*?## / {printf "\033[36m%-10s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.PHONY: build
build: ## Build the binary to dist/localiam
	$(GO) build -o dist/$(BINARY) ./cmd/localiam

.PHONY: install
install: build ## Build and install to ~/.local/bin
	@mkdir -p $(INSTALL_DIR)
	@cp dist/$(BINARY) $(INSTALL_DIR)/$(BINARY)

.PHONY: test
test: ## Run tests with the race detector
	$(GO) test -race ./...

.PHONY: fmt
fmt: ## Format with gofumpt
	$(GO) tool gofumpt -l -w .

.PHONY: vet
vet: ## go vet
	$(GO) vet ./...

.PHONY: tidy
tidy: ## go mod tidy
	$(GO) mod tidy

.PHONY: image
image: ## Build the container image as localiam:dev
	docker build -t $(BINARY):dev .

# There is no lint target: golangci-lint runs as a pre-commit hook and in CI.
.PHONY: check
check: vet test ## What CI runs
	$(GO) build ./...

.PHONY: clean
clean: ## Remove build output
	rm -rf dist
