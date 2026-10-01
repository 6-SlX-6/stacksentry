# StackSentry developer tasks. Run `make help` for an overview.

BINARY   := stacksentry
PKG      := github.com/6-SlX-6/stacksentry
BIN_DIR  := bin
GO       ?= go

VERSION  ?= $(shell git describe --tags --exact-match 2>/dev/null)
COMMIT   ?= $(shell git rev-parse --short=12 HEAD 2>/dev/null)
DATE     ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS  := -s -w -X $(PKG)/internal/version.Commit=$(COMMIT) -X $(PKG)/internal/version.Date=$(DATE)
ifneq ($(VERSION),)
LDFLAGS  += -X $(PKG)/internal/version.Version=$(VERSION)
endif

# Packages whose statement coverage must stay at or above COVERAGE_MIN percent.
COVERAGE_PKGS := ./internal/engine ./internal/report ./internal/findings ./internal/rules/...
COVERAGE_MIN  := 80

.PHONY: help build test test-race lint fmt fmt-check vet coverage install run-example \
        verify-examples golden docs release-snapshot clean

help: ## Show this help
	@awk 'BEGIN {FS = ":.*## "} /^[a-zA-Z_-]+:.*## / {printf "  %-18s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build ./bin/stacksentry for the current platform
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o $(BIN_DIR)/$(BINARY) ./cmd/stacksentry

test: ## Run all tests
	$(GO) test ./...

test-race: ## Run all tests with the race detector
	$(GO) test -race ./...

lint: ## Run golangci-lint
	golangci-lint run ./...

fmt: ## Format code (gofmt, plus goimports via golangci-lint when installed)
	gofmt -s -w cmd internal
	@if command -v golangci-lint >/dev/null 2>&1; then golangci-lint fmt ./...; else echo "golangci-lint not found: ran gofmt only"; fi

fmt-check: ## Fail if code is not gofmt-formatted
	@out="$$(gofmt -s -l cmd internal)"; if [ -n "$$out" ]; then echo "Not formatted:"; echo "$$out"; exit 1; fi

vet: ## Run go vet
	$(GO) vet ./...

coverage: ## Write coverage.out and enforce the minimum for core packages
	$(GO) test -covermode=atomic -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -n 1
	@$(GO) test -cover $(COVERAGE_PKGS) | awk -v min=$(COVERAGE_MIN) '\
		/coverage:/ { for (i = 1; i <= NF; i++) if ($$i ~ /%$$/) { v = $$i; sub(/%/, "", v); \
			printf "  %-55s %s%%\n", $$2, v; if (v + 0 < min) { bad = 1; print "  ^ below " min "%" } } } \
		END { exit bad }'

install: ## Install stacksentry into GOBIN (or GOPATH/bin)
	CGO_ENABLED=0 $(GO) install -trimpath -ldflags "$(LDFLAGS)" ./cmd/stacksentry

run-example: build ## Scan the bundled example stacks
	./$(BIN_DIR)/$(BINARY) scan compose examples/n8n-postgres-compose.yaml --severity medium
	./$(BIN_DIR)/$(BINARY) scan compose examples/reasonably-secure-compose.yaml
	./$(BIN_DIR)/$(BINARY) scan compose examples/insecure-compose.yaml --severity high

verify-examples: build ## Run documented commands and check their exit codes
	./scripts/verify-examples.sh ./$(BIN_DIR)/$(BINARY)

golden: ## Regenerate golden reports (review the diff before committing)
	$(GO) test ./internal/app -run 'TestGolden' -update

docs: ## Regenerate the rule reference in docs/rules.md
	$(GO) test ./internal/cli -run TestRulesDocUpToDate -update

release-snapshot: ## Build release binaries and checksums into ./dist
	./scripts/build-release.sh $(or $(VERSION),v0.0.0-snapshot)

clean: ## Remove build and coverage output
	rm -rf $(BIN_DIR) dist coverage.out coverage.html
