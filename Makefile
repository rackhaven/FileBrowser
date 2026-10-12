# Makefile. Everything works with plain `go` too; this is just shorthand.
#
#   make dev        run the server locally on :8080 against ./data/files
#   make test       vet + unit tests (Linux, where the symlink cases run)
#   make check      the full pre-commit gate: fmt, vet, tests, PWA wiring
#   make build      static binaries for linux, darwin and windows
#   make image      build the container image
#   make icons      regenerate the PWA icons
#   make shots      screenshot the PWA against a running dev server

BINARY  := filebrowser
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath

export CGO_ENABLED := 0

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

.PHONY: build
build: ## static binary for the current platform
	go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o $(BINARY) ./cmd/filebrowser

.PHONY: build-all
build-all: ## cross-compile for linux/amd64, linux/arm64, darwin, windows
	CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64   ./cmd/filebrowser
	CGO_ENABLED=0 GOOS=linux   GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64   ./cmd/filebrowser
	CGO_ENABLED=0 GOOS=darwin  GOARCH=arm64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-darwin-arm64  ./cmd/filebrowser
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-windows-amd64.exe ./cmd/filebrowser
	@ls -lh dist/

.PHONY: test
test: ## go vet + unit tests
	go vet ./...
	go test ./...

.PHONY: test-race
test-race: ## unit tests under the race detector (needs cgo)
	CGO_ENABLED=1 go test -race -count=1 ./...

.PHONY: fmt
fmt: ## format Go sources
	gofmt -w ./cmd ./internal ./web

.PHONY: check
check: fmt test wiring ## everything CI runs
	@echo "all checks passed"

.PHONY: wiring
wiring: ## check the PWA's html/js/css agree with each other
	node tools/check-wiring.mjs

.PHONY: icons
icons: ## regenerate the PWA icons from tools/gen-icons.mjs
	node tools/gen-icons.mjs

.PHONY: shots
shots: ## screenshot the PWA (needs a server on :8199 and Chrome with --remote-debugging-port=9222)
	node tools/screenshot.mjs "$(SESSION)" "$(OUT)"

.PHONY: image
image: ## build the container image
	docker build --build-arg VERSION=$(VERSION) -t $(BINARY):$(VERSION) -t $(BINARY):latest .

.PHONY: run
run: ## run against ./data/files on :8080
	FB_ADMIN_USER=admin ./$(BINARY) serve -listen :8080 -root ./data/files -data ./data

.PHONY: dev
dev: build ## build then run against ./data/files on :8080
	FB_ADMIN_USER=admin ./$(BINARY) serve -listen :8080 -root ./data/files -data ./data

.PHONY: clean
clean: ## remove build output
	rm -rf dist $(BINARY) $(BINARY).exe
