# SEC-AF Go port — build/test targets. Run from the go/ directory.
# Mirrors the acceptance gate CI runs (.github/workflows/go.yml):
#   go build ./... && go vet ./... && go test ./... && test -z "$(gofmt -l .)"
#
# The AgentField Go SDK is a REAL versioned require resolved from
# proxy.golang.org (no replace directive), so no GOWORK/replace dance is needed
# for CI/Docker. A gitignored go.work is the local dev path; set GOWORK=off to
# ignore it explicitly.

.PHONY: build vet test check fmt fmtcheck lint run docker-build docker-up docker-down

# Compile every package in the module.
build:
	go build ./...

# Static analysis (go vet) across the module.
vet:
	go vet ./...

# Unit tests across the module.
test:
	go test ./...

# Fail when any file is not gofmt-clean (the CI gate).
fmtcheck:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt: files above need formatting" && exit 1)

# The full local gate CI runs.
check: build vet test fmtcheck

# Format every Go source file in place.
fmt:
	gofmt -w .

# Optional lint pass; no-op with a hint when golangci-lint is not installed.
#
# The if/else is load-bearing: `probe && golangci-lint run || echo ...` chains
# left to right in ONE shell, so the `|| echo` arm fires for a real lint failure
# just as it does for a missing binary — printing "not installed" over the
# findings and exiting 0. Only the ABSENCE of the tool may be a no-op; a lint
# failure must fail the target.
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed; skipping (install: https://golangci-lint.run)"; \
	fi

# Run the SEC-AF node (sec-af, default port 8013).
run:
	go run ./cmd/sec-af

# --- Docker (multi-stage image + Go-node compose add-on) ------------------
# The Dockerfile expects the REPO ROOT as the build context (it COPYs
# go/go.mod, go/ ...), so the context is the parent directory. The compose
# add-on (docker-compose.go.yml) lives at the repo root and joins the Python
# sec-af stack's network + workspaces volume.
# The tag is `sec-af-go`, NOT `sec-af`: the root README documents
# `docker build -t sec-af .` for the PYTHON image, which resolves to the same
# `sec-af:latest`, and a user following both docs would silently overwrite one
# image with the other. `sec-af-go` also matches the CI job's tag
# (.github/workflows/go.yml) and the compose service/node id.
# Override the image tag with: make docker-build IMAGE=myrepo/sec-af-go:dev
IMAGE ?= sec-af-go:latest

docker-build:
	docker build -f Dockerfile -t $(IMAGE) ..

# Bring up the Go node (sec-af-go:8013) as an ADD-ON to the Python stack. Start
# the Python stack first (`docker compose up` — it owns the control plane +
# shared network); this add-on joins that network as an external reference.
docker-up:
	docker compose -f ../docker-compose.go.yml up --build

# Tear the Go-node add-on down.
docker-down:
	docker compose -f ../docker-compose.go.yml down
