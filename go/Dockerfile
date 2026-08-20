# SEC-AF Go node — multi-stage build.
#
# Build from the SEC-AF repo ROOT so the go/ module is in the build context and
# the paths below (go/go.mod, go/) resolve. docker-compose.go.yml builds it
# exactly this way (build.context: ., dockerfile: go/Dockerfile):
#
#     docker build -f go/Dockerfile -t sec-af-go:latest .
#
# The AgentField Go SDK is a REAL versioned require resolved from
# proxy.golang.org, so there is no SDK clone stage, no GOWORK=off and no
# `replace` dance: `go mod download` pulls everything from the module proxy,
# cache-keyed on go.mod/go.sum.

# ---------------------------------------------------------------------------
# Stage 0 — aforge: fetch the released AForge CLI from the public download host
# and verify it against the release checksums (which hash the DECOMPRESSED
# binaries). Lifted from this repo's own Python Dockerfile so both images ship
# the identical, checksum-verified binary. Both ARGs are overridable:
#
#     docker build --build-arg AFORGE_BASE_URL=... --build-arg AFORGE_VERSION=... .
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS aforge

ARG AFORGE_BASE_URL=https://agentfield.ai/downloads/aforge
ARG AFORGE_VERSION=v0.1.0
# Provided automatically by BuildKit; defaults to the builder's own arch.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /out

RUN set -eux; \
    arch="${TARGETARCH:-$(dpkg --print-architecture)}"; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/aforge-linux-${arch}.gz" -o aforge.gz; \
    gunzip -c aforge.gz > aforge; \
    rm -f aforge.gz; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/checksums.txt" -o checksums.txt; \
    tr -d '\r' < checksums.txt \
        | grep " aforge-linux-${arch}$" \
        | sed 's/  aforge-linux-.*/  aforge/' > aforge.sha256; \
    test -s aforge.sha256; \
    sha256sum -c aforge.sha256; \
    rm -f checksums.txt aforge.sha256; \
    chmod +x aforge


# ---------------------------------------------------------------------------
# Stage 1 — builder: fetch modules from the proxy, build the static binary.
# Go 1.23 satisfies go.mod's `go 1.21` directive.
# ---------------------------------------------------------------------------
FROM golang:1.23-bookworm AS builder

WORKDIR /src

# Prime the module cache from go.mod/go.sum first so dependency downloads cache
# independently of source edits (this layer re-runs only when they change).
COPY go/go.mod go/go.sum ./
RUN go mod download

COPY go/ ./
ENV CGO_ENABLED=0 GOOS=linux
RUN go build -trimpath -ldflags="-s -w" -o /out/sec-af ./cmd/sec-af


# ---------------------------------------------------------------------------
# Stage 2 — runtime: slim Debian mirroring the Python image (opencode CLI + a
# non-root secaf user), shipping the single static Go binary instead of a Python
# runtime. The entrypoint generates opencode.json from HARNESS_MODEL at
# container start, so the env var is honored instead of a baked-in model.
# ---------------------------------------------------------------------------
FROM debian:bookworm-slim AS runtime

ARG OPENCODE_VERSION=1.17.15

# AGENTFIELD_SERVER is deliberately NOT baked in: sec-af's Python image does not
# set it either (Dockerfile runtime ENV block), so both images fall back to the
# node's own default, http://localhost:8080 (app.py:39, go/internal/node/node.go:180)
# — which is what go/README.md's env table documents. docker-compose.go.yml sets
# it explicitly for the compose stack; a bare `docker run` keeps the localhost
# default instead of reaching for a hostname that only exists inside compose.
ENV HARNESS_PROVIDER=aforge \
    AGENTFIELD_AFORGE_COMMAND=exec \
    HARNESS_MODEL=openrouter/minimax/minimax-m2.5 \
    AI_MODEL=openrouter/minimax/minimax-m2.5 \
    PORT=8013 \
    NODE_ID=sec-af \
    HOME=/home/secaf \
    PATH=/home/secaf/.opencode/bin:${PATH} \
    SEC_AF_WORKSPACES_DIR=/workspaces

# XDG_DATA_HOME is deliberately NOT set, for the same reason as
# AGENTFIELD_SERVER above: sec-af's Python image does not set it (Dockerfile
# runtime ENV block) and neither does its compose file, so
# `AIIntegrationConfig.provider_env()` (src/sec_af/config.py:123) takes its
# `os.path.join(tempfile.gettempdir(), "opencode-shared-data")` fallback in the
# container. Setting it here — as the pr-af image does, where BOTH sides set it
# and it IS parity — would give the Go node a different opencode data directory
# with a different lifetime (a persistent volume instead of an ephemeral /tmp)
# and would mean config.ProviderEnv never exercises the fallback branch it was
# written to port.

# System deps: ca-certificates (HTTPS to the LLM provider + git hosts), curl
# (healthcheck + opencode installer), git (audit clones the target repository).
# Create the non-root secaf user (uid/gid 10001) and install the opencode CLI as
# that user so it lands under /home/secaf/.opencode (on PATH above).
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git && \
    groupadd --gid 10001 secaf && \
    useradd --uid 10001 --gid secaf --create-home --home-dir /home/secaf --shell /bin/sh secaf && \
    su -s /bin/sh secaf -c "curl -fsSL https://opencode.ai/install | bash -s -- --version ${OPENCODE_VERSION} --no-modify-path" && \
    mkdir -p /workspaces && \
    chown -R secaf:secaf /workspaces /home/secaf && \
    rm -rf /var/lib/apt/lists/*

COPY --from=builder /out/sec-af /usr/local/bin/sec-af
COPY --from=aforge /out/aforge /usr/local/bin/aforge
COPY go/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

USER secaf
# Cwd must be writable by secaf: the AgentField Go SDK creates its schema output
# dir under the process cwd when a harness call carries no Cwd, and `/` is
# root-owned. /workspaces is secaf-owned and is SEC_AF_WORKSPACES_DIR already.
WORKDIR /workspaces

EXPOSE 8013

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8013/health || exit 1

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["/usr/local/bin/sec-af"]
