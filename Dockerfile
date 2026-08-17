# AForge CLI is fetched as a released, checksum-verified binary rather than
# copied out of a container image, so the build depends only on the public
# download host. Both ARGs are overridable (e.g. to point at a staging mirror).
ARG AFORGE_BASE_URL=https://agentfield.ai/downloads/aforge
ARG AFORGE_VERSION=build-9b3ff482de3f

FROM debian:bookworm-slim AS aforge

ARG AFORGE_BASE_URL
ARG AFORGE_VERSION
# Provided automatically by BuildKit; defaults to amd64 for legacy builders.
ARG TARGETARCH

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /out

# Download the gzipped release binary, decompress it, and verify the
# *decompressed* SHA-256 against the release checksums.txt before use.
RUN set -eux; \
    arch="${TARGETARCH:-amd64}"; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/aforge-linux-${arch}.gz" -o aforge.gz; \
    gunzip -c aforge.gz > aforge; \
    rm aforge.gz; \
    curl -fsSL "${AFORGE_BASE_URL}/${AFORGE_VERSION}/checksums.txt" -o checksums.txt; \
    tr -d '\r' < checksums.txt \
        | grep " aforge-linux-${arch}$" \
        | sed 's/  aforge-linux-.*/  aforge/' > aforge.sha256; \
    test -s aforge.sha256; \
    sha256sum -c aforge.sha256; \
    rm checksums.txt aforge.sha256; \
    chmod +x aforge


FROM python:3.11-slim AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install \
    "agentfield>=0.1.129" \
    "pydantic>=2.0" \
    "httpx>=0.27" \
    "python-dotenv>=1.0" && \
    pip install --no-cache-dir --prefix=/install --no-deps .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HARNESS_PROVIDER=aforge \
    AGENTFIELD_AFORGE_COMMAND=exec \
    HARNESS_MODEL=openrouter/minimax/minimax-m2.5 \
    AI_MODEL=openrouter/minimax/minimax-m2.5 \
    PORT=8080 \
    HOME=/home/secaf \
    PYTHONPATH=/app/src \
    PATH=/home/secaf/.opencode/bin:${PATH}

WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    git && \
    groupadd --gid 10001 secaf && \
    useradd --uid 10001 --gid secaf --create-home --home-dir /home/secaf --shell /bin/sh secaf && \
    su -s /bin/sh secaf -c "curl -fsSL https://opencode.ai/install | bash" && \
    mkdir -p /workspaces && \
    chown -R secaf:secaf /app /workspaces /home/secaf && \
    rm -rf /var/lib/apt/lists/*

# Generate minimal opencode config for OpenRouter provider (no MCP servers)
RUN mkdir -p /home/secaf/.config/opencode && \
    echo '{"$schema":"https://opencode.ai/config.json","model":"openrouter/minimax/minimax-m2.5","small_model":"openrouter/minimax/minimax-m2.5","provider":{"openrouter":{"options":{"apiKey":"{env:OPENROUTER_API_KEY}"},"models":{"minimax/minimax-m2.5":{},"moonshotai/kimi-k2.5":{}}}}}' \
    > /home/secaf/.config/opencode/opencode.json && \
    chown -R secaf:secaf /home/secaf/.config

COPY --from=builder /install /usr/local
COPY --from=aforge /out/aforge /usr/local/bin/aforge
COPY src/ /app/src/

USER secaf

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

CMD ["python", "-m", "sec_af.app"]
