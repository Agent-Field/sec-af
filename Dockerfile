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
    "agentfield @ git+https://github.com/Agent-Field/agentfield.git#subdirectory=sdk/python" \
    "pydantic>=2.0" \
    "httpx>=0.27" && \
    pip install --no-cache-dir --prefix=/install --no-deps .


FROM python:3.11-slim AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    AGENTFIELD_SERVER=http://agentfield:8080 \
    HARNESS_PROVIDER=opencode \
    HARNESS_MODEL=moonshotai/kimi-k2.5 \
    AI_MODEL=moonshotai/kimi-k2.5 \
    PORT=8003 \
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

COPY --from=builder /install /usr/local
COPY src/ /app/src/
COPY prompts/ /app/prompts/

USER secaf

EXPOSE 8003

HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD curl -f http://localhost:8003/health || exit 1

CMD ["python", "-m", "sec_af.app"]
