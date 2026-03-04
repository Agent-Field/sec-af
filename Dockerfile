FROM python:3.11-slim AS base
WORKDIR /app
COPY pyproject.toml README.md ./
COPY src/ src/
RUN pip install --no-cache-dir .

FROM base AS runtime
ENV AGENTFIELD_SERVER=http://agentfield:8080
ENV HARNESS_PROVIDER=opencode
ENV HARNESS_MODEL=moonshotai/kimi-k2.5
ENV AI_MODEL=moonshotai/kimi-k2.5
ENV PORT=8003
EXPOSE 8003
HEALTHCHECK --interval=30s --timeout=5s CMD curl -f http://localhost:8003/health || exit 1
CMD ["python", "-m", "sec_af.app"]
