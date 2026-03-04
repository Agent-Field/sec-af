# SEC-AF

**AI-native security analysis and red-teaming on AgentField.**

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)
![AgentField](https://img.shields.io/badge/built%20on-AgentField-0A7BFF.svg)
![Version](https://img.shields.io/badge/version-0.1.0-black.svg)
![CI](https://img.shields.io/badge/CI-ready-2EA043.svg)

SEC-AF is an open-source security audit agent built on AgentField that analyzes repositories through a staged, agentic pipeline and returns evidence-backed findings instead of raw pattern matches. You trigger audits via the AgentField control plane REST API, then consume structured results in JSON/SARIF plus a human-readable markdown report. The design focuses on transparent scoring, exploit verification, attack-chain correlation, and compliance mapping so teams can prioritize real risk.

## What SEC-AF Does

- Runs a **Signal Cascade** pipeline: **RECON -> HUNT -> PROVE**
- Produces findings with explicit verdicts: `confirmed`, `likely`, `inconclusive`, `not_exploitable`
- Maps findings to compliance controls (PCI-DSS, SOC2, OWASP, HIPAA, ISO27001)
- Exports machine-readable output (`sarif`, `json`) and human-readable report content (`markdown`)
- Runs as an AgentField reasoner endpoint: `sec-af.audit`

## Quick Start (Docker Compose)

SEC-AF is designed to run with AgentField control plane using Docker Compose.

```bash
docker compose up --build
```

This starts:

- `agentfield` at `http://localhost:8080`
- `sec-af` agent at `http://localhost:8003` (registered against control plane)

Trigger an async audit from your terminal:

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "repo_url": "https://github.com/Agent-Field/sec-af",
      "depth": "standard",
      "output_formats": ["sarif", "json", "markdown"]
    }
  }'
```

Example response:

```json
{
  "execution_id": "exec_1234567890",
  "status": "queued"
}
```

Then poll execution status:

```bash
curl http://localhost:8080/api/v1/executions/exec_1234567890
```

## Architecture

SEC-AF is built on AgentField's execution model as an API-first reasoner (`sec-af.audit`) exposed through control-plane execute endpoints.

- **`POST /api/v1/execute/async/sec-af.audit`** is the primary entrypoint
- **`.harness()`** handles deep, multi-turn security reasoning and structured extraction
- **`.ai()`** handles lightweight gating/classification decisions
- The orchestrator combines phase results into a single `SecurityAuditResult`

### `.ai()` vs `.harness()` Split

| Primitive | Used For | Why |
|---|---|---|
| `.ai()` | Fast gates (strategy picks, yes/no or enum decisions) | Low latency, flat schema decisions |
| `.harness()` | RECON/HUNT/PROVE, dedup, correlation, evidence building | Multi-turn analysis over large context and nested outputs |

### Signal Cascade (RECON -> HUNT -> PROVE)

```text
Request: POST /api/v1/execute/async/sec-af.audit
  |
  v
[RECON] 5 agents build security context
  - architecture, data flows, dependencies, config, security profile
  |
  v
[HUNT] 8-20+ strategy agents discover and correlate potential issues
  - injection, auth, crypto, logic, data exposure, supply chain, API, config
  |
  v
[PROVE] per-finding adversarial verification
  - confirm exploitability, assign verdict + evidence level
  |
  v
[OUTPUT]
  - SARIF 2.1.0
  - JSON (full structured result)
  - Markdown security report
```

## API Usage

### Minimal request

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/org/repo"}}'
```

### Full request (AuditInput schema)

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $AGENTFIELD_API_KEY" \
  -d '{
    "input": {
      "repo_url": "https://github.com/org/repo",
      "branch": "main",
      "commit_sha": null,
      "base_commit_sha": null,
      "depth": "thorough",
      "severity_threshold": "high",
      "scan_types": ["sast", "sca", "secrets", "config"],
      "output_formats": ["sarif", "json", "markdown"],
      "compliance_frameworks": ["pci-dss", "soc2", "owasp", "hipaa"],
      "max_cost_usd": 15.0,
      "max_provers": 30,
      "max_duration_seconds": 1800,
      "include_paths": ["src/", "services/"],
      "exclude_paths": ["tests/", "vendor/", "node_modules/", ".git/"],
      "is_pr": false,
      "pr_id": null,
      "post_pr_comments": false,
      "fail_on_findings": false
    }
  }'
```

## Input Schema (AuditInput)

`src/sec_af/schemas/input.py` defines the reasoner contract:

- Required: `repo_url`
- Scope: `branch`, `commit_sha`, `base_commit_sha`, `include_paths`, `exclude_paths`
- Analysis profile: `depth` (`quick|standard|thorough`), `scan_types`, `severity_threshold`
- Output control: `output_formats`, `compliance_frameworks`
- Budget/runtime: `max_cost_usd`, `max_provers`, `max_duration_seconds`
- PR mode: `is_pr`, `pr_id`, `post_pr_comments`, `fail_on_findings`

## Depth Profiles

| Profile | RECON | HUNT | PROVE | Typical Runtime | Typical Cost |
|---|---|---|---|---|---|
| `quick` | Core context agents | Core strategies | Top findings | 2-5 min | ~$0.50-2.00 |
| `standard` | Full baseline context | Core + extended strategies | Top 30 findings | 5-15 min | ~$2.00-10.00 |
| `thorough` | Full context + language-specific expansion | Full strategy set | All findings within budget | 15-45 min | ~$10.00-50.00 |

## Output Formats

SEC-AF outputs are optimized for both automation and human triage.

| Format | Intended Consumer | Notes |
|---|---|---|
| `sarif` | GitHub Code Scanning / Security tooling | SARIF 2.1.0-compatible payload with severity and locations |
| `json` | Pipelines, APIs, data lakes | Full `SecurityAuditResult` with verdicts, costs, and metadata |
| `markdown` | Security teams and engineering leadership | Narrative report with key findings, attack chains, and remediation guidance |

Sample JSON result shape:

```json
{
  "repository": "https://github.com/org/repo",
  "depth_profile": "standard",
  "findings": [
    {
      "title": "SQL Injection in user lookup",
      "verdict": "confirmed",
      "evidence_level": 3,
      "severity": "high"
    }
  ],
  "attack_chains": [],
  "cost_usd": 4.27
}
```

## Verdict Model

Each finding includes a verdict that separates exploitable issues from noise:

- `confirmed`: exploitability demonstrated with concrete evidence
- `likely`: strong indicators, partial verification
- `inconclusive`: insufficient evidence, requires manual review
- `not_exploitable`: evidence indicates no practical exploit path

This model is critical for reducing false positives and prioritizing remediation.

## Configuration

### Environment variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AGENTFIELD_SERVER` | Yes | `http://localhost:8080` | AgentField control-plane URL |
| `AGENTFIELD_API_KEY` | No (dev), Yes (secured envs) | unset | API key for control-plane auth |
| `HARNESS_PROVIDER` | No | `opencode` | Harness backend provider |
| `HARNESS_MODEL` | No | `minimax/minimax-m2.5` | Model used for harness-heavy analysis |
| `AI_MODEL` | No | `minimax/minimax-m2.5` | Model used for lightweight `.ai()` calls |
| `SEC_AF_PROVIDER` | No | fallback to `HARNESS_PROVIDER` | SEC-AF provider override |
| `SEC_AF_MODEL` | No | fallback to `HARNESS_MODEL` | SEC-AF harness model override |
| `SEC_AF_AI_MODEL` | No | fallback to `AI_MODEL` | SEC-AF `.ai()` model override |
| `SEC_AF_MAX_TURNS` | No | `50` | Max harness turns per invocation |
| `SEC_AF_AI_MAX_RETRIES` | No | `3` | Retry count for model calls |
| `SEC_AF_AI_INITIAL_BACKOFF_SECONDS` | No | `2.0` | Initial retry backoff |
| `SEC_AF_AI_MAX_BACKOFF_SECONDS` | No | `8.0` | Max retry backoff |
| `SEC_AF_OPENCODE_BIN` | No | `opencode` | Path to OpenCode binary |
| `SEC_AF_REPO_PATH` | No | current working dir | Local repository path for harness cwd/checkpoints |
| `OPENROUTER_API_KEY` | Required for OpenRouter-backed models | unset | Provider credential used in `docker-compose.yml` |

## Competitive Comparison

| Feature | SEC-AF | Nullify ($6K/mo) | Snyk | Semgrep OSS |
|---|---|---|---|---|
| Transparent scoring formula | ✅ Published composite scoring | ❌ Opaque score | ❌ Opaque Priority Score | N/A |
| Verified findings (not just pattern matches) | ✅ 4-level verdict model | ✅ Claimed, proprietary method | ❌ Primarily static + policy signals | ❌ Pattern/rule based |
| Attack-chain correlation | ✅ Linked multi-step chains | ❌ | ❌ | ❌ |
| Multi-framework compliance mapping | ✅ PCI-DSS, SOC2, OWASP, HIPAA, ISO27001 | ⚠️ Partial | ⚠️ Partial (plan-dependent) | ⚠️ Rule dependent |
| Evidence hierarchy | ✅ Explicit levels from static match to full exploit | ⚠️ Not fully transparent | ❌ | ❌ |
| SARIF output | ✅ Native 2.1.0 | ❌ | ✅ Partial | ✅ |
| Open source | ✅ Apache 2.0 | ❌ | ❌ | ✅ |
| Provider-agnostic LLM backend | ✅ AgentField + pluggable providers | ❌ | N/A | N/A |
| Typical cost profile | ✅ Usage-based (~$2-10 standard audit) | $6K/month entry point | $$$ | Free rules, manual triage overhead |

## GitHub Actions Integration

```yaml
name: sec-af-audit

on:
  pull_request:

jobs:
  security-audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
    steps:
      - uses: actions/checkout@v4

      - name: Trigger SEC-AF
        run: |
          RESPONSE=$(curl -sS -X POST "$AGENTFIELD_SERVER/api/v1/execute/async/sec-af.audit" \
            -H "Content-Type: application/json" \
            -H "X-API-Key: $AGENTFIELD_API_KEY" \
            -d '{
              "input": {
                "repo_url": "${{ github.event.repository.clone_url }}",
                "branch": "${{ github.head_ref }}",
                "commit_sha": "${{ github.event.pull_request.head.sha }}",
                "base_commit_sha": "${{ github.event.pull_request.base.sha }}",
                "depth": "standard",
                "severity_threshold": "medium",
                "output_formats": ["sarif"]
              }
            }')
          EXEC_ID=$(echo "$RESPONSE" | jq -r '.execution_id')
          echo "execution_id=$EXEC_ID" >> "$GITHUB_ENV"
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}
          AGENTFIELD_API_KEY: ${{ secrets.AGENTFIELD_API_KEY }}

      - name: Poll for completion
        run: |
          for i in {1..60}; do
            STATUS_JSON=$(curl -sS "$AGENTFIELD_SERVER/api/v1/executions/$execution_id" \
              -H "X-API-Key: $AGENTFIELD_API_KEY")
            STATUS=$(echo "$STATUS_JSON" | jq -r '.status')
            if [ "$STATUS" = "succeeded" ]; then
              echo "$STATUS_JSON" | jq -r '.result.sarif' > sec-af-results.sarif
              exit 0
            fi
            if [ "$STATUS" = "failed" ]; then
              echo "SEC-AF execution failed"
              echo "$STATUS_JSON"
              exit 1
            fi
            sleep 10
          done
          echo "Timed out waiting for SEC-AF execution"
          exit 1
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}
          AGENTFIELD_API_KEY: ${{ secrets.AGENTFIELD_API_KEY }}

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: sec-af-results.sarif
```

## Optional Python Usage

If you want to trigger audits programmatically:

```python
import httpx

payload = {
    "input": {
        "repo_url": "https://github.com/org/repo",
        "depth": "standard",
        "output_formats": ["json", "sarif", "markdown"],
    }
}

resp = httpx.post(
    "http://localhost:8080/api/v1/execute/async/sec-af.audit",
    json=payload,
    timeout=30,
)
resp.raise_for_status()
print(resp.json())
```

## Development

### Local setup

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e .[dev]
```

### Run checks

```bash
pytest
ruff check src tests
mypy src
```

### Contributing

1. Fork and create a feature branch.
2. Keep changes scoped and include tests for behavior changes.
3. Ensure lint/type/tests pass locally.
4. Open a PR with problem statement, approach, and verification notes.

Project architecture details live in `docs/DESIGN.md`.

## License

Licensed under the Apache License, Version 2.0. See `LICENSE` for details.
