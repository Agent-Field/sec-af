<div align="center">

# SEC-AF

### AI-Native Security Auditor Built on [AgentField](https://github.com/Agent-Field/agentfield)

[![Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-16a34a?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Built with AgentField](https://img.shields.io/badge/Built%20with-AgentField-0A66C2?style=for-the-badge)](https://github.com/Agent-Field/agentfield)

<p>
  <a href="#what-you-get-back">Output</a> •
  <a href="#benchmark-dvga">Benchmark</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#comparison">Comparison</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api">API</a>
</p>

</div>

Other tools flag patterns. SEC-AF **proves exploitability** — every finding comes with a verdict, a data flow trace, and evidence you can act on. Free, open source, one API call.

<p align="center">
  <img src="assets/hero-b-swarm.png" alt="SEC-AF — AI-native security auditor" width="100%" />
</p>

## What You Get Back

This is a real finding from SEC-AF auditing [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) (a deliberately vulnerable GraphQL app):

```jsonc
{
  "title": "OS Command Injection in run_cmd Helper Function",
  "severity": "critical",
  "verdict": "confirmed",           // not "maybe" — confirmed exploitable
  "evidence_level": 5,
  "cwe_id": "CWE-78",

  "rationale": "Tracer confirms complete data flow from GraphQL parameters
    (host, port, path, scheme, cmd, arg) to os.popen(cmd).read() sink.
    Sanitization functions are bypassable in Easy mode...",

  "proof": {
    "verification_method": "composite_subagent_chain:sast",
    "data_flow_trace": [
      { "description": "core/views.py:203 — GraphQL args defined (host, port, path, scheme)", "tainted": true },
      { "description": "core/views.py:210 — URL constructed from user input", "tainted": true },
      { "description": "core/views.py:211 — helpers.run_cmd(f'curl {url}') called", "tainted": true },
      { "description": "core/helpers.py:9 — os.popen(cmd).read() executes input", "tainted": true }
    ]
  },

  "location": {
    "file_path": "core/helpers.py",
    "start_line": 9,
    "code_snippet": "def run_cmd(cmd):\n  return os.popen(cmd).read()"
  }
}
```

Every finding includes a **verdict** (`confirmed` / `likely` / `inconclusive` / `not_exploitable`), a **proof object** with the full taint trace, and the **exact code location**. Not "this might be a problem" — SEC-AF traces the data from source to sink and proves whether it's exploitable.

> Full benchmark output (30 findings): [`exampl/dvga-benchmark-result.json`](exampl/dvga-benchmark-result.json)

## Benchmark: DVGA

We run SEC-AF against [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) — a purpose-built vulnerable app with 21 documented security scenarios.

| Metric | Value |
|---|---|
| Raw findings discovered | 89 |
| After AI deduplication | 55 |
| **After adversarial verification** | **30 confirmed** |
| DVGA official scenarios detected | 12 / 21 (57%) |
| Findings beyond the official list | **16 additional** |
| False positive rate | 3% (1/30) |

<details>
<summary><strong>Breakdown: 30 verified findings by category</strong></summary>

| Category | Count | Examples |
|---|---|---|
| Command Injection | 6 | `os.popen(cmd)` via 3 GraphQL resolvers, curl injection, broken allowlist bypass |
| SQL Injection | 3 | Unsanitized `filter` in `resolve_pastes`, LIKE pattern injection |
| Missing Authentication | 5 | CreatePaste, CreateUser, file upload, ImportPaste, user enumeration |
| Authorization Bypass | 3 | BOLA on DeletePaste, IDOR on EditPaste, password disclosure |
| Authentication Flaws | 3 | JWT signature verification disabled, hardcoded JWT secret, plaintext passwords |
| SSRF | 1 | ImportPaste mutation follows user-supplied URLs server-side |
| Path Traversal | 1 | Unsanitized filename in `save_file` |
| DoS | 3 | Missing pagination on search/audit queries, infinite WebSocket loop |
| Info Disclosure / Config | 5 | Stack traces in errors, debug mode on, disabled TLS verification |

</details>

<details>
<summary><strong>What it missed (and why)</strong></summary>

The 9 missed scenarios are primarily **GraphQL protocol-level attacks**: batch queries, deep recursion, alias abuse, field duplication, introspection exposure. These require runtime/DAST analysis. SEC-AF is currently SAST-focused — protocol-level detection is on the roadmap.

</details>

## How It Works

SEC-AF runs a **Signal Cascade** pipeline — each phase narrows the signal:

```mermaid
flowchart TD
    A["POST /execute/async/sec-af.audit"] --> B["RECON"]
    B --> C["HUNT"]
    C --> D["DEDUP"]
    D --> E["PROVE"]
    E --> F["OUTPUT"]

    B -.- B1["5 agents build security context\n(architecture, data flows, deps, config, security profile)"]
    C -.- C1["11 strategy agents scan + enrich findings\n(injection, auth, crypto, SSRF, XSS, DoS, ...)"]
    D -.- D1["AI-powered deduplication + chain correlation\n89 raw → 55 unique"]
    E -.- E1["Adversarial per-finding verification\n55 unique → 30 confirmed"]
    F -.- F1["SARIF 2.1.0 · JSON · Markdown"]
```

**Key design decisions:**

- **`.ai()` vs `.harness()` split** — fast gates (strategy selection, yes/no) use `.ai()`. Deep analysis (recon, hunt, prove) uses `.harness()` with multi-turn sessions. No monolithic prompts.
- **Scan + enrich decomposition** — hunters don't produce findings in one shot. A scanner identifies locations, then an enricher analyzes each one individually. Higher evidence quality per finding.
- **Adversarial verification** — the PROVE phase doesn't confirm findings, it tries to **disprove** them. What survives gets a verdict and evidence level.

## Comparison

> Claims sourced from official docs and pricing pages. If something is wrong, [open an issue](https://github.com/Agent-Field/sec-af/issues).

| | SEC-AF | Nullify | Snyk Code | Semgrep | CodeQL |
|---|---|---|---|---|---|
| **Approach** | **AI-native** | **AI-native** | **AI-assisted** | **Rule-based** | **Rule-based** |
| | LLM reasons about code | Autonomous security workforce | DeepCode AI engine | Pattern + taint matching | Semantic analysis + dataflow |
| **Open source** | ✅ Apache 2.0 | ❌ Proprietary | ❌ Proprietary | Engine: LGPL-2.1 · Pro rules: proprietary | Queries: MIT · Engine: proprietary |
| **Verified findings** | ✅ Adversarial PROVE phase · verdict + proof per finding | ✅ Proof-of-exploit generation | ❌ Priority Score (opaque) · no exploit proof | ❌ Pattern matches only | ❌ Static analysis alerts |
| **Evidence per finding** | Data flow trace with taint propagation | Exploit path + reproduction steps | Source-to-sink flow shown | — | Path queries show data flow |
| **Scoring** | ✅ Published composite formula | Internal | Opaque Priority Score | Internal | — |
| **SARIF** | ✅ Native 2.1.0 | Not documented | ✅ | ✅ | ✅ Native |
| **Compliance mapping** | PCI-DSS, SOC2, OWASP, HIPAA, ISO27001 | Not documented | Platform compliance only | OWASP rules available | — |
| **Languages** | Any LLM-supported language | Not documented | 14+ | 35+ (parser-based) | 10 |
| **Pricing** | **Free · open source** | **$6,000/mo** | $25–105/mo/developer | OSS engine: free to use · Pro: $30/mo/contributor | Free for public repos · $49/mo/committer (GHAS) |

**Where SEC-AF is strongest**: Verified findings with proof objects, transparent scoring, compliance mapping, and fully open source.

**Where others are stronger**: Semgrep and CodeQL have years of battle-tested rule coverage across 35+ languages. Snyk has deep IDE/SCA integration. Nullify adds runtime cloud context and auto-remediation campaigns. SEC-AF is newer and currently strongest on AI-driven code-level analysis.

## Quick Start

```bash
docker compose up --build
```

Starts AgentField control plane (`http://localhost:8080`) + SEC-AF agent (`http://localhost:8003`).

Trigger an audit:

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"}}'
```

Poll for results:

```bash
curl http://localhost:8080/api/v1/executions/<execution_id>
```

## API

<details>
<summary><strong>Full request options</strong></summary>

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{
    "input": {
      "repo_url": "https://github.com/org/repo",
      "branch": "main",
      "depth": "thorough",
      "severity_threshold": "high",
      "scan_types": ["sast", "sca", "secrets", "config"],
      "output_formats": ["sarif", "json", "markdown"],
      "compliance_frameworks": ["pci-dss", "soc2", "owasp", "hipaa"],
      "max_cost_usd": 15.0,
      "max_provers": 30,
      "max_duration_seconds": 1800,
      "include_paths": ["src/"],
      "exclude_paths": ["tests/", "vendor/"]
    }
  }'
```

</details>

<details>
<summary><strong>Depth profiles</strong></summary>

| Profile | Strategies | Verification | Typical time | Typical cost |
|---|---|---|---|---|
| `quick` | 5 core strategies | Top findings only | 2–5 min | ~$0.50–2 |
| `standard` | 11 strategies (core + extended) | Top 30 findings | 5–15 min | ~$2–10 |
| `thorough` | Full strategy set | All findings | 15–45 min | ~$10–50 |

</details>

<details>
<summary><strong>Verdict model</strong></summary>

| Verdict | Meaning |
|---|---|
| `confirmed` | Exploitability demonstrated with concrete evidence |
| `likely` | Strong indicators, partial verification |
| `inconclusive` | Insufficient evidence, requires manual review |
| `not_exploitable` | Evidence indicates no practical exploit path |

</details>

<details>
<summary><strong>Output formats</strong></summary>

| Format | Consumer | Description |
|---|---|---|
| `sarif` | GitHub Code Scanning, security tooling | SARIF 2.1.0 with severity and locations |
| `json` | Pipelines, APIs | Full structured result with verdicts, proofs, costs |
| `markdown` | Security teams | Narrative report with findings and remediation |

</details>

## GitHub Actions

<details>
<summary><strong>CI integration</strong></summary>

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
            -d '{
              "input": {
                "repo_url": "${{ github.event.repository.clone_url }}",
                "branch": "${{ github.head_ref }}",
                "commit_sha": "${{ github.event.pull_request.head.sha }}",
                "base_commit_sha": "${{ github.event.pull_request.base.sha }}",
                "depth": "standard",
                "output_formats": ["sarif"]
              }
            }')
          echo "execution_id=$(echo "$RESPONSE" | jq -r '.execution_id')" >> "$GITHUB_ENV"
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - name: Wait for results
        run: |
          for i in {1..60}; do
            RESULT=$(curl -sS "$AGENTFIELD_SERVER/api/v1/executions/$execution_id")
            STATUS=$(echo "$RESULT" | jq -r '.status')
            [ "$STATUS" = "succeeded" ] && { echo "$RESULT" | jq -r '.result.sarif' > results.sarif; exit 0; }
            [ "$STATUS" = "failed" ] && { echo "Audit failed"; exit 1; }
            sleep 10
          done
          echo "Timed out"; exit 1
        env:
          AGENTFIELD_SERVER: ${{ secrets.AGENTFIELD_SERVER }}

      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif
```

</details>

## Configuration

<details>
<summary><strong>Environment variables</strong></summary>

| Variable | Required | Default | Description |
|---|---|---|---|
| `AGENTFIELD_SERVER` | Yes | `http://localhost:8080` | Control plane URL |
| `OPENROUTER_API_KEY` | Yes | — | LLM provider credential |
| `HARNESS_MODEL` | No | `minimax/minimax-m2.5` | Model for deep `.harness()` analysis |
| `AI_MODEL` | No | `minimax/minimax-m2.5` | Model for fast `.ai()` gates |
| `SEC_AF_MAX_TURNS` | No | `50` | Max harness turns per call |
| `AGENTFIELD_API_KEY` | No | unset | API key for secured environments |
| `HARNESS_PROVIDER` | No | `opencode` | Harness backend provider |
| `SEC_AF_AI_MAX_RETRIES` | No | `3` | Retry count for model calls |

</details>

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
ruff check src tests
```

Architecture: [`docs/DESIGN.md`](docs/DESIGN.md)

---

<div align="center">

SEC-AF is built on [AgentField](https://github.com/Agent-Field/agentfield) — open infrastructure for production-grade autonomous agents.

**[Apache-2.0](LICENSE)**

</div>
