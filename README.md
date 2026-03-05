# SEC-AF

**AI-native security auditor that verifies what it finds.** Point it at a repo, get back evidence-backed findings — not pattern-match noise.

![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-3776AB.svg)
![AgentField](https://img.shields.io/badge/built%20on-AgentField-0A7BFF.svg)

## Here's what you get back

When SEC-AF audits [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) (a deliberately vulnerable GraphQL app), it returns findings like this:

```json
{
  "title": "OS Command Injection in run_cmd Helper Function",
  "severity": "critical",
  "verdict": "confirmed",
  "evidence_level": 5,
  "cwe_id": "CWE-78",
  "description": "The run_cmd() function at core/helpers.py:9 directly executes user-controlled input via os.popen(cmd).read() without any input validation or sanitization...",
  "rationale": "Tracer confirms complete data flow from GraphQL parameters (host, port, path, scheme, cmd, arg) to os.popen(cmd).read() sink. Sanitization functions allowed_cmds() and strip_dangerous_characters() are bypassable in Easy mode...",
  "proof": {
    "verification_method": "composite_subagent_chain:sast",
    "evidence_level": 5,
    "data_flow_trace": [
      { "description": "core/views.py:203-207: GraphQL Arguments defined (host, port, path, scheme)", "tainted": true },
      { "description": "core/views.py:211: helpers.run_cmd(f'curl --insecure {url}') called with tainted input", "tainted": true },
      { "description": "core/helpers.py:9: os.popen(cmd).read() executes arbitrary commands", "tainted": true }
    ]
  },
  "location": {
    "file_path": "core/helpers.py",
    "start_line": 9,
    "code_snippet": "def run_cmd(cmd):\n  return os.popen(cmd).read()"
  }
}
```

Every finding includes a **verdict** (`confirmed` / `likely` / `inconclusive` / `not_exploitable`), a **proof object** with data flow traces, and the **exact location** in your code. No "maybe this is a problem" — SEC-AF traces the data flow and tells you whether it's exploitable.

> Full benchmark output (30 findings): [`exampl/dvga-benchmark-result.json`](exampl/dvga-benchmark-result.json)

## DVGA Benchmark Results

We run SEC-AF against [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application), a purpose-built vulnerable app with 21 documented security scenarios.

| Metric | Result |
|---|---|
| Raw findings discovered | 89 |
| After AI deduplication | 55 |
| After adversarial verification | **30 verified** |
| DVGA official scenarios detected | 12 / 21 (57%) |
| Additional findings beyond official list | 16 |
| False positive rate (verified findings) | 3% (1/30 marked not_exploitable) |

**What it found** (30 verified findings):

| Category | Count | Examples |
|---|---|---|
| Command Injection | 6 | `os.popen(cmd)` via 3 GraphQL resolvers, curl injection, broken allowlist bypass |
| SQL Injection | 3 | Unsanitized `filter` param in `resolve_pastes`, LIKE pattern injection |
| Missing Authentication | 5 | CreatePaste, CreateUser, file upload, ImportPaste, user enumeration — all unauthenticated |
| Authorization Bypass | 3 | BOLA on DeletePaste, IDOR on EditPaste, password disclosure via resolve_password |
| Authentication Flaws | 3 | JWT signature verification disabled, hardcoded JWT secret, plaintext password storage |
| SSRF | 1 | ImportPaste mutation follows user-supplied URLs server-side |
| Path Traversal | 1 | Unsanitized filename in save_file |
| DoS | 3 | Missing pagination on search/audit queries, infinite WebSocket subscription loop |
| Info Disclosure | 2 | Stack traces in GraphQL errors, debug mode enabled by default |
| Config / TLS | 3 | Plaintext password storage, hardcoded secret, disabled TLS verification |

**What it missed**: Primarily GraphQL protocol-level attacks (batch queries, deep recursion, alias abuse, field duplication) that require runtime/DAST analysis. SEC-AF is currently SAST-focused — these are on the roadmap.

## How It Works

SEC-AF runs a **Signal Cascade** pipeline — each phase narrows the signal:

```
                    ┌─────────────────────────────────────────┐
  POST /execute     │                                         │
  ───────────────►  │  RECON    5 agents build security       │
                    │           context (architecture,        │
                    │           data flows, dependencies,     │
                    │           config, security profile)     │
                    │                    │                     │
                    │                    ▼                     │
                    │  HUNT     11 strategy agents discover   │
                    │           findings using scan+enrich    │  89 raw
                    │           decomposition pattern         │
                    │                    │                     │
                    │                    ▼                     │
                    │  DEDUP    AI-powered deduplication      │  55 unique
                    │           and chain correlation         │
                    │                    │                     │
                    │                    ▼                     │
                    │  PROVE    Per-finding adversarial       │  30 verified
                    │           verification with verdicts    │
                    │                    │                     │
                    │                    ▼                     │
                    │  OUTPUT   SARIF 2.1.0 / JSON / Markdown │
                    └─────────────────────────────────────────┘
```

**Key design decisions:**
- Every LLM call is either a fast `.ai()` gate (yes/no decisions, strategy picks) or a deep `.harness()` session (multi-turn analysis). No monolithic prompts.
- Hunters use **scan+enrich decomposition**: a scanner identifies locations, then an enricher analyzes each finding individually. This produces higher-quality evidence per finding.
- The PROVE phase is **adversarial** — it tries to disprove each finding. Anything that survives gets a verdict and evidence level.

## Comparison

> We only include claims we can verify from official docs and pricing pages. If we're wrong about something, [open an issue](https://github.com/Agent-Field/sec-af/issues).

| | SEC-AF | Semgrep OSS | Semgrep Pro | Snyk Code | CodeQL | Nullify |
|---|---|---|---|---|---|---|
| **What it is** | AI-native audit agent | Pattern-matching SAST | Pattern + taint analysis | AI-assisted SAST | Semantic code analysis | AI security workforce |
| **Open source** | ✅ Apache 2.0 | ✅ LGPL-2.1 | ❌ Commercial | ❌ Proprietary | Queries: MIT, Engine: proprietary (free for public repos) | ❌ Proprietary |
| **Findings are verified** | ✅ Adversarial PROVE phase with verdict + proof object | ❌ Pattern matches | ❌ Pattern + dataflow matches | ❌ Priority scoring, no exploit proof | ❌ Static analysis results | ✅ Proof-of-exploit generation |
| **Evidence traces** | ✅ Data flow trace per finding with taint propagation | ❌ | ⚠️ Dataflow in Pro engine | ⚠️ Source-to-sink data flow shown | ✅ Path queries show data flow | ✅ Exploit path shown |
| **Scoring transparency** | ✅ Published composite formula | N/A | ❌ Internal scoring | ❌ Opaque Priority Score | N/A | ❌ Internal scoring |
| **SARIF output** | ✅ Native 2.1.0 | ✅ | ✅ | ✅ | ✅ Native | Not documented |
| **Compliance mapping** | ✅ PCI-DSS, SOC2, OWASP, HIPAA, ISO27001 | ⚠️ OWASP rules available | ⚠️ OWASP rules available | ❌ Platform-level compliance only | ❌ | Not documented |
| **Languages** | Any LLM-supported language (not parser-bound) | 35+ | 35+ | 14+ | 10 | Not documented |
| **Pricing** | Usage-based (~$2–10/audit via OpenRouter) | Free | $30/mo/contributor | $25–105/mo/developer | Free (public), $49/mo/committer (GHAS) | $6,000/mo |

**Where SEC-AF wins**: Verified findings with proof objects, transparent scoring, compliance mapping, and open source — at usage-based cost. Traditional SAST tools flag patterns; SEC-AF traces data flows and proves exploitability.

**Where others win**: Semgrep and CodeQL have years of rule coverage across 35+ languages with battle-tested parsers. Snyk has deep IDE integration and SCA. Nullify adds runtime cloud context and auto-remediation campaigns. SEC-AF is newer and currently strongest on code-level SAST with AI reasoning.

## Quick Start

```bash
docker compose up --build
```

This starts the AgentField control plane (`http://localhost:8080`) and the SEC-AF agent (`http://localhost:8003`).

Trigger an audit:

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"}}'
```

Response:

```json
{"execution_id": "exec_1234567890", "status": "queued"}
```

Poll for results:

```bash
curl http://localhost:8080/api/v1/executions/exec_1234567890
```

## API

### Minimal

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/org/repo"}}'
```

### Full options

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

### Depth profiles

| Profile | Strategies | Verification | Typical time | Typical cost |
|---|---|---|---|---|
| `quick` | Core (5 strategies) | Top findings only | 2–5 min | ~$0.50–2 |
| `standard` | Core + extended (11) | Top 30 findings | 5–15 min | ~$2–10 |
| `thorough` | Full set | All findings | 15–45 min | ~$10–50 |

## Verdict Model

Each finding gets a verdict based on the PROVE phase:

| Verdict | Meaning |
|---|---|
| `confirmed` | Exploitability demonstrated with concrete evidence |
| `likely` | Strong indicators, partial verification |
| `inconclusive` | Insufficient evidence, requires manual review |
| `not_exploitable` | Evidence indicates no practical exploit path |

## Output Formats

| Format | Consumer | Description |
|---|---|---|
| `sarif` | GitHub Code Scanning, security tooling | SARIF 2.1.0 with severity and locations |
| `json` | Pipelines, APIs | Full structured result with verdicts, proofs, costs |
| `markdown` | Security teams | Narrative report with findings and remediation |

## GitHub Actions

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

## Configuration

| Variable | Required | Default | Description |
|---|---|---|---|
| `AGENTFIELD_SERVER` | Yes | `http://localhost:8080` | Control plane URL |
| `OPENROUTER_API_KEY` | Yes | — | LLM provider credential |
| `HARNESS_MODEL` | No | `minimax/minimax-m2.5` | Model for deep analysis |
| `AI_MODEL` | No | `minimax/minimax-m2.5` | Model for fast gates |
| `SEC_AF_MAX_TURNS` | No | `50` | Max harness turns per call |

<details>
<summary>All environment variables</summary>

| Variable | Default | Description |
|---|---|---|
| `AGENTFIELD_API_KEY` | unset | API key for secured environments |
| `HARNESS_PROVIDER` | `opencode` | Harness backend provider |
| `SEC_AF_PROVIDER` | fallback to `HARNESS_PROVIDER` | Provider override |
| `SEC_AF_MODEL` | fallback to `HARNESS_MODEL` | Harness model override |
| `SEC_AF_AI_MODEL` | fallback to `AI_MODEL` | `.ai()` model override |
| `SEC_AF_AI_MAX_RETRIES` | `3` | Retry count for model calls |
| `SEC_AF_AI_INITIAL_BACKOFF_SECONDS` | `2.0` | Initial retry backoff |
| `SEC_AF_AI_MAX_BACKOFF_SECONDS` | `8.0` | Max retry backoff |
| `SEC_AF_OPENCODE_BIN` | `opencode` | Path to OpenCode binary |
| `SEC_AF_REPO_PATH` | cwd | Local repository path |

</details>

## Development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
ruff check src tests
```

Architecture details: [`docs/DESIGN.md`](docs/DESIGN.md)

## License

Apache License 2.0 — see [`LICENSE`](LICENSE).
