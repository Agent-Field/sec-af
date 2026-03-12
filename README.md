<div align="center">

# SEC-AF

### AI-Native Security Auditor Built on [AgentField](https://github.com/Agent-Field/agentfield)

[![Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-16a34a?style=for-the-badge)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/downloads/)
[![Built with AgentField](https://img.shields.io/badge/Built%20with-AgentField-0A66C2?style=for-the-badge)](https://github.com/Agent-Field/agentfield)
[![More from Agent-Field](https://img.shields.io/badge/More_from-Agent--Field-111827?style=for-the-badge&logo=github)](https://github.com/Agent-Field)

<p>
  <a href="#what-you-get-back">Output</a> •
  <a href="#benchmark-dvga">Benchmark</a> •
  <a href="#how-it-works">How It Works</a> •
  <a href="#comparison">Comparison</a> •
  <a href="#quick-start">Quick Start</a> •
  <a href="#api">API</a>
</p>

</div>

Other tools flag patterns. SEC-AF **proves exploitability**: every finding ships with a verdict, a data flow trace, and evidence you can act on. Free, open source, one API call. A full audit with 30 verified findings costs about **$1.40 in LLM calls**.

<p align="center">
  <img src="assets/hero-b-swarm.png" alt="SEC-AF — AI-native security auditor" width="100%" />
</p>

## One-Call DX

```bash
curl -X POST http://localhost:8080/api/v1/execute/async/sec-af.audit \
  -H "Content-Type: application/json" \
  -d '{"input": {"repo_url": "https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"}}'
```

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

Every finding includes a **verdict** (`confirmed` / `likely` / `inconclusive` / `not_exploitable`), a **proof object** with the full taint trace, and the exact code location. Not "this might be a problem." SEC-AF traces data from source to sink and proves whether it's actually exploitable.

> Full benchmark output (30 findings): [`exampl/dvga-benchmark-result.json`](exampl/dvga-benchmark-result.json) | Performance analysis: [`exampl/benchmark-analysis.json`](exampl/benchmark-analysis.json)

## Benchmark: DVGA

We run SEC-AF against [Damn Vulnerable GraphQL Application](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application), a deliberately vulnerable app with 21 documented security scenarios.

| Metric | Value |
|---|---|
| Raw findings discovered | 106 |
| After AI deduplication | 61 |
| **After adversarial verification** | **28 confirmed** |
| Inconclusive (needs manual review) | 1 |
| Not exploitable (correctly rejected) | 1 |
| Noise reduction | 94% |
| DAG edges (reasoner calls) | 82 |
| Agent calls | ~166–255 |
| Strategies run | 11 |
| Wall-clock time | ~78 min |
| Estimated cost (Kimi K2.5) | ~$0.18–$0.90 |

<details>
<summary><strong>Breakdown: 30 verified findings by category</strong></summary>

| Category | Count | Examples |
|---|---|---|
| Missing Authentication | 8 | ImportPaste, delete_all_pastes, system_debug, CreateUser, file upload |
| Command Injection | 4 | `os.popen(cmd)` via ImportPaste, system_debug, system_diagnostics |
| SQL Injection | 3 | Unsanitized `filter` in `resolve_pastes`, LIKE pattern injection, login |
| Authentication Bypass | 3 | JWT signature disabled, JWT authorization bypass, broken password auth |
| Plaintext Credentials | 3 | Cleartext password storage, plaintext comparison, password in diagnostics |
| SSRF | 2 | ImportPaste mutation follows user-supplied URLs server-side |
| Business Logic / URL Sanitization | 2 | Inadequate URL sanitization, unauthenticated mass deletion |
| DoS / Resource Exhaustion | 3 | Missing pagination on users/audits queries, uncontrolled simulate_load |
| Config / Secrets | 2 | Hardcoded JWT/Flask secrets, debug mode enabled in production |

</details>

<details>
<summary><strong>Design patterns: how AI-native security analysis works</strong></summary>

SEC-AF applies several architectural patterns that are uniquely enabled by composing many focused AI agents instead of running one monolithic scan. These patterns address fundamental challenges in AI-driven security analysis.

**1. Adversarial agent tension (HUNT vs. PROVE)**

Most AI security tools ask a single model "is this vulnerable?" and accept the answer. SEC-AF structurally separates the _finding_ agents from the _disproving_ agents. Hunters are incentivized to find vulnerabilities; provers are incentivized to disprove them. Each finding passes through a 4-agent verification chain — a tracer reconstructs the data flow, a sanitization analyzer looks for mitigations the hunter may have missed, an exploit hypothesizer constructs a concrete attack scenario, and a verdict agent weighs all the conflicting evidence. This adversarial tension between agents is what drives the 94% noise reduction — the architecture itself encodes skepticism.

**2. Signal cascade with progressive narrowing**

Instead of dumping all findings on the user, the pipeline compresses signal at every stage: 106 raw findings → 61 after AI deduplication → 30 after adversarial verification. Each phase is a filter. This mirrors how human security teams triage — broad discovery first, then progressively stricter scrutiny. The key insight is that each filter is a _different kind_ of AI reasoning: semantic similarity for dedup, taint analysis for verification, exploit construction for confirmation.

**3. Information economy via context pruning**

LLMs hallucinate more when given irrelevant context. SEC-AF routes only the information each agent needs: an injection hunter receives the recon context pruned to data flow maps and input entry points, while a crypto hunter receives dependency trees and key management patterns. Verifiers receive projected finding views with only the fields needed for their specific verification method. This per-strategy context pruning reduces both hallucination and cost — agents can't confuse themselves with information they never see.

**4. Streaming phase overlap**

Traditional pipelines run sequentially: finish recon, then start hunting, then start proving. SEC-AF overlaps phases via `asyncio.Queue` — hunters start consuming recon output as it arrives, and dedup processes findings as each hunter completes. Provers begin verifying the first deduplicated findings while later hunters are still running. This streaming architecture reduces wall-clock time without sacrificing the signal cascade — each finding still passes through every filter, just earlier.

**5. Dynamic routing via AI gates**

The pipeline adapts at runtime based on what it discovers. An AI gate examines recon output and selects which hunt strategies to activate — a Flask app with JWT auth triggers different hunters than a Go microservice with gRPC. A separate CWE expansion gate dynamically broadens the vulnerability target list based on the detected technology stack. A reachability gate assesses whether dependency vulnerabilities have exploitable call paths before wasting verification resources on unreachable code.

**6. Guided autonomy for coding agents**

SEC-AF runs on top of coding agents (Claude Code, OpenCode, Codex) via the AgentField harness. Rather than giving the agent a single massive prompt, each reasoner provides phase-aware guided autonomy: the agent receives a narrow task definition, a flat output schema (2-4 fields), and strategy-specific context. The agent has full autonomy within these boundaries — it can read files, trace code, and reason freely — but the harness constrains the _shape_ of its output. This prevents the common failure mode where autonomous agents go off-task or produce unstructured results.

**7. Composable reasoner DAG with full observability**

Every agent call flows through the AgentField control plane, creating a complete directed acyclic graph of the audit. You can see which hunter found which finding, how long each verification took, what evidence the prover generated, and where the pipeline spent its time. Adding a new vulnerability class is one file — a new hunter. The orchestrator discovers it, routes context to it, and integrates its findings into the existing dedup → prove → remediation pipeline. The DAG is the architecture.

</details>

<details>
<summary><strong>What it missed (and why)</strong></summary>

The 9 missed scenarios are primarily **GraphQL protocol-level attacks**: batch queries, deep recursion, alias abuse, field duplication, introspection exposure. These require runtime/DAST analysis. SEC-AF is currently SAST-focused. Protocol-level detection is on the roadmap.

</details>

## How It Works

SEC-AF is built on the [Composite Intelligence](https://github.com/Agent-Field/agentfield) philosophy: instead of relying on a single monolithic LLM call, it composes many focused, guided LLM calls into a **reasoner DAG** where the architecture itself encodes intelligence (for a deeper dive on this pattern, see [The Atomic Unit of Intelligence](https://www.santoshkumarradha.com/writing/atomic-unit-of-intelligence)). Each LLM call handles a small, well-defined task with a flat Pydantic schema (2-4 attributes). The orchestrator manages context flow, parallelism, and dynamic routing.

### Architecture: Reasoner Call Graph (DAG)

Every phase is a `@reasoner` that calls sub-reasoners through the AgentField control plane totaling around ~200-300 agents working synchronously for a given query:

<p align="center">
  <img src="assets/architecture.png" alt="SEC-AF Signal Cascade Pipeline — RECON → HUNT → DEDUP → PROVE → OUTPUT" width="100%" />
</p>

### Signal Cascade Pipeline

Each phase narrows the signal. Raw findings are filtered through progressively stricter gates:

| Phase | Purpose | Parallelism |
|---|---|---|
| **RECON** | Map architecture, dependencies, data flows, security context | 3-way parallel (arch + deps + config), then 2-way (data flow + security) |
| **HUNT** | Run 10+ specialized strategy hunters | Semaphore-bounded parallel (default 4 concurrent) with incremental dedup |
| **PROVE** | Adversarial verification: try to **disprove** each finding | Semaphore-bounded parallel (default 3 concurrent) |
| **REMEDIATION** | Generate fix suggestions for confirmed/likely findings | Semaphore-bounded parallel (default 3 concurrent) |

### Why Multi-Reasoner Architecture

Most AI security tools run one big prompt and hope the LLM gets it right. SEC-AF decomposes the problem into ~258 focused agent calls, each with a flat schema (2-4 fields) and a narrow task. The architecture encodes the reasoning strategy, not the prompt (see [The Atomic Unit of Intelligence](https://www.santoshkumarradha.com/writing/atomic-unit-of-intelligence) for why this matters).

- **Many focused agents > one powerful agent.** A single LLM call can't simultaneously map architecture, trace data flows, hunt for injection, verify exploitability, and suggest fixes. SEC-AF gives each of those to a separate reasoner that does one thing well. The orchestrator handles composition, parallelism, and context routing.
- **Adversarial verification, not confirmation bias.** The PROVE phase runs 4 sub-agents per finding with opposing goals: the tracer reconstructs the data flow, the sanitization analyzer looks for blocks, the exploit hypothesizer constructs an attack, and the verdict agent weighs all the evidence. This tension between agents produces higher confidence than asking a single model "is this exploitable?"
- **Dynamic routing via AI gates.** The system adapts at runtime. An AI gate examines recon output and selects which hunt strategies to activate. A separate gate expands the CWE target list based on the detected stack. A Flask app with JWT auth gets different hunters than a Go microservice with gRPC.
- **Progressive signal narrowing.** 106 raw findings become 61 after dedup, then 30 after adversarial verification — 94% noise reduction. Each phase is a filter. The pipeline compresses noise, it doesn't just detect vulnerabilities and dump them.
- **Information economy.** Each agent sees only what it needs. Hunters receive recon context pruned for their strategy. Verifiers receive projected finding views with minimal fields. This reduces hallucination, reduces cost, and keeps each LLM call focused.
- **Incremental streaming.** Dedup runs as a consumer while hunters are still producing. Findings are fingerprint-deduplicated as each hunter completes, then a final semantic pass catches cross-strategy duplicates. The pipeline streams, it doesn't batch.

## Comparison

> Claims sourced from official docs and pricing pages. If something is wrong, [open an issue](https://github.com/Agent-Field/sec-af/issues).

| | SEC-AF | Nullify | Snyk Code | Semgrep | CodeQL |
|---|---|---|---|---|---|
| **Approach** | **AI-native** | **AI-native** | **AI-assisted** | **Rule-based** | **Rule-based** |
| | Multi-reasoner DAG · LLM reasons about code | Autonomous security workforce | DeepCode AI engine | Pattern + taint matching | Semantic analysis + dataflow |
| **Open source** | ✅ Apache 2.0 | ❌ Proprietary | ❌ Proprietary | Engine: LGPL-2.1 · Pro rules: proprietary | Queries: MIT · Engine: proprietary |
| **Verified findings** | ✅ Adversarial PROVE phase · verdict + proof per finding | ✅ Proof-of-exploit generation | ❌ Priority Score (opaque) · no exploit proof | ❌ Pattern matches only | ❌ Static analysis alerts |
| **Evidence per finding** | Data flow trace with taint propagation | Exploit path + reproduction steps | Source-to-sink flow shown | - | Path queries show data flow |
| **Architecture** | Composable reasoner DAG with full observability | Monolithic agent | Single-pass engine | Rule engine | Query engine |
| **Parallelism** | ✅ Parallel hunters, verifiers, remediators with incremental dedup | Not documented | Not documented | ✅ Rule parallelism | ✅ Query parallelism |
| **Scoring** | ✅ Published composite formula | Internal | Opaque Priority Score | Internal | - |
| **SARIF** | ✅ Native 2.1.0 | Not documented | ✅ | ✅ | ✅ Native |
| **Compliance mapping** | PCI-DSS, SOC2, OWASP, HIPAA, ISO27001 | Not documented | Platform compliance only | OWASP rules available | - |
| **Languages** | Any LLM-supported language | Not documented | 14+ | 35+ (parser-based) | 10 |
| **Pricing** | **Free · open source** (~$0.18–$0.90/audit in LLM costs) | **$6,000/mo** | $25-105/mo/developer | OSS engine: free to use · Pro: $30/mo/contributor | Free for public repos · $49/mo/committer (GHAS) |

**Where SEC-AF is strongest**: Verified findings with proof objects, transparent scoring, compliance mapping, composable multi-agent architecture with full DAG observability, and fully open source.

**Where others are stronger**: Semgrep and CodeQL have years of battle-tested rule coverage across 35+ languages. Snyk has deep IDE/SCA integration. Nullify adds runtime cloud context and auto-remediation campaigns. SEC-AF is newer and currently strongest on AI-driven code-level analysis.

> **Same architecture, different domain:** [Contract-AF](https://github.com/Agent-Field/contract-af) applies adversarial HUNT→PROVE to legal contracts — agents spawn agents to find clause interactions solo LLMs miss.

### Why Multi-Agent Architecture Matters

Traditional security scanners are monolithic: one engine, one pass, one set of rules. SEC-AF's multi-reasoner architecture provides structural advantages:

- **Specialization**: Each hunter is a guided LLM specialist — an injection hunter reasons differently from a crypto hunter. The architecture encodes domain knowledge in the routing, not just the prompts.
- **Composability**: Add a new vulnerability class by adding one hunter file. The orchestrator discovers and runs it automatically. No changes to the pipeline.
- **Adversarial verification**: The PROVE phase is structurally separate from HUNT. Hunters try to find vulnerabilities; provers try to disprove them. This adversarial tension reduces false positives.
- **Observability**: Every reasoner call flows through the control plane, creating a complete DAG. You can see exactly which hunter found which finding, how long each phase took, and what the LLM reasoned at each step.
- **Cost efficiency**: Context pruning and schema views mean each LLM call receives only the context it needs. A full standard-depth audit with 30 verified findings costs an estimated ~$0.18–$0.90 in LLM calls (Kimi K2.5 via OpenRouter).

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
| `quick` | 5 core strategies | Top findings only | 2-5 min | ~$0.10-0.40 |
| `standard` | 11 strategies (core + extended) | Top 30 findings | 15-80 min | ~$0.18-0.90 |
| `thorough` | Full strategy set | All findings | 30-120 min | ~$2-8 |

Costs based on Kimi K2.5 via OpenRouter ($0.22/M input, $0.88/M output). The DVGA benchmark (standard depth, 30 verified findings, ~166-255 estimated LLM calls, 82 DAG edges) cost an estimated **$0.18–$0.90**. Full analysis: [`exampl/benchmark-analysis.json`](exampl/benchmark-analysis.json). Any OpenRouter-compatible model works — set `HARNESS_MODEL` and `AI_MODEL` to switch.

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
| `OPENROUTER_API_KEY` | Yes | - | LLM provider credential |
| `HARNESS_MODEL` | No | `moonshotai/kimi-k2.5` | Model for deep `.harness()` analysis |
| `AI_MODEL` | No | `moonshotai/kimi-k2.5` | Model for fast `.ai()` gates and verdicts |
| `SEC_AF_MAX_TURNS` | No | `50` | Max harness turns per call |
| `AGENTFIELD_API_KEY` | No | unset | API key for secured environments |
| `HARNESS_PROVIDER` | No | `opencode` | Harness backend provider |
| `SEC_AF_AI_MAX_RETRIES` | No | `3` | Retry count for model calls |

</details>

## Development Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .[dev]
pytest
ruff check src tests
```

---

### Also built on AgentField

> **[SWE-AF](https://github.com/Agent-Field/af-swe-claude)** — Autonomous engineering team. One API call ships planned, coded, tested, reviewed code. Scored 95/100.
>
> **[Contract-AF](https://github.com/Agent-Field/contract-af)** — Legal contract risk analyzer. Agents spawn agents at runtime. Adversarial review catches what solo LLMs miss.

[All repos →](https://github.com/Agent-Field)

---

<div align="center">

SEC-AF is built on [AgentField](https://github.com/Agent-Field/agentfield), open infrastructure for production-grade autonomous agents. [See what else we're building →](https://github.com/Agent-Field)

**[Apache-2.0](LICENSE)**

</div>
