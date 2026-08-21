# SEC-AF — Go node

A Go implementation of the SEC-AF security-audit node. It registers the same
reasoner surface under the same names as the Python node, exposes a
byte-compatible HTTP API, and reaches every sub-agent through the control plane,
so the control-plane DAG UI renders the same multi-node orchestration graph as
the Python node (see [Pipeline DAG on the control plane](#pipeline-dag-on-the-control-plane)).
The Python package under `src/sec_af/` is untouched; this implementation lives
entirely under `go/`.

One binary:

| Binary   | Node ID  | Default port | Role                                        |
|----------|----------|--------------|---------------------------------------------|
| `sec-af` | `sec-af` | `8013`       | Full audit pipeline (recon → hunt → prove → remediation) |

Module path: `github.com/Agent-Field/sec-af/go`.

## Install

Installing the bare repository URL follows the root manifest's redirect to this
package and registers the Go node as `sec-af` on `:8013`:

```bash
af install https://github.com/Agent-Field/sec-af
af run sec-af
af call sec-af.audit --in '{"repo_url":"https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application"}'
```

To install the Python node deliberately, clone the repository and run
`af install ./sec-af`; local-path installs do not follow the redirect. `NODE_ID`
and `PORT` still override the Go defaults if you want a different id or port.

## Pipeline DAG on the control plane

An audit is not one execution. Every phase and every sub-agent runs as a
**tracked child execution** of the parent `audit`, and the control-plane UI
renders the run as that DAG:

```
audit
├── recon_phase
│   ├── run_architecture_mapper ┐
│   ├── run_dependency_auditor  ├ gather (3)
│   ├── run_config_scanner      ┘
│   ├── run_data_flow_mapper           ┐ gather (2) — skipped when depth == quick
│   └── run_security_context_profiler  ┘
├── hunt_phase
│   ├── run_<strategy>_hunter × N   semaphore max(1, min(max_concurrent_hunters=4, N))
│   └── run_deduplicator            only when ≥1 fingerprint-unique finding
├── prove_phase
│   └── run_verifier × K            K = min(len(findings), prover cap)  semaphore 3
└── remediation_phase
    └── run_remediation × M         M = confirmed/likely findings without a remediation
```

Python draws that graph with `await router.call(f"{NODE_ID}.<reasoner>", ...)`;
the Go port makes the identical `Agent.Call` with the same target name and the
same kwargs, so the node/edge multiset is the same. The registered surface is 34
reasoners: `audit` plus the 33 router reasoners, tagged
`["security","audit","red-team"]`.

Two nodes that are registered but never `.call`ed — `run_cwe_expansion` and the
individual `run_tracer` / `run_sanitization_analyzer` / `run_exploit_hypothesizer`
/ `run_verdict_agent` reasoners — are part of the surface because Python
registers them; the verifier runs those four in process, exactly as Python does,
so they contribute no DAG node on a normal audit.

## Depending on the AgentField Go SDK

This module depends on the AgentField Go SDK
(`github.com/Agent-Field/agentfield/sdk/go`) via a **real, committed `require`**
resolved from `proxy.golang.org` — there is **no `replace` directive** and no
sibling checkout to lay out. `go build ./...` works out of the box against the
pinned SDK version in `go.mod`.

- **CI / Docker.** `go mod download` pulls the SDK (and every other dependency)
  straight from the module proxy. No `GOWORK=off`, no sparse clone.
- **Dev — optional Go workspace.** A gitignored `go.work` (spanning this module
  and a local `agentfield/sdk/go` checkout) is the way to develop against
  unreleased SDK changes; with it present, `go build ./...` picks up local SDK
  edits live. It is never committed.

Bumping the SDK is a deliberate, reviewable change: bump the `require` version
in `go.mod`, and move the Docker builder image tag together with it if the SDK's
own `go` directive ever advances past `go 1.21`.

## Build & run locally

From `go/`:

```bash
make build          # go build ./...
make vet            # go vet ./...
make test           # go test ./...
make fmtcheck       # test -z "$(gofmt -l .)"
make check          # build + vet + test + fmtcheck (the CI gate)
make fmt            # gofmt -w .
make run            # run the node (sec-af, :8013)
```

`make run` needs a control plane reachable at `AGENTFIELD_SERVER` (default
`http://localhost:8080`). The node reads all configuration from the environment
at startup.

## Docker

The image is a multi-stage build: `go mod download` + `go build` in a
`golang:1.23` stage, then a slim Debian runtime mirroring the Python image —
the pinned `opencode` CLI (`1.17.15`), the checksum-verified `aforge` binary,
a non-root `secaf` user (uid/gid 10001), and a `docker-entrypoint.sh` that
generates `opencode.json` from `HARNESS_MODEL` at container start.

The build context is the **repo root** so the `go/` module is in context:

```bash
# from the repo root
docker build -f go/Dockerfile -t sec-af-go:latest .
```

The tag is `sec-af-go`, not `sec-af`: the root README's `docker build -t sec-af .`
builds the **Python** image under `sec-af:latest`, and the two are different
artifacts (different entrypoint, different port).

### Compose: opt-in add-on to the Python stack

`docker-compose.go.yml` (at the repo root) is an **add-on**, not a standalone
stack. It defines only the Go node and joins the Python stack's compose network
as an external reference, sharing the control plane (`agentfield`) and the
`workspaces` volume the Python stack brings up. The Python `docker-compose.yml`
is left untouched. Start the Python stack first, then layer the Go node:

```bash
docker compose up -d                          # Python stack (control plane + sec-af :8003)
docker compose -f docker-compose.go.yml up -d # adds sec-af-go :8013
```

Adds:

| Service     | Port   | Node id     | Notes               |
|-------------|--------|-------------|---------------------|
| `sec-af-go` | `8013` | `sec-af-go` | full audit pipeline |

The control plane (`:8080`) and the `workspaces` volume come from the Python
stack — the Go add-on joins them via the external `sec-af_default` network and
`sec-af_workspaces` volume. This assumes the Python stack was brought up with
the default project name `sec-af` (the Python compose has no explicit `name:`,
so its project name is the checkout directory's basename); see the compose file
header for the `COMPOSE_PROJECT_NAME` override. Health:
`curl -f http://localhost:8013/health`.

## Environment variables

The node is configured entirely through the environment.

| Variable                    | Purpose                                                          |
|-----------------------------|------------------------------------------------------------------|
| `OPENROUTER_API_KEY`        | LLM provider key (OpenRouter) — required                         |
| `AGENTFIELD_URL`            | Control-plane URL — checked **first** in this repo               |
| `AGENTFIELD_SERVER`         | Control-plane URL fallback (default `http://localhost:8080`)     |
| `AGENTFIELD_API_KEY`        | Control-plane API key (if the CP has auth enabled)               |
| `AGENT_CALLBACK_URL`        | Base URL the control plane uses to reach this node               |
| `NODE_ID`                   | Node ID (default `sec-af`)                                       |
| `PORT`                      | Listen port (default `8013`)                                     |
| `HARNESS_PROVIDER`          | Harness provider (default `aforge`; `opencode` to roll back). `SEC_AF_PROVIDER` wins when both are set |
| `AGENTFIELD_AFORGE_COMMAND` | AForge headless command — `exec` (default) or `do`               |
| `HARNESS_MODEL`             | Harness model (`SEC_AF_MODEL` wins when both are set)            |
| `AI_MODEL`                  | Model for direct `.ai()` calls (`SEC_AF_AI_MODEL` wins)          |
| `SEC_AF_AFORGE_BIN`         | AForge executable override (falls back to `AFORGE_BIN`, then `aforge` on PATH) |
| `SEC_AF_OPENCODE_BIN`       | OpenCode executable override (default `opencode`)                |
| `SEC_AF_MAX_TURNS`          | Harness turn cap (default `50`)                                  |
| `SEC_AF_AI_MAX_RETRIES`     | Retry count for `.ai()` gate calls (default `3`)                 |
| `SEC_AF_AI_INITIAL_BACKOFF_SECONDS` | First retry backoff in seconds (default `2.0`)           |
| `SEC_AF_AI_MAX_BACKOFF_SECONDS` | Backoff ceiling in seconds (default `8.0`)                   |
| `SEC_AF_OPENCODE_SERVER`    | OpenCode server URL (falls back to `OPENCODE_SERVER`; unset by default) |
| `SEC_AF_WORKSPACES_DIR`     | Clone destination for remote repo URLs (default `/workspaces`; falls back to `~/.sec-af/workspaces` when not writable) |
| `SEC_AF_REPO_PATH`          | Local checkout used when `repo_url` is neither a directory nor a URL |

The image ships the released AForge CLI (fetched and checksum-verified at build
time from `https://agentfield.ai/downloads/aforge`, pinned by the
`AFORGE_VERSION` build arg) and runs `exec` by default. OpenCode remains
installed and can be selected with `HARNESS_PROVIDER=opencode` without
rebuilding.

Note on model defaults — there are three, and they are all deliberate (each one
mirrors the Python node's corresponding artifact):

| Where | Default | Why |
| --- | --- | --- |
| Code (`internal/config`, `src/sec_af/config.py`) | `minimax/minimax-m2.5` | Bare slug; the fallback when nothing is set. |
| Docker image (`go/Dockerfile`, root `Dockerfile`) | `openrouter/minimax/minimax-m2.5` | Same model, `openrouter/`-prefixed for the harness router. |
| Compose, `.env.example`, `agentfield-package.yaml` | `deepseek/deepseek-v4-flash-0731` | A different model — the one an installed or composed node runs. |

`SEC_AF_MODEL` / `SEC_AF_AI_MODEL` win over `HARNESS_MODEL` / `AI_MODEL`, and
either env var wins over every default above.

## Parity notes

Behaviour is a 1:1 port of `src/sec_af/`, including its quirks. Four
differences are deliberate and are documented at their call sites:

- **Callback URL.** Python computes `http://127.0.0.1:${PORT:-8004}` while its
  `main()` listens on `${PORT:-8080}` — the two defaults disagree, so an unset
  `PORT` makes the Python node advertise an address it is not listening on. The
  Go node sets its public URL from `AGENT_CALLBACK_URL` when set and otherwise
  lets the SDK derive `http://localhost:<actual listen port>`.
- **`/health` body.** Python's route returns
  `{"status":"healthy","version":"0.1.0"}`; the SDK's built-in route returns
  `{"status":"ok"}` with the same 200. Every consumer here (the Dockerfile
  healthcheck, the compose healthcheck, the manifest) only checks the status
  code, so the SDK route is used as-is. The SDK also serves `/status`, which is
  what the control plane's own health monitor polls.
- **AI credentials.** The Go SDK's `ai.Config` rejects an empty API key at
  construction, so the AI client is attached only when `OPENROUTER_API_KEY` is
  set. Python accepts the empty key and fails at call time instead; either way
  an `.ai()` call without a key fails.
- **Control plane unreachable at boot.** This one is SDK-level, not something
  the port chose, and it is the only one with an operational consequence. The
  Python SDK's `ConnectionManager` treats registration as best-effort: it logs
  `AgentField server unavailable - running in degraded mode`, keeps serving, and
  retries every 10s, so the Python node survives a control plane that is not up
  yet or that restarts under it. The Go SDK's `Agent.Serve` returns the
  registration error (`client.RegisterNode` has no retry), and
  `cmd/sec-af/main.go` treats that as fatal — the process binds its port, logs
  `node.register.failed`, and exits. In practice the Go node therefore
  restart-loops (compose sets `restart: unless-stopped`) until the control plane
  answers, instead of degrading in place. Start the Python stack — which owns
  the control plane — first, and expect the add-on container to retry until that
  stack is healthy.

## Deployment: `af install`

Because the root package redirects git installs here, install the Go node with
the repository's bare URL:

```bash
af install https://github.com/Agent-Field/sec-af
```

This resolves to `go/agentfield-package.yaml` (node id `sec-af`, default port
`8013`) and builds `./cmd/sec-af`. A prior Python `sec-af` installation is
replaced in place, retaining its node id, triggers, and node-scoped secrets.
