# SEC-AF Go port — design contract

This document is the design contract the Go port under `go/` is written
against: parity rules, package layout, SDK mapping, DAG shape, packaging and the
testing contract. It mirrors the established Agent-Field porting pattern (pr-af
PRs #53/#54/#64, SWE-AF `go/`), adapted to the fact that this node builds its
reasoner DAG with `app.call(f"{NODE_ID}.<reasoner>")` through the control
plane.

Reference material (read-only):

- pr-af Go port — <https://github.com/Agent-Field/pr-af> under `go/`
  (afx.Bind/ToMap, harnessx.Run[T] with embedded pydantic schemas, node/ wiring,
  register.go, Dockerfile/Makefile/compose, go/README.md, root README section)
- SWE-AF Go port — <https://github.com/Agent-Field/SWE-AF> under `go/`
  (app.Call DAG, envelope.UnwrapCallResult)
- AgentField Go SDK (v0.1.131 is the pinned tag) —
  <https://github.com/Agent-Field/agentfield> under `sdk/go`
  (`agent/agent.go` Call/CallLocal/AI/Note, `agent/harness.go`, `agent/router.go`,
  `harness/provider.go` Options, `harness/result.go`, `ai/request.go` WithSchema)
- AgentField Python SDK (to check what Python does) — the same repository under
  `sdk/python/agentfield`

The Python node this port reproduces lives in this repository: `src/sec_af`
(sources) and `tests/` (its test suite).

## -1. Tooling facts

- The generators (`go/scripts/gen_schemas.py`, `go/scripts/gen_golden.py`) need a
  Python 3.11 interpreter with pydantic v2, `agentfield` and this repo's own
  dependencies — the interpreter `af install` provisions for the Python node is
  the convenient one. Run them as
  `PYTHONPATH=<repo>/src <python> go/scripts/gen_schemas.py`.
- Go toolchain: go1.25 or newer on PATH; the module targets the Go 1.21 language
  level. `go mod tidy` resolves
  `github.com/Agent-Field/agentfield/sdk/go v0.1.131` from the proxy.
- Never register a test node against a control plane you do not own: bring up an
  isolated one (see §7).

## 0. Non-negotiables

1. **Python is byte-untouched.** Every diff lives under `go/`, plus
   `docker-compose.go.yml`, the root `agentfield-package.yaml` redirect, one
   root-README section, and `.github/workflows/go.yml`. Never edit `src/`,
   `tests/`, `pyproject.toml`, `Dockerfile`, `docker-compose.yml`.
2. **1:1 parity is the goal.** Same reasoner names, same input parameter
   names/defaults, same result JSON key sets (snake_case, pydantic
   `model_dump()` shape), same prompts (byte-verbatim), same concurrency
   shape (gather/semaphore), same notes (message + tags), same error mapping.
   When Python does something odd, reproduce it and leave a comment
   `// Python parity: ...`. Do not "improve" behavior. If a Python behavior is
   non-deterministic (set iteration order) make it deterministic and comment it.
3. **Same DAG.** Every place Python does `router.call(f"{NODE_ID}.x", ...)` /
   `app.call(...)`, Go does `app.Call(ctx, nodeID+".x", kwargsMap)` with the
   SAME target name and the SAME kwargs keys. Never replace a Python `.call`
   with a direct Go function call — that collapses the control-plane DAG.
   Conversely never add a `.Call` where Python calls a function in-process.
4. **Gate: `cd go && go build ./... && go vet ./... && go test ./... && test -z "$(gofmt -l .)"`**
   must be green for everything you touch. Tests are derived from the Python
   tests and from the behaviors in this doc (validation contract), not from
   the Go implementation.
5. Go 1.21 language level in `go.mod` (`go 1.21`), matching the SDK. Local
   toolchain is go1.25 — fine, but do not use APIs newer than 1.21 (no
   `slices`/`maps` std packages? — those ARE 1.21, ok; `min`/`max` builtins
   are 1.21, ok; avoid `range over int` (1.22) and `iter` (1.23)).
6. No new third-party dependencies beyond: the SDK, `golang.org/x/sync`,
   `github.com/invopop/jsonschema` and `github.com/santhosh-tekuri/jsonschema/v5`
   (pulled by the SDK). Ask before adding anything else.

## 1. Repository layout (`go/` at the repo root)

```
go/
├── agentfield-package.yaml   # name: sec-af, language: go
├── Dockerfile                # multi-stage, aforge fetch + opencode, non-root user, static binary
├── docker-entrypoint.sh      # writes opencode.json from HARNESS_MODEL at container start
├── Makefile                  # build/vet/test/check/fmt/run/docker-*
├── README.md                 # build/run/compose/install story (model on pr-af go/README.md)
├── .gitignore                # bin/, go.work*, coverage
├── doc.go                    # package doc for the module root
├── go.mod / go.sum           # module github.com/Agent-Field/sec-af/go ; go 1.21 ; sdk/go v0.1.131
├── cmd/sec-af/main.go        # the node binary
├── docs/DESIGN.md            # this document
├── scripts/gen_schemas.py    # pydantic model_json_schema() → internal/harnessx/testdata/schemas/*.json
├── scripts/gen_golden.py     # (where useful) Python prompt-builder goldens → internal/.../testdata/*.txt
├── internal/
│   ├── afx/        Bind[T], ToMap, Unwrap/AsMap (the _unwrap/_as_dict parity), DropNulls (model_dump(exclude_none=True))
│   ├── pyfmt/      Round(x, ndigits) banker's rounding (Python round()), Repr(v) Python repr for list/dict/str/bool/None
│   │               (needed wherever a prompt f-string embeds a Python list/dict), FormatFloat (Python str(float))
│   ├── appx/       App interface {Harness, AI, Note, Call} that *agent.Agent satisfies; fakes for tests
│   ├── config/     DepthProfile, BudgetConfig, AuditConfig, AIIntegrationConfig (env), ProviderEnv()
│   ├── schemas/    every pydantic model → Go struct (json tags = pydantic field names), enums → string types
│   ├── harnessx/   Run[T] + RegisterSchema + embedded pydantic schema fixtures; Extract (extract_harness_result parity)
│   ├── aix/        Structured[T]: Python `.ai(user=, schema=Model)` = app.AI(WithSystem?, WithSchema(strictified pydantic schema)) → parse T
│   ├── prompts/    embedded copies of the Python prompt .txt files + Load(relpath) + drift test vs the Python tree
│   ├── <domain pkgs>  see §3
│   ├── reasoners/  Name* constants + RegisterAll (router with the Python AgentRouter tags) + handler adapters
│   ├── phases/     the *_phase reasoners (Call-based DAG)
│   ├── orch/       orchestrator (generate_output, checkpoints, budget/cost bookkeeping, progress notes)
│   └── node/       BuildAgent (env → agent.Config), the top-level `audit` reasoner handler, Serve
└── test/functional/   (build tag `functional`) registration parity against a live control plane
```

Root additions: `docker-compose.go.yml` (Go node as an add-on to the Python
stack, distinct NODE_ID `sec-af-go` and port), root `agentfield-package.yaml`
gains the `superseded_by: https://github.com/Agent-Field/sec-af//go` block
(copy the comment block from pr-af's root manifest verbatim, adjusting names),
root README gains a "Go implementation" section, `.github/workflows/go.yml`
(build/vet/test/gofmt on push + PR, paths-filtered to `go/**`).

Node identity / ports:

| Python code default NODE_ID | Go default NODE_ID | Python port | Go default port | router tags |
|---|---|---|---|---|
| `sec-af` | `sec-af` | 8080 (manifest) / 8003 (compose) | **8013** | `["security","audit","red-team"]` |

`NODE_ID` and `PORT` env override both (Python parity). `docker-compose.go.yml`
sets `NODE_ID=sec-af-go` so both stacks can share one control plane.

## 2. SDK mapping (Python → Go)

| Python (agentfield py SDK) | Go (sdk/go v0.1.131) |
|---|---|
| `Agent(node_id, version, description, agentfield_server, callback_url, api_key, harness_config=HarnessConfig(provider, model, max_turns, env, opencode_bin, aforge_bin, permission_mode="auto"), ai_config=AIConfig(model, api_key, api_base))` | `agent.New(agent.Config{NodeID, Version:"0.1.0", AgentFieldURL, Token, ListenAddress:":"+port, PublicURL: AGENT_CALLBACK_URL, CLIConfig:&agent.CLIConfig{AppDescription}, HarnessConfig:&agent.HarnessConfig{Provider, Model, MaxTurns, PermissionMode:"auto", Env: ProviderEnv(), BinPath: <aforge_bin if provider==aforge, opencode_bin if opencode, else "">}, AIConfig: &ai.Config{Model: strip "openrouter/" prefix, APIKey, BaseURL:"https://openrouter.ai/api/v1"} ONLY when the key is non-empty})` — copy pr-af `node.BuildAgent` incl. the `aiModelForAPI` prefix-strip rationale. |
| `@app.reasoner()` (top-level) | `app.RegisterReasoner(name, handler, agent.WithInputSchema(raw))` — transcribe the Python signature into the input schema (see pr-af `reviewInputSchema`). |
| `router = AgentRouter(tags=[...])`, `@router.reasoner()`, `app.include_router(router)` | `r := agent.NewRouter(); r.RegisterReasoner(name, h)`; `app.IncludeRouter(r, agent.RouterOptions{Tags: tags})` (no Prefix). |
| `await router.call(f"{NODE_ID}.x", a=1, b=2)` | `app.Call(ctx, nodeID+".x", map[string]any{"a":1,"b":2})` — returns the reasoner's result map already unwrapped on success; error on failure. Keep `afx.Unwrap(raw, name)` that mirrors `_unwrap` (error dict → error; `"output"` / `"result"` keys → inner) and `afx.AsMap` (`_as_dict`) for parity; apply them to the returned map exactly where Python does. The ctx passed MUST be the handler's ctx (carries the execution context so the CP parents the child execution). |
| `await app.harness(prompt=p, schema=Model, cwd=c, project_dir=d)` | `harnessx.Run[Model](ctx, app, p, harness.Options{Cwd:c, ProjectDir:d})` — provider/model/max_turns/env/permission come from the agent default HarnessConfig (the Go SDK merges them). `chain_builder` calls harness with NO schema (`app.harness(prompt, cwd=repo_path)`) → `app.Harness(ctx, prompt, nil, nil, opts)` and read `Result.Result` text. |
| `extract_harness_result(result, Model, name)` | `harnessx.Extract[Model](res, name)`: IsError → print the same diagnostic line and return `fmt.Errorf("%s harness error: %s", name, res.ErrorMessage)`; Parsed → value; else TypeError-equivalent error `"%s did not return a valid %s"`. |
| `await app.ai(user=prompt, schema=Model)` / `router.ai(system=, user=, schema=)` | `aix.Structured[Model](ctx, app, system, user)` → `app.AI(ctx, user, ai.WithSystem(system) if system!="", ai.WithSchema(json.RawMessage(strictified schema)))` then `resp.JSON(&v)`. Strictify exactly like Python's `_strictify_openai_schema` (every object: `additionalProperties:false`, `required` = all property names, recursing into `$defs`/`properties`/`items`/`anyOf`). |
| `app.note(msg, tags=[...])` / `router.note(...)` | `app.Note(ctx, msg, tags...)` — same message string, same tag order. |
| `HTTPException(400, detail={"error": msg})` | `return nil, &agent.ExecuteError{StatusCode: 400, Message: msg}` |
| `HTTPException(500, detail={"error": "audit execution failed: ..."})` | `&agent.ExecuteError{StatusCode: 500, Message: "audit execution failed: "+err.Error()}` (after the same `app.Note("Audit pipeline failed: ...", "audit","error")`) |
| `asyncio.gather(*coros)` | `errgroup` / WaitGroup writing into a pre-indexed slice (order preserved). `return_exceptions=True` → per-index error slots. |
| `asyncio.Semaphore(n)` | `semaphore.NewWeighted(n)` from x/sync (or a buffered chan). |
| `asyncio.Queue` producer/consumer (hunt incremental dedup) | channel + consumer goroutine; preserve the note strings. |
| `model_dump()` | `json.Marshal(struct)` — all fields emitted, no `omitempty` (except where Python has `exclude_none=True`: use `afx.DropNulls` on the marshaled map). |
| `Model.model_validate(d)` / `Model(**d)` | `afx.Bind[Model](d)` (JSON round-trip; UnmarshalJSON seeds defaults). |
| `str(float)` in prompts | `pyfmt.FormatFloat` ; `round(x, n)` → `pyfmt.Round` (half-even, like pr-af's). |
| `datetime.now(UTC)` inside `model_dump()` (serialized by FastAPI `jsonable_encoder` → `datetime.isoformat()`) | VERIFIED: `2026-01-02T03:04:05.123456+00:00` (microseconds omitted when zero: `2026-01-02T03:04:05+00:00`). Implement `schemas.Timestamp` (time.Time wrapper) whose MarshalJSON emits exactly that; UnmarshalJSON accepts RFC3339 with or without fraction and `Z`. |

Python round-trips every reasoner boundary through JSON (`model_dump()` →
control plane → `model_validate`). Go must tolerate the same inputs: numbers
arrive as float64 in `map[string]any`; `afx.Bind` handles that.

## 2b. Shared test fake and Python-JSON parity helper

- `internal/appx.Fake` (already written) is THE test double for every package:
  scripted `HarnessFn`/`AIFn`/`CallFn` (helpers `appx.HarnessJSON`, `appx.AIJSON`),
  recorded `Harnesses`/`AIs`/`Notes`/`Calls`, and `MaxConcurrentHarness()` /
  `MaxConcurrentCalls()` for semaphore assertions. Do not write another fake.
- `pyfmt.Dumps(v any, indent int) string` reproduces Python `json.dumps(x, indent=n)`
  applied to a pydantic `model_dump()` dict: walks Go values by reflection
  (struct fields in declaration order honoring json tags, pointers, slices,
  maps with SORTED keys — documented deviation, Python keeps insertion order —
  float64 kinds rendered as Python float repr e.g. `1.0`, ints as ints,
  `true/false/null`, strings escaped like Python's `ensure_ascii=True` (non-ASCII
  → `\uXXXX`, and NO escaping of `<>&`), values implementing json.Marshaler
  (e.g. `schemas.Timestamp`) rendered via their MarshalJSON. `pyfmt.Dumps(v, 0)`
  /`DumpsCompact` = `json.dumps(x)` with `", "` and `": "` separators. Use it
  wherever Python embeds `json.dumps(...)` output in a prompt, a checkpoint file,
  or an output artifact that a test compares textually.

## 2c. Foundation API facts (as actually landed — read the code, these are pointers)

- `harnessx.Run[T](ctx, app, prompt, opts) (*T, *harness.Result, error)`,
  `harnessx.Extract[T](res *harness.Result, dest *T, agentName string) (T, error)`,
  `harnessx.RunExtract[T](ctx, app appx.Harnesser, prompt string, opts harness.Options, agentName string) (T, error)`
  (the 3-arg Extract is deliberate: the Go SDK stores the dest pointer in Result.Parsed),
  `harnessx.SchemaFor[T]() map[string]any` (fixture by Go type name, invopop fallback).
- `aix.Structured[T](ctx, app appx.AIer, system, user string) (T, error)`, `aix.Strictify`.
- `afx.Bind[T]`, `afx.ToMap`, `afx.Unwrap(raw any, name string) (any, error)`, `afx.AsMap(payload any, name string) (map[string]any, error)`, `afx.DropNulls(any) any`. sec-af has only the lenient `Unwrap` (its two Python copies — app.py's and reasoners/phases.py's — are identical).
- `pyfmt.Round(x, ndigits)`, `pyfmt.FormatFloat`, `pyfmt.Str`, `pyfmt.Repr` (maps sorted; use `pyfmt.Ordered`/`pyfmt.O(...)` for insertion-ordered dict repr), `pyfmt.KV`, `pyfmt.Dumps` (`pyfmt/pyjson.go`).
- `prompts.Load(rel) (string, error)`, `prompts.MustLoad(rel)`, `prompts.Names()`; files under `internal/prompts/files/<same relative layout as src/<pkg>/prompts>`.
- `config`: sec-af `DepthProfile` + `NormalizeDepth`, `BudgetConfig`/`DefaultBudgetConfig`, `AuditConfig` + `FromInput(in any, repoPath) (AuditConfig, error)` (JSON-projects any AuditInput-shaped value; `FromInputFields` typed core), `AIIntegrationConfig` + `AIConfigFromEnv() (AIIntegrationConfig, error)` + `ProviderEnv() (map[string]string, error)` (node must fail boot on error, like Python).
- `schemas`: struct per pydantic class, `New<Model>()` constructors (these mint uuid4 ids; `UnmarshalJSON` seeds defaults but never mints ids), `Timestamp`, enums as string types with `Parse*`/`Valid`. The enums have NO strict `UnmarshalJSON`, so `afx.Bind` alone will accept an out-of-vocabulary value — `internal/phases/validate.go` is where pydantic's enum gate is reproduced, and every `.call` boundary must bind through it.
  Name collisions: `schemas.DataFlowStep` = prove's (file/line/description/tainted); `schemas.ReconDataFlowStep` = recon's (file_path/line/component/operation); `Location/CvssV4Score/EpssScore/ReproductionStep` declared once (output.go); `HuntStrategy` has the LOGIC_BUGS value alias; `schemas.PolicyEvalResult` exists.
- Stale Python tests discovered (port the CODE behavior, note the stale assertion): `tests/test_scoring.py` has two reachability-default assertions the code contradicts (empty tags → externally_reachable 1.0).
- Live verification uses a mock `opencode` shim that resolves every prompt role and writes canned schema-valid JSON (see §7). Known nondeterminism: `run_verdict_agent` is a real `.ai()` call, so the remediation fan-out varies with the LLM.

## 3. sec-af port map (Python module → Go package)

| Python | Go package | Notes |
|---|---|---|
| `app.py` | `internal/node` (+ `cmd/sec-af`) | `audit` reasoner: build AuditInput (same defaults: scan_types `["sast","sca","secrets","config"]`, output_formats `["json"]`, exclude_paths `["tests/","vendor/","node_modules/",".git/"]`), `_resolve_repo` (local dir → abs; http(s)/git@ → clone into `SEC_AF_WORKSPACES_DIR` default `/workspaces`, PermissionError fallback `~/.sec-af/workspaces`, `git pull --ff-only` if exists, `git clone --depth 1`, env GIT_TERMINAL_PROMPT=0 GIT_ASKPASS=echo, timeouts 60/120s; else `SEC_AF_REPO_PATH` or cwd), orchestrator construction, `resume_from_checkpoint` branch, the 4 `app.call`s in order with the SAME kwargs, checkpoint writes, `agent_invocations = total_selected + len(strategies_run) + 3`, `_generate_output`, notes, error mapping. `/health` is served by the SDK already (`{"status":"healthy",...}`) — do not add a custom route unless the SDK's differs materially; document. |
| `reasoners/__init__.py` + `recon.py` + `hunt.py` + `prove.py` + `phases.py` | `internal/reasoners` (registration + thin adapters) and `internal/phases` (the `*_phase` + `run_cwe_expansion` bodies) | Register EXACTLY these 33 router reasoners (tags `security, audit, red-team`) in this order: `run_architecture_mapper, run_dependency_auditor, run_config_scanner, run_data_flow_mapper, run_security_context_profiler, run_injection_hunter, run_dos_hunter, run_ssrf_hunter, run_auth_hunter, run_xss_hunter, run_crypto_hunter, run_business_logic_hunter, run_logic_bugs_hunter, run_data_exposure_hunter, run_supply_chain_hunter, run_config_secrets_hunter, run_api_security_hunter, run_deduplicator, run_dep_reachability, run_verifier, run_tracer, run_sanitization_analyzer, run_exploit_hypothesizer, run_verdict_agent, run_remediation, run_remediation_agent, run_dast_verifier, run_cross_service_analyzer, run_cwe_expansion, recon_phase, hunt_phase, prove_phase, remediation_phase` plus the top-level `audit` (34 total). Each adapter: the "X starting" note with its exact tags, bind inputs, call the agent function, return `model_dump()` map. `_run_hunter`'s TypeError-cascade is Python duck-typing noise — Go calls each hunter with the single real signature `(ctx, app, repoPath, recon, depth, maxFilesWithoutSignal)`. `_recon_model` normalization (seed defaults then overlay) → Bind with default-seeding handles it; keep `security_context` default `{"auth_model":"unknown","auth_details":""}`. `_coerce_verifier_finding` (RawFinding or FindingForVerifier projection) must be ported. |
| `orchestrator.py` | `internal/orch` | Port the whole class: `AuditOrchestrator` fields, `run()` (streaming in-process path — keep for completeness, it is not reached by the API but `run_from_checkpoint` uses `_run_hunt/_run_prove` which are in-process), `run_from_checkpoint`, `_run_recon/_run_fast_recon/_run_deep_recon_async/_merge_recon`, `_run_hunt(_streaming)`, `_run_prove(_streaming)`, `_run_dast_verification`, `_generate_output` (severity threshold filter, CWE floor, exploitability score, `get_compliance_mappings_hybrid` with the AI gate, verdict/severity counts, noise reduction, AttackChain mapping, compliance gaps, SecurityAuditResult, sarif/json/report generation, compliance report files under checkpoint_dir), checkpoints (`checkpoint-<phase>.json` with `{"phase","created_at","data"}` and `indent=2`), `_prover_cap`, `_prioritize_findings`, `_assess_reachability_parallel` (semaphore min(5,n), fallback tag `requires_auth`), budget/cost helpers, `_PhaseHarnessProxy` (a wrapper that checks budget, counts invocations and registers cost — it exposes ONLY `harness`, exactly as the Python class does, so dedup's `hasattr(app,"ai")` gate is False and run_prove's verdict call raises AttributeError), `_emit_progress` (AuditProgress JSON note), `_track_drop`, `_verified_finding_fallback`, `merge_recon_findings_into_hunt`. |
| `harness.py` | `internal/harnessx` (+ `AIGateWrapper` in `internal/gates`) | `HarnessWrapper` is unused by the live path — port `AIGateWrapper` (invoke with retry on transient errors, `classify_severity`, `check_duplicate`, `select_strategy`, `assess_reachability`, the exact prompt strings incl. Python list repr of `default_candidates`) since the orchestrator uses it (`assess_reachability`, `get_compliance_mappings_hybrid`). `_is_transient_error` patterns + backoff (`min(initial*2**attempt, max)`) must match. Port `HarnessWrapper` too only if cheap (it is pure; `_with_phase_guidance`/`_schema_guidance` strings are testable) — lower priority. |
| `config.py` | `internal/config` | env names: `SEC_AF_PROVIDER`/`HARNESS_PROVIDER` (default `aforge`), `SEC_AF_MODEL`/`HARNESS_MODEL` (default `minimax/minimax-m2.5`), `SEC_AF_AI_MODEL`/`AI_MODEL`/`SEC_AF_MODEL` (default `minimax/minimax-m2.5`), `SEC_AF_MAX_TURNS` 50, `SEC_AF_AI_MAX_RETRIES` 3, `SEC_AF_AI_INITIAL_BACKOFF_SECONDS` 2.0, `SEC_AF_AI_MAX_BACKOFF_SECONDS` 8.0, `SEC_AF_OPENCODE_BIN` opencode, `SEC_AF_AFORGE_BIN`/`AFORGE_BIN` aforge, `SEC_AF_OPENCODE_SERVER`/`OPENCODE_SERVER`. `provider_env()`: the 6 keys + `AGENTFIELD_AFORGE_COMMAND` (default exec) + `XDG_DATA_HOME` (default `<tmp>/opencode-shared-data`, mkdir). Malformed ints crash at boot (Python crashes at import) → return error from `FromEnv`. |
| `context.py` | `internal/context` (package name `recontext` to avoid clashing with std `context`) | `prune_recon_for_strategy`, `recon_context_generic`, the per-strategy projections, `get_framework_hints`/`get_language_hints` wiring (hints live in agents/hunt in Python — put them in `internal/agents/hunt/hints.go` and import). Outputs are embedded in prompts → byte-exact; golden test against Python via `scripts/gen_golden.py`. |
| `schemas/*.py` | `internal/schemas` | One Go file per Python module. Enums: `Severity, Confidence, FindingType, HuntStrategy, Verdict, EvidenceLevel, ...` as `type X string` + consts. Pydantic defaults ≠ Go zero → `UnmarshalJSON` default seeding (pr-af `schemas/defaults.go` pattern). Computed properties (`RawFinding.fingerprint` default, `id` default uuid/hash, `for_verifier()` projection) → methods; check how `id`/`fingerprint` defaults are generated in Python and reproduce (if `uuid4` → `uuid.NewString()` — accept nondeterminism; if hash → exact). `SecurityAuditResult.timestamp` → Timestamp type (§2). Field descriptions: keep as Go doc comments (they matter for the pydantic schema fixtures, which come from Python, so no need to reproduce in Go tags). |
| `schemas/gates.py` | `internal/schemas/gates.go` | `CWEExpansion, DuplicateCheck, ReachabilityGate, SeverityClassification, StrategySelection, ...` — used by aix. |
| `scoring.py` | `internal/scoring` | port + port `tests/test_scoring.py` fully. |
| `compliance/mapping.py` | `internal/compliance` | static tables byte-exact; `get_compliance_mappings`, `get_compliance_gaps`, `get_compliance_mappings_hybrid(cwe, frameworks, ai_gate)`; port `tests/test_compliance.py`. |
| `output/sarif.py, json_output.py, report.py, compliance_report.py` | `internal/output` | SARIF JSON must be byte-comparable modulo key order → build with ordered structs; port `tests/test_sarif.py`, `test_json_output.py`, `test_compliance_report.py`. Python `json.dumps(indent=2)` → Go `json.MarshalIndent(v,"","  ")` (note Python puts a space after `:` and `,` — MarshalIndent matches; but Python escapes non-ASCII as `\uXXXX` by default (`ensure_ascii=True`) and Go escapes `<>&` as `<` — document; where a test compares strings, compare parsed JSON). |
| `diff_analysis.py`, `monitoring.py`, `policies.py` | `internal/diffanalysis`, `internal/monitoring`, `internal/policies` | pure modules with Python tests → port them + tests (monitoring/policies are not wired into the API; port for 1:1 completeness; `audit.py` stub can be skipped — note it). |
| `agents/_utils.py` | `internal/harnessx` (Extract) | see §2. |
| `agents/recon/*` | `internal/agents/recon` | 5 mappers (each: read prompt template, append the exact CONTEXT block, `tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")` → `os.MkdirTemp("", "secaf-"+name+"-")`, harness with `cwd=tmp, project_dir=repo`, extract, parse `*Raw` → typed via `_parsers.py` port, `defer os.RemoveAll`), `_repo_metrics` (same SKIP_DIRS/CODE_EXTS, count lines of code files, count all files), `extract_recon_findings` (+ `tests/test_recon_findings.py`), `run_recon`, `run_fast_recon`, `run_deep_recon`. |
| `agents/hunt/*` | `internal/agents/hunt` | `_scan_enrich.py` (scan_locations prompt, enrich_finding prompt, `enrich_locations_parallel`, `assemble_finding`), 12 hunters (injection, dos, ssrf, auth, xss, crypto, business_logic, logic, data_exposure, supply_chain, config_secrets, api_security) — each hunter file is a thin wrapper with its strategy name/CWE baseline/prompt path: read them all; `_framework_hints.py`, `_language_hints.py` (static tables, byte-exact), `__init__.py` `run_hunt` + `run_hunt_streaming` + `_default_strategies` + dedup-by-fingerprint + `include_paths` handling (`tests/test_hunt_include_paths.py`, `test_hunt_crypto.py`, `test_strategy_selection.py`). |
| `agents/dedup.py` | `internal/agents/dedup` | `deduplicate_and_correlate` (fingerprint + semantic `.ai(DuplicateCheck)` pass + chain correlation harness call), `tests/test_dedup.py`. |
| `agents/prove/*` | `internal/agents/prove` | `verifier.py` (orchestrates tracer→sanitization→exploit→verdict in-process + `assembler`, `fallback(finding, reason, drop_reason, original_verdict)`), `tracer`, `sanitization`, `exploit`, `verdict` (uses `.ai(schema=VerdictDecision)` — aix), `chain_builder` (no-schema harness), `cross_service`, `dast_verifier`, `dep_reachability`, `sandbox` (subprocess w/ limits → `exec.CommandContext` + timeout), `__init__.py` `run_prove`/`run_prove_streaming`; `tests/test_prove_phase_demotion.py`. |
| `agents/remediation.py` | `internal/agents/remediation` | `generate_remediation` (VerifiedFinding → RemediationSuggestion) and `run_remediation` (RawFinding+verdict+rationale). |
| `prompts/**/*.txt` (in `src/sec_af/prompts`) | `internal/prompts/files/**` (go:embed) | byte-identical copies; `prompts.Load("hunt/injection.txt")`; drift test walks `../../../src/sec_af/prompts` when it exists and asserts byte equality for every file in both directions. |

### The DAG the control plane must show

```
audit
├── recon_phase
│   ├── run_architecture_mapper ┐
│   ├── run_dependency_auditor  ├ gather (3)
│   ├── run_config_scanner      ┘
│   ├── run_data_flow_mapper           ┐ gather (2) — skipped when depth == quick
│   └── run_security_context_profiler  ┘
├── hunt_phase
│   ├── run_<strategy>_hunter × N   (semaphore max(1,min(max_concurrent_hunters=4, N)); N from _default_strategies)
│   └── run_deduplicator            (only when ≥1 fingerprint-unique finding)
├── prove_phase
│   └── run_verifier × K            (K = min(len(findings), prover cap: quick 10 / standard 30 / thorough 10000, max_provers); semaphore 3)
└── remediation_phase
    └── run_remediation × M         (M = confirmed/likely findings without remediation; semaphore 3)
```

`run_cwe_expansion` is registered but Python calls `expand_cwes_for_hunt`
in-process from `hunt_phase` (an `.ai()` call, not a `.call`) — reproduce
that: no DAG node for it.

## 5. Testing contract

- Port EVERY Python test file to a Go test in the owning package (same
  assertions, same fixtures). Name tests after the Python ones so reviewers
  can diff coverage (`TestScoring_...` ↔ `test_scoring.py::test_...`).
- Add golden tests for every prompt-building function whose output reaches
  the LLM (`scripts/gen_golden.py` runs the Python builders with fixed inputs
  and writes `testdata/golden/*.txt`; the Go test renders the same inputs and
  compares byte-for-byte). Commit the generator AND the goldens.
- Schema fixtures: `scripts/gen_schemas.py` imports the pydantic models and
  writes `model_json_schema()` JSON for every model that is passed to
  `app.harness(schema=)` or `app.ai(schema=)`. Commit them under
  `internal/harnessx/testdata/schemas/`. Add the pr-af drift test that checks
  every embedded schema's `properties` keys ⊆ the Go struct's json tags and
  vice-versa (required ones).
- Concurrency tests for each phase: a fake `appx.App` whose `Call` records
  (target, kwargs) — assert the exact target names, kwargs keys, call counts,
  order where Python orders, and the max observed concurrency ≤ the semaphore
  limit.
- Node tests: registration parity (exact ordered name list + tags), `audit` /
  `scan` input binding defaults, error mapping.
- Functional test (build tag) against a live CP is optional; the manual live
  verification (§7) is mandatory and done by the integrator.

## 6. Packaging

Copy pr-af's `go/Dockerfile`, `go/docker-entrypoint.sh`, `go/Makefile`,
`docker-compose.go.yml`, `go/README.md`, root README section, root manifest
redirect, and adapt: binary name, user (`secaf`), ports, env var names
(`HARNESS_PROVIDER`, `HARNESS_MODEL`, `AI_MODEL`, `SEC_AF_*`,
`SEC_AF_WORKSPACES_DIR`), the aforge fetch
stage (take it from the repo's OWN Python Dockerfile — it is already the
checksum-verified download), the Python image's opencode config (the Go
entrypoint generates it from `HARNESS_MODEL`). The Go manifest's
`user_environment` block = the root manifest's block (same keys) — the Go node
reads the same env vars. `go.mod` requires
`github.com/Agent-Field/agentfield/sdk/go v0.1.131` (no replace).
CI: `.github/workflows/go.yml` — `actions/setup-go` with `go-version-file:
go/go.mod`, `working-directory: go`, steps `go build ./...`, `go vet ./...`,
`go test ./...`, `test -z "$(gofmt -l .)"`, `docker build -f go/Dockerfile .`.

## 7. Live verification (integrator)

1. Isolated control plane (the `af` binary, or a fresh build) on a free port
   with `HOME` + `AGENTFIELD_HOME` pointed at a scratch dir — never a control
   plane you do not own.
2. Python node (`pip install -e .` in a venv, or the installed package) and Go
   node (`go run ./cmd/sec-af`) both registered (distinct NODE_IDs), same
   `OPENROUTER_API_KEY`, same harness provider/model, same
   `SEC_AF_WORKSPACES_DIR`.
3. Deterministic DAG comparison: a mock harness CLI (`HARNESS_PROVIDER=opencode`
   + `SEC_AF_OPENCODE_BIN` pointing at a shim that recognizes the prompt's role
   and writes canned schema-valid JSON to the output file; see pr-af
   `go/test/mockcli`) → run `audit` on the same fixture repo through both nodes → pull `/api/v1/executions?...`/workflow
   tree for each run and compare the node/edge multiset (parent→child
   reasoner names, counts). Must be identical.
4. Real run (depth `quick`) of the Go node on a small public vulnerable repo
   with the real key → succeeds, result JSON has the expected keys, DAG shape
   matches the Python structure.
