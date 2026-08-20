// Package orch ports src/sec_af/orchestrator.py — the AuditOrchestrator class,
// its budget/cost bookkeeping, its checkpoint format, and the output-generation
// step every entry point funnels through.
//
// # Two paths through this package
//
// The class has TWO ways of driving an audit, and only one of them is reached
// by the live REST API:
//
//   - Run (`AuditOrchestrator.run`) is the STREAMING, in-process pipeline:
//     fast recon, then deep recon / hunt / prove concurrently, with hunt
//     publishing findings to prove through a queue. Every sub-agent is a Go
//     function call, so the control plane sees ONE execution. app.py does not
//     use it — it issues four `.call`s into internal/phases instead — but
//     RunFromCheckpoint shares its `_run_hunt` / `_run_prove` halves, so the
//     whole thing is ported.
//   - GenerateOutput is the shared tail: severity filtering, the CWE severity
//     floor, exploitability scoring, compliance mapping, the counters, the
//     SARIF/JSON/Markdown artifacts. Both paths end here, and app.py calls it
//     directly after its four `.call`s.
//
// # What the node wiring must know
//
// app.py constructs the orchestrator and then OVERWRITES two fields:
//
//	orchestrator = AuditOrchestrator(app=app, input=audit_input)
//	repo_path = _resolve_repo(repo_url)
//	orchestrator.repo_path = Path(repo_path)
//	orchestrator.checkpoint_dir = orchestrator.repo_path / ".sec-af"
//
// so New computes its own repo path from SEC_AF_REPO_PATH/cwd (Python parity —
// including running the PR-mode diff analysis against THAT path, before the
// override) and RepoPath/CheckpointDir are exported for the caller to replace.
// SetRepoPath does both assignments in one call.
//
// app.py likewise writes agent_invocations, findings_not_verified and
// prove_drop_summary from the phase results before calling GenerateOutput.
// FindingsNotVerified and ProveDropSummary are exported fields for the same
// reason; the invocation counter is mutex-guarded (see below), so it is written
// through SetAgentInvocations instead.
//
// # Concurrency
//
// Python's orchestrator is single-threaded asyncio, so its counters need no
// locking. The Go port fans phases out across goroutines and the phase proxy is
// shared by all of them, so the cost/invocation bookkeeping is mutex-guarded.
// All four guarded values are unexported and reachable only through
// TotalCostUSD / CostBreakdown / AgentInvocations / SetAgentInvocations /
// BudgetExhausted, so the lock contract cannot be bypassed by a later caller
// that reads a partial result while a phase is still running.
// That is the only structural addition; every value it computes is the value
// Python computes.
package orch
