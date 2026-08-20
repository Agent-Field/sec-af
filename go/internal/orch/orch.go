package orch

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/config"
	"github.com/Agent-Field/sec-af/go/internal/diffanalysis"
	"github.com/Agent-Field/sec-af/go/internal/gates"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// nowMonotonic is `time.monotonic()` — the clock New stamps StartedAt with and
// elapsedSeconds measures against. It is a variable purely so a test can pin
// the elapsed times that reach the progress notes and duration_seconds;
// production never reassigns it.
//
// Go's time.Now carries a monotonic reading that Sub prefers over the wall
// clock, so the DIFFERENCE has exactly Python's time.monotonic() semantics
// (immune to clock adjustments) even though the absolute value is a wall time.
var nowMonotonic = time.Now

// PhaseOrder ports `AuditOrchestrator._PHASE_ORDER = ("recon", "hunt", "prove")`
// — the three cost buckets, and the key set of cost_breakdown.
var PhaseOrder = [...]string{"recon", "hunt", "prove"}

// The three phase names, spelled once so a typo cannot silently create a fourth
// cost bucket.
const (
	PhaseRecon = "recon"
	PhaseHunt  = "hunt"
	PhaseProve = "prove"
)

// AuditOrchestrator ports the class of the same name (orchestrator.py:53).
//
// Every field Python assigns in `__init__` is here, exported where a caller
// (app.py, and therefore internal/node) reads or writes it:
//
//	self.app, self.input, self.started_at, self.repo_path, self.checkpoint_dir,
//	self.is_pr_mode, self.diff_analysis, self.config, self.budget_config,
//	self.max_cost_usd, self.max_duration_seconds, self.total_cost_usd,
//	self.cost_breakdown, self.agent_invocations, self.budget_exhausted,
//	self.findings_not_verified, self.prove_drop_summary, self.ai_gate
type AuditOrchestrator struct {
	// App is the SDK agent. Python stores it as `cast("Any", app)` purely to
	// silence the type checker; the capability set it actually uses is
	// harness + ai + note (never call — the orchestrator's own pipeline is
	// in-process).
	App appx.App
	// Input is the audit request.
	Input schemas.AuditInput
	// StartedAt is `time.monotonic()` at construction. Go's time.Now is a wall
	// clock, but every read is a DIFFERENCE (`time.monotonic() - self.started_at`)
	// and Go's time.Time carries a monotonic reading that Sub prefers, so the
	// elapsed values match Python's semantics.
	StartedAt time.Time
	// RepoPath is `Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve()`.
	// app.py replaces it right after construction — see SetRepoPath.
	RepoPath string
	// CheckpointDir is `self.repo_path / ".sec-af"`.
	CheckpointDir string
	// IsPRMode is `input.is_pr`.
	IsPRMode bool
	// DiffAnalysis is populated only in PR mode with a base commit; nil is
	// Python's None.
	DiffAnalysis *diffanalysis.DiffAnalysis
	// Config is `AuditConfig.from_input(input, str(repo_path))`.
	Config config.AuditConfig
	// BudgetConfig is `self.config.budget`.
	BudgetConfig config.BudgetConfig
	// MaxCostUSD is `input.max_cost_usd` (None => nil => no cost budget).
	MaxCostUSD *float64
	// MaxDurationSeconds is `input.max_duration_seconds`.
	MaxDurationSeconds *int
	// FindingsNotVerified is the count GenerateOutput reports in metadata.
	//
	// Unlike the two guarded counters it stays an EXPORTED field, because
	// every writer runs on the sequential audit path and never inside the
	// phase fan-out: run.go's two phases, and app.py's own
	// `orchestrator.findings_not_verified = ...` (node/audit.go).
	FindingsNotVerified int
	// ProveDropSummary is the `{"demoted_total", "by_reason", "findings"}`
	// dict, rebuilt at the start of each prove pass and copied verbatim into
	// the result metadata.
	//
	// Typed `any`, not `map[string]any`, because on the app.py path it is
	// assigned straight from a `.call` payload with
	// `prove_dict.get("drop_summary", {...})` — a `.get`, so the default fires
	// ONLY when the key is absent. A key that is present with an odd value (a
	// JSON null, a string, a list) is threaded through to
	// `metadata["prove_drop_summary"]` verbatim in Python, and a
	// `map[string]any` field cannot hold it. See node/audit.go.
	ProveDropSummary any
	// AIGate is `AIGateWrapper(app=self.app)` — used by
	// AssessReachabilityParallel and by GenerateOutput's compliance fallback.
	AIGate *gates.AIGate

	// mu guards the cost/invocation counters. Python needs no lock (asyncio is
	// single-threaded); the Go phases fan out across goroutines that share one
	// proxy, so the bookkeeping must be safe for concurrent use. It guards
	// totalCostUSD, costBreakdown, agentInvocations and budgetExhausted.
	//
	// All four are UNEXPORTED so the contract is enforceable rather than
	// merely documented: every access goes through the guarded accessors below
	// (TotalCostUSD, CostBreakdown, AgentInvocations, SetAgentInvocations,
	// BudgetExhausted) and there is no way for a caller to read one while a
	// phase proxy is still writing it. An earlier revision exported the two
	// counters, and GenerateOutput read both of them bare — harmless today,
	// because Run joins its errgroup before calling it, but a latent race for
	// the first caller that reads a partial result (a progress endpoint, an
	// early return on budget exhaustion) and one the race detector would only
	// catch if a test happened to schedule the overlap.
	mu               sync.Mutex
	totalCostUSD     float64
	costBreakdown    map[string]float64
	agentInvocations int
	budgetExhausted  bool
}

// New ports `AuditOrchestrator.__init__(app, input)`.
//
//	self.started_at = time.monotonic()
//	self.repo_path = Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve()
//	self.checkpoint_dir = self.repo_path / ".sec-af"
//	self.is_pr_mode = input.is_pr
//	if self.is_pr_mode and input.base_commit_sha:
//	    self.diff_analysis = analyze_diff(str(self.repo_path), input.base_commit_sha, input.commit_sha or "HEAD")
//	self.config = AuditConfig.from_input(self.input, str(self.repo_path))
//	...
//	self.ai_gate = AIGateWrapper(app=self.app)
//
// Python parity:
//
//   - the diff analysis runs against the CONSTRUCTOR's repo path, before app.py
//     substitutes the resolved (possibly cloned) one. Reproduced: callers that
//     want the diff against the real checkout must construct after resolving,
//     which app.py does not do.
//   - `input.base_commit_sha` and `input.commit_sha` are tested with PYTHON
//     TRUTHINESS, so an empty string behaves like None — no diff analysis, and
//     the head defaults to "HEAD".
//   - AIGateWrapper's config falls back to `AIIntegrationConfig.from_env()`,
//     which in Go can fail on a malformed SEC_AF_AI_* integer. Python crashes at
//     import time for the same input; Go returns the error here, which is the
//     earliest point it can.
//
// Signature parity note: Python's `__init__` is synchronous and carries no
// context, so New takes none. analyze_diff shells out to git, and
// diffanalysis.AnalyzeDiff gives each invocation its own 30s timeout, so
// context.Background() is the honest translation. NewWithContext is for a
// caller that already holds a cancellable context.
func New(app appx.App, input schemas.AuditInput) (*AuditOrchestrator, error) {
	return NewWithContext(context.Background(), app, input)
}

// NewWithContext is New with the context the PR-mode git commands run under.
func NewWithContext(ctx context.Context, app appx.App, input schemas.AuditInput) (*AuditOrchestrator, error) {
	repoPath := resolveRepoPath()

	o := &AuditOrchestrator{
		App:                 app,
		Input:               input,
		StartedAt:           nowMonotonic(),
		RepoPath:            repoPath,
		CheckpointDir:       filepath.Join(repoPath, ".sec-af"),
		IsPRMode:            input.IsPr,
		MaxCostUSD:          input.MaxCostUsd,
		MaxDurationSeconds:  input.MaxDurationSeconds,
		FindingsNotVerified: 0,
		ProveDropSummary:    NewDropSummary(),
		costBreakdown:       map[string]float64{},
	}
	for _, phase := range PhaseOrder {
		o.costBreakdown[phase] = 0.0
	}

	if o.IsPRMode && input.BaseCommitSha != nil && *input.BaseCommitSha != "" {
		head := "HEAD"
		if input.CommitSha != nil && *input.CommitSha != "" {
			head = *input.CommitSha
		}
		analysis := diffanalysis.AnalyzeDiff(ctx, o.RepoPath, *input.BaseCommitSha, head)
		o.DiffAnalysis = &analysis
	}

	cfg, err := config.AuditConfig{}.FromInput(input, o.RepoPath)
	if err != nil {
		return nil, err
	}
	o.Config = cfg
	o.BudgetConfig = cfg.Budget

	gate, err := gates.NewAIGate(app, nil)
	if err != nil {
		return nil, err
	}
	o.AIGate = gate

	return o, nil
}

// SetRepoPath performs the two assignments app.py makes right after
// construction:
//
//	orchestrator.repo_path = Path(repo_path)
//	orchestrator.checkpoint_dir = orchestrator.repo_path / ".sec-af"
//
// Python parity: app.py does NOT re-resolve the path here (it passes the
// already-absolute result of _resolve_repo) and does NOT recompute self.config,
// so AuditConfig.repo_path keeps the constructor's value. Both are reproduced —
// this setter touches exactly the two fields Python touches.
func (o *AuditOrchestrator) SetRepoPath(repoPath string) {
	o.RepoPath = repoPath
	o.CheckpointDir = filepath.Join(repoPath, ".sec-af")
}

// resolveRepoPath ports `Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve()`.
//
// Python parity: `Path.resolve()` makes the path absolute AND follows symlinks,
// with strict=False so a non-existent path still resolves. Go splits that in
// two: filepath.Abs handles the absolute part and always succeeds for a
// non-empty path; filepath.EvalSymlinks handles the link part but FAILS on a
// path that does not exist, in which case the absolute form is kept — the same
// answer Python gives for a path with no symlinked ancestors, which is every
// path in practice.
func resolveRepoPath() string {
	raw := os.Getenv("SEC_AF_REPO_PATH")
	if raw == "" {
		cwd, err := os.Getwd()
		if err != nil {
			// os.getcwd() raises in Python too; there is no path that is more
			// correct than the relative one.
			cwd = "."
		}
		raw = cwd
	}
	abs, err := filepath.Abs(raw)
	if err != nil {
		return raw
	}
	if resolved, err := filepath.EvalSymlinks(abs); err == nil {
		return resolved
	}
	return abs
}

// NewDropSummary builds the `{"demoted_total": 0, "by_reason": {}, "findings": []}`
// literal the orchestrator resets prove_drop_summary to.
func NewDropSummary() map[string]any {
	return map[string]any{
		"demoted_total": 0,
		"by_reason":     map[string]int{},
		"findings":      []map[string]any{},
	}
}

// AgentInvocations reports `self.agent_invocations` — the number of harness
// invocations made through the phase proxy.
func (o *AuditOrchestrator) AgentInvocations() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.agentInvocations
}

// SetAgentInvocations OVERWRITES the counter, which is what app.py:220 does
// (`orchestrator.agent_invocations = total_selected + len(...) + 3`) before
// calling _generate_output.
func (o *AuditOrchestrator) SetAgentInvocations(n int) {
	o.mu.Lock()
	o.agentInvocations = n
	o.mu.Unlock()
}

// BudgetExhausted reports `self.budget_exhausted`, which latches true the first
// time a budget check trips.
func (o *AuditOrchestrator) BudgetExhausted() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.budgetExhausted
}

// TotalCostUSD reports the accumulated harness cost (`self.total_cost_usd`).
func (o *AuditOrchestrator) TotalCostUSD() float64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.totalCostUSD
}

// CostBreakdown returns a COPY of the per-phase cost map
// (`self.cost_breakdown`), so a caller cannot corrupt the running totals.
func (o *AuditOrchestrator) CostBreakdown() map[string]float64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	out := make(map[string]float64, len(o.costBreakdown))
	for k, v := range o.costBreakdown {
		out[k] = v
	}
	return out
}

// depthProfile ports `_depth_profile()`:
//
//	try:    return DepthProfile(self.input.depth.lower())
//	except ValueError: return DepthProfile.STANDARD
func (o *AuditOrchestrator) depthProfile() config.DepthProfile {
	return config.NormalizeDepth(o.Input.Depth)
}
