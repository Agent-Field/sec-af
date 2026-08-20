package orch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/compliance"
	"github.com/Agent-Field/sec-af/go/internal/phases"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// construction
// ---------------------------------------------------------------------------

// TestNew_InitializesEveryField mirrors the assignments of Python's __init__.
func TestNew_InitializesEveryField(t *testing.T) {
	repo := t.TempDir()
	t.Setenv("SEC_AF_REPO_PATH", repo)

	input := schemas.NewAuditInput()
	input.RepoURL = "https://example.invalid/repo"
	cost := 12.5
	provers := 7
	duration := 900
	input.MaxCostUsd = &cost
	input.MaxProvers = &provers
	input.MaxDurationSeconds = &duration

	o, err := New(&appx.Fake{}, input)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	wantRepo := repo
	if resolved, err := filepath.EvalSymlinks(repo); err == nil {
		wantRepo = resolved
	}
	if o.RepoPath != wantRepo {
		t.Errorf("RepoPath = %q, want %q", o.RepoPath, wantRepo)
	}
	if want := filepath.Join(wantRepo, ".sec-af"); o.CheckpointDir != want {
		t.Errorf("CheckpointDir = %q, want %q", o.CheckpointDir, want)
	}
	if o.IsPRMode {
		t.Error("IsPRMode must default to false")
	}
	if o.DiffAnalysis != nil {
		t.Error("DiffAnalysis must stay nil outside PR mode")
	}
	if o.Config.RepoPath != wantRepo {
		t.Errorf("Config.RepoPath = %q, want %q", o.Config.RepoPath, wantRepo)
	}
	if o.MaxCostUSD == nil || *o.MaxCostUSD != cost {
		t.Errorf("MaxCostUSD = %v, want %v", o.MaxCostUSD, cost)
	}
	if o.MaxDurationSeconds == nil || *o.MaxDurationSeconds != duration {
		t.Errorf("MaxDurationSeconds = %v, want %v", o.MaxDurationSeconds, duration)
	}
	// budget_config comes from the config, and carries the three input caps.
	if o.BudgetConfig.MaxProvers == nil || *o.BudgetConfig.MaxProvers != provers {
		t.Errorf("BudgetConfig.MaxProvers = %v, want %v", o.BudgetConfig.MaxProvers, provers)
	}
	if o.BudgetConfig.MaxConcurrentHunters != 4 || o.BudgetConfig.MaxConcurrentProvers != 3 {
		t.Errorf("BudgetConfig concurrency = %d/%d, want 4/3",
			o.BudgetConfig.MaxConcurrentHunters, o.BudgetConfig.MaxConcurrentProvers)
	}
	// cost_breakdown starts as {phase: 0.0} for exactly the three phases.
	if got := o.CostBreakdown(); !reflect.DeepEqual(got, map[string]float64{"recon": 0, "hunt": 0, "prove": 0}) {
		t.Errorf("CostBreakdown = %v", got)
	}
	if o.AgentInvocations() != 0 || o.BudgetExhausted() || o.FindingsNotVerified != 0 {
		t.Error("counters must start at zero")
	}
	want := map[string]any{"demoted_total": 0, "by_reason": map[string]int{}, "findings": []map[string]any{}}
	if !reflect.DeepEqual(o.ProveDropSummary, want) {
		t.Errorf("ProveDropSummary = %#v, want %#v", o.ProveDropSummary, want)
	}
	if o.AIGate == nil {
		t.Error("AIGate must be constructed")
	}
}

// TestNew_RejectsInvalidDepth: AuditConfig.from_input uses the STRICT
// DepthProfile constructor, so an unrecognised depth is a ValueError — which
// app.py maps to HTTP 400.
func TestNew_RejectsInvalidDepth(t *testing.T) {
	input := schemas.NewAuditInput()
	input.RepoURL = "https://example.invalid/repo"
	input.Depth = "QUICK"
	if _, err := New(&appx.Fake{}, input); err == nil {
		t.Fatal("want an error for depth QUICK")
	}
}

// TestSetRepoPath performs app.py's two post-construction assignments.
func TestSetRepoPath(t *testing.T) {
	o, _ := newTestOrchestrator(t)
	before := o.Config.RepoPath
	o.SetRepoPath("/elsewhere/repo")
	if o.RepoPath != "/elsewhere/repo" {
		t.Errorf("RepoPath = %q", o.RepoPath)
	}
	if want := filepath.Join("/elsewhere/repo", ".sec-af"); o.CheckpointDir != want {
		t.Errorf("CheckpointDir = %q, want %q", o.CheckpointDir, want)
	}
	// Python parity: app.py does NOT recompute self.config, so AuditConfig
	// keeps the constructor's repo_path.
	if o.Config.RepoPath != before {
		t.Errorf("Config.RepoPath = %q, want it unchanged (%q)", o.Config.RepoPath, before)
	}
}

// TestNew_PRModeRunsDiffAnalysis: the branch fires only with is_pr AND a
// truthy base_commit_sha.
func TestNew_PRModeRunsDiffAnalysis(t *testing.T) {
	cases := []struct {
		name     string
		isPR     bool
		baseSHA  *string
		wantDiff bool
	}{
		{"not a PR", false, strPtr("abc"), false},
		{"PR without base", true, nil, false},
		{"PR with empty base", true, strPtr(""), false},
		{"PR with base", true, strPtr("abc"), true},
	}
	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SEC_AF_REPO_PATH", t.TempDir())
			input := schemas.NewAuditInput()
			input.RepoURL = "https://example.invalid/repo"
			input.IsPr = tc.isPR
			input.BaseCommitSha = tc.baseSHA

			o, err := New(&appx.Fake{}, input)
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if got := o.DiffAnalysis != nil; got != tc.wantDiff {
				t.Errorf("DiffAnalysis present = %v, want %v", got, tc.wantDiff)
			}
			if tc.wantDiff && o.DiffAnalysis.HeadSHA != "HEAD" {
				t.Errorf("HeadSHA = %q, want HEAD when commit_sha is absent", o.DiffAnalysis.HeadSHA)
			}
		})
	}
}

func strPtr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// budget
// ---------------------------------------------------------------------------

// TestBudget_CostChecks walks _check_cost_budget's two limits.
func TestBudget_CostChecks(t *testing.T) {
	t.Run("no cost budget never trips", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		o.registerCost(PhaseHunt, floatPtr(1000))
		if o.budgetOrTimeoutExhausted(PhaseHunt) {
			t.Error("a nil max_cost_usd must never exhaust")
		}
	})

	t.Run("total budget trips at >= and wins over the phase limit", func(t *testing.T) {
		// The three phase percentages sum to exactly 1.0 (0.10 + 0.45 + 0.45),
		// so spending under every phase share also keeps the total under the
		// cap — and reaching the cap necessarily saturates a phase too. The
		// TOTAL check runs first, so its message is the one Python raises.
		o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.MaxCostUsd = floatPtr(1.0) })
		o.registerCost(PhaseRecon, floatPtr(0.09)) // limit 0.10
		o.registerCost(PhaseHunt, floatPtr(0.44))  // limit 0.45
		o.registerCost(PhaseProve, floatPtr(0.44)) // limit 0.45
		if o.budgetOrTimeoutExhausted(PhaseHunt) {
			t.Error("0.97 total with every phase under its share must not exhaust")
		}

		o.registerCost(PhaseRecon, floatPtr(0.01))
		o.registerCost(PhaseHunt, floatPtr(0.01))
		o.registerCost(PhaseProve, floatPtr(0.01)) // total 1.0
		if !o.budgetOrTimeoutExhausted(PhaseHunt) {
			t.Error("exactly the cap must exhaust (the comparison is >=)")
		}
		if !o.BudgetExhausted() {
			t.Error("the flag must latch")
		}
		if err := o.checkCostBudget(PhaseHunt); !IsBudgetExhausted(err) || err.Error() != "Total budget exhausted" {
			t.Errorf("err = %v, want `Total budget exhausted`", err)
		}
	})

	t.Run("per-phase budget uses the configured percentages", func(t *testing.T) {
		o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.MaxCostUsd = floatPtr(10.0) })
		// recon_budget_pct = 0.10 -> a 1.0 allowance.
		o.registerCost(PhaseRecon, floatPtr(0.99))
		if o.budgetOrTimeoutExhausted(PhaseRecon) {
			t.Error("0.99 < 1.0 must not exhaust the recon phase")
		}
		o.registerCost(PhaseRecon, floatPtr(0.01))
		err := o.checkCostBudget(PhaseRecon)
		if !IsBudgetExhausted(err) || err.Error() != "recon budget exhausted" {
			t.Errorf("err = %v, want `recon budget exhausted`", err)
		}
		// The other phases are untouched.
		if o.budgetOrTimeoutExhausted(PhaseHunt) {
			t.Error("the hunt phase must still have budget")
		}
	})
}

// TestBudget_TimeCheck: strictly greater, and only when a duration cap is set.
func TestBudget_TimeCheck(t *testing.T) {
	base := time.Now()
	restore := nowMonotonic
	defer func() { nowMonotonic = restore }()

	o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) {
		limit := 10
		in.MaxDurationSeconds = &limit
	})
	o.StartedAt = base

	nowMonotonic = func() time.Time { return base.Add(10 * time.Second) }
	if err := o.checkTimeBudget(); err != nil {
		t.Errorf("exactly the limit must NOT trip (>, not >=): %v", err)
	}
	nowMonotonic = func() time.Time { return base.Add(10*time.Second + time.Millisecond) }
	err := o.checkTimeBudget()
	if !IsBudgetExhausted(err) || err.Error() != "Duration budget exhausted" {
		t.Errorf("err = %v, want `Duration budget exhausted`", err)
	}

	unbounded, _ := newTestOrchestrator(t)
	unbounded.StartedAt = base
	if err := unbounded.checkTimeBudget(); err != nil {
		t.Errorf("a nil max_duration_seconds must never trip: %v", err)
	}
}

// TestRegisterCost reproduces the None/negative guard and the double
// accumulation.
func TestRegisterCost(t *testing.T) {
	o, _ := newTestOrchestrator(t)
	o.registerCost(PhaseHunt, nil)
	o.registerCost(PhaseHunt, floatPtr(-1))
	if o.TotalCostUSD() != 0 {
		t.Errorf("total = %v, want 0 after a nil and a negative cost", o.TotalCostUSD())
	}
	o.registerCost(PhaseHunt, floatPtr(0)) // exactly zero IS registered
	o.registerCost(PhaseHunt, floatPtr(0.25))
	o.registerCost(PhaseProve, floatPtr(0.5))
	if got := o.TotalCostUSD(); got != 0.75 {
		t.Errorf("total = %v, want 0.75", got)
	}
	if got := o.CostBreakdown(); got["hunt"] != 0.25 || got["prove"] != 0.5 || got["recon"] != 0 {
		t.Errorf("breakdown = %v", got)
	}
}

// ---------------------------------------------------------------------------
// _PhaseHarnessProxy
// ---------------------------------------------------------------------------

// TestPhaseProxy_CountsAndCosts is the happy path of the Python class.
func TestPhaseProxy_CountsAndCosts(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.HarnessFn = func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{CostUSD: floatPtr(0.125)}, nil
	}

	proxy := o.PhaseProxy(PhaseHunt)
	for i := 0; i < 3; i++ {
		if _, err := proxy.Harness(context.Background(), "p", nil, nil, harness.Options{}); err != nil {
			t.Fatalf("Harness: %v", err)
		}
	}
	if o.AgentInvocations() != 3 {
		t.Errorf("AgentInvocations = %d, want 3", o.AgentInvocations())
	}
	if got := o.TotalCostUSD(); got != 0.375 {
		t.Errorf("total cost = %v, want 0.375", got)
	}
	if got := o.CostBreakdown()["hunt"]; got != 0.375 {
		t.Errorf("hunt bucket = %v, want 0.375", got)
	}
	if got := o.CostBreakdown()["recon"]; got != 0 {
		t.Errorf("recon bucket = %v, want 0", got)
	}
}

// TestPhaseProxy_BudgetExhaustion: the guard fires BEFORE the wrapped harness,
// so a spent phase makes no provider call at all.
func TestPhaseProxy_BudgetExhaustion(t *testing.T) {
	o, fake := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.MaxCostUsd = floatPtr(0.2) })
	fake.HarnessFn = func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{CostUSD: floatPtr(0.5)}, nil
	}

	proxy := o.PhaseProxy(PhaseProve)
	if _, err := proxy.Harness(context.Background(), "first", nil, nil, harness.Options{}); err != nil {
		t.Fatalf("the first call must succeed: %v", err)
	}
	_, err := proxy.Harness(context.Background(), "second", nil, nil, harness.Options{})
	if !IsBudgetExhausted(err) {
		t.Fatalf("err = %v, want a BudgetExhaustedError", err)
	}
	// Python raises f"{phase} budget exhausted" whichever check tripped.
	if err.Error() != "prove budget exhausted" {
		t.Errorf("message = %q, want `prove budget exhausted`", err.Error())
	}
	if len(fake.Harnesses) != 1 {
		t.Errorf("harness calls = %d, want 1 (the second is blocked before the provider)", len(fake.Harnesses))
	}
	if o.AgentInvocations() != 1 {
		t.Errorf("AgentInvocations = %d, want 1", o.AgentInvocations())
	}
	if !o.BudgetExhausted() {
		t.Error("the flag must latch")
	}
}

// TestPhaseProxy_TransportErrorSkipsAccounting matches Python, where the raised
// `await` never reaches the counter or the cost registration.
func TestPhaseProxy_TransportErrorSkipsAccounting(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.HarnessFn = func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return nil, errors.New("provider unreachable")
	}
	if _, err := o.PhaseProxy(PhaseRecon).Harness(context.Background(), "p", nil, nil, harness.Options{}); err == nil {
		t.Fatal("want the transport error")
	}
	if o.AgentInvocations() != 0 || o.TotalCostUSD() != 0 {
		t.Errorf("a failed harness must not be counted or costed (%d, %v)", o.AgentInvocations(), o.TotalCostUSD())
	}
}

// TestPhaseProxy_ExposesOnlyHarness pins the Python class's capability
// surface. `_PhaseHarnessProxy` (orchestrator.py:39) defines `harness` and
// nothing else — VERIFIED on the repo interpreter:
//
//	hasattr(proxy, "ai")   -> False
//	hasattr(proxy, "note") -> False
//	hasattr(proxy, "call") -> False
//
// The dedup pass reads exactly that (`hasattr(app, "ai")`, agents/dedup.py:150),
// so a proxy that satisfied appx.AIer would make the Go node issue AI duplicate
// checks Python never issues.
func TestPhaseProxy_ExposesOnlyHarness(t *testing.T) {
	o, _ := newTestOrchestrator(t)

	for _, phase := range []string{PhaseRecon, PhaseHunt, PhaseProve} {
		proxy := o.PhaseProxy(phase)
		if _, ok := proxy.(appx.AIer); ok {
			t.Errorf("%s proxy satisfies appx.AIer; Python's hasattr(proxy, \"ai\") is False", phase)
		}
		if _, ok := proxy.(appx.Noter); ok {
			t.Errorf("%s proxy satisfies appx.Noter; Python's hasattr(proxy, \"note\") is False", phase)
		}
		if _, ok := proxy.(appx.Caller); ok {
			t.Errorf("%s proxy satisfies appx.Caller; Python's hasattr(proxy, \"call\") is False", phase)
		}
	}
}

// TestProvePhaseProxy_AIRaisesPythonsAttributeError: run_prove's verdict
// sub-agent calls `await app.ai(...)` unguarded (agents/prove/verdict.py:99),
// which against `_PhaseHarnessProxy` raises
//
//	AttributeError: '_PhaseHarnessProxy' object has no attribute 'ai'
//
// The Go seam returns that error verbatim instead, and — like an attribute
// lookup that never happened — never reaches the wrapped app and never counts
// or costs anything.
func TestProvePhaseProxy_AIRaisesPythonsAttributeError(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"ok":true}`), nil })

	resp, err := o.ProvePhaseProxy().AI(context.Background(), "hello")
	if err == nil {
		t.Fatal("AI must fail: Python's proxy has no `ai` attribute")
	}
	if resp != nil {
		t.Errorf("resp = %v, want nil", resp)
	}
	const want = "'_PhaseHarnessProxy' object has no attribute 'ai'"
	if err.Error() != want {
		t.Errorf("message = %q, want %q", err.Error(), want)
	}
	var attrErr *AttributeError
	if !errors.As(err, &attrErr) {
		t.Errorf("err %T is not an *AttributeError", err)
	}
	if len(fake.AIs) != 0 {
		t.Errorf("the wrapped app was reached %d times, want 0", len(fake.AIs))
	}
	if o.AgentInvocations() != 0 || o.TotalCostUSD() != 0 {
		t.Error("a nonexistent attribute must not be counted or costed")
	}
}

// TestRunProve_DemotesEveryFindingBecauseTheProxyHasNoAI is the observable
// consequence, at the level `audit(resume_from_checkpoint=...)` reaches it.
//
// Python: `_run_prove` hands run_prove the proxy; run_verifier's tracer,
// sanitization and exploit stages succeed through `.harness`, then
// `run_verdict_agent` raises AttributeError, which `_verify`'s
// `except BaseException` (agents/prove/__init__.py:89) turns into
// `verifier_fallback(finding, str(exc), drop_reason="verifier_error")`. So
// EVERY finding comes back INCONCLUSIVE / STATIC_MATCH / score 0.0 with
// tags ["low_confidence"], whatever the harness said.
func TestRunProve_DemotesEveryFindingBecauseTheProxyHasNoAI(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.HarnessFn = appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
		switch {
		case strings.Contains(prompt, "You are DataFlowTracer"):
			return json.Marshal(map[string]any{
				"source": "req.query.id", "sink": "db.query", "steps": []string{"a.go:1"}, "sink_reached": true,
			})
		case strings.Contains(prompt, "You are SanitizationAnalyzer"):
			return json.Marshal(map[string]any{"found": false})
		case strings.Contains(prompt, "You are ExploitHypothesizer"):
			return json.Marshal(map[string]any{
				"hypothesis": "h", "payload": "p", "expected_outcome": "o",
			})
		}
		return nil, errors.New("unexpected harness prompt")
	})
	// A working `.ai()` on the WRAPPED app: the proxy must not reach it.
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.Marshal(map[string]any{
			"verdict": "confirmed", "evidence_level": 6, "rationale": "r", "confidence": "high",
		})
	})

	finding := schemas.RawFinding{
		ID: "f1", Fingerprint: "fp1", HunterStrategy: "injection",
		Title: "SQLi", Description: "d", FindingType: schemas.FindingTypeSast,
		CweID: "CWE-89", CweName: "SQL Injection",
		FilePath: "app.go", StartLine: 10, EndLine: 12, CodeSnippet: "q",
		EstimatedSeverity: schemas.SeverityHigh, Confidence: schemas.ConfidenceHigh,
	}
	hunt := schemas.NewHuntResult()
	hunt.Findings = []schemas.RawFinding{finding}

	verified, err := o.RunProve(context.Background(), schemas.NewReconResult(), hunt)
	if err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if len(verified) != 1 {
		t.Fatalf("verified = %d findings, want 1", len(verified))
	}
	got := verified[0]
	if got.Verdict != schemas.VerdictInconclusive {
		t.Errorf("verdict = %q, want %q", got.Verdict, schemas.VerdictInconclusive)
	}
	if got.EvidenceLevel != schemas.EvidenceLevelStaticMatch {
		t.Errorf("evidence_level = %v, want STATIC_MATCH", got.EvidenceLevel)
	}
	if got.DropReason == nil || *got.DropReason != "verifier_error" {
		t.Errorf("drop_reason = %v, want \"verifier_error\"", got.DropReason)
	}
	// Python's rationale is `f"Verification incomplete: {str(exc)}"`. Go's
	// aix.Structured prefixes every `.ai()` failure with
	// "aix.Structured[VerdictDecision]: " (a pre-existing, package-wide
	// wrapping unrelated to the proxy), so the CPython text is asserted as a
	// substring rather than the whole string.
	if !strings.HasPrefix(got.Rationale, "Verification incomplete: ") ||
		!strings.HasSuffix(got.Rationale, "'_PhaseHarnessProxy' object has no attribute 'ai'") {
		t.Errorf("rationale = %q, want `Verification incomplete: ...'_PhaseHarnessProxy' object has no attribute 'ai'`", got.Rationale)
	}
	if len(got.Tags) == 0 || got.Tags[0] != "low_confidence" {
		t.Errorf("tags = %v, want low_confidence first", got.Tags)
	}
	// _assess_reachability_parallel runs on self.app (not the proxy), so the
	// ONE recorded .ai() is the reachability gate — never the verdict agent.
	if len(fake.AIs) != 1 {
		t.Errorf("recorded .ai() calls = %d, want 1 (the reachability gate only)", len(fake.AIs))
	}
}

// TestPhaseProxy_ConcurrentAccountingIsRaceFree is the Go-only requirement:
// the phases fan out across goroutines that share one proxy.
func TestPhaseProxy_ConcurrentAccountingIsRaceFree(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.HarnessFn = func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{CostUSD: floatPtr(0.01)}, nil
	}
	proxy := o.PhaseProxy(PhaseHunt)

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = proxy.Harness(context.Background(), "p", nil, nil, harness.Options{})
		}()
	}
	wg.Wait()

	if o.AgentInvocations() != 50 {
		t.Errorf("AgentInvocations = %d, want 50", o.AgentInvocations())
	}
	if got := o.CostBreakdown()["hunt"]; got < 0.49 || got > 0.51 {
		t.Errorf("hunt bucket = %v, want ~0.5", got)
	}
}

// ---------------------------------------------------------------------------
// checkpoints
// ---------------------------------------------------------------------------

// TestCheckpoints_RoundTrip covers write -> read for both payload shapes plus
// the _try_load_cached_recon fallbacks.
func TestCheckpoints_RoundTrip(t *testing.T) {
	o, _ := newTestOrchestrator(t)

	if want := filepath.Join(o.CheckpointDir, "checkpoint-recon.json"); o.CheckpointPath("recon") != want {
		t.Errorf("CheckpointPath = %q, want %q", o.CheckpointPath("recon"), want)
	}

	recon := reconFixture(t, "full")
	if err := o.WriteCheckpoint(PhaseRecon, recon); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	back, err := ReadCheckpoint(o, PhaseRecon, phases.BindReconResult)
	if err != nil {
		t.Fatalf("ReadCheckpoint: %v", err)
	}
	if !reflect.DeepEqual(normalizeJSON(t, back), normalizeJSON(t, recon)) {
		t.Error("recon checkpoint did not round-trip")
	}

	verified := []schemas.VerifiedFinding{readJSON[schemas.VerifiedFinding](t, "verified_fixture.json")}
	if err := o.WriteCheckpoint(PhaseProve, verified); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
	list, err := ReadCheckpointList(o, PhaseProve, phases.BindVerifiedFinding)
	if err != nil {
		t.Fatalf("ReadCheckpointList: %v", err)
	}
	if !reflect.DeepEqual(normalizeJSON(t, list), normalizeJSON(t, verified)) {
		t.Error("prove checkpoint did not round-trip")
	}

	// The directory is created on demand.
	if _, err := os.Stat(o.CheckpointDir); err != nil {
		t.Errorf("checkpoint dir was not created: %v", err)
	}

	// _try_load_cached_recon: present -> value; absent/corrupt -> nil.
	if cached := o.TryLoadCachedRecon(); cached == nil {
		t.Error("TryLoadCachedRecon must find the checkpoint just written")
	}
	other, _ := newTestOrchestrator(t)
	if cached := other.TryLoadCachedRecon(); cached != nil {
		t.Error("TryLoadCachedRecon must return nil when the file is missing")
	}

	// `_read_checkpoint(phase, schema)` is `schema(**data)`: it VALIDATES.
	// A hand-edited checkpoint whose finding carries an out-of-vocabulary
	// severity is a pydantic ValidationError in Python, and _try_load_cached_recon's
	// blanket `except Exception` turns a failed validation into None.
	corrupt, _ := newTestOrchestrator(t)
	if err := os.MkdirAll(corrupt.CheckpointDir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := `{"phase":"prove","created_at":"2026-01-02T03:04:05+00:00","data":[{"title":"malformed"}]}`
	if err := os.WriteFile(corrupt.CheckpointPath(PhaseProve), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCheckpointList(corrupt, PhaseProve, phases.BindVerifiedFinding); err == nil {
		t.Error("a checkpoint row that is not a VerifiedFinding must fail, not bind to defaults")
	}
	reconBody := `{"phase":"recon","created_at":"2026-01-02T03:04:05+00:00","data":{"languages":["go"]}}`
	if err := os.WriteFile(corrupt.CheckpointPath(PhaseRecon), []byte(reconBody), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadCheckpoint(corrupt, PhaseRecon, phases.BindReconResult); err == nil {
		t.Error("a recon checkpoint missing its five required models must fail")
	}
	if cached := corrupt.TryLoadCachedRecon(); cached != nil {
		t.Error("_try_load_cached_recon swallows a failed validation and returns None")
	}
	if err := os.MkdirAll(other.CheckpointDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other.CheckpointPath(PhaseRecon), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if cached := other.TryLoadCachedRecon(); cached != nil {
		t.Error("TryLoadCachedRecon must return nil for a corrupt file")
	}
}

// ---------------------------------------------------------------------------
// _assess_reachability_parallel
// ---------------------------------------------------------------------------

// gateAI is an AIer that answers the reachability gate, records the prompts, and
// stalls so the semaphore bound is observable.
type gateAI struct {
	mu               sync.Mutex
	prompts          []string
	inflight, peak   int
	reachability     string
	fail             bool
	delay            time.Duration
	promptsToObserve *[]string
}

func (g *gateAI) AI(_ context.Context, prompt string, _ ...ai.Option) (*ai.Response, error) {
	g.mu.Lock()
	g.prompts = append(g.prompts, prompt)
	g.inflight++
	if g.inflight > g.peak {
		g.peak = g.inflight
	}
	g.mu.Unlock()
	if g.delay > 0 {
		time.Sleep(g.delay)
	}
	defer func() {
		g.mu.Lock()
		g.inflight--
		g.mu.Unlock()
	}()
	if g.fail {
		return nil, errors.New("gate down")
	}
	body := `{"reachability":"` + g.reachability + `","rationale":"r","confidence":"high"}`
	return &ai.Response{Choices: []ai.Choice{{Message: ai.Message{
		Role: "assistant", Content: []ai.ContentPart{{Type: "text", Text: body}},
	}}}}, nil
}

func (g *gateAI) peakConcurrency() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.peak
}

func makeVerified(t *testing.T, n int, tags ...string) []schemas.VerifiedFinding {
	t.Helper()
	base := readJSON[schemas.VerifiedFinding](t, "verified_fixture.json")
	out := make([]schemas.VerifiedFinding, 0, n)
	for i := 0; i < n; i++ {
		f := base
		f.ID = base.ID + "-" + string(rune('a'+i))
		// `[]string{}`, never nil: pydantic's `tags: list[str] = Field(
		// default_factory=list)` can never dump `null`, and a nil slice here
		// would marshal a checkpoint the Go node's own BindVerifiedFinding
		// rejects (as `VerifiedFinding(tags=None)` does in Python).
		f.Tags = append([]string{}, tags...)
		out = append(out, f)
	}
	return out
}

func TestAssessReachabilityParallel(t *testing.T) {
	t.Run("nothing to do when every finding is tagged", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		gate := &gateAI{reachability: "externally_reachable"}
		o.AIGate.App = gate
		verified := makeVerified(t, 3, "requires_auth")
		o.AssessReachabilityParallel(context.Background(), verified)
		if len(gate.prompts) != 0 {
			t.Errorf("gate called %d times, want 0", len(gate.prompts))
		}
		for _, f := range verified {
			if len(f.Tags) != 1 {
				t.Errorf("tags = %v, want the original single tag", f.Tags)
			}
		}
	})

	t.Run("the gate answer is appended verbatim", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		gate := &gateAI{reachability: "internal_only"}
		o.AIGate.App = gate
		verified := makeVerified(t, 2)
		o.AssessReachabilityParallel(context.Background(), verified)
		for _, f := range verified {
			if !reflect.DeepEqual(f.Tags, []string{"internal_only"}) {
				t.Errorf("tags = %v, want [internal_only]", f.Tags)
			}
		}
		if len(gate.prompts) != 2 {
			t.Fatalf("gate called %d times, want 2", len(gate.prompts))
		}
		if want := ReachabilitySummary(verified[0]); !strings.Contains(gate.prompts[0], "Finding: ") {
			t.Errorf("prompt %q does not embed the summary %q", gate.prompts[0], want)
		}
	})

	t.Run("gate failure falls back to requires_auth", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		// Retries would make the test slow; one attempt is enough to observe
		// the fallback, so drop the backoff to zero.
		o.AIGate.Config.MaxRetries = 1
		o.AIGate.App = &gateAI{fail: true}
		verified := makeVerified(t, 2)
		o.AssessReachabilityParallel(context.Background(), verified)
		for _, f := range verified {
			if !reflect.DeepEqual(f.Tags, []string{"requires_auth"}) {
				t.Errorf("tags = %v, want [requires_auth]", f.Tags)
			}
		}
	})

	t.Run("semaphore is min(5, n)", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		gate := &gateAI{reachability: "unreachable", delay: 25 * time.Millisecond}
		o.AIGate.App = gate
		o.AssessReachabilityParallel(context.Background(), makeVerified(t, 12))
		if got := gate.peakConcurrency(); got > 5 {
			t.Errorf("peak concurrency = %d, want <= 5", got)
		}
		if got := gate.peakConcurrency(); got != 5 {
			t.Errorf("peak concurrency = %d, want exactly 5", got)
		}
	})

	t.Run("fewer findings than the limit", func(t *testing.T) {
		o, _ := newTestOrchestrator(t)
		gate := &gateAI{reachability: "unreachable", delay: 20 * time.Millisecond}
		o.AIGate.App = gate
		o.AssessReachabilityParallel(context.Background(), makeVerified(t, 2))
		if got := gate.peakConcurrency(); got > 2 {
			t.Errorf("peak concurrency = %d, want <= 2", got)
		}
	})
}

// ---------------------------------------------------------------------------
// _track_drop / drop summary
// ---------------------------------------------------------------------------

func TestTrackDrop(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	o.TrackDrop(context.Background(), "First", nil, "verifier_error")
	o.TrackDrop(context.Background(), "Second", strPtr("unverified"), "verdict_unverified")
	o.TrackDrop(context.Background(), "Third", strPtr(""), "verifier_error")

	summary := dropSummaryMap(t, o)
	if got := summary["demoted_total"]; got != 3 {
		t.Errorf("demoted_total = %v, want 3", got)
	}
	want := map[string]int{"verifier_error": 2, "verdict_unverified": 1}
	if got := summary["by_reason"]; !reflect.DeepEqual(got, want) {
		t.Errorf("by_reason = %v, want %v", got, want)
	}
	entries := summary["findings"].([]map[string]any)
	if len(entries) != 3 {
		t.Fatalf("findings = %d, want 3", len(entries))
	}
	if entries[0]["original_verdict"] != nil {
		t.Errorf("entries[0].original_verdict = %v, want null", entries[0]["original_verdict"])
	}
	if entries[1]["original_verdict"] != "unverified" {
		t.Errorf("entries[1].original_verdict = %v", entries[1]["original_verdict"])
	}

	wantNotes := []string{
		"Demoted finding 'First' (verdict=unknown): verifier_error",
		"Demoted finding 'Second' (verdict=unverified): verdict_unverified",
		// PYTHON TRUTHINESS: an EMPTY verdict also prints "unknown".
		"Demoted finding 'Third' (verdict=unknown): verifier_error",
	}
	if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
		t.Errorf("notes\n got: %q\nwant: %q", fake.NoteMessages(), wantNotes)
	}
	// The orchestrator's tags differ from phases' ["prove","drop","demotion"].
	for _, note := range fake.Notes {
		if !reflect.DeepEqual(note.Tags, []string{"audit", "prove", "drop"}) {
			t.Errorf("tags = %v, want [audit prove drop]", note.Tags)
		}
	}
}

// TestRebuildDropSummary is the sweep both run() and _run_prove() perform.
func TestRebuildDropSummary(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	verified := makeVerified(t, 3)
	verified[0].DropReason = strPtr("verifier_error")
	verified[1].DropReason = strPtr("") // falsy -> skipped
	verified[2].DropReason = nil

	o.rebuildDropSummary(context.Background(), verified)

	if got := dropSummaryMap(t, o)["demoted_total"]; got != 1 {
		t.Errorf("demoted_total = %v, want 1 (an empty drop_reason is falsy)", got)
	}
	if len(fake.Notes) != 1 {
		t.Errorf("notes = %d, want 1", len(fake.Notes))
	}
}

// ---------------------------------------------------------------------------
// _run_dast_verification
// ---------------------------------------------------------------------------

// TestRunDASTVerification_IsUnreachableInProduction pins the two independent
// reasons DAST never runs, and the behavior of the loop when it is forced.
func TestRunDASTVerification_IsUnreachableInProduction(t *testing.T) {
	if enableDast {
		t.Fatal("enableDast must be false: AuditInput has no `enable_dast` field, so getattr(...) is always False")
	}

	t.Run("no confirmed findings", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		verified := makeVerified(t, 2)
		for i := range verified {
			verified[i].Verdict = schemas.VerdictInconclusive
		}
		o.RunDASTVerification(context.Background(), verified)
		wantNotes := []string{"No confirmed findings available for DAST step"}
		if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
			t.Errorf("notes = %q, want %q", fake.NoteMessages(), wantNotes)
		}
	})

	t.Run("the production seam always raises the arity TypeError", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		verified := makeVerified(t, 2) // the fixture verdict is "confirmed"
		o.RunDASTVerification(context.Background(), verified)
		for i, f := range verified {
			if !contains(f.Tags, "dast_error") {
				t.Errorf("verified[%d].tags = %v, want dast_error", i, f.Tags)
			}
		}
		if len(fake.Notes) != 2 {
			t.Fatalf("notes = %d, want one per confirmed finding", len(fake.Notes))
		}
		for _, note := range fake.Notes {
			if !strings.HasPrefix(note.Message, "DAST verifier failed for '") {
				t.Errorf("note = %q", note.Message)
			}
			if !strings.Contains(note.Message, "missing 2 required positional arguments") {
				t.Errorf("note %q must carry the arity TypeError", note.Message)
			}
			if !reflect.DeepEqual(note.Tags, []string{"audit", "prove", "dast", "error"}) {
				t.Errorf("tags = %v", note.Tags)
			}
		}
	})

	t.Run("the ported loop body, with the seam substituted", func(t *testing.T) {
		restore := dastVerify
		dastVerify = func(context.Context, appx.Harnesser, string, schemas.VerifiedFinding) (dastOutcome, error) {
			return dastOutcome{
				ExploitAttempted: true,
				ExploitSucceeded: false,
				Evidence:         "no reflection observed",
				Confidence:       "medium",
				ResponseAnalysis: "the payload was rejected",
			}, nil
		}
		defer func() { dastVerify = restore }()

		o, _ := newTestOrchestrator(t)
		verified := makeVerified(t, 1)
		proof := schemas.Proof{}
		verified[0].Proof = &proof
		verified[0].Rationale = "base rationale"

		o.RunDASTVerification(context.Background(), verified)

		if want := []string{"dast_attempted", "dast_not_confirmed"}; !reflect.DeepEqual(verified[0].Tags, want) {
			t.Errorf("tags = %v, want %v", verified[0].Tags, want)
		}
		if want := "base rationale\nDAST: the payload was rejected"; verified[0].Rationale != want {
			t.Errorf("rationale = %q, want %q", verified[0].Rationale, want)
		}
		if verified[0].Proof.PocExecutionOutput == nil {
			t.Fatal("poc_execution_output must be filled in")
		}
		// json.dumps({...}, indent=2) over a dict literal: INSERTION order.
		want := "{\n  \"exploit_attempted\": true,\n  \"exploit_succeeded\": false,\n" +
			"  \"evidence\": \"no reflection observed\",\n  \"confidence\": \"medium\"\n}"
		if got := *verified[0].Proof.PocExecutionOutput; got != want {
			t.Errorf("poc_execution_output\n got: %q\nwant: %q", got, want)
		}
	})
}

// ---------------------------------------------------------------------------
// run_from_checkpoint
// ---------------------------------------------------------------------------

// TestRunFromCheckpoint_UnknownPhase pins the ValueError text app.py turns into
// HTTP 400 — including that the message carries the ORIGINAL spelling.
func TestRunFromCheckpoint_UnknownPhase(t *testing.T) {
	o, _ := newTestOrchestrator(t)
	for _, phase := range []string{"bogus", "Recon!", "", "hunt2"} {
		_, err := o.RunFromCheckpoint(context.Background(), phase)
		if err == nil {
			t.Fatalf("phase %q: want an error", phase)
		}
		var target *UnknownCheckpointPhaseError
		if !errors.As(err, &target) {
			t.Fatalf("phase %q: err = %v, want UnknownCheckpointPhaseError", phase, err)
		}
		if want := "Unknown checkpoint phase: " + phase; err.Error() != want {
			t.Errorf("message = %q, want %q", err.Error(), want)
		}
	}
}

// TestRunFromCheckpoint_ProveBranch re-runs nothing: it reads all three
// checkpoints and goes straight to GenerateOutput.
func TestRunFromCheckpoint_ProveBranch(t *testing.T) {
	compliance.ClearAICache()
	o, fake := newTestOrchestrator(t)
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[],"confidence":"low"}`), nil
	})

	recon := reconFixture(t, "minimal")
	hunt := schemas.NewHuntResult()
	hunt.TotalRaw = 4
	hunt.StrategiesRun = []string{"injection", "auth"}
	verified := makeVerified(t, 2)

	for _, w := range []struct {
		phase   string
		payload any
	}{{PhaseRecon, recon}, {PhaseHunt, hunt}, {PhaseProve, verified}} {
		if err := o.WriteCheckpoint(w.phase, w.payload); err != nil {
			t.Fatalf("WriteCheckpoint(%s): %v", w.phase, err)
		}
	}

	for _, spelling := range []string{"prove", "  PROVE ", "Prove"} {
		result, err := o.RunFromCheckpoint(context.Background(), spelling)
		if err != nil {
			t.Fatalf("RunFromCheckpoint(%q): %v", spelling, err)
		}
		if result.TotalRawFindings != 4 {
			t.Errorf("total_raw_findings = %d, want 4", result.TotalRawFindings)
		}
		if !reflect.DeepEqual(result.StrategiesUsed, []string{"injection", "auth"}) {
			t.Errorf("strategies_used = %v", result.StrategiesUsed)
		}
		if len(result.Findings) != 2 {
			t.Errorf("findings = %d, want 2", len(result.Findings))
		}
	}
}

// TestRunFromCheckpoint_MissingCheckpoint surfaces the file error rather than
// silently producing an empty report.
func TestRunFromCheckpoint_MissingCheckpoint(t *testing.T) {
	o, _ := newTestOrchestrator(t)
	if _, err := o.RunFromCheckpoint(context.Background(), "prove"); err == nil {
		t.Fatal("want an error when checkpoint-recon.json is missing")
	}
}

// dropSummaryMap reads ProveDropSummary as the dict the orchestrator path
// always installs. The field is typed `any` so the app.py path can thread a
// non-dict `.call` value through untouched (see orch.go); every orchestrator
// caller still puts a real dict there.
func dropSummaryMap(t *testing.T, o *AuditOrchestrator) map[string]any {
	t.Helper()
	summary, ok := o.ProveDropSummary.(map[string]any)
	if !ok {
		t.Fatalf("ProveDropSummary = %#v, want a map[string]any", o.ProveDropSummary)
	}
	return summary
}

// TestGuardedCountersAreSafeToReadWhileAPhaseIsRunning states the lock contract
// as behaviour rather than as a comment.
//
// Validation contract:
//
//   - a caller may read agent_invocations / budget_exhausted / total_cost_usd /
//     cost_breakdown AT ANY TIME, including while phase goroutines sharing one
//     proxy are still incrementing them;
//   - the values are the Python ones once the phases have joined.
//
// Python needs no lock (asyncio is single-threaded) and so has no equivalent
// test; this is the obligation the Go fan-out creates. Under -race it fails if
// any of the four accessors, or the writers behind registerInvocation /
// markBudgetExhausted, touches the state unguarded — which is exactly what the
// bare `o.AgentInvocations` and `o.BudgetExhausted` field reads inside
// GenerateOutput used to do.
func TestGuardedCountersAreSafeToReadWhileAPhaseIsRunning(t *testing.T) {
	o, fake := newTestOrchestrator(t)
	fake.HarnessFn = func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return &harness.Result{CostUSD: floatPtr(0.01)}, nil
	}
	proxy := o.PhaseProxy(PhaseHunt)

	const writers, perWriter = 4, 25
	stop := make(chan struct{})

	var reader sync.WaitGroup
	reader.Add(1)
	go func() {
		defer reader.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// The four reads GenerateOutput performs.
			_ = o.AgentInvocations()
			_ = o.BudgetExhausted()
			_ = o.TotalCostUSD()
			_ = o.CostBreakdown()
		}
	}()

	var phases sync.WaitGroup
	phases.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer phases.Done()
			for j := 0; j < perWriter; j++ {
				if _, err := proxy.Harness(context.Background(), "p", nil, nil, harness.Options{}); err != nil {
					t.Error(err)
					return
				}
			}
			o.markBudgetExhausted()
		}()
	}
	phases.Wait()
	close(stop)
	reader.Wait()

	if got := o.AgentInvocations(); got != writers*perWriter {
		t.Errorf("AgentInvocations = %d, want %d", got, writers*perWriter)
	}
	if !o.BudgetExhausted() {
		t.Error("BudgetExhausted = false, want true")
	}
}
