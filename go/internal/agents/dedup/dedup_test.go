package dedup

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// ---------------------------------------------------------------------------
// test doubles
// ---------------------------------------------------------------------------

// harnessOnly exposes ONLY the Harness seam of the wrapped Fake.
//
// It is the Go equivalent of tests/test_dedup.py's `_HarnessApp`, which defines
// `async def harness(...)` and nothing else: dedup._deduplicate_with_ai probes
// `hasattr(app, "ai")` and skips the whole semantic pass when it is absent.
// *appx.Fake implements appx.AIer, so handing it over directly would take the
// OTHER branch — this wrapper is what makes the Python test's shape reachable.
type harnessOnly struct{ f *appx.Fake }

func (h harnessOnly) Harness(ctx context.Context, prompt string, schema map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
	return h.f.Harness(ctx, prompt, schema, dest, opts)
}

// chainFake returns a Fake whose harness answers every call with resp, plus the
// harness-only wrapper around it.
func chainFake(t *testing.T, resp schemas.ChainCorrelationResult) (*appx.Fake, harnessOnly) {
	t.Helper()
	raw, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("marshal ChainCorrelationResult: %v", err)
	}
	f := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return raw, nil
	})}
	return f, harnessOnly{f}
}

// finding ports tests/test_dedup.py::_finding.
func finding(id, cweID, cweName string, severity schemas.Severity) schemas.RawFinding {
	f := schemas.NewRawFinding()
	f.ID = id
	f.HunterStrategy = "injection"
	f.Title = "Finding " + id
	f.Description = "Description for " + id
	f.FindingType = schemas.FindingTypeSast
	f.CweID = cweID
	f.CweName = cweName
	f.FilePath = "src/" + strings.ToLower(id) + ".py"
	f.StartLine = 10
	f.EndLine = 10
	f.CodeSnippet = "dangerous_call(user_input)"
	f.EstimatedSeverity = severity
	f.Confidence = schemas.ConfidenceHigh
	f.RelatedFiles = []string{}
	f.Fingerprint = "fp-" + id
	return f
}

func emptyChains() schemas.ChainCorrelationResult { return schemas.NewChainCorrelationResult() }

// ---------------------------------------------------------------------------
// ports of tests/test_dedup.py
// ---------------------------------------------------------------------------

// Ports test_dedup_prompt_includes_seed_chain_candidates.
func TestDedup_PromptIncludesSeedChainCandidates(t *testing.T) {
	findings := []schemas.RawFinding{
		finding("F1", "CWE-918", "Server-Side Request Forgery (SSRF)", schemas.SeverityHigh),
		finding("F3", "CWE-798", "Use of Hard-coded Credentials", schemas.SeverityHigh),
	}
	fake, app := chainFake(t, emptyChains())

	if _, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, "."); err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}

	if len(fake.Harnesses) != 1 {
		t.Fatalf("want exactly 1 harness call, got %d", len(fake.Harnesses))
	}
	prompt := fake.Harnesses[0].Prompt
	for _, want := range []string{
		"Seed chain candidates (validate and expand these):",
		"Potential chain: Server-Side Request Forgery (SSRF) -> Use of Hard-coded Credentials (findings F1, F3)",
		"Look for additional multi-step attack chains beyond these seeds.",
	} {
		if !strings.Contains(prompt, want) {
			t.Errorf("prompt missing %q\n--- prompt ---\n%s", want, prompt)
		}
	}
}

// Ports test_seed_chains_are_used_when_ai_returns_no_chains.
func TestDedup_SeedChainsUsedWhenAIReturnsNoChains(t *testing.T) {
	findings := []schemas.RawFinding{
		finding("F1", "CWE-89", "SQL Injection", schemas.SeverityCritical),
		finding("F2", "CWE-200", "Exposure of Sensitive Information", schemas.SeverityHigh),
	}
	_, app := chainFake(t, emptyChains())

	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(result.Chains))
	}
	if got := result.Chains[0].FindingIDs; len(got) != 2 || got[0] != "F1" || got[1] != "F2" {
		t.Errorf("finding_ids = %v, want [F1 F2]", got)
	}
	if got, want := result.Chains[0].Title, "Potential attack chain: CWE-89 -> CWE-200"; got != want {
		t.Errorf("title = %q, want %q", got, want)
	}
	if got, want := result.ChainCount, 1; got != want {
		t.Errorf("chain_count = %d, want %d", got, want)
	}
}

// Ports test_ai_discovered_chains_take_priority_over_seed_chains.
func TestDedup_AIDiscoveredChainsTakePriorityOverSeedChains(t *testing.T) {
	findings := []schemas.RawFinding{
		finding("F1", "CWE-918", "Server-Side Request Forgery (SSRF)", schemas.SeverityHigh),
		finding("F2", "CWE-200", "Exposure of Sensitive Information", schemas.SeverityMedium),
		finding("F3", "CWE-798", "Use of Hard-coded Credentials", schemas.SeverityHigh),
	}
	resp := schemas.NewChainCorrelationResult()
	resp.Chains = []string{
		"AI-discovered chain: SSRF to data exfiltration|F1,F2,F3|SSRF reaches metadata; stolen secret enables privileged API access and data exfiltration.|critical",
	}
	_, app := chainFake(t, resp)

	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(result.Chains))
	}
	if got, want := result.Chains[0].Title, "AI-discovered chain: SSRF to data exfiltration"; got != want {
		t.Errorf("title = %q, want %q", got, want)
	}
	if got := result.Chains[0].FindingIDs; len(got) != 3 || got[0] != "F1" || got[1] != "F2" || got[2] != "F3" {
		t.Errorf("finding_ids = %v, want [F1 F2 F3]", got)
	}
	if got, want := result.Chains[0].EstimatedSeverity, schemas.SeverityCritical; got != want {
		t.Errorf("severity = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// compute_fingerprint
// ---------------------------------------------------------------------------

func TestComputeFingerprint(t *testing.T) {
	f := schemas.RawFinding{FilePath: "src/f1.py", StartLine: 10, CweID: "CWE-89"}
	// Ground truth from the venv interpreter:
	//   hashlib.sha256(b"src/f1.py:10:CWE-89").hexdigest()[:16]
	if got, want := ComputeFingerprint(f), "afd9dad9b5320992"; got != want {
		t.Errorf("ComputeFingerprint = %q, want %q", got, want)
	}
	if got := len(ComputeFingerprint(f)); got != 16 {
		t.Errorf("fingerprint length = %d, want 16", got)
	}
}

// A finding that arrives with an empty fingerprint gets one computed, and the
// CALLER's slice sees it (Python mutates the pydantic models in place).
func TestDedup_SeedsFingerprintsInPlace(t *testing.T) {
	findings := []schemas.RawFinding{finding("F1", "CWE-89", "SQL Injection", schemas.SeverityHigh)}
	findings[0].Fingerprint = ""
	_, app := chainFake(t, emptyChains())

	if _, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, "."); err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	want := ComputeFingerprint(findings[0])
	if findings[0].Fingerprint != want {
		t.Errorf("caller's finding fingerprint = %q, want %q", findings[0].Fingerprint, want)
	}
}

// ---------------------------------------------------------------------------
// fingerprint collapse + _merge_duplicate
// ---------------------------------------------------------------------------

func TestDedup_CollapsesSharedFingerprintAndMerges(t *testing.T) {
	a := finding("A", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	a.Fingerprint = "same"
	a.Description = "short"
	a.RelatedFiles = []string{"z.py", "b.py"}
	a.Confidence = schemas.ConfidenceMedium

	b := finding("B", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	b.Fingerprint = "same"
	b.Description = "a much much longer description"
	b.RelatedFiles = []string{"a.py", "b.py"}
	b.Confidence = schemas.ConfidenceLow // lower, so A stays the winner
	b.DataFlow = []schemas.ReconDataFlowStep{{FilePath: "src/x.py", Line: 3, Component: "c", Operation: "op"}}

	findings := []schemas.RawFinding{a, b}
	_, app := chainFake(t, emptyChains())

	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("want 1 finding after fingerprint collapse, got %d", len(result.Findings))
	}
	got := result.Findings[0]
	if got.ID != "A" {
		t.Errorf("winner id = %q, want A (existing wins unless incoming has HIGHER confidence)", got.ID)
	}
	if got.Description != "a much much longer description" {
		t.Errorf("description = %q, want the loser's longer text", got.Description)
	}
	if want := []string{"a.py", "b.py", "z.py"}; !equalStrings(got.RelatedFiles, want) {
		t.Errorf("related_files = %v, want %v (sorted set union)", got.RelatedFiles, want)
	}
	if len(got.DataFlow) != 1 || got.DataFlow[0].FilePath != "src/x.py" {
		t.Errorf("data_flow = %v, want the loser's flow adopted when the winner had none", got.DataFlow)
	}
	if result.TotalRaw != 2 {
		t.Errorf("total_raw = %d, want 2 (pre-dedup count)", result.TotalRaw)
	}
	if result.DeduplicatedCount != 1 {
		t.Errorf("deduplicated_count = %d, want 1", result.DeduplicatedCount)
	}
}

func TestDedup_HigherConfidenceIncomingWins(t *testing.T) {
	a := finding("A", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	a.Fingerprint = "same"
	a.Confidence = schemas.ConfidenceLow
	b := finding("B", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	b.Fingerprint = "same"
	b.Confidence = schemas.ConfidenceHigh

	_, app := chainFake(t, emptyChains())
	result, err := DeduplicateAndCorrelate(context.Background(), []schemas.RawFinding{a, b}, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "B" {
		t.Fatalf("want the higher-confidence incoming finding to win, got %+v", result.Findings)
	}
}

// A winner whose data_flow is an EMPTY (non-nil) list is not None in Python, so
// the loser's flow must NOT overwrite it.
func TestDedup_EmptyDataFlowIsNotNone(t *testing.T) {
	winner := schemas.NewRawFinding()
	winner.DataFlow = []schemas.ReconDataFlowStep{}
	winner.Confidence = schemas.ConfidenceHigh
	loser := schemas.NewRawFinding()
	loser.DataFlow = []schemas.ReconDataFlowStep{{FilePath: "a", Line: 1}}
	loser.Confidence = schemas.ConfidenceLow

	got := mergeDuplicate(&winner, &loser)
	if len(got.DataFlow) != 0 {
		t.Errorf("data_flow = %v, want the winner's empty list preserved", got.DataFlow)
	}
}

// ---------------------------------------------------------------------------
// the .ai(DuplicateCheck) semantic pass
// ---------------------------------------------------------------------------

func dupCheckFake(isDuplicate bool, hook func()) *appx.Fake {
	return &appx.Fake{AIFn: func(_ context.Context, _ string, _ ...ai.Option) (*ai.Response, error) {
		if hook != nil {
			hook()
		}
		body := `{"is_duplicate":false,"duplicate_of":null,"reason":"different"}`
		if isDuplicate {
			body = `{"is_duplicate":true,"duplicate_of":"x","reason":"same root cause"}`
		}
		return &ai.Response{Choices: []ai.Choice{{Message: ai.Message{
			Role:    "assistant",
			Content: []ai.ContentPart{{Type: "text", Text: body}},
		}}}}, nil
	}}
}

// sameFile builds n findings in one file with one CWE and distinct fingerprints,
// so every pair is an AI-check candidate.
func sameFile(n int) []schemas.RawFinding {
	out := make([]schemas.RawFinding, 0, n)
	for i := 0; i < n; i++ {
		f := finding(string(rune('A'+i)), "CWE-89", "SQL Injection", schemas.SeverityHigh)
		f.FilePath = "src/shared.py"
		f.StartLine = 10 + i
		f.Fingerprint = "fp-" + string(rune('A'+i))
		out = append(out, f)
	}
	return out
}

func TestDedup_AIPassRemovesSemanticDuplicates(t *testing.T) {
	fake := dupCheckFake(true, nil)
	fake.HarnessFn = appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(`{"chains":[],"duplicate_ids":[]}`), nil
	})

	result, err := DeduplicateAndCorrelate(context.Background(), sameFile(3), schemas.ReconResult{}, fake, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(fake.AIs) != 3 {
		t.Errorf("want 3 pair checks (C(3,2)), got %d", len(fake.AIs))
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "A" {
		t.Fatalf("want only the first finding to survive, got %+v", result.Findings)
	}
}

// Python fans every pair out with asyncio.gather and NO semaphore. The barrier
// below deadlocks (and the test fails on the timeout) if the Go port checks the
// pairs one at a time.
func TestDedup_AIPairChecksRunConcurrently(t *testing.T) {
	const pairs = 3
	var mu sync.Mutex
	arrived := 0
	release := make(chan struct{})
	timedOut := make(chan struct{})

	fake := dupCheckFake(false, func() {
		mu.Lock()
		arrived++
		full := arrived == pairs
		mu.Unlock()
		if full {
			close(release)
		}
		select {
		case <-release:
		case <-timedOut:
		}
	})
	fake.HarnessFn = appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return json.RawMessage(`{"chains":[],"duplicate_ids":[]}`), nil
	})

	done := make(chan struct{})
	go func() {
		defer close(done)
		if _, err := DeduplicateAndCorrelate(context.Background(), sameFile(3), schemas.ReconResult{}, fake, "."); err != nil {
			t.Errorf("DeduplicateAndCorrelate: %v", err)
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		close(timedOut)
		<-done
		t.Fatal("pair checks did not run concurrently: only " + itoa(arrived) + " of 3 were in flight at once")
	}
}

// The `except Exception: return False` in _ai_check_duplicate means a failing
// gate keeps BOTH findings.
func TestDedup_AIErrorMeansNotDuplicate(t *testing.T) {
	fake := &appx.Fake{
		AIFn: func(context.Context, string, ...ai.Option) (*ai.Response, error) {
			return nil, context.DeadlineExceeded
		},
		HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
			return json.RawMessage(`{"chains":[],"duplicate_ids":[]}`), nil
		}),
	}
	result, err := DeduplicateAndCorrelate(context.Background(), sameFile(2), schemas.ReconResult{}, fake, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Findings) != 2 {
		t.Errorf("want both findings kept when the gate fails, got %d", len(result.Findings))
	}
}

// The hasattr(app, "ai") probe: a harness-only app skips the semantic pass.
func TestDedup_HarnessOnlyAppSkipsAIPass(t *testing.T) {
	fake, app := chainFake(t, emptyChains())
	result, err := DeduplicateAndCorrelate(context.Background(), sameFile(3), schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(fake.AIs) != 0 {
		t.Errorf("want no .ai calls for a harness-only app, got %d", len(fake.AIs))
	}
	if len(result.Findings) != 3 {
		t.Errorf("want all 3 findings kept, got %d", len(result.Findings))
	}
}

func TestDedup_DuplicateCheckPromptShape(t *testing.T) {
	a := finding("A", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	b := finding("B", "CWE-79", "XSS", schemas.SeverityLow)
	a.Description = strings.Repeat("x", 250)

	prompt := buildDuplicateCheckPrompt(&a, &b)
	if !strings.HasPrefix(prompt, "Determine if these two security findings are duplicates (same root cause).\n\nFinding A:\n") {
		t.Errorf("unexpected prompt head:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- CWE: CWE-89 (SQL Injection)\n") {
		t.Errorf("missing candidate CWE line:\n%s", prompt)
	}
	if !strings.Contains(prompt, "- File: src/a.py:10\n") {
		t.Errorf("missing candidate file line:\n%s", prompt)
	}
	if strings.Contains(prompt, strings.Repeat("x", 201)) {
		t.Error("description was not truncated to 200 characters")
	}
	if !strings.Contains(prompt, strings.Repeat("x", 200)) {
		t.Error("description was truncated to fewer than 200 characters")
	}
	if strings.HasSuffix(prompt, "\n") {
		t.Error("prompt must not end with a newline (Python's f-string does not)")
	}
}

// ---------------------------------------------------------------------------
// ordering
// ---------------------------------------------------------------------------

func TestDedup_SortsBySeverityThenConfidenceDescendingStable(t *testing.T) {
	mk := func(id string, sev schemas.Severity, conf schemas.Confidence) schemas.RawFinding {
		f := finding(id, "CWE-1", "one", sev)
		f.Confidence = conf
		return f
	}
	findings := []schemas.RawFinding{
		mk("L", schemas.SeverityLow, schemas.ConfidenceHigh),
		mk("C1", schemas.SeverityCritical, schemas.ConfidenceLow),
		mk("H", schemas.SeverityHigh, schemas.ConfidenceHigh),
		mk("C2", schemas.SeverityCritical, schemas.ConfidenceLow), // ties C1 -> stable
		mk("CH", schemas.SeverityCritical, schemas.ConfidenceHigh),
	}
	_, app := chainFake(t, emptyChains())
	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	got := make([]string, 0, len(result.Findings))
	for _, f := range result.Findings {
		got = append(got, f.ID)
	}
	want := []string{"CH", "C1", "C2", "H", "L"}
	if !equalStrings(got, want) {
		t.Errorf("order = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// harness interaction
// ---------------------------------------------------------------------------

func TestDedup_HarnessOptionsAndTempDirLifecycle(t *testing.T) {
	var seenCwd string
	var existedDuringCall bool
	fake := &appx.Fake{HarnessFn: func(_ context.Context, _ string, _ map[string]any, dest any, opts harness.Options) (*harness.Result, error) {
		seenCwd = opts.Cwd
		if st, err := os.Stat(opts.Cwd); err == nil && st.IsDir() {
			existedDuringCall = true
		}
		if err := json.Unmarshal([]byte(`{"chains":[],"duplicate_ids":[]}`), dest); err != nil {
			return nil, err
		}
		return &harness.Result{Parsed: dest}, nil
	}}

	findings := []schemas.RawFinding{finding("F1", "CWE-89", "SQL Injection", schemas.SeverityHigh)}
	if _, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, harnessOnly{fake}, "/repo/root"); err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if !existedDuringCall {
		t.Error("harness cwd did not exist during the call")
	}
	if base := lastPathSegment(seenCwd); !strings.HasPrefix(base, "secaf-dedup-") {
		t.Errorf("harness cwd %q does not use the secaf-dedup- prefix", seenCwd)
	}
	if _, err := os.Stat(seenCwd); !os.IsNotExist(err) {
		t.Errorf("harness cwd %q was not removed after the call (err=%v)", seenCwd, err)
	}
	if got, want := fake.Harnesses[0].Opts.ProjectDir, "/repo/root"; got != want {
		t.Errorf("project_dir = %q, want %q", got, want)
	}
}

// A harness that fails (is_error) leaves chains empty, so the seed chains win —
// Python's bare `except Exception: chains = []` plus `if not chains:`.
func TestDedup_HarnessFailureFallsBackToSeedChains(t *testing.T) {
	fake := &appx.Fake{HarnessFn: appx.HarnessJSON(func(string, harness.Options) (json.RawMessage, error) {
		return nil, errString("provider exploded")
	})}
	findings := []schemas.RawFinding{
		finding("F1", "CWE-89", "SQL Injection", schemas.SeverityCritical),
		finding("F2", "CWE-200", "Exposure of Sensitive Information", schemas.SeverityHigh),
	}
	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, harnessOnly{fake}, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate must swallow harness failures, got %v", err)
	}
	if len(result.Chains) != 1 || result.Chains[0].Title != "Potential attack chain: CWE-89 -> CWE-200" {
		t.Errorf("want the seed chain, got %+v", result.Chains)
	}
}

// A transport error out of app.Harness is the `await` raising in Python.
func TestDedup_HarnessTransportErrorFallsBackToSeedChains(t *testing.T) {
	fake := &appx.Fake{HarnessFn: func(context.Context, string, map[string]any, any, harness.Options) (*harness.Result, error) {
		return nil, errString("connection refused")
	}}
	findings := []schemas.RawFinding{
		finding("F1", "CWE-89", "SQL Injection", schemas.SeverityCritical),
		finding("F2", "CWE-200", "Exposure of Sensitive Information", schemas.SeverityHigh),
	}
	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, harnessOnly{fake}, ".")
	if err != nil {
		t.Fatalf("want the error swallowed, got %v", err)
	}
	if len(result.Chains) != 1 {
		t.Errorf("want the seed chain, got %+v", result.Chains)
	}
}

func TestDedup_DuplicateIDsFromHarnessDropFindings(t *testing.T) {
	resp := schemas.NewChainCorrelationResult()
	resp.DuplicateIDs = []string{"F2"}
	_, app := chainFake(t, resp)

	findings := []schemas.RawFinding{
		finding("F1", "CWE-89", "SQL Injection", schemas.SeverityCritical),
		finding("F2", "CWE-200", "Exposure of Sensitive Information", schemas.SeverityHigh),
	}
	result, err := DeduplicateAndCorrelate(context.Background(), findings, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(result.Findings) != 1 || result.Findings[0].ID != "F1" {
		t.Fatalf("want F2 dropped, got %+v", result.Findings)
	}
	if result.DeduplicatedCount != 1 {
		t.Errorf("deduplicated_count = %d, want 1", result.DeduplicatedCount)
	}
	if result.TotalRaw != 2 {
		t.Errorf("total_raw = %d, want 2", result.TotalRaw)
	}
	// The seed chain referenced F2, and Python does NOT re-derive chains after
	// the drop, so the (now dangling) seed chain survives.
	if len(result.Chains) != 1 {
		t.Errorf("chains = %+v, want the seed chain retained", result.Chains)
	}
}

// No findings means no harness call at all (Python guards with `if deduplicated:`).
func TestDedup_NoFindingsSkipsHarness(t *testing.T) {
	fake, app := chainFake(t, emptyChains())
	result, err := DeduplicateAndCorrelate(context.Background(), nil, schemas.ReconResult{}, app, ".")
	if err != nil {
		t.Fatalf("DeduplicateAndCorrelate: %v", err)
	}
	if len(fake.Harnesses) != 0 {
		t.Errorf("want no harness call for an empty finding list, got %d", len(fake.Harnesses))
	}
	if result.Findings == nil || len(result.Findings) != 0 {
		t.Errorf("findings = %v, want an empty (non-nil) list", result.Findings)
	}
	if result.Chains == nil || len(result.Chains) != 0 {
		t.Errorf("chains = %v, want an empty (non-nil) list", result.Chains)
	}
	if result.StrategiesRun == nil {
		t.Error("strategies_run must be [] (pydantic default_factory=list), not null")
	}
}

// ---------------------------------------------------------------------------
// _parse_chain_from_str / _split_pipe / _seed_chain_context
// ---------------------------------------------------------------------------

func TestSplitPipe(t *testing.T) {
	cases := []struct {
		in       string
		expected int
		want     []string
	}{
		{"a|b|c|d|e", 4, []string{"a", "b", "c", "d|e"}},
		{"only-title", 4, []string{"only-title", "", "", ""}},
		{" a | b ", 4, []string{"a", "b", "", ""}},
		{"", 2, []string{"", ""}},
	}
	for _, c := range cases {
		got := splitPipe(c.in, c.expected)
		if !equalStrings(got, c.want) {
			t.Errorf("splitPipe(%q, %d) = %v, want %v", c.in, c.expected, got, c.want)
		}
	}
}

func TestParseChainFromStr(t *testing.T) {
	available := map[string]struct{}{"F1": {}, "F2": {}, "F3": {}}

	if _, ok := parseChainFromStr("t|F1|impact|high", available); ok {
		t.Error("want a chain with a single valid id to be dropped")
	}
	if _, ok := parseChainFromStr("t|F1,NOPE|impact|high", available); ok {
		t.Error("want unknown ids filtered out before the <2 check")
	}

	chain, ok := parseChainFromStr("Title|F1, F2 ,,F3||bogus", available)
	if !ok {
		t.Fatal("want the chain parsed")
	}
	if chain.Title != "Title" {
		t.Errorf("title = %q", chain.Title)
	}
	if !equalStrings(chain.FindingIDs, []string{"F1", "F2", "F3"}) {
		t.Errorf("finding_ids = %v", chain.FindingIDs)
	}
	if chain.CombinedImpact != "Combined exploitation path" {
		t.Errorf("impact = %q, want the empty-string default", chain.CombinedImpact)
	}
	if chain.EstimatedSeverity != schemas.SeverityHigh {
		t.Errorf("severity = %q, want the HIGH default for an unknown label", chain.EstimatedSeverity)
	}
	if chain.ChainID == "" {
		t.Error("chain_id must be minted (pydantic default_factory=uuid4)")
	}

	for label, want := range map[string]schemas.Severity{
		"critical": schemas.SeverityCritical,
		" HIGH ":   schemas.SeverityHigh,
		"Medium":   schemas.SeverityMedium,
		"low":      schemas.SeverityLow,
		"info":     schemas.SeverityHigh, // not in Python's severity_map -> default
	} {
		c, ok := parseChainFromStr("t|F1,F2|i|"+label, available)
		if !ok {
			t.Fatalf("chain %q did not parse", label)
		}
		if c.EstimatedSeverity != want {
			t.Errorf("severity for %q = %q, want %q", label, c.EstimatedSeverity, want)
		}
	}
}

func TestSeedChainContext_UnresolvableIDsFallBackToTitle(t *testing.T) {
	f := finding("F1", "CWE-89", "SQL Injection", schemas.SeverityHigh)
	chain := schemas.NewPotentialChain()
	chain.Title = "Fallback title"
	chain.FindingIDs = []string{"NOPE", "ALSO-NOPE"}

	got := seedChainContext([]schemas.PotentialChain{chain}, []*schemas.RawFinding{&f})
	want := "Seed chain candidates (validate and expand these):\n" +
		"- Potential chain: Fallback title (findings NOPE, ALSO-NOPE)\n" +
		"Look for additional multi-step attack chains beyond these seeds."
	if got != want {
		t.Errorf("seedChainContext =\n%q\nwant\n%q", got, want)
	}
}

// _fallback_correlate upper-cases the CWE id before matching, and `max(...)`
// keeps the FIRST argument on a severity tie.
func TestFallbackCorrelate_UpperCasesAndTieKeepsFirst(t *testing.T) {
	a := finding("A", "cwe-918", "SSRF", schemas.SeverityHigh)
	b := finding("B", "CWE-798", "Creds", schemas.SeverityHigh)
	chains := fallbackCorrelate([]*schemas.RawFinding{&a, &b})
	if len(chains) != 1 {
		t.Fatalf("want 1 chain, got %d", len(chains))
	}
	if chains[0].Title != "Potential attack chain: CWE-918 -> CWE-798" {
		t.Errorf("title = %q", chains[0].Title)
	}
	if chains[0].EstimatedSeverity != schemas.SeverityHigh {
		t.Errorf("severity = %q", chains[0].EstimatedSeverity)
	}
	if chains[0].CombinedImpact != "Combined exploitation path discovered by correlation heuristics; verify chain during PROVE phase." {
		t.Errorf("impact = %q", chains[0].CombinedImpact)
	}
}

// Every pattern in _CHAIN_PATTERNS fires, in table order.
func TestFallbackCorrelate_AllPatternsInOrder(t *testing.T) {
	cwes := []string{"CWE-918", "CWE-798", "CWE-862", "CWE-285", "CWE-89", "CWE-200", "CWE-16"}
	ptrs := make([]*schemas.RawFinding, 0, len(cwes))
	for i, cwe := range cwes {
		f := finding(string(rune('A'+i)), cwe, cwe, schemas.SeverityMedium)
		ptrs = append(ptrs, &f)
	}
	chains := fallbackCorrelate(ptrs)
	want := []string{
		"Potential attack chain: CWE-918 -> CWE-798",
		"Potential attack chain: CWE-862 -> CWE-285",
		"Potential attack chain: CWE-89 -> CWE-200",
		"Potential attack chain: CWE-16 -> CWE-798",
	}
	got := make([]string, 0, len(chains))
	for _, c := range chains {
		got = append(got, c.Title)
	}
	if !equalStrings(got, want) {
		t.Errorf("chains = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// Deduplicator
// ---------------------------------------------------------------------------

func TestDeduplicator_Run(t *testing.T) {
	fake, app := chainFake(t, emptyChains())
	d := NewDeduplicator(app, "/repo")
	findings := []schemas.RawFinding{finding("F1", "CWE-89", "SQL Injection", schemas.SeverityHigh)}
	result, err := d.Run(context.Background(), findings, schemas.ReconResult{})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(result.Findings) != 1 {
		t.Fatalf("findings = %+v", result.Findings)
	}
	if got, want := fake.Harnesses[0].Opts.ProjectDir, "/repo"; got != want {
		t.Errorf("project_dir = %q, want %q", got, want)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type errString string

func (e errString) Error() string { return string(e) }

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func lastPathSegment(p string) string {
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}
