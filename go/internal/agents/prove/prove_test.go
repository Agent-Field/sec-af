package prove

// Tests for prove.go — the PROVE driver.
//
// Validation contract:
//   - PrioritySort orders by (severity rank, confidence rank) DESCENDING and is
//     stable for ties; the input slice is not mutated;
//   - ApplyMetadata applies the CWE severity floor BEFORE scoring, fills the
//     compliance mappings, mirrors the score into sarif_security_severity, and
//     backfills the rule id only when it is empty;
//   - RunProve verifies every finding, applies metadata, and returns the set
//     sorted by (exploitability_score, evidence_level) descending;
//   - RunProve's verification fan-out never exceeds
//     max(1, min(max_concurrent_provers, len(findings))) in flight;
//   - a failing sub-agent demotes that finding via Fallback instead of failing
//     the phase;
//   - RunProveStreaming consumes batches until the nil sentinel, stops
//     scheduling at prover_cap, drains the producer afterwards, and bounds
//     concurrency at max(1, max_concurrent_provers).

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/agentfield/sdk/go/ai"
	"github.com/Agent-Field/agentfield/sdk/go/harness"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// cannedApp mirrors gen_golden_prove._CannedApp: it recognises each prove
// sub-agent by its ROLE line and answers with a fixed model.
func cannedApp(verdict string, level int) *appx.Fake {
	return &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
			switch {
			case strings.Contains(prompt, "You are DataFlowTracer"):
				return json.Marshal(traceRich())
			case strings.Contains(prompt, "You are SanitizationAnalyzer"):
				return json.Marshal(sanitizationRich())
			case strings.Contains(prompt, "You are ExploitHypothesizer"):
				return json.Marshal(exploitRich())
			}
			return nil, errors.New("unexpected harness prompt")
		}),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{
				"verdict":        verdict,
				"evidence_level": level,
				"rationale":      "canned rationale",
				"confidence":     "high",
			})
		}),
	}
}

func TestPrioritySortGolden(t *testing.T) {
	var golden struct {
		Input []struct {
			ID                string `json:"id"`
			EstimatedSeverity string `json:"estimated_severity"`
			Confidence        string `json:"confidence"`
		} `json:"input"`
		WantIDs []string `json:"want_ids"`
	}
	goldenJSON(t, "priority_sort", &golden)

	input := make([]schemas.RawFinding, len(golden.Input))
	for i, row := range golden.Input {
		input[i] = schemas.RawFinding{
			ID:                row.ID,
			EstimatedSeverity: schemas.Severity(row.EstimatedSeverity),
			Confidence:        schemas.Confidence(row.Confidence),
		}
	}

	got := PrioritySort(input)
	gotIDs := make([]string, len(got))
	for i, f := range got {
		gotIDs[i] = f.ID
	}
	if !reflect.DeepEqual(gotIDs, golden.WantIDs) {
		t.Errorf("PrioritySort order = %v, want %v", gotIDs, golden.WantIDs)
	}

	// `sorted()` returns a NEW list; the caller's slice keeps its order.
	if input[0].ID != golden.Input[0].ID {
		t.Error("PrioritySort must not reorder its input slice")
	}
}

// TestPrioritySortStability pins that reverse=True does NOT reverse ties: "b"
// and "e" share (critical, low) and keep their input order.
func TestPrioritySortStability(t *testing.T) {
	in := []schemas.RawFinding{
		{ID: "b", EstimatedSeverity: schemas.SeverityCritical, Confidence: schemas.ConfidenceLow},
		{ID: "e", EstimatedSeverity: schemas.SeverityCritical, Confidence: schemas.ConfidenceLow},
	}
	got := PrioritySort(in)
	if got[0].ID != "b" || got[1].ID != "e" {
		t.Errorf("ties must keep input order, got %s,%s", got[0].ID, got[1].ID)
	}
}

// TestPrioritySortUnknownRanksLast pins `.get(key, 0)` — an out-of-vocabulary
// severity or confidence ranks below every declared member.
func TestPrioritySortUnknownRanksLast(t *testing.T) {
	in := []schemas.RawFinding{
		{ID: "unknown", EstimatedSeverity: "bogus", Confidence: "bogus"},
		{ID: "info", EstimatedSeverity: schemas.SeverityInfo, Confidence: schemas.ConfidenceLow},
	}
	got := PrioritySort(in)
	if got[0].ID != "info" || got[1].ID != "unknown" {
		t.Errorf("unknown values must sort last, got %s,%s", got[0].ID, got[1].ID)
	}
}

func TestApplyMetadataGolden(t *testing.T) {
	var want map[string]any
	goldenJSON(t, "apply_metadata", &want)

	mints := verified("m2", "fp-m2", 0.0, 6)
	mints.SarifRuleID = ""
	mints.CweName = "Broken Access/Control Check"

	cases := map[string]schemas.VerifiedFinding{
		"keeps_rule_id":         ApplyMetadata(verified("m1", "fp-m1", 0.0, 3)),
		"mints_rule_id":         ApplyMetadata(mints),
		"with_reachability_tag": ApplyMetadata(verified("m3", "fp-m3", 0.0, 6, "externally_reachable")),
	}
	if len(cases) != len(want) {
		t.Fatalf("case count drift: go has %d, golden has %d", len(cases), len(want))
	}
	for name, got := range cases {
		if !reflect.DeepEqual(jsonTree(t, got), want[name]) {
			t.Errorf("apply_metadata[%s] mismatch:\n got: %#v\nwant: %#v", name, jsonTree(t, got), want[name])
		}
	}
}

// TestApplyMetadataFloorsBeforeScoring pins the ORDER inside _apply_metadata:
// CWE-89 floors "low" up to "critical", and the score must reflect the FLOORED
// severity, not the original one.
func TestApplyMetadataFloorsBeforeScoring(t *testing.T) {
	f := verified("x", "fp-x", 0.0, 6)
	f.Severity = schemas.SeverityLow
	got := ApplyMetadata(f)
	if got.Severity != schemas.SeverityCritical {
		t.Fatalf("CWE-89 must floor severity to critical, got %q", got.Severity)
	}
	if got.ExploitabilityScore != 10.0 {
		t.Errorf("score must use the floored severity (10.0), got %v", got.ExploitabilityScore)
	}
	if got.SarifSecuritySeverity != got.ExploitabilityScore {
		t.Errorf("sarif_security_severity must mirror the score, got %v", got.SarifSecuritySeverity)
	}
	if len(got.Compliance) == 0 {
		t.Error("CWE-89 has static compliance mappings; they must be attached")
	}
}

func TestRunProveGolden(t *testing.T) {
	var golden struct {
		RepoPath string            `json:"repo_path"`
		Depth    string            `json:"depth"`
		Want     []json.RawMessage `json:"want"`
	}
	goldenJSON(t, "run_prove", &golden)

	hunt := schemas.HuntResult{
		Findings:          []schemas.RawFinding{findingBare(), findingRich()},
		Chains:            []schemas.PotentialChain{},
		TotalRaw:          2,
		DeduplicatedCount: 2,
		StrategiesRun:     []string{"injection"},
	}
	got, err := RunProve(context.Background(), cannedApp("confirmed", 5), golden.RepoPath, hunt, golden.Depth, 3)
	if err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if len(got) != len(golden.Want) {
		t.Fatalf("got %d findings, want %d", len(got), len(golden.Want))
	}
	for i := range got {
		var want any
		if err := json.Unmarshal(golden.Want[i], &want); err != nil {
			t.Fatalf("decode want[%d]: %v", i, err)
		}
		if !reflect.DeepEqual(jsonTree(t, got[i]), want) {
			t.Errorf("run_prove[%d] mismatch:\n got: %#v\nwant: %#v", i, jsonTree(t, got[i]), want)
		}
	}
}

// TestRunProveNormalizesDepth pins that the sub-agent prompts receive the
// NORMALIZED profile value — an unrecognised depth becomes "standard".
func TestRunProveNormalizesDepth(t *testing.T) {
	app := cannedApp("likely", 3)
	hunt := schemas.HuntResult{Findings: []schemas.RawFinding{findingBare()}}
	if _, err := RunProve(context.Background(), app, fixtureRepo, hunt, "NoSuchDepth", 1); err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	for _, call := range app.Harnesses {
		if strings.Contains(call.Prompt, "- Analysis depth: NoSuchDepth") {
			t.Fatal("an unrecognised depth must be normalized to standard before it reaches a prompt")
		}
	}
	if len(app.Harnesses) == 0 {
		t.Fatal("expected harness calls")
	}
	if !strings.Contains(app.Harnesses[0].Prompt, "- Analysis depth: standard") {
		t.Errorf("prompt should carry the normalized depth; got:\n%s", app.Harnesses[0].Prompt)
	}
}

// TestRunProveEmptyHunt pins that an empty finding list short-circuits to an
// empty (non-nil) result with no harness traffic.
func TestRunProveEmptyHunt(t *testing.T) {
	app := &appx.Fake{}
	got, err := RunProve(context.Background(), app, fixtureRepo, schemas.HuntResult{}, "quick", 3)
	if err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if got == nil || len(got) != 0 {
		t.Errorf("want an empty non-nil slice, got %#v", got)
	}
	if len(app.Harnesses) != 0 || len(app.AIs) != 0 {
		t.Error("no findings must mean no sub-agent calls")
	}
}

// TestRunProveDemotesVerifierFailure pins that a sub-agent failure demotes ONE
// finding rather than failing the phase — the behaviour orchestrator.py and
// reasoners/phases.py both depend on.
func TestRunProveDemotesVerifierFailure(t *testing.T) {
	app := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
			if strings.Contains(prompt, "You are ExploitHypothesizer") {
				return nil, errors.New("provider exploded")
			}
			if strings.Contains(prompt, "You are DataFlowTracer") {
				return json.Marshal(traceRich())
			}
			return json.Marshal(sanitizationRich())
		}),
	}
	hunt := schemas.HuntResult{Findings: []schemas.RawFinding{findingRich()}}
	got, err := RunProve(context.Background(), app, fixtureRepo, hunt, "quick", 3)
	if err != nil {
		t.Fatalf("RunProve must absorb a sub-agent failure, got %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("want 1 demoted finding, got %d", len(got))
	}
	if got[0].Verdict != schemas.VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", got[0].Verdict)
	}
	if got[0].DropReason == nil || *got[0].DropReason != "verifier_error" {
		t.Errorf("drop_reason = %v, want verifier_error", got[0].DropReason)
	}
	if !strings.Contains(got[0].Rationale, "ExploitHypothesizer harness error: provider exploded") {
		t.Errorf("rationale must carry the failure message, got %q", got[0].Rationale)
	}
	if len(got[0].Tags) != 1 || got[0].Tags[0] != "low_confidence" {
		t.Errorf("tags = %v, want [low_confidence]", got[0].Tags)
	}
}

// TestDemoteOnErrorClassification pins the three drop-reason branches of the
// shared `except BaseException` body, including the "validationerror" probe
// that Python spells WITHOUT a space.
func TestDemoteOnErrorClassification(t *testing.T) {
	f := findingBare()
	for _, tc := range []struct {
		name          string
		err           error
		dropReason    string
		rationalePart string
	}{
		{"unverified verdict", errors.New("Verdict unverified for finding"), "verdict_unverified",
			"Verifier returned unverified verdict; demoted for manual review (original verdict: unverified)"},
		{"validationerror substring", errors.New("pydantic ValidationError: bad"), "schema_parse_failure",
			"pydantic ValidationError: bad"},
		{"anything else", errors.New("boom"), "verifier_error", "boom"},
		// A real pydantic message says "1 validation error for X" — with a
		// SPACE — so it does NOT hit the schema_parse_failure branch here.
		{"spaced validation error", errors.New("1 validation error for VerifiedFinding"), "verifier_error",
			"1 validation error for VerifiedFinding"},
	} {
		got := demoteOnError(f, tc.err)
		if got.DropReason == nil || *got.DropReason != tc.dropReason {
			t.Errorf("%s: drop_reason = %v, want %q", tc.name, got.DropReason, tc.dropReason)
		}
		if !strings.Contains(got.Rationale, tc.rationalePart) {
			t.Errorf("%s: rationale = %q, want it to contain %q", tc.name, got.Rationale, tc.rationalePart)
		}
	}
}

// TestRunProveConcurrencyBound pins the semaphore:
// max(1, min(max_concurrent_provers, len(findings))). Each verification issues
// three harness calls, two of which (tracer + sanitization) run concurrently
// WITHIN a verification, so the observable ceiling is 2*limit.
func TestRunProveConcurrencyBound(t *testing.T) {
	findings := make([]schemas.RawFinding, 8)
	for i := range findings {
		f := findingBare()
		f.ID = "f" + string(rune('a'+i))
		f.Fingerprint = f.ID
		findings[i] = f
	}

	for _, limit := range []int{1, 2, 3} {
		app := cannedApp("confirmed", 4)
		if _, err := RunProve(context.Background(), app, fixtureRepo,
			schemas.HuntResult{Findings: findings}, "quick", limit); err != nil {
			t.Fatalf("RunProve: %v", err)
		}
		if got := app.MaxConcurrentHarness(); got > 2*limit {
			t.Errorf("limit %d: peak concurrent harness calls = %d, want <= %d", limit, got, 2*limit)
		}
	}

	// A zero/negative limit still admits one prover — `max(1, ...)`.
	app := cannedApp("confirmed", 4)
	if _, err := RunProve(context.Background(), app, fixtureRepo,
		schemas.HuntResult{Findings: findings}, "quick", 0); err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if got := app.MaxConcurrentHarness(); got > 2 {
		t.Errorf("a zero limit must behave like 1 prover; peak = %d", got)
	}
}

// TestRunVerifierRunsTracerAndSanitizationConcurrently pins the
// asyncio.gather(tracer, sanitization) shape: both are in flight at once.
func TestRunVerifierRunsTracerAndSanitizationConcurrently(t *testing.T) {
	release := make(chan struct{})
	seen := make(chan string, 2)
	app := &appx.Fake{
		HarnessFn: func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
			switch {
			case strings.Contains(prompt, "You are DataFlowTracer"):
				seen <- "tracer"
				<-release
				b, _ := json.Marshal(traceRich())
				_ = json.Unmarshal(b, dest)
			case strings.Contains(prompt, "You are SanitizationAnalyzer"):
				seen <- "sanitization"
				<-release
				b, _ := json.Marshal(sanitizationRich())
				_ = json.Unmarshal(b, dest)
			default:
				b, _ := json.Marshal(exploitRich())
				_ = json.Unmarshal(b, dest)
			}
			return &harness.Result{Parsed: dest}, nil
		},
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"verdict": "likely", "evidence_level": 2, "rationale": "r", "confidence": "low"})
		}),
	}

	done := make(chan error, 1)
	go func() {
		_, err := RunVerifier(context.Background(), app, fixtureRepo, findingRich(), "quick")
		done <- err
	}()

	// Both stage-1 agents must arrive before either is allowed to finish.
	first, second := <-seen, <-seen
	if first == second {
		t.Fatalf("expected tracer and sanitization concurrently, saw %q twice", first)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("RunVerifier: %v", err)
	}
}

func TestRunVerifierGolden(t *testing.T) {
	var want map[string]any
	goldenJSON(t, "run_verifier", &want)

	notExploitable, err := RunVerifier(context.Background(), cannedApp("not_exploitable", 1), fixtureRepo, findingRich(), "quick")
	if err != nil {
		t.Fatalf("RunVerifier(not_exploitable): %v", err)
	}
	likely, err := RunVerifier(context.Background(), cannedApp("likely", 3), fixtureRepo, findingBare(), "quick")
	if err != nil {
		t.Fatalf("RunVerifier(likely): %v", err)
	}
	for name, got := range map[string]schemas.VerifiedFinding{
		"not_exploitable": notExploitable,
		"likely":          likely,
	} {
		if !reflect.DeepEqual(jsonTree(t, got), want[name]) {
			t.Errorf("run_verifier[%s] mismatch:\n got: %#v\nwant: %#v", name, jsonTree(t, got), want[name])
		}
	}
}

// TestRunVerifierFallsBackOnTracerFailure pins the return_exceptions=True
// contract: a failed tracer falls back to the SEED trace built from the
// hunter's data_flow, and a failed sanitization falls back to the explicit
// "nothing found" result — neither aborts the verification.
func TestRunVerifierFallsBackOnStageOneFailures(t *testing.T) {
	var exploitPrompt string
	app := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
			switch {
			case strings.Contains(prompt, "You are DataFlowTracer"),
				strings.Contains(prompt, "You are SanitizationAnalyzer"):
				return nil, errors.New("stage one down")
			}
			exploitPrompt = prompt
			return json.Marshal(exploitRich())
		}),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"verdict": "likely", "evidence_level": 2, "rationale": "r", "confidence": "low"})
		}),
	}
	got, err := RunVerifier(context.Background(), app, fixtureRepo, findingRich(), "quick")
	if err != nil {
		t.Fatalf("stage-one failures must not abort verification: %v", err)
	}
	// The seed trace's source is "<file>:<start_line>" and its steps come from
	// the hunter's data_flow.
	if got.Proof == nil || got.Proof.DataFlowEvidence == nil {
		t.Fatal("proof/data flow evidence missing")
	}
	if src := got.Proof.DataFlowEvidence.Source; src == nil || *src != "src/users.py:42" {
		t.Errorf("seed trace source = %v, want src/users.py:42", src)
	}
	if got.Proof.DataFlowEvidence.SinkReached {
		t.Error("the seed trace must never claim the sink was reached")
	}
	if len(got.Proof.DataFlowTrace) != 2 {
		t.Errorf("seed trace should carry the hunter's 2 data-flow steps, got %d", len(got.Proof.DataFlowTrace))
	}
	if !strings.Contains(exploitPrompt, "Sanitization found: no") {
		t.Error("a failed sanitization analysis must reach the exploit prompt as 'no'")
	}
	if !strings.Contains(exploitPrompt, "Sanitization sufficient: unknown") {
		t.Error("the sanitization fallback leaves `sufficient` None, which renders as 'unknown'")
	}
}

// TestSeedTraceSinkFallback pins `finding.function_name or finding.file_path`.
func TestSeedTraceSinkFallback(t *testing.T) {
	f := findingBare()
	if got := seedTraceFor(f).Sink; got != "src/hash.py" {
		t.Errorf("a nil function_name must fall back to the file path, got %q", got)
	}
	f.FunctionName = str("")
	if got := seedTraceFor(f).Sink; got != "src/hash.py" {
		t.Errorf("an EMPTY function_name is falsy and must fall back too, got %q", got)
	}
	f.FunctionName = str("do_hash")
	if got := seedTraceFor(f).Sink; got != "do_hash" {
		t.Errorf("sink = %q, want do_hash", got)
	}
	// No data flow means an empty (non-nil) step list.
	if steps := seedTraceFor(findingBare()).Steps; steps == nil || len(steps) != 0 {
		t.Errorf("want empty non-nil steps, got %#v", steps)
	}
}

// TestVerdictAgentUsesAINotHarness pins that the verdict stage goes through
// `.ai()` — one structured request, no harness session and no temp dir.
func TestVerdictAgentUsesAINotHarness(t *testing.T) {
	app := &appx.Fake{
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"verdict": "confirmed", "evidence_level": 6, "rationale": "r", "confidence": "high"})
		}),
	}
	got, err := RunVerdictAgent(context.Background(), app, ".", findingRich(), traceRich(), sanitizationRich(), exploitRich())
	if err != nil {
		t.Fatalf("RunVerdictAgent: %v", err)
	}
	if got.Verdict != "confirmed" || got.EvidenceLevel != 6 {
		t.Errorf("unexpected decision %+v", got)
	}
	if len(app.Harnesses) != 0 {
		t.Error("the verdict stage must not open a harness session")
	}
	if len(app.AIs) != 1 {
		t.Fatalf("want exactly one .ai() call, got %d", len(app.AIs))
	}
	// Python passes no `system=`, so the request carries no system message —
	// ai.WithSystem is the only option that prepends one.
	req := &ai.Request{}
	for _, opt := range app.AIs[0].Opts {
		_ = opt(req)
	}
	for _, msg := range req.Messages {
		if msg.Role == "system" {
			t.Errorf("verdict.py passes no system prompt, got %+v", msg)
		}
	}
	if req.ResponseFormat == nil {
		t.Fatal("the request must carry the strictified VerdictDecision schema")
	}
	if req.ResponseFormat.JSONSchema == nil || !req.ResponseFormat.JSONSchema.Strict {
		t.Errorf("the schema must be sent in OpenAI strict mode, got %+v", req.ResponseFormat)
	}
	// It must be the committed PYDANTIC schema (title == the class name), then
	// strictified: every object gets additionalProperties:false and a required
	// list naming all of its properties.
	var sent map[string]any
	if err := json.Unmarshal(req.ResponseFormat.JSONSchema.Schema, &sent); err != nil {
		t.Fatalf("decode sent schema: %v", err)
	}
	if title, _ := sent["title"].(string); title != "VerdictDecision" {
		t.Errorf("schema title = %v, want VerdictDecision", sent["title"])
	}
	if extra, ok := sent["additionalProperties"].(bool); !ok || extra {
		t.Errorf("strict mode requires additionalProperties:false, got %v", sent["additionalProperties"])
	}
	required, _ := sent["required"].([]any)
	if len(required) != 4 {
		t.Errorf("strict mode requires all 4 properties, got %v", required)
	}
}

// --- run_prove_streaming ----------------------------------------------------

func TestRunProveStreamingConsumesUntilSentinel(t *testing.T) {
	app := cannedApp("confirmed", 4)
	queue := make(chan []schemas.RawFinding, 4)
	queue <- []schemas.RawFinding{findingBare()}
	queue <- []schemas.RawFinding{} // an EMPTY batch is not the sentinel
	queue <- []schemas.RawFinding{findingRich()}
	queue <- nil // sentinel
	close(queue)

	got := RunProveStreaming(context.Background(), app, fixtureRepo, queue, "standard", 3, 30)
	if len(got) != 2 {
		t.Fatalf("want 2 verified findings, got %d", len(got))
	}
	// Sorted by (exploitability_score, evidence_level) descending: the rich
	// finding is CWE-89 (critical floor) so it outscores the CWE-327 one.
	if got[0].ID != "raw-1" || got[1].ID != "raw-2" {
		t.Errorf("order = %s,%s, want raw-1,raw-2", got[0].ID, got[1].ID)
	}
	if got[0].ExploitabilityScore < got[1].ExploitabilityScore {
		t.Error("results must be sorted by exploitability score, descending")
	}
}

func TestRunProveStreamingRespectsProverCap(t *testing.T) {
	app := cannedApp("confirmed", 4)
	queue := make(chan []schemas.RawFinding, 4)
	batch := make([]schemas.RawFinding, 5)
	for i := range batch {
		f := findingBare()
		f.ID = "f" + string(rune('a'+i))
		f.Fingerprint = f.ID
		batch[i] = f
	}
	queue <- batch
	queue <- batch // never scheduled: the cap is already reached
	queue <- nil
	close(queue)

	got := RunProveStreaming(context.Background(), app, fixtureRepo, queue, "quick", 2, 3)
	if len(got) != 3 {
		t.Fatalf("prover_cap=3 must stop after 3 verifications, got %d", len(got))
	}
	// Each verification issues exactly three harness calls.
	if len(app.Harnesses) != 9 {
		t.Errorf("want 9 harness calls (3 findings x 3 sub-agents), got %d", len(app.Harnesses))
	}
	if got := app.MaxConcurrentHarness(); got > 4 {
		t.Errorf("max_concurrent_provers=2 caps in-flight harness calls at 4, got %d", got)
	}
}

// TestRunProveStreamingDrainsProducer pins that once the cap is hit the queue
// is drained to its sentinel rather than abandoned — otherwise a producer
// blocked on an unbuffered channel would never finish.
func TestRunProveStreamingDrainsProducer(t *testing.T) {
	app := cannedApp("confirmed", 4)
	queue := make(chan []schemas.RawFinding) // UNBUFFERED
	producerDone := make(chan struct{})
	go func() {
		defer close(producerDone)
		for i := 0; i < 4; i++ {
			queue <- []schemas.RawFinding{findingBare()}
		}
		queue <- nil
	}()

	got := RunProveStreaming(context.Background(), app, fixtureRepo, queue, "quick", 2, 1)
	if len(got) != 1 {
		t.Fatalf("prover_cap=1 must verify exactly one finding, got %d", len(got))
	}
	select {
	case <-producerDone:
	default:
		t.Fatal("the producer must have been drained to its sentinel")
	}
}

func TestRunProveStreamingEmptyQueue(t *testing.T) {
	app := &appx.Fake{}
	queue := make(chan []schemas.RawFinding, 1)
	queue <- nil
	close(queue)

	got := RunProveStreaming(context.Background(), app, fixtureRepo, queue, "quick", 3, 30)
	if got == nil || len(got) != 0 {
		t.Errorf("want an empty non-nil slice, got %#v", got)
	}
	if len(app.Harnesses) != 0 {
		t.Error("an immediate sentinel must schedule no work")
	}
}

// TestRunProveStreamingDemotesFailures pins that a failing verification is
// demoted and KEPT, not dropped — the `except BaseException` inside
// `_verify_one` means gather's exception filter never actually fires.
func TestRunProveStreamingDemotesFailures(t *testing.T) {
	app := &appx.Fake{
		HarnessFn: appx.HarnessJSON(func(prompt string, _ harness.Options) (json.RawMessage, error) {
			if strings.Contains(prompt, "You are ExploitHypothesizer") {
				return nil, errors.New("nope")
			}
			if strings.Contains(prompt, "You are DataFlowTracer") {
				return json.Marshal(traceRich())
			}
			return json.Marshal(sanitizationRich())
		}),
	}
	queue := make(chan []schemas.RawFinding, 2)
	queue <- []schemas.RawFinding{findingBare()}
	queue <- nil
	close(queue)

	got := RunProveStreaming(context.Background(), app, fixtureRepo, queue, "quick", 3, 30)
	if len(got) != 1 {
		t.Fatalf("a failed verification must still be reported, got %d findings", len(got))
	}
	if got[0].DropReason == nil || *got[0].DropReason != "verifier_error" {
		t.Errorf("drop_reason = %v, want verifier_error", got[0].DropReason)
	}
}

// TestRunProveSemaphoreAdmitsExactlyTheLimit is the strong form of the
// concurrency contract: `asyncio.Semaphore(max(1, min(n, len(findings))))` must
// admit EXACTLY that many verifications at once — no more (an over-wide
// semaphore would stampede the provider) and no fewer (a serialized phase would
// take N times as long).
//
// Every tracer call parks until the test releases it, so the number that have
// arrived after a grace period IS the semaphore width. A too-narrow semaphore
// never fills the wave and the test fails on its deadline.
func TestRunProveSemaphoreAdmitsExactlyTheLimit(t *testing.T) {
	const findingsN, limit = 6, 3

	var (
		mu       sync.Mutex
		arrived  int
		inFlight int
		peak     int
	)
	release := make(chan struct{})
	timedOut := make(chan struct{})

	app := &appx.Fake{
		HarnessFn: func(_ context.Context, prompt string, _ map[string]any, dest any, _ harness.Options) (*harness.Result, error) {
			var canned any = exploitRich()
			switch {
			case strings.Contains(prompt, "You are DataFlowTracer"):
				mu.Lock()
				arrived++
				inFlight++
				if inFlight > peak {
					peak = inFlight
				}
				mu.Unlock()
				select {
				case <-release:
				case <-timedOut:
				}
				mu.Lock()
				inFlight--
				mu.Unlock()
				canned = traceRich()
			case strings.Contains(prompt, "You are SanitizationAnalyzer"):
				canned = sanitizationRich()
			}
			b, _ := json.Marshal(canned)
			if err := json.Unmarshal(b, dest); err != nil {
				return nil, err
			}
			return &harness.Result{Parsed: dest}, nil
		},
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.Marshal(map[string]any{"verdict": "likely", "evidence_level": 2, "rationale": "r", "confidence": "low"})
		}),
	}

	findings := make([]schemas.RawFinding, findingsN)
	for i := range findings {
		f := findingBare()
		f.ID = "f" + strconv.Itoa(i)
		f.Fingerprint = f.ID
		findings[i] = f
	}

	done := make(chan error, 1)
	go func() {
		_, err := RunProve(context.Background(), app, fixtureRepo,
			schemas.HuntResult{Findings: findings}, "quick", limit)
		done <- err
	}()

	// Wait for the first wave to fill, then give a too-wide semaphore a chance
	// to let a fourth verification through.
	deadline := time.Now().Add(10 * time.Second)
	for {
		mu.Lock()
		n := arrived
		mu.Unlock()
		if n >= limit {
			break
		}
		if time.Now().After(deadline) {
			close(timedOut)
			<-done
			t.Fatalf("only %d of %d verifications were in flight: the semaphore is too narrow", n, limit)
		}
		time.Sleep(time.Millisecond)
	}
	time.Sleep(150 * time.Millisecond)
	mu.Lock()
	over := arrived
	mu.Unlock()
	close(release)

	if err := <-done; err != nil {
		t.Fatalf("RunProve: %v", err)
	}
	if over != limit {
		t.Errorf("%d verifications entered the first wave, want exactly %d", over, limit)
	}
	if peak != limit {
		t.Errorf("peak concurrent verifications = %d, want exactly %d", peak, limit)
	}
}
