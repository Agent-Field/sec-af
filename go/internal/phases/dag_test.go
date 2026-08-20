package phases

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/afx"
	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// These tests pin the DAG: the exact `.call` target names, the exact kwargs
// keys, the call counts, and the semaphore bounds. They are the Go counterpart
// of "what the control plane must show" in DESIGN.md §3 — a phase that
// collapses a `.call` into an in-process function call, or that renames a
// kwarg, fails here rather than silently changing the workflow graph.

const testNodeID = "sec-af"

// callSpy answers Call from a table keyed by the reasoner name (the part after
// "sec-af."), records every invocation, and optionally stalls so the peak
// concurrency is observable.
type callSpy struct {
	mu       sync.Mutex
	answers  map[string]json.RawMessage
	failures map[string]error
	// nullResults names the reasoners that answer with a SUCCEEDED execution
	// carrying a null result — sdk/go/agent.Call's `(nil, nil)`.
	nullResults map[string]bool
	delay       time.Duration
}

func (s *callSpy) fn() func(context.Context, string, map[string]any) (map[string]any, error) {
	return func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		name := target
		if i := lastDot(target); i >= 0 {
			name = target[i+1:]
		}
		s.mu.Lock()
		answer, ok := s.answers[name]
		failure := s.failures[name]
		isNull := s.nullResults[name]
		delay := s.delay
		s.mu.Unlock()

		if delay > 0 {
			time.Sleep(delay)
		}
		if failure != nil {
			return nil, failure
		}
		if isNull {
			// Exactly what sdk/go/agent.Call returns for a SUCCEEDED
			// execution whose status payload has `result: null`.
			return nil, nil
		}
		if !ok {
			return nil, errors.New("callSpy: no answer scripted for " + name)
		}
		var out map[string]any
		if err := json.Unmarshal(answer, &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

func lastDot(s string) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == '.' {
			return i
		}
	}
	return -1
}

func reconContextFixture(t *testing.T, name string) map[string]any {
	t.Helper()
	fixtures := readJSON[map[string]json.RawMessage](t, "recon_fixture.json")
	raw, ok := fixtures[name]
	if !ok {
		t.Fatalf("recon_fixture.json has no %q", name)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode recon context %q: %v", name, err)
	}
	return out
}

// ---------------------------------------------------------------------------
// recon_phase
// ---------------------------------------------------------------------------

func reconAnswers() map[string]json.RawMessage {
	return map[string]json.RawMessage{
		"run_architecture_mapper": json.RawMessage(`{
			"app_type": "web_api",
			"modules": [
				{"name":"api","path":"src/api","language":"Python","dependencies":[]},
				{"name":"web","path":"web","language":"typescript","dependencies":[]},
				{"name":"blank","path":"blank","language":"","dependencies":[]}
			],
			"api_surface": []
		}`),
		"run_dependency_auditor": json.RawMessage(`{"direct_count": 3, "transitive_count": 9}`),
		"run_config_scanner":     json.RawMessage(`{"secrets": [], "misconfigs": []}`),
		"run_data_flow_mapper":   json.RawMessage(`{"flows": []}`),
		"run_security_context_profiler": json.RawMessage(`{
			"auth_model": "jwt",
			"auth_details": "Bearer",
			"framework_security": ["Django", "", "django", "Django"]
		}`),
	}
}

// TestReconPhase_StandardDAG pins the five-call graph, the kwargs, and the
// derived languages/frameworks.
func TestReconPhase_StandardDAG(t *testing.T) {
	spy := &callSpy{answers: reconAnswers(), delay: 20 * time.Millisecond}
	fake := &appx.Fake{CallFn: spy.fn()}

	result, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "standard")
	if err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}

	wantTargets := []string{
		"sec-af.run_architecture_mapper",
		"sec-af.run_config_scanner",
		"sec-af.run_data_flow_mapper",
		"sec-af.run_dependency_auditor",
		"sec-af.run_security_context_profiler",
	}
	got := fake.CallTargets()
	sort.Strings(got)
	if !reflect.DeepEqual(got, wantTargets) {
		t.Errorf("targets\n got: %v\nwant: %v", got, wantTargets)
	}

	for _, call := range fake.Calls {
		keys := sortedMapKeys(call.Input)
		switch call.Target {
		case "sec-af.run_architecture_mapper", "sec-af.run_dependency_auditor", "sec-af.run_config_scanner":
			if !reflect.DeepEqual(keys, []string{"repo_path"}) {
				t.Errorf("%s kwargs = %v, want [repo_path]", call.Target, keys)
			}
		default:
			if !reflect.DeepEqual(keys, []string{"architecture", "repo_path"}) {
				t.Errorf("%s kwargs = %v, want [architecture repo_path]", call.Target, keys)
			}
		}
	}

	// languages: lowered, deduplicated, sorted, blanks dropped.
	if want := []string{"python", "typescript"}; !reflect.DeepEqual(result["languages"], want) {
		t.Errorf("languages = %#v, want %v", result["languages"], want)
	}
	// frameworks: case preserved, deduplicated, sorted, blanks dropped.
	if want := []string{"Django", "django"}; !reflect.DeepEqual(result["frameworks"], want) {
		t.Errorf("frameworks = %#v, want %v", result["frameworks"], want)
	}
	// Python parity: recon_phase never sets recon_duration_seconds.
	if got := result["recon_duration_seconds"]; got != 0.0 {
		t.Errorf("recon_duration_seconds = %#v, want 0", got)
	}

	wantNotes := []string{"RECON phase starting", "RECON phase complete"}
	if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
		t.Errorf("notes = %q, want %q", fake.NoteMessages(), wantNotes)
	}
	if !reflect.DeepEqual(fake.Notes[0].Tags, []string{"phase", "recon"}) {
		t.Errorf("start tags = %v", fake.Notes[0].Tags)
	}
	if !reflect.DeepEqual(fake.Notes[1].Tags, []string{"phase", "recon", "done"}) {
		t.Errorf("done tags = %v", fake.Notes[1].Tags)
	}
}

// TestReconPhase_QuickSkipsDeepMappers is the depth branch: three calls only,
// with the hard-coded "unknown"/"unknown" security context.
func TestReconPhase_QuickSkipsDeepMappers(t *testing.T) {
	for _, depth := range []string{"quick", "QUICK", "Quick"} {
		depth := depth
		t.Run(depth, func(t *testing.T) {
			spy := &callSpy{answers: reconAnswers()}
			fake := &appx.Fake{CallFn: spy.fn()}

			result, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), depth)
			if err != nil {
				t.Fatalf("ReconPhase: %v", err)
			}
			if len(fake.Calls) != 3 {
				t.Fatalf("call count = %d (%v), want 3", len(fake.Calls), fake.CallTargets())
			}
			for _, target := range fake.CallTargets() {
				if target == "sec-af.run_data_flow_mapper" || target == "sec-af.run_security_context_profiler" {
					t.Errorf("quick depth must not call %s", target)
				}
			}
			sc, _ := result["security_context"].(schemas.SecurityContext)
			if sc.AuthModel != "unknown" || sc.AuthDetails != "unknown" {
				t.Errorf("quick security context = %+v, want auth_model/auth_details both %q", sc, "unknown")
			}
			// frameworks derive from the placeholder context, so they are empty.
			if want := []string{}; !reflect.DeepEqual(result["frameworks"], want) {
				t.Errorf("frameworks = %#v, want []", result["frameworks"])
			}
		})
	}
}

// TestReconPhase_ConcurrencyAndErrors: the first gather runs all three at once,
// and a failing child aborts the phase.
func TestReconPhase_ConcurrencyAndErrors(t *testing.T) {
	t.Run("base mappers run concurrently", func(t *testing.T) {
		spy := &callSpy{answers: reconAnswers(), delay: 30 * time.Millisecond}
		fake := &appx.Fake{CallFn: spy.fn()}
		if _, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "quick"); err != nil {
			t.Fatalf("ReconPhase: %v", err)
		}
		if got := fake.MaxConcurrentCalls(); got != 3 {
			t.Errorf("max concurrent calls = %d, want 3", got)
		}
	})

	t.Run("child failure propagates", func(t *testing.T) {
		spy := &callSpy{
			answers:  reconAnswers(),
			failures: map[string]error{"run_config_scanner": errors.New("boom")},
		}
		fake := &appx.Fake{CallFn: spy.fn()}
		if _, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "quick"); err == nil {
			t.Fatal("want an error when run_config_scanner fails")
		}
	})

	t.Run("error envelope propagates through _unwrap", func(t *testing.T) {
		answers := reconAnswers()
		answers["run_dependency_auditor"] = json.RawMessage(`{"error": {"message": "nope"}}`)
		fake := &appx.Fake{CallFn: (&callSpy{answers: answers}).fn()}
		_, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "quick")
		if err == nil || err.Error() != "run_dependency_auditor failed: nope" {
			t.Fatalf("err = %v, want `run_dependency_auditor failed: nope`", err)
		}
	})
}

// TestReconPhase_UnwrapsOutputEnvelope covers the `{"output": {...}}` shape the
// control plane actually returns.
func TestReconPhase_UnwrapsOutputEnvelope(t *testing.T) {
	answers := map[string]json.RawMessage{}
	for name, payload := range reconAnswers() {
		answers[name] = json.RawMessage(`{"output": ` + string(payload) + `}`)
	}
	fake := &appx.Fake{CallFn: (&callSpy{answers: answers}).fn()}
	result, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "standard")
	if err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}
	if want := []string{"python", "typescript"}; !reflect.DeepEqual(result["languages"], want) {
		t.Errorf("languages = %#v, want %v", result["languages"], want)
	}
}

// TestReconPhase_DepthNormalizationDoesNotStrip pins a Python quirk worth
// knowing: `_normalize_depth` LOWERCASES but never strips, so " quick " is not
// a valid DepthProfile and silently becomes standard — five calls, not three.
func TestReconPhase_DepthNormalizationDoesNotStrip(t *testing.T) {
	fake := &appx.Fake{CallFn: (&callSpy{answers: reconAnswers()}).fn()}
	if _, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), " Quick "); err != nil {
		t.Fatalf("ReconPhase: %v", err)
	}
	if len(fake.Calls) != 5 {
		t.Errorf("call count = %d, want 5 (a padded depth is NOT quick)", len(fake.Calls))
	}
}

func sortedMapKeys(m map[string]any) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// hunt_phase
// ---------------------------------------------------------------------------

// huntAnswers scripts every hunter with one finding whose fingerprint is
// derived from the strategy, plus a deduplicator that echoes what it was given.
func huntAnswers(t *testing.T, strategies []string) map[string]json.RawMessage {
	t.Helper()
	answers := map[string]json.RawMessage{
		"run_deduplicator": json.RawMessage(`{"findings": [], "chains": [], "total_raw": 999, "deduplicated_count": 0, "chain_count": 0, "strategies_run": ["ignored"]}`),
	}
	for _, s := range strategies {
		answers["run_"+s+"_hunter"] = json.RawMessage(`{"findings": [` + rawFindingJSON(s) + `], "chains": []}`)
	}
	return answers
}

func rawFindingJSON(strategy string) string {
	return `{
		"id": "` + strategy + `-1",
		"hunter_strategy": "` + strategy + `",
		"title": "finding from ` + strategy + `",
		"description": "d",
		"finding_type": "sast",
		"cwe_id": "CWE-1",
		"cwe_name": "n",
		"file_path": "` + strategy + `.py",
		"start_line": 1,
		"end_line": 1,
		"code_snippet": "x",
		"estimated_severity": "high",
		"confidence": "high",
		"fingerprint": "fp-` + strategy + `"
	}`
}

func TestHuntPhase_DAGAndCounters(t *testing.T) {
	reconCtx := reconContextFixture(t, "full")
	recon := reconFixture(t, "full")
	strategies := strategyValues(DefaultStrategies(recon, "standard"))
	if len(strategies) != 11 {
		t.Fatalf("fixture sanity: %d strategies, want 11 (%v)", len(strategies), strategies)
	}

	spy := &callSpy{answers: huntAnswers(t, strategies), delay: 15 * time.Millisecond}
	fake := &appx.Fake{
		CallFn: spy.fn(),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`{"additional_cwes":["CWE-77"],"rationale":"r"}`), nil
		}),
	}

	result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "standard",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}

	// One call per strategy plus exactly one deduplicator call.
	wantTargets := make([]string, 0, len(strategies)+1)
	for _, s := range strategies {
		wantTargets = append(wantTargets, "sec-af.run_"+s+"_hunter")
	}
	wantTargets = append(wantTargets, "sec-af.run_deduplicator")
	sort.Strings(wantTargets)
	gotTargets := fake.CallTargets()
	sort.Strings(gotTargets)
	if !reflect.DeepEqual(gotTargets, wantTargets) {
		t.Errorf("targets\n got: %v\nwant: %v", gotTargets, wantTargets)
	}

	// Hunter kwargs — the four keys, spelled exactly as in Python.
	for _, call := range fake.Calls {
		if call.Target == "sec-af.run_deduplicator" {
			if want := []string{"findings", "recon_context", "repo_path"}; !reflect.DeepEqual(sortedMapKeys(call.Input), want) {
				t.Errorf("run_deduplicator kwargs = %v, want %v", sortedMapKeys(call.Input), want)
			}
			// recon_context is forwarded VERBATIM, not the pruned projection.
			if !reflect.DeepEqual(call.Input["recon_context"], reconCtx) {
				t.Error("run_deduplicator recon_context must be the caller's full map")
			}
			continue
		}
		want := []string{"depth", "max_files_without_signal", "recon_context", "repo_path"}
		if !reflect.DeepEqual(sortedMapKeys(call.Input), want) {
			t.Errorf("%s kwargs = %v, want %v", call.Target, sortedMapKeys(call.Input), want)
		}
		if call.Input["depth"] != "standard" {
			t.Errorf("%s depth = %v", call.Target, call.Input["depth"])
		}
		if call.Input["max_files_without_signal"] != DefaultEarlyStopFileThreshold {
			t.Errorf("%s max_files_without_signal = %v", call.Target, call.Input["max_files_without_signal"])
		}
		if call.Input["repo_path"] != "/repo" {
			t.Errorf("%s repo_path = %v", call.Target, call.Input["repo_path"])
		}
	}

	if got := fake.MaxConcurrentCalls(); got > DefaultMaxConcurrentHunters {
		t.Errorf("max concurrent hunters = %d, want <= %d", got, DefaultMaxConcurrentHunters)
	}
	if got := fake.MaxConcurrentCalls(); got != DefaultMaxConcurrentHunters {
		t.Errorf("max concurrent hunters = %d, want exactly %d (the semaphore limit)", got, DefaultMaxConcurrentHunters)
	}

	// strategies_run and total_raw are OVERWRITTEN after the dedup call, so the
	// deduplicator's own values ("ignored" / 999) are discarded.
	if !reflect.DeepEqual(result["strategies_run"], strategies) {
		t.Errorf("strategies_run = %#v, want %v", result["strategies_run"], strategies)
	}
	if result["total_raw"] != len(strategies) {
		t.Errorf("total_raw = %#v, want %d", result["total_raw"], len(strategies))
	}
}

func TestHuntPhase_NotesAndFailures(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	answers := huntAnswers(t, strategies)
	spy := &callSpy{
		answers:  answers,
		failures: map[string]error{"run_ssrf_hunter": errors.New("hunter exploded")},
	}
	fake := &appx.Fake{
		CallFn: spy.fn(),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`{"additional_cwes":[],"rationale":""}`), nil
		}),
	}

	result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}

	// A failed hunter is noted and contributes an EMPTY batch — the phase
	// still succeeds and the strategy still appears in strategies_run.
	foundFailureNote := false
	for _, msg := range fake.NoteMessages() {
		if len(msg) > len("Hunt strategy failed: ssrf") && msg[:len("Hunt strategy failed: ssrf")] == "Hunt strategy failed: ssrf" {
			foundFailureNote = true
		}
	}
	if !foundFailureNote {
		t.Errorf("no `Hunt strategy failed: ssrf: ...` note in %q", fake.NoteMessages())
	}
	if !reflect.DeepEqual(result["strategies_run"], strategies) {
		t.Errorf("strategies_run = %#v, want %v", result["strategies_run"], strategies)
	}
	if want := len(strategies) - 1; result["total_raw"] != want {
		t.Errorf("total_raw = %#v, want %d (the failed hunter contributes 0)", result["total_raw"], want)
	}

	// Bookend notes.
	msgs := fake.NoteMessages()
	if msgs[0] != "HUNT phase starting" {
		t.Errorf("first note = %q", msgs[0])
	}
	if msgs[len(msgs)-1] != "HUNT phase complete" {
		t.Errorf("last note = %q", msgs[len(msgs)-1])
	}

	// No CWE-expansion note when the gate returns nothing.
	for _, msg := range msgs {
		if len(msg) >= len("CWE expansion") && msg[:len("CWE expansion")] == "CWE expansion" {
			t.Errorf("unexpected CWE expansion note %q", msg)
		}
	}
}

// TestHuntPhase_NullCallResultIsRejectedAsNoneType covers the `.call` that
// SUCCEEDS with a null result. Python's `Agent.call` returns None there, and
// `_as_dict(None, name)` raises
// `RuntimeError("<name> returned non-dict payload: NoneType")`
// (reasoners/phases.py:46). The Go SDK returns a nil map[string]any for the
// identical execution, which used to slip through afx.AsMap and bind to an
// EMPTY model — silently discarding a hunter batch, or every fingerprint-unique
// finding when run_deduplicator was the caller.
func TestHuntPhase_NullCallResultIsRejectedAsNoneType(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	t.Run("a hunter returning null is noted and contributes an empty batch", func(t *testing.T) {
		answers := huntAnswers(t, strategies)
		spy := &callSpy{answers: answers, nullResults: map[string]bool{"run_ssrf_hunter": true}}
		fake := &appx.Fake{
			CallFn: spy.fn(),
			AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
		}

		result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
			nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
		if err != nil {
			t.Fatalf("HuntPhase: %v", err)
		}
		want := "Hunt strategy failed: ssrf: run_ssrf_hunter returned non-dict payload: NoneType"
		if !hasNote(fake, want, []string{"hunt", "error"}) {
			t.Errorf("missing note %q in %q", want, fake.NoteMessages())
		}
		if want := len(strategies) - 1; result["total_raw"] != want {
			t.Errorf("total_raw = %#v, want %d (the null hunter contributes 0)", result["total_raw"], want)
		}
	})

	t.Run("run_deduplicator returning null fails the phase", func(t *testing.T) {
		answers := huntAnswers(t, strategies)
		spy := &callSpy{answers: answers, nullResults: map[string]bool{"run_deduplicator": true}}
		fake := &appx.Fake{
			CallFn: spy.fn(),
			AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
		}

		_, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
			nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
		if err == nil {
			t.Fatal("a null run_deduplicator result must fail the phase, not silently drop every finding")
		}
		if want := "run_deduplicator returned non-dict payload: NoneType"; err.Error() != want {
			t.Errorf("err = %q, want %q", err.Error(), want)
		}
	})
}

// TestHuntPhase_NoFindingsSkipsDeduplicator is the `if deduped_findings:` guard.
func TestHuntPhase_NoFindingsSkipsDeduplicator(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	answers := map[string]json.RawMessage{}
	for _, s := range strategies {
		answers["run_"+s+"_hunter"] = json.RawMessage(`{"findings": [], "chains": []}`)
	}
	fake := &appx.Fake{
		CallFn: (&callSpy{answers: answers}).fn(),
		AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
	}

	result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	for _, target := range fake.CallTargets() {
		if target == "sec-af.run_deduplicator" {
			t.Error("run_deduplicator must not be called when no finding survived")
		}
	}
	if result["total_raw"] != 0 {
		t.Errorf("total_raw = %#v, want 0", result["total_raw"])
	}
	if got, ok := result["findings"].([]schemas.RawFinding); !ok || len(got) != 0 {
		t.Errorf("findings = %#v, want an empty list", result["findings"])
	}
}

// TestHuntPhase_IncrementalDedupSeedsFingerprints covers the consumer: a
// hunter that returns a finding WITHOUT a fingerprint gets the
// "file:line:cwe" seed, and a repeat of the same fingerprint is dropped.
func TestHuntPhase_IncrementalDedupSeedsFingerprints(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	// Every hunter returns the SAME unfingerprinted finding, so exactly one
	// survives and the rest are fingerprint duplicates.
	shared := `{
		"id": "shared",
		"hunter_strategy": "injection",
		"title": "same finding",
		"description": "d",
		"finding_type": "sast",
		"cwe_id": "CWE-89",
		"cwe_name": "n",
		"file_path": "app.py",
		"start_line": 42,
		"end_line": 42,
		"code_snippet": "x",
		"estimated_severity": "high",
		"confidence": "high",
		"fingerprint": ""
	}`
	answers := map[string]json.RawMessage{
		"run_deduplicator": json.RawMessage(`{"findings": [], "chains": []}`),
	}
	for _, s := range strategies {
		answers["run_"+s+"_hunter"] = json.RawMessage(`{"findings": [` + shared + `], "chains": []}`)
	}

	var forwarded []any
	fake := &appx.Fake{
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
	}
	base := (&callSpy{answers: answers}).fn()
	fake.CallFn = func(ctx context.Context, target string, input map[string]any) (map[string]any, error) {
		if target == "sec-af.run_deduplicator" {
			forwarded, _ = input["findings"].([]any)
		}
		return base(ctx, target, input)
	}

	if _, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold); err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}

	if len(forwarded) != 1 {
		t.Fatalf("deduplicator received %d findings, want 1 (the rest are fingerprint duplicates)", len(forwarded))
	}
	entry, _ := forwarded[0].(map[string]any)
	if got := entry["fingerprint"]; got != "app.py:42:CWE-89" {
		t.Errorf("seeded fingerprint = %#v, want %q", got, "app.py:42:CWE-89")
	}
}

// gateStub is the MockAIGate of tests/test_strategy_selection.py: it returns
// the first two default candidates.
type gateStub struct {
	calls      int
	reconSeen  string
	depthSeen  string
	candidates []string
	err        error
	answer     []string
}

func (g *gateStub) SelectStrategy(_ context.Context, reconSummary, depth string, defaultCandidates []string) (schemas.StrategySelection, error) {
	g.calls++
	g.reconSeen = reconSummary
	g.depthSeen = depth
	g.candidates = defaultCandidates
	if g.err != nil {
		return schemas.StrategySelection{}, g.err
	}
	return schemas.StrategySelection{Strategies: g.answer, Rationale: "Selected based on recon context"}, nil
}

// TestHuntPhase_AIGateSelection ports the selection logic
// tests/test_strategy_selection.py exercises through its MockAIGate, plus the
// two fallbacks the Python test does not reach.
func TestHuntPhase_AIGateSelection(t *testing.T) {
	reconCtx := reconContextFixture(t, "full")
	recon := reconFixture(t, "full")
	defaults := strategyValues(DefaultStrategies(recon, "standard"))

	run := func(t *testing.T, gate *gateStub) (map[string]any, *appx.Fake) {
		t.Helper()
		answers := huntAnswers(t, defaults)
		fake := &appx.Fake{
			CallFn: (&callSpy{answers: answers}).fn(),
			AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
		}
		result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "standard",
			gate, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
		if err != nil {
			t.Fatalf("HuntPhase: %v", err)
		}
		return result, fake
	}

	t.Run("subset selection narrows the hunters", func(t *testing.T) {
		gate := &gateStub{answer: defaults[:2]}
		result, fake := run(t, gate)

		if gate.calls != 1 {
			t.Fatalf("gate called %d times, want 1", gate.calls)
		}
		if !reflect.DeepEqual(gate.candidates, defaults) {
			t.Errorf("default_candidates = %v, want %v", gate.candidates, defaults)
		}
		if gate.depthSeen != "standard" {
			t.Errorf("depth = %q", gate.depthSeen)
		}
		if want := ReconSummaryString(recon); gate.reconSeen != want {
			t.Errorf("recon_summary\n got: %q\nwant: %q", gate.reconSeen, want)
		}
		if !reflect.DeepEqual(result["strategies_run"], defaults[:2]) {
			t.Errorf("strategies_run = %#v, want %v", result["strategies_run"], defaults[:2])
		}
		hunterCalls := 0
		for _, target := range fake.CallTargets() {
			if target != "sec-af.run_deduplicator" {
				hunterCalls++
			}
		}
		if hunterCalls != 2 {
			t.Errorf("hunter calls = %d, want 2", hunterCalls)
		}
	})

	t.Run("unknown names are dropped", func(t *testing.T) {
		gate := &gateStub{answer: []string{"injection", "not_a_strategy", "auth"}}
		result, _ := run(t, gate)
		if want := []string{"injection", "auth"}; !reflect.DeepEqual(result["strategies_run"], want) {
			t.Errorf("strategies_run = %#v, want %v", result["strategies_run"], want)
		}
	})

	t.Run("empty selection falls back to the defaults with a note", func(t *testing.T) {
		gate := &gateStub{answer: []string{"nope"}}
		result, fake := run(t, gate)
		if !reflect.DeepEqual(result["strategies_run"], defaults) {
			t.Errorf("strategies_run = %#v, want the full defaults", result["strategies_run"])
		}
		if !hasNote(fake, "AI gate returned no valid strategies, using defaults", []string{"hunt", "ai_gate"}) {
			t.Errorf("missing fallback note in %q", fake.NoteMessages())
		}
	})

	t.Run("gate failure falls back to the defaults with a note", func(t *testing.T) {
		gate := &gateStub{err: errors.New("gate down")}
		result, fake := run(t, gate)
		if !reflect.DeepEqual(result["strategies_run"], defaults) {
			t.Errorf("strategies_run = %#v, want the full defaults", result["strategies_run"])
		}
		if !hasNote(fake, "AI gate failed: gate down, using default strategies", []string{"hunt", "ai_gate", "error"}) {
			t.Errorf("missing gate-failure note in %q", fake.NoteMessages())
		}
	})

	t.Run("nil gate never consults the selector", func(t *testing.T) {
		var typedNil *gateStub
		answers := huntAnswers(t, defaults)
		fake := &appx.Fake{
			CallFn: (&callSpy{answers: answers}).fn(),
			AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
		}
		// A TYPED nil must behave like Python's None rather than panicking.
		result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "standard",
			typedNil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
		if err != nil {
			t.Fatalf("HuntPhase: %v", err)
		}
		if !reflect.DeepEqual(result["strategies_run"], defaults) {
			t.Errorf("strategies_run = %#v, want the full defaults", result["strategies_run"])
		}
	})
}

// TestHuntPhase_JSONAIGateEmitsTheAttributeErrorNote covers the `ai_gate`
// parameter a control-plane caller can send to the REGISTERED hunt_phase
// reasoner. Python binds the JSON value verbatim (`ai_gate: Any | None`), so
// `ai_gate is not None` is True, `ai_gate.select_strategy(...)` raises
// AttributeError, and hunt_phase's `except Exception as e` emits
//
//	AI gate failed: 'dict' object has no attribute 'select_strategy', using default strategies
//
// with tags ["hunt","ai_gate","error"] — VERIFIED by driving
// sec_af.reasoners.phases.hunt_phase on the repo interpreter. The strategy list
// is unchanged, so only the note stream differs.
func TestHuntPhase_JSONAIGateEmitsTheAttributeErrorNote(t *testing.T) {
	reconCtx := reconContextFixture(t, "full")
	recon := reconFixture(t, "full")
	defaults := strategyValues(DefaultStrategies(recon, "standard"))

	cases := []struct {
		raw    string
		pyType string
	}{
		{`{"model": "x"}`, "dict"},
		{`["a"]`, "list"},
		{`"gate"`, "str"},
		{`1`, "int"},
		{`1.5`, "float"},
		{`true`, "bool"},
	}
	for _, tc := range cases {
		t.Run(tc.pyType, func(t *testing.T) {
			answers := huntAnswers(t, defaults)
			fake := &appx.Fake{
				CallFn: (&callSpy{answers: answers}).fn(),
				AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
			}
			result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "standard",
				NewJSONAIGate(json.RawMessage(tc.raw)), DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
			if err != nil {
				t.Fatalf("HuntPhase: %v", err)
			}
			want := "AI gate failed: '" + tc.pyType + "' object has no attribute 'select_strategy', using default strategies"
			if !hasNote(fake, want, []string{"hunt", "ai_gate", "error"}) {
				t.Errorf("missing note %q in %q", want, fake.NoteMessages())
			}
			if !reflect.DeepEqual(result["strategies_run"], defaults) {
				t.Errorf("strategies_run = %#v, want the full defaults", result["strategies_run"])
			}
		})
	}

	// `ai_gate` absent or explicitly null is Python's None: no note, no branch.
	for _, raw := range []string{"", "null"} {
		answers := huntAnswers(t, defaults)
		fake := &appx.Fake{
			CallFn: (&callSpy{answers: answers}).fn(),
			AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
		}
		if gate := NewJSONAIGate(json.RawMessage(raw)); gate != nil {
			t.Fatalf("NewJSONAIGate(%q) = %v, want nil (Python's None)", raw, gate)
		}
		if _, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "standard",
			NewJSONAIGate(json.RawMessage(raw)), DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold); err != nil {
			t.Fatalf("HuntPhase: %v", err)
		}
		for _, msg := range fake.NoteMessages() {
			if strings.HasPrefix(msg, "AI gate failed") {
				t.Errorf("ai_gate=%q must take the None branch; got note %q", raw, msg)
			}
		}
	}
}

// TestHuntPhase_CWEExpansionNote fires only when the gate suggests something.
func TestHuntPhase_CWEExpansionNote(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	answers := map[string]json.RawMessage{}
	for _, s := range strategies {
		answers["run_"+s+"_hunter"] = json.RawMessage(`{"findings": [], "chains": []}`)
	}
	fake := &appx.Fake{
		CallFn: (&callSpy{answers: answers}).fn(),
		AIFn: appx.AIJSON(func(string) (json.RawMessage, error) {
			return json.RawMessage(`{"additional_cwes":["CWE-77","CWE-611","CWE-918"],"rationale":"r"}`), nil
		}),
	}
	if _, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold); err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	if !hasNote(fake, "CWE expansion suggested 3 additional CWEs", []string{"hunt", "ai_gate", "cwe_expansion"}) {
		t.Errorf("missing CWE-expansion note in %q", fake.NoteMessages())
	}
}

func hasNote(fake *appx.Fake, message string, tags []string) bool {
	for _, note := range fake.Notes {
		if note.Message == message && reflect.DeepEqual(note.Tags, tags) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// required-field validation on the .call boundaries
// ---------------------------------------------------------------------------
//
// pydantic's `Model.model_validate(payload)` raises on a missing required
// field, and each of these sites turns that into a different observable
// outcome. afx.Bind cannot express "required", so the phases use the checked
// binders in validate.go; these tests pin the resulting control flow.

// TestReconPhase_SecurityContextRequiresAuthFields: SecurityContext declares
// auth_model and auth_details with no default, so a profiler payload without
// them fails the phase rather than yielding an empty auth model.
func TestReconPhase_SecurityContextRequiresAuthFields(t *testing.T) {
	answers := reconAnswers()
	answers["run_security_context_profiler"] = json.RawMessage(`{"framework_security": ["Django"]}`)
	fake := &appx.Fake{CallFn: (&callSpy{answers: answers}).fn()}

	_, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "standard")
	if err == nil {
		t.Fatal("want a validation error for a security context with no auth_model/auth_details")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) || verr.Model != "SecurityContext" {
		t.Fatalf("err = %v, want a SecurityContext ValidationError", err)
	}
	if len(verr.Errors) != 2 {
		t.Errorf("errors = %v, want one per missing field", verr.Errors)
	}
}

// TestHuntPhase_MalformedReconContextFails: ReconResult declares its five
// nested models as required, so `ReconResult(**recon_context)` raises for a
// context that omits one.
func TestHuntPhase_MalformedReconContextFails(t *testing.T) {
	full := reconContextFixture(t, "full")
	delete(full, "dependencies")

	fake := &appx.Fake{}
	_, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", full, "standard",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
	if err == nil {
		t.Fatal("want a validation error for a recon context missing `dependencies`")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) || verr.Model != "ReconResult" {
		t.Fatalf("err = %v, want a ReconResult ValidationError", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("no hunter may run once the recon context failed to bind (%v)", fake.CallTargets())
	}
}

// TestHuntPhase_MalformedHunterResultIsNoted: a hunter whose payload carries a
// finding missing required fields is treated exactly like a hunter that raised
// — noted, and contributing an empty batch.
func TestHuntPhase_MalformedHunterResultIsNoted(t *testing.T) {
	reconCtx := reconContextFixture(t, "minimal")
	recon := reconFixture(t, "minimal")
	strategies := strategyValues(DefaultStrategies(recon, "quick"))

	answers := huntAnswers(t, strategies)
	answers["run_injection_hunter"] = json.RawMessage(`{"findings": [{"title": "no other fields"}], "chains": []}`)
	fake := &appx.Fake{
		CallFn: (&callSpy{answers: answers}).fn(),
		AIFn:   appx.AIJSON(func(string) (json.RawMessage, error) { return json.RawMessage(`{"additional_cwes":[]}`), nil }),
	}

	result, err := HuntPhase(context.Background(), fake, testNodeID, "/repo", reconCtx, "quick",
		nil, DefaultMaxConcurrentHunters, DefaultEarlyStopFileThreshold)
	if err != nil {
		t.Fatalf("HuntPhase: %v", err)
	}
	noted := false
	for _, msg := range fake.NoteMessages() {
		if len(msg) >= len("Hunt strategy failed: injection") && msg[:len("Hunt strategy failed: injection")] == "Hunt strategy failed: injection" {
			noted = true
		}
	}
	if !noted {
		t.Errorf("a malformed hunter payload must be noted; got %q", fake.NoteMessages())
	}
	if want := len(strategies) - 1; result["total_raw"] != want {
		t.Errorf("total_raw = %#v, want %d (the malformed hunter contributes 0)", result["total_raw"], want)
	}
}

// TestProvePhase_MalformedHuntResultFails: prove_phase's own
// `HuntResult.model_validate(hunt_result)` is outside any try, so a malformed
// finding aborts the reasoner.
func TestProvePhase_MalformedHuntResultFails(t *testing.T) {
	fake := &appx.Fake{}
	_, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
		map[string]any{"findings": []any{map[string]any{"title": "incomplete"}}},
		DefaultDepth, nil, DefaultMaxConcurrentProvers)
	if err == nil {
		t.Fatal("want a validation error for a hunt result with an incomplete finding")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) || verr.Model != "HuntResult" {
		t.Fatalf("err = %v, want a HuntResult ValidationError", err)
	}
	if len(fake.Calls) != 0 {
		t.Error("no verifier may run once the hunt result failed to bind")
	}
}

// TestReconPhase_ValidatesEveryChildPayload is the recon_phase half of the
// depth rule validate.go states: all four child `.call` payloads are
// `Model.model_validate(...)` in Python (reasoners/phases.py:163-188), so a
// nested entry that is missing a required field must FAIL the phase.
//
// Validation contract (behaviour, derived from the pinned interpreter — each
// payload below was run through the real pydantic model and the error count is
// what it reported):
//
//   - run_architecture_mapper -> {"modules":[{"name":"x"}]} raises
//     (2 errors: modules.0.path, modules.0.language);
//   - run_dependency_auditor  -> {"sbom":[{"name":"a"}]} raises
//     (3 errors: version, ecosystem, direct);
//   - run_config_scanner      -> a secrets[] entry with no `confidence` raises
//     (1 error);
//   - run_data_flow_mapper    -> a flows[] entry with no `sanitized` raises
//     (1 error);
//   - the failure PROPAGATES: recon_phase returns an error rather than a
//     zero-filled ReconResult.
//
// The regression this pins is laundering. Before the fix these four sites used
// a bare afx.Bind, which zero-fills the missing keys; afx.ToMap then re-emitted
// the subtree with EVERY key present, so the checked phases.BindReconResult the
// caller runs (node/audit.go) accepted the tree and the malformed mapper output
// became a successful audit with a silently zero-filled architecture.
func TestReconPhase_ValidatesEveryChildPayload(t *testing.T) {
	for _, tc := range []struct {
		reasoner string
		payload  string
		problem  string
	}{
		{"run_architecture_mapper", `{"modules":[{"name":"x"}]}`, "modules.0.path: field required"},
		{"run_dependency_auditor", `{"sbom":[{"name":"a"}]}`, "sbom.0.version: field required"},
		{"run_config_scanner",
			`{"secrets":[{"secret_type":"aws","file_path":"f","line":1,"match":"m"}]}`,
			"secrets.0.confidence: field required"},
		{"run_data_flow_mapper", `{"flows":[{"source":"s","sink":"k"}]}`, "flows.0.sanitized: field required"},
	} {
		t.Run(tc.reasoner, func(t *testing.T) {
			answers := reconAnswers()
			answers[tc.reasoner] = json.RawMessage(tc.payload)
			fake := &appx.Fake{CallFn: (&callSpy{answers: answers}).fn()}

			_, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "standard")
			if err == nil {
				t.Fatalf("ReconPhase accepted a %s payload pydantic rejects", tc.reasoner)
			}
			var verr *ValidationError
			if !errors.As(err, &verr) {
				t.Fatalf("error = %T (%v), want *phases.ValidationError", err, err)
			}
			if !strings.Contains(err.Error(), tc.problem) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.problem)
			}
		})
	}
}

// TestReconPhase_MalformedChildIsNotLaunderedPastBindReconResult states the
// same contract end to end, and pins the MECHANISM that made the bug invisible.
//
// Contract: whatever recon_phase returns is re-bound by its caller with the
// checked `ReconResult(**recon_context)` (node/audit.go, hunt_phase,
// run_deduplicator). That later bind cannot be the safety net, because a
// loosely-bound child is zero-FILLED — every required key is present in the
// re-serialised tree, so the checked bind passes. The phase itself is the only
// place the malformed payload is still recognisable.
func TestReconPhase_MalformedChildIsNotLaunderedPastBindReconResult(t *testing.T) {
	malformed := map[string]any{"modules": []any{map[string]any{"name": "x"}}}

	// 1. The checked binder rejects it, exactly as pydantic does.
	if _, err := BindArchitectureMap(malformed); err == nil {
		t.Fatal("BindArchitectureMap accepted a payload pydantic rejects")
	}

	// 2. The loose bind accepts it and zero-fills, and the zero-filled tree
	//    then passes the caller's checked ReconResult bind — the laundering.
	loose, err := afx.Bind[schemas.ArchitectureMap](malformed)
	if err != nil {
		t.Fatalf("afx.Bind: %v", err)
	}
	if len(loose.Modules) != 1 || loose.Modules[0].Path != "" || loose.Modules[0].Language != "" {
		t.Fatalf("afx.Bind did not zero-fill as expected: %+v", loose.Modules)
	}
	launderable := roundTripJSON(t, map[string]any{
		"architecture":     loose,
		"data_flows":       schemas.NewDataFlowMap(),
		"dependencies":     schemas.NewDependencyReport(),
		"config":           schemas.NewConfigReport(),
		"security_context": map[string]any{"auth_model": "a", "auth_details": "b"},
	})
	if _, err := BindReconResult(launderable); err != nil {
		t.Fatalf("the zero-filled tree was expected to pass the downstream bind "+
			"(that is why the phase must validate); got %v", err)
	}

	// 3. Therefore the phase must fail at the child boundary.
	answers := reconAnswers()
	answers["run_architecture_mapper"] = json.RawMessage(`{"modules":[{"name":"x"}]}`)
	fake := &appx.Fake{CallFn: (&callSpy{answers: answers}).fn()}
	if _, err := ReconPhase(context.Background(), fake, testNodeID, t.TempDir(), "standard"); err == nil {
		t.Fatal("recon_phase accepted a malformed architecture: the payload was laundered " +
			"into a successful audit with a zero-filled module")
	}
}

// roundTripJSON re-decodes a phase result the way the control plane delivers it
// to the caller: marshal, then unmarshal into map[string]any.
func roundTripJSON(t *testing.T, v map[string]any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal phase result: %v", err)
	}
	var out map[string]any
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal phase result: %v", err)
	}
	return out
}
