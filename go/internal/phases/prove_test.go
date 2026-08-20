package phases

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// provePhaseInput reads the hunt_result the Python demotion test uses.
func provePhaseInput(t *testing.T) map[string]any {
	t.Helper()
	return readJSON[map[string]any](t, "prove_phase_input.json")
}

// normalizeJSON re-marshals v and decodes it back into plain JSON values so two
// results can be compared without caring whether a number arrived as an int or
// a float64 (Python's model_dump keeps ints; the Go port's exclude-none filter
// round-trips through JSON and yields float64 — see dumpExcludeNone).
func normalizeJSON(t *testing.T, v any) any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	return out
}

// verifierRouter is the _RouterStub of tests/test_prove_phase_demotion.py: it
// answers run_verifier with one canned payload and rejects anything else.
func verifierRouter(payload json.RawMessage, delay time.Duration) func(context.Context, string, map[string]any) (map[string]any, error) {
	return func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		if delay > 0 {
			time.Sleep(delay)
		}
		if target != "sec-af.run_verifier" {
			return nil, errors.New("unexpected call: " + target)
		}
		var out map[string]any
		if err := json.Unmarshal(json.RawMessage(`{"output": `+string(payload)+`}`), &out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// TestProvePhase_DemotesUnverifiedVerdict ports
// tests/test_prove_phase_demotion.py::test_prove_phase_demotes_unverified_verdict
// and additionally compares the WHOLE result against the golden the Python
// function produced for the same input.
func TestProvePhase_DemotesUnverifiedVerdict(t *testing.T) {
	payload := json.RawMessage(`{
		"id": "raw-1",
		"fingerprint": "fp-1",
		"title": "Potential SQL injection",
		"description": "Potential injection from request parameter",
		"finding_type": "sast",
		"cwe_id": "CWE-89",
		"cwe_name": "SQL Injection",
		"verdict": "unverified",
		"evidence_level": 1,
		"rationale": "Could not fully verify",
		"severity": "high",
		"exploitability_score": 0.0,
		"location": {
			"file_path": "src/users.py",
			"start_line": 10,
			"end_line": 12,
			"code_snippet": "cursor.execute(f\"SELECT * FROM users WHERE id = {user_id}\")"
		},
		"sarif_rule_id": "sec-af/sast/sql-injection",
		"sarif_security_severity": 0.0
	}`)

	fake := &appx.Fake{CallFn: verifierRouter(payload, 0)}
	result, err := ProvePhase(context.Background(), fake, testNodeID, "/tmp/repo",
		provePhaseInput(t), DefaultDepth, nil, DefaultMaxConcurrentProvers)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}

	// --- the four assertions of the Python test ---------------------------
	dropSummary := result["drop_summary"].(map[string]any)
	if dropSummary["demoted_total"] != 1 {
		t.Errorf("demoted_total = %v, want 1", dropSummary["demoted_total"])
	}
	verified := result["verified"].([]any)
	if len(verified) != 1 {
		t.Fatalf("verified length = %d, want 1", len(verified))
	}
	first := verified[0].(map[string]any)
	if first["verdict"] != string(schemas.VerdictInconclusive) {
		t.Errorf("verdict = %v, want inconclusive", first["verdict"])
	}
	if first["drop_reason"] != "verdict_unverified" {
		t.Errorf("drop_reason = %v, want verdict_unverified", first["drop_reason"])
	}
	tags, _ := first["tags"].([]any)
	if !containsAny(tags, "low_confidence") {
		t.Errorf("tags = %v, want to contain low_confidence", tags)
	}

	// --- the whole result, against Python's own output --------------------
	want := readJSON[any](t, "golden/prove_phase_unverified.json")
	if got := normalizeJSON(t, result); !reflect.DeepEqual(got, want) {
		gotJSON, _ := json.MarshalIndent(got, "", "  ")
		wantJSON, _ := json.MarshalIndent(want, "", "  ")
		t.Errorf("prove_phase result differs from the Python golden\n got: %s\nwant: %s", gotJSON, wantJSON)
	}

	wantNotes := readJSON[[]string](t, "golden/prove_phase_unverified_notes.json")
	if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
		t.Errorf("notes\n got: %q\nwant: %q", fake.NoteMessages(), wantNotes)
	}
	// The demotion note carries phases' own tag triple.
	if !reflect.DeepEqual(fake.Notes[1].Tags, []string{"prove", "drop", "demotion"}) {
		t.Errorf("demotion tags = %v", fake.Notes[1].Tags)
	}
}

// TestProvePhase_DemotesParseFailure ports
// tests/test_prove_phase_demotion.py::test_prove_phase_demotes_parse_failure.
//
// The payload `{"title": "malformed"}` is missing every required VerifiedFinding
// field, so pydantic's model_validate raises and the finding is demoted with
// drop_reason "schema_parse_failure". BindVerifiedFinding is what reproduces
// that check in Go (afx.Bind alone would happily default-seed the payload).
func TestProvePhase_DemotesParseFailure(t *testing.T) {
	fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"title": "malformed"}`), 0)}
	result, err := ProvePhase(context.Background(), fake, testNodeID, "/tmp/repo",
		provePhaseInput(t), DefaultDepth, nil, DefaultMaxConcurrentProvers)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}

	dropSummary := result["drop_summary"].(map[string]any)
	if dropSummary["demoted_total"] != 1 {
		t.Errorf("demoted_total = %v, want 1", dropSummary["demoted_total"])
	}
	first := result["verified"].([]any)[0].(map[string]any)
	if first["verdict"] != string(schemas.VerdictInconclusive) {
		t.Errorf("verdict = %v, want inconclusive", first["verdict"])
	}
	if first["drop_reason"] != "schema_parse_failure" {
		t.Errorf("drop_reason = %v, want schema_parse_failure", first["drop_reason"])
	}
	// The demoted finding keeps the RAW finding's identity, not the payload's.
	if first["title"] != "Potential SQL injection" {
		t.Errorf("title = %v, want the raw finding's title", first["title"])
	}
	byReason := dropSummary["by_reason"].(map[string]int)
	if byReason["schema_parse_failure"] != 1 {
		t.Errorf("by_reason = %v", byReason)
	}
}

// TestProvePhase_DemotionReasons walks the remaining classification branches.
func TestProvePhase_DemotionReasons(t *testing.T) {
	cases := []struct {
		name       string
		callFn     func(context.Context, string, map[string]any) (map[string]any, error)
		wantReason string
		// wantVerdictInSummary is the original_verdict recorded in drop_summary.
		wantVerdictInSummary any
	}{
		{
			name: "call failure is verifier_error",
			callFn: func(context.Context, string, map[string]any) (map[string]any, error) {
				return nil, errors.New("transport down")
			},
			wantReason:           "verifier_error",
			wantVerdictInSummary: nil,
		},
		{
			name: "error envelope is schema_parse_failure",
			callFn: func(context.Context, string, map[string]any) (map[string]any, error) {
				return map[string]any{"error": map[string]any{"message": "nope"}}, nil
			},
			wantReason:           "schema_parse_failure",
			wantVerdictInSummary: nil,
		},
		{
			name: "non-dict payload is schema_parse_failure",
			callFn: func(context.Context, string, map[string]any) (map[string]any, error) {
				return map[string]any{"output": "a string, not a dict"}, nil
			},
			wantReason:           "schema_parse_failure",
			wantVerdictInSummary: nil,
		},
		{
			name:   "UNVERIFIED is matched case-insensitively",
			callFn: verifierRouter(json.RawMessage(`{"verdict": "UNVERIFIED"}`), 0),
			// The unverified branch fires BEFORE model_validate, so the missing
			// required fields never matter.
			wantReason:           "verdict_unverified",
			wantVerdictInSummary: "UNVERIFIED",
		},
		{
			name:       "non-string verdict falls through to model_validate",
			callFn:     verifierRouter(json.RawMessage(`{"verdict": 7}`), 0),
			wantReason: "schema_parse_failure",
			// Python: str(7) — the control plane decoded the JSON literal 7 to
			// an int, so there is no ".0". See phases.pyStr.
			wantVerdictInSummary: "7",
		},
		{
			name:                 "unknown verdict string fails the enum check",
			callFn:               verifierRouter(json.RawMessage(`{"verdict": "maybe"}`), 0),
			wantReason:           "schema_parse_failure",
			wantVerdictInSummary: "maybe",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			fake := &appx.Fake{CallFn: tc.callFn}
			result, err := ProvePhase(context.Background(), fake, testNodeID, "/tmp/repo",
				provePhaseInput(t), DefaultDepth, nil, DefaultMaxConcurrentProvers)
			if err != nil {
				t.Fatalf("ProvePhase: %v", err)
			}
			dropSummary := result["drop_summary"].(map[string]any)
			byReason := dropSummary["by_reason"].(map[string]int)
			if byReason[tc.wantReason] != 1 {
				t.Errorf("by_reason = %v, want %s=1", byReason, tc.wantReason)
			}
			entries := dropSummary["findings"].([]map[string]any)
			if len(entries) != 1 {
				t.Fatalf("drop entries = %d, want 1", len(entries))
			}
			if entries[0]["original_verdict"] != tc.wantVerdictInSummary {
				t.Errorf("original_verdict = %#v, want %#v", entries[0]["original_verdict"], tc.wantVerdictInSummary)
			}
			first := result["verified"].([]any)[0].(map[string]any)
			if first["drop_reason"] != tc.wantReason {
				t.Errorf("drop_reason = %v, want %s", first["drop_reason"], tc.wantReason)
			}
		})
	}
}

// TestProvePhase_ValidPayloadIsKept: the happy path binds the payload with no
// demotion at all.
func TestProvePhase_ValidPayloadIsKept(t *testing.T) {
	payload := json.RawMessage(`{
		"id": "verified-1",
		"fingerprint": "fp-1",
		"title": "Confirmed SQLi",
		"description": "d",
		"finding_type": "sast",
		"cwe_id": "CWE-89",
		"cwe_name": "SQL Injection",
		"tags": ["externally_reachable"],
		"verdict": "confirmed",
		"evidence_level": 5,
		"rationale": "traced",
		"severity": "critical",
		"exploitability_score": 9.1,
		"location": {"file_path": "src/users.py", "start_line": 10, "end_line": 12},
		"sarif_rule_id": "sec-af/sast/sql-injection",
		"sarif_security_severity": 9.1
	}`)
	fake := &appx.Fake{CallFn: verifierRouter(payload, 0)}
	result, err := ProvePhase(context.Background(), fake, testNodeID, "/tmp/repo",
		provePhaseInput(t), DefaultDepth, nil, DefaultMaxConcurrentProvers)
	if err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	dropSummary := result["drop_summary"].(map[string]any)
	if dropSummary["demoted_total"] != 0 {
		t.Errorf("demoted_total = %v, want 0", dropSummary["demoted_total"])
	}
	first := result["verified"].([]any)[0].(map[string]any)
	if first["verdict"] != "confirmed" || first["id"] != "verified-1" {
		t.Errorf("verified[0] = %v", first)
	}
	// exclude_none: the untouched optionals must be ABSENT, not null.
	for _, key := range []string{"drop_reason", "proof", "remediation", "cvss_v4", "epss", "chain_id"} {
		if _, present := first[key]; present {
			t.Errorf("model_dump(exclude_none=True) must omit %q", key)
		}
	}
}

// TestProvePhase_CallContract pins the run_verifier target and kwargs.
func TestProvePhase_CallContract(t *testing.T) {
	fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"verdict": "unverified"}`), 0)}
	if _, err := ProvePhase(context.Background(), fake, testNodeID, "/tmp/repo",
		provePhaseInput(t), "thorough", nil, DefaultMaxConcurrentProvers); err != nil {
		t.Fatalf("ProvePhase: %v", err)
	}
	if len(fake.Calls) != 1 {
		t.Fatalf("call count = %d, want 1", len(fake.Calls))
	}
	call := fake.Calls[0]
	if call.Target != "sec-af.run_verifier" {
		t.Errorf("target = %q", call.Target)
	}
	if want := []string{"depth", "finding", "repo_path"}; !reflect.DeepEqual(sortedMapKeys(call.Input), want) {
		t.Errorf("kwargs = %v, want %v", sortedMapKeys(call.Input), want)
	}
	if call.Input["depth"] != "thorough" {
		t.Errorf("depth = %v", call.Input["depth"])
	}
	// finding is the for_verifier() PROJECTION, not the whole RawFinding.
	finding, ok := call.Input["finding"].(map[string]any)
	if !ok {
		t.Fatalf("finding kwarg = %#v, want a map", call.Input["finding"])
	}
	want := []string{
		"code_snippet", "cwe_id", "data_flow_summary", "description", "end_line",
		"file_path", "function_name", "id", "start_line", "title",
	}
	if got := sortedMapKeys(finding); !reflect.DeepEqual(got, want) {
		t.Errorf("for_verifier keys = %v, want %v", got, want)
	}
}

// TestProvePhase_CapAndConcurrency: the prover cap truncates the prioritized
// list and the semaphore bounds the fan-out.
func TestProvePhase_CapAndConcurrency(t *testing.T) {
	findings := findingsFixture(t) // 5 findings
	huntResult := map[string]any{
		"findings":            toAnyList(t, findings),
		"chains":              []any{},
		"total_raw":           len(findings),
		"deduplicated_count":  len(findings),
		"chain_count":         0,
		"strategies_run":      []any{"injection"},
		"hunt_duration_secon": 0.0,
	}

	t.Run("max_provers caps the selection", func(t *testing.T) {
		cap2 := 2
		fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"verdict": "unverified"}`), 0)}
		result, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
			huntResult, "standard", &cap2, DefaultMaxConcurrentProvers)
		if err != nil {
			t.Fatalf("ProvePhase: %v", err)
		}
		if len(fake.Calls) != 2 {
			t.Errorf("run_verifier calls = %d, want 2", len(fake.Calls))
		}
		if result["total_selected"] != 2 {
			t.Errorf("total_selected = %v, want 2", result["total_selected"])
		}
		if result["total_findings"] != 5 {
			t.Errorf("total_findings = %v, want 5", result["total_findings"])
		}
		if result["not_verified"] != 3 {
			t.Errorf("not_verified = %v, want 3", result["not_verified"])
		}
	})

	t.Run("a zero cap selects nothing and calls nothing", func(t *testing.T) {
		zero := 0
		fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"verdict": "unverified"}`), 0)}
		result, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
			huntResult, "standard", &zero, DefaultMaxConcurrentProvers)
		if err != nil {
			t.Fatalf("ProvePhase: %v", err)
		}
		if len(fake.Calls) != 0 {
			t.Errorf("run_verifier calls = %d, want 0", len(fake.Calls))
		}
		if result["not_verified"] != 5 {
			t.Errorf("not_verified = %v, want 5", result["not_verified"])
		}
		if verified := result["verified"].([]any); len(verified) != 0 {
			t.Errorf("verified = %v, want empty", verified)
		}
	})

	t.Run("semaphore bounds the fan-out", func(t *testing.T) {
		fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"verdict": "unverified"}`), 25*time.Millisecond)}
		if _, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
			huntResult, "standard", nil, 2); err != nil {
			t.Fatalf("ProvePhase: %v", err)
		}
		if got := fake.MaxConcurrentCalls(); got > 2 {
			t.Errorf("max concurrent provers = %d, want <= 2", got)
		}
		if got := fake.MaxConcurrentCalls(); got != 2 {
			t.Errorf("max concurrent provers = %d, want exactly 2", got)
		}
	})

	t.Run("selection follows the prioritized order", func(t *testing.T) {
		cap1 := 1
		fake := &appx.Fake{CallFn: verifierRouter(json.RawMessage(`{"verdict": "unverified"}`), 0)}
		if _, err := ProvePhase(context.Background(), fake, testNodeID, "/repo",
			huntResult, "standard", &cap1, DefaultMaxConcurrentProvers); err != nil {
			t.Fatalf("ProvePhase: %v", err)
		}
		finding := fake.Calls[0].Input["finding"].(map[string]any)
		if finding["id"] != "critical-low" {
			t.Errorf("first verified finding = %v, want the critical one", finding["id"])
		}
	})
}

func toAnyList(t *testing.T, findings []schemas.RawFinding) []any {
	t.Helper()
	out := make([]any, 0, len(findings))
	for i := range findings {
		b, err := json.Marshal(findings[i])
		if err != nil {
			t.Fatalf("marshal finding: %v", err)
		}
		var m map[string]any
		if err := json.Unmarshal(b, &m); err != nil {
			t.Fatalf("decode finding: %v", err)
		}
		out = append(out, m)
	}
	return out
}

func containsAny(list []any, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// remediation_phase
// ---------------------------------------------------------------------------

func verifiedFindingJSON(id string, verdict schemas.Verdict, withRemediation bool) string {
	remediation := ""
	if withRemediation {
		remediation = `, "remediation": {"fix_description": "already fixed", "patch_diff": "d", "confidence": "high"}`
	}
	return `{
		"id": "` + id + `",
		"fingerprint": "fp-` + id + `",
		"title": "finding ` + id + `",
		"description": "d",
		"finding_type": "sast",
		"cwe_id": "CWE-89",
		"cwe_name": "SQL Injection",
		"tags": [],
		"verdict": "` + string(verdict) + `",
		"evidence_level": 3,
		"rationale": "r",
		"severity": "high",
		"exploitability_score": 1.0,
		"location": {"file_path": "a.py", "start_line": 1, "end_line": 1},
		"sarif_rule_id": "sec-af/sast/sql-injection",
		"sarif_security_severity": 1.0` + remediation + `
	}`
}

func verifiedInputs(t *testing.T, raws ...string) []map[string]any {
	t.Helper()
	out := make([]map[string]any, 0, len(raws))
	for _, raw := range raws {
		var m map[string]any
		if err := json.Unmarshal([]byte(raw), &m); err != nil {
			t.Fatalf("decode verified finding: %v", err)
		}
		out = append(out, m)
	}
	return out
}

// TestRemediationPhase_EligibilityAndDAG pins which findings get a
// run_remediation child and what the call carries.
func TestRemediationPhase_EligibilityAndDAG(t *testing.T) {
	inputs := verifiedInputs(t,
		verifiedFindingJSON("confirmed", schemas.VerdictConfirmed, false),
		verifiedFindingJSON("likely", schemas.VerdictLikely, false),
		verifiedFindingJSON("inconclusive", schemas.VerdictInconclusive, false),
		verifiedFindingJSON("not-exploitable", schemas.VerdictNotExploitable, false),
		verifiedFindingJSON("already-fixed", schemas.VerdictConfirmed, true),
	)

	fake := &appx.Fake{CallFn: func(_ context.Context, target string, _ map[string]any) (map[string]any, error) {
		if target != "sec-af.run_remediation" {
			return nil, errors.New("unexpected call: " + target)
		}
		time.Sleep(15 * time.Millisecond)
		return map[string]any{
			"output": map[string]any{
				"fix_description": "use a parameterised query",
				"patch_diff":      "--- a\n+++ b",
				"confidence":      "high",
			},
		}, nil
	}}

	result, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", inputs, DefaultMaxConcurrentRemediations)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}

	// Only the confirmed/likely findings WITHOUT a remediation are eligible.
	if len(fake.Calls) != 2 {
		t.Fatalf("run_remediation calls = %d, want 2", len(fake.Calls))
	}
	seen := map[string]bool{}
	for _, call := range fake.Calls {
		if call.Target != "sec-af.run_remediation" {
			t.Errorf("target = %q", call.Target)
		}
		if want := []string{"finding", "repo_path"}; !reflect.DeepEqual(sortedMapKeys(call.Input), want) {
			t.Errorf("kwargs = %v, want %v", sortedMapKeys(call.Input), want)
		}
		finding := call.Input["finding"].(map[string]any)
		seen[finding["id"].(string)] = true
		// model_dump() — NOT exclude_none — so the null optionals are present.
		if _, present := finding["drop_reason"]; !present {
			t.Error("run_remediation must receive the FULL model_dump, nulls included")
		}
	}
	if !seen["confirmed"] || !seen["likely"] {
		t.Errorf("remediated ids = %v, want confirmed + likely", sortedKeys(seen))
	}

	// Every finding comes back, in input order, and only the eligible two grew
	// a remediation.
	verified := result["verified"].([]any)
	if len(verified) != 5 {
		t.Fatalf("verified length = %d, want 5", len(verified))
	}
	for i, want := range []string{"confirmed", "likely", "inconclusive", "not-exploitable", "already-fixed"} {
		entry := verified[i].(map[string]any)
		if entry["id"] != want {
			t.Errorf("verified[%d].id = %v, want %v", i, entry["id"], want)
		}
	}
	for _, i := range []int{0, 1} {
		remediation, ok := verified[i].(map[string]any)["remediation"].(map[string]any)
		if !ok {
			t.Fatalf("verified[%d] has no remediation", i)
		}
		if remediation["fix_description"] != "use a parameterised query" {
			t.Errorf("verified[%d].remediation = %v", i, remediation)
		}
	}
	for _, i := range []int{2, 3} {
		if _, present := verified[i].(map[string]any)["remediation"]; present {
			t.Errorf("verified[%d] must keep remediation absent (exclude_none)", i)
		}
	}
	if got := verified[4].(map[string]any)["remediation"].(map[string]any)["fix_description"]; got != "already fixed" {
		t.Errorf("pre-existing remediation was overwritten: %v", got)
	}

	if got := fake.MaxConcurrentCalls(); got > DefaultMaxConcurrentRemediations {
		t.Errorf("max concurrent remediations = %d, want <= %d", got, DefaultMaxConcurrentRemediations)
	}

	wantNotes := []string{"REMEDIATION phase starting", "REMEDIATION phase complete: 2/2 generated"}
	if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
		t.Errorf("notes\n got: %q\nwant: %q", fake.NoteMessages(), wantNotes)
	}
}

// TestRemediationPhase_NothingToDo is the early-return branch.
func TestRemediationPhase_NothingToDo(t *testing.T) {
	inputs := verifiedInputs(t, verifiedFindingJSON("inconclusive", schemas.VerdictInconclusive, false))
	fake := &appx.Fake{}

	result, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", inputs, DefaultMaxConcurrentRemediations)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}
	if len(fake.Calls) != 0 {
		t.Errorf("call count = %d, want 0", len(fake.Calls))
	}
	wantNotes := []string{"REMEDIATION phase starting", "No findings need remediation"}
	if !reflect.DeepEqual(fake.NoteMessages(), wantNotes) {
		t.Errorf("notes\n got: %q\nwant: %q", fake.NoteMessages(), wantNotes)
	}
	if !reflect.DeepEqual(fake.Notes[1].Tags, []string{"phase", "remediation", "done"}) {
		t.Errorf("tags = %v", fake.Notes[1].Tags)
	}
	if len(result["verified"].([]any)) != 1 {
		t.Error("the untouched finding must still be returned")
	}
}

// TestRemediationPhase_FailuresAreSwallowed: a failing call and a malformed
// payload both leave the finding without a remediation and out of the tally.
func TestRemediationPhase_FailuresAreSwallowed(t *testing.T) {
	inputs := verifiedInputs(t,
		verifiedFindingJSON("call-fails", schemas.VerdictConfirmed, false),
		verifiedFindingJSON("bad-payload", schemas.VerdictConfirmed, false),
		verifiedFindingJSON("ok", schemas.VerdictLikely, false),
	)

	fake := &appx.Fake{CallFn: func(_ context.Context, _ string, input map[string]any) (map[string]any, error) {
		id := input["finding"].(map[string]any)["id"]
		switch id {
		case "call-fails":
			return nil, errors.New("remediation agent down")
		case "bad-payload":
			// A dict that is not a RemediationSuggestion: model_validate raises
			// and `except Exception: pass` swallows it.
			return map[string]any{"output": map[string]any{"unexpected": true}}, nil
		default:
			return map[string]any{"output": map[string]any{
				"fix_description": "f", "patch_diff": "p", "confidence": "medium",
			}}, nil
		}
	}}

	result, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo", inputs, DefaultMaxConcurrentRemediations)
	if err != nil {
		t.Fatalf("RemediationPhase: %v", err)
	}
	verified := result["verified"].([]any)
	for _, i := range []int{0, 1} {
		if _, present := verified[i].(map[string]any)["remediation"]; present {
			t.Errorf("verified[%d] must have no remediation", i)
		}
	}
	if _, present := verified[2].(map[string]any)["remediation"]; !present {
		t.Error("the successful finding must carry its remediation")
	}
	if got := fake.NoteMessages()[len(fake.NoteMessages())-1]; got != "REMEDIATION phase complete: 1/3 generated" {
		t.Errorf("completion note = %q, want `REMEDIATION phase complete: 1/3 generated`", got)
	}
}

// TestRemediationPhase_InvalidInputPropagates: the list comprehension is
// outside any try, so a malformed VerifiedFinding aborts the reasoner.
func TestRemediationPhase_InvalidInputPropagates(t *testing.T) {
	fake := &appx.Fake{}
	_, err := RemediationPhase(context.Background(), fake, testNodeID, "/repo",
		[]map[string]any{{"title": "malformed"}}, DefaultMaxConcurrentRemediations)
	if err == nil {
		t.Fatal("want a validation error for a malformed verified finding")
	}
	var verr *ValidationError
	if !errors.As(err, &verr) || verr.Model != "VerifiedFinding" {
		t.Errorf("err = %v, want a VerifiedFinding ValidationError", err)
	}
}
