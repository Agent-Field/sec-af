package prove

// Tests for assembler.go and the two other pure helpers verifier.py exposes
// (Fallback, sarifRuleID), all pinned against the Python goldens.
//
// Validation contract (behaviour, not implementation):
//   - assembling four sub-agent outputs yields exactly the VerifiedFinding
//     Python's assemble_verified_finding produces, field for field;
//   - an unrecognised verdict word degrades to "inconclusive";
//   - an out-of-range evidence level is clamped into 1..6;
//   - NOT_EXPLOITABLE suppresses the reproduction steps, every other verdict
//     emits the two-step recipe carrying the exploit payload;
//   - Fallback demotes to inconclusive/static_match with a zero score, adds
//     "low_confidence" only when a drop reason is given, and appends the
//     original verdict to the rationale only when one is given.

import (
	"reflect"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

func TestAssembleVerifiedFindingGolden(t *testing.T) {
	var want map[string]any
	goldenJSON(t, "assemble", &want)

	rich, bare := findingRich(), findingBare()
	cases := map[string]schemas.VerifiedFinding{
		"confirmed": AssembleVerifiedFinding(rich, traceRich(), sanitizationRich(), exploitRich(),
			verdictDecision("confirmed", 5)),
		"not_exploitable": AssembleVerifiedFinding(rich, traceRich(), sanitizationRich(), exploitRich(),
			verdictDecision("not_exploitable", 1)),
		"unknown_verdict": AssembleVerifiedFinding(bare, traceBare(), sanitizationBare(), exploitBare(),
			verdictDecision("unverified", 9)),
		"clamped_low": AssembleVerifiedFinding(bare, traceBare(), sanitizationBare(), exploitBare(),
			verdictDecision("likely", 0)),
	}
	if len(cases) != len(want) {
		t.Fatalf("case count drift: go has %d, golden has %d", len(cases), len(want))
	}
	for name, got := range cases {
		if !reflect.DeepEqual(jsonTree(t, got), want[name]) {
			t.Errorf("assemble[%s] mismatch:\n got: %#v\nwant: %#v", name, jsonTree(t, got), want[name])
		}
	}
}

// TestAssembleVerdictMapping pins the _VERDICT_MAP lookup and its default.
func TestAssembleVerdictMapping(t *testing.T) {
	for in, want := range map[string]schemas.Verdict{
		"confirmed":       schemas.VerdictConfirmed,
		"likely":          schemas.VerdictLikely,
		"inconclusive":    schemas.VerdictInconclusive,
		"not_exploitable": schemas.VerdictNotExploitable,
		"unverified":      schemas.VerdictInconclusive, // unknown -> default
		"":                schemas.VerdictInconclusive,
		"CONFIRMED":       schemas.VerdictInconclusive, // the map is case-SENSITIVE
	} {
		got := AssembleVerifiedFinding(findingBare(), traceBare(), sanitizationBare(), exploitBare(),
			verdictDecision(in, 3)).Verdict
		if got != want {
			t.Errorf("verdict %q -> %q, want %q", in, got, want)
		}
	}
}

// TestToEvidenceLevelClamp pins `max(1, min(6, level))`.
func TestToEvidenceLevelClamp(t *testing.T) {
	for in, want := range map[int]schemas.EvidenceLevel{
		-5: 1, 0: 1, 1: 1, 3: 3, 6: 6, 7: 6, 99: 6,
	} {
		if got := toEvidenceLevel(in); got != want {
			t.Errorf("toEvidenceLevel(%d) = %d, want %d", in, got, want)
		}
	}
}

// TestToDataFlowStepsNumbering pins the 1-based enumerate and the synthetic
// file/line handles.
func TestToDataFlowStepsNumbering(t *testing.T) {
	got := toDataFlowSteps(schemas.DataFlowTrace{Steps: []string{"a", "b", "c"}})
	want := []schemas.DataFlowStep{
		{File: "trace_step_1", Line: 1, Description: "a", Tainted: true},
		{File: "trace_step_2", Line: 2, Description: "b", Tainted: true},
		{File: "trace_step_3", Line: 3, Description: "c", Tainted: true},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("toDataFlowSteps = %+v, want %+v", got, want)
	}
	// An empty trace yields an empty (non-nil) list, so Proof.data_flow_trace
	// marshals as [] rather than null.
	if empty := toDataFlowSteps(schemas.DataFlowTrace{}); empty == nil || len(empty) != 0 {
		t.Errorf("empty trace must give a non-nil empty slice, got %#v", empty)
	}
}

// TestReproductionStepsCarryExploit pins _reproduction_steps' two branches.
func TestReproductionStepsCarryExploit(t *testing.T) {
	if got := reproductionSteps(schemas.VerdictNotExploitable, exploitRich()); len(got) != 0 {
		t.Errorf("NOT_EXPLOITABLE must suppress reproduction steps, got %d", len(got))
	}
	got := reproductionSteps(schemas.VerdictLikely, exploitRich())
	if len(got) != 2 {
		t.Fatalf("want 2 reproduction steps, got %d", len(got))
	}
	if got[1].Description != exploitRich().Hypothesis {
		t.Errorf("step 2 description = %q, want the exploit hypothesis", got[1].Description)
	}
	if got[1].Command == nil || *got[1].Command != "1 OR 1=1" {
		t.Errorf("step 2 command must be the exploit payload, got %v", got[1].Command)
	}
	// A None payload passes straight through as null.
	noPayload := reproductionSteps(schemas.VerdictLikely, exploitBare())
	if noPayload[1].Command != nil {
		t.Errorf("a nil payload must stay nil, got %v", noPayload[1].Command)
	}
}

// TestBypassPossibleTruthiness pins `bool(sanitization.bypass_method)`.
func TestBypassPossibleTruthiness(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method *string
		want   bool
	}{
		{"nil", nil, false},
		{"empty", str(""), false},
		{"set", str("x"), true},
	} {
		got := AssembleVerifiedFinding(findingBare(), traceBare(),
			schemas.SanitizationResult{BypassMethod: tc.method}, exploitBare(),
			verdictDecision("likely", 2))
		if got.Proof == nil || got.Proof.SanitizationAnalysis == nil {
			t.Fatalf("%s: proof/sanitization analysis missing", tc.name)
		}
		bp := got.Proof.SanitizationAnalysis.BypassPossible
		if bp == nil || *bp != tc.want {
			t.Errorf("%s: bypass_possible = %v, want %v", tc.name, bp, tc.want)
		}
	}
}

func TestFallbackGolden(t *testing.T) {
	var want map[string]any
	goldenJSON(t, "fallback", &want)

	rich, bare := findingRich(), findingBare()
	cases := map[string]schemas.VerifiedFinding{
		"plain":            Fallback(rich, "harness blew up", nil, nil),
		"with_drop_reason": Fallback(rich, "boom", StrPtr("verifier_error"), nil),
		"demoted": Fallback(bare,
			"Verifier returned unverified verdict; demoted for manual review",
			StrPtr("verdict_unverified"), StrPtr("unverified")),
		"original_verdict_only": Fallback(bare, "why", nil, StrPtr("unverified")),
	}
	if len(cases) != len(want) {
		t.Fatalf("case count drift: go has %d, golden has %d", len(cases), len(want))
	}
	for name, got := range cases {
		if !reflect.DeepEqual(jsonTree(t, got), want[name]) {
			t.Errorf("fallback[%s] mismatch:\n got: %#v\nwant: %#v", name, jsonTree(t, got), want[name])
		}
	}
}

// TestFallbackDemotionContract restates what tests/test_prove_phase_demotion.py
// asserts about a demoted finding, at the level this package owns.
func TestFallbackDemotionContract(t *testing.T) {
	got := Fallback(findingRich(), "Verifier returned unverified verdict; demoted for manual review",
		StrPtr("verdict_unverified"), StrPtr("unverified"))

	if got.Verdict != schemas.VerdictInconclusive {
		t.Errorf("verdict = %q, want inconclusive", got.Verdict)
	}
	if got.EvidenceLevel != schemas.EvidenceLevelStaticMatch {
		t.Errorf("evidence_level = %d, want 1 (STATIC_MATCH)", got.EvidenceLevel)
	}
	if got.DropReason == nil || *got.DropReason != "verdict_unverified" {
		t.Errorf("drop_reason = %v, want verdict_unverified", got.DropReason)
	}
	if len(got.Tags) != 1 || got.Tags[0] != "low_confidence" {
		t.Errorf("tags = %v, want [low_confidence]", got.Tags)
	}
	wantRationale := "Verification incomplete: Verifier returned unverified verdict; " +
		"demoted for manual review (original verdict: unverified)"
	if got.Rationale != wantRationale {
		t.Errorf("rationale = %q, want %q", got.Rationale, wantRationale)
	}
	if got.ExploitabilityScore != 0 || got.SarifSecuritySeverity != 0 {
		t.Errorf("a demoted finding must score 0, got %v/%v", got.ExploitabilityScore, got.SarifSecuritySeverity)
	}
	if got.Proof != nil {
		t.Error("a demoted finding carries no proof")
	}
}

// TestFallbackEmptyOptionalsAreFalsy pins that "" behaves like None for both
// keyword arguments, which is what Python's truthiness tests do.
func TestFallbackEmptyOptionalsAreFalsy(t *testing.T) {
	got := Fallback(findingBare(), "reason", StrPtr(""), StrPtr(""))
	if len(got.Tags) != 0 {
		t.Errorf("an empty drop_reason is falsy, so tags must stay empty; got %v", got.Tags)
	}
	if got.Rationale != "Verification incomplete: reason" {
		t.Errorf("an empty original_verdict must not be appended; got %q", got.Rationale)
	}
	// The field itself still carries the pointer Python would store.
	if got.DropReason == nil || *got.DropReason != "" {
		t.Errorf("drop_reason field must hold the value passed, got %v", got.DropReason)
	}
}

func TestSarifRuleIDSlug(t *testing.T) {
	for _, tc := range []struct {
		cweName string
		want    string
	}{
		{"SQL Injection", "sec-af/sast/sql-injection"},
		{"Improper Neutralization/Escaping of Special Elements",
			"sec-af/sast/improper-neutralization-escaping-of-special-elements"},
		{"Broken Access/Control Check", "sec-af/sast/broken-access-control-check"},
		{"", "sec-af/sast/"},
		// Only SPACE and SLASH are replaced — an underscore survives.
		{"Weak_Crypto", "sec-af/sast/weak_crypto"},
	} {
		if got := sarifRuleID(schemas.FindingTypeSast, tc.cweName); got != tc.want {
			t.Errorf("sarifRuleID(%q) = %q, want %q", tc.cweName, got, tc.want)
		}
	}
}
