package phases

// Tests for the checked binders (validate.go).
//
// Validation contract, derived from pydantic's behaviour on the pinned
// interpreter (`PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python`),
// not from the Go implementation:
//
//   - `Model.model_validate(payload)` raises when a required field is absent or
//     null, ANYWHERE IN THE TREE — a nested `proof: {}` fails just as a missing
//     top-level `title` does;
//   - it raises when an enum-typed field carries a value outside its member
//     list, including inside a list element;
//   - it accepts a payload whose optional fields are absent, and seeds their
//     defaults.
//
// Every "raises" case below was executed against the real models first; the
// per-case comment records what Python answered.

import (
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// validVerifiedFinding is the minimal payload VerifiedFinding.model_validate
// accepts: every field with no default, and nothing else.
func validVerifiedFinding() map[string]any {
	return map[string]any{
		"fingerprint":             "fp",
		"title":                   "t",
		"description":             "d",
		"finding_type":            "sast",
		"cwe_id":                  "CWE-89",
		"cwe_name":                "SQL Injection",
		"verdict":                 "confirmed",
		"evidence_level":          float64(3),
		"rationale":               "r",
		"severity":                "high",
		"exploitability_score":    1.0,
		"location":                map[string]any{"file_path": "a.go", "start_line": float64(1), "end_line": float64(2)},
		"sarif_rule_id":           "rule",
		"sarif_security_severity": 1.0,
	}
}

// validRawFinding is the minimal payload RawFinding(**payload) accepts.
func validRawFinding() map[string]any {
	return map[string]any{
		"hunter_strategy":    "injection",
		"title":              "t",
		"description":        "d",
		"finding_type":       "sast",
		"cwe_id":             "CWE-89",
		"cwe_name":           "SQL Injection",
		"file_path":          "a.go",
		"start_line":         float64(1),
		"end_line":           float64(2),
		"code_snippet":       "q",
		"estimated_severity": "high",
		"confidence":         "high",
	}
}

func withKey(base map[string]any, key string, value any) map[string]any {
	out := make(map[string]any, len(base)+1)
	for k, v := range base {
		out[k] = v
	}
	out[key] = value
	return out
}

// TestBindVerifiedFinding_AcceptsTheMinimalPayload is the control: the checks
// must not reject what pydantic accepts.
func TestBindVerifiedFinding_AcceptsTheMinimalPayload(t *testing.T) {
	got, err := BindVerifiedFinding(validVerifiedFinding())
	if err != nil {
		t.Fatalf("BindVerifiedFinding: %v", err)
	}
	if got.Verdict != schemas.VerdictConfirmed || got.Severity != schemas.SeverityHigh {
		t.Errorf("bound finding = %+v", got)
	}
}

// TestBindVerifiedFinding_ValidatesTheNestedTree.
//
// Every case here raises in Python. VERIFIED, error counts included:
//
//	{"proof": {}}                                  -> 3 validation errors
//	{"cvss_v4": {"vector": "v"}}                    -> 4 validation errors
//	{"epss": {}}                                    -> 3 validation errors
//	{"reproduction_steps": [{"step": 1}]}           -> 1 validation error
//	{"compliance": [{"framework": "x"}]}            -> 2 validation errors
//	{"remediation": {"fix_description": "x"}}       -> 2 validation errors
//	{"related_locations": [{"file_path": "a"}]}     -> 2 validation errors
//
// Before the nested layer existed these all bound cleanly, shipping a Proof
// with `evidence_level: 0` — not a member of the EvidenceLevel IntEnum — into
// the final report and the SARIF `sec-af/evidence_level` property, and skipping
// prove_phase's schema_parse_failure demotion entirely.
func TestBindVerifiedFinding_ValidatesTheNestedTree(t *testing.T) {
	cases := []struct {
		name  string
		key   string
		value any
		want  string
	}{
		{"empty proof", "proof", map[string]any{}, "proof.exploit_hypothesis: field required"},
		{"proof evidence_level out of range", "proof", map[string]any{
			"exploit_hypothesis": "h", "verification_method": "m", "evidence_level": float64(0),
		}, "proof.evidence_level: 0 is not a valid EvidenceLevel"},
		{"proof data_flow_trace element", "proof", map[string]any{
			"exploit_hypothesis": "h", "verification_method": "m", "evidence_level": float64(1),
			"data_flow_trace": []any{map[string]any{"file": "a"}},
		}, "proof.data_flow_trace.0.line: field required"},
		{"proof reachability", "proof", map[string]any{
			"exploit_hypothesis": "h", "verification_method": "m", "evidence_level": float64(1),
			"reachability": map[string]any{"vulnerable_function": "f"},
		}, "proof.reachability.reachable: field required"},
		{"proof chain_steps element", "proof", map[string]any{
			"exploit_hypothesis": "h", "verification_method": "m", "evidence_level": float64(1),
			"chain_steps": []any{map[string]any{"step_number": float64(1)}},
		}, "proof.chain_steps.0.finding_id: field required"},
		{"cvss_v4 vector only", "cvss_v4", map[string]any{"vector": "v"}, "cvss_v4.base_score: field required"},
		{"empty epss", "epss", map[string]any{}, "epss.score: field required"},
		{"reproduction step without description", "reproduction_steps",
			[]any{map[string]any{"step": float64(1)}}, "reproduction_steps.0.description: field required"},
		{"compliance mapping without control_id", "compliance",
			[]any{map[string]any{"framework": "x"}}, "compliance.0.control_id: field required"},
		{"remediation without patch_diff", "remediation",
			map[string]any{"fix_description": "x"}, "remediation.patch_diff: field required"},
		{"related location without start_line", "related_locations",
			[]any{map[string]any{"file_path": "a"}}, "related_locations.0.start_line: field required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := BindVerifiedFinding(withKey(validVerifiedFinding(), tc.key, tc.value))
			if err == nil {
				t.Fatalf("want a ValidationError; Python raises for %s", tc.name)
			}
			var verr *ValidationError
			if !asValidationError(err, &verr) {
				t.Fatalf("err %T is not a *ValidationError: %v", err, err)
			}
			if verr.Model != "VerifiedFinding" {
				t.Errorf("model = %q, want VerifiedFinding", verr.Model)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err.Error(), tc.want)
			}
		})
	}
}

// TestBindVerifiedFinding_AcceptsAWellFormedNestedTree: the nested checks must
// not reject a complete payload.
func TestBindVerifiedFinding_AcceptsAWellFormedNestedTree(t *testing.T) {
	payload := validVerifiedFinding()
	payload["proof"] = map[string]any{
		"exploit_hypothesis":    "h",
		"verification_method":   "m",
		"evidence_level":        float64(6),
		"data_flow_trace":       []any{map[string]any{"file": "a.go", "line": float64(1), "description": "d", "tainted": true}},
		"sanitization_analysis": map[string]any{"sanitization_found": false},
		"http_request":          map[string]any{},
		"reachability": map[string]any{
			"vulnerable_function": "f", "reachable": true, "direct_dependency": false,
		},
		"chain_steps": []any{map[string]any{
			"step_number": float64(1), "finding_id": "f1", "description": "d", "enables": "e",
		}},
	}
	payload["cvss_v4"] = map[string]any{
		"vector": "v", "base_score": 9.8, "severity": "critical", "automatable": true, "subsequent_impact": false,
	}
	payload["epss"] = map[string]any{"score": 0.1, "percentile": 0.9, "date": "2026-01-01"}
	payload["reproduction_steps"] = []any{map[string]any{"step": float64(1), "description": "d"}}
	payload["compliance"] = []any{map[string]any{"framework": "f", "control_id": "c", "control_name": "n"}}
	payload["remediation"] = map[string]any{"fix_description": "x", "patch_diff": "d", "confidence": "high"}
	payload["related_locations"] = []any{map[string]any{"file_path": "b.go", "start_line": float64(3), "end_line": float64(4)}}

	got, err := BindVerifiedFinding(payload)
	if err != nil {
		t.Fatalf("BindVerifiedFinding: %v", err)
	}
	if got.Proof == nil || got.Proof.EvidenceLevel != schemas.EvidenceLevelFullExploit {
		t.Errorf("proof = %+v", got.Proof)
	}
	if got.CvssV4 == nil || got.CvssV4.BaseScore != 9.8 {
		t.Errorf("cvss_v4 = %+v", got.CvssV4)
	}
}

// TestBindRawFinding_RejectsOutOfVocabularyEnums.
//
// VERIFIED: `RawFinding(**{... finding_type:"bogus_type", estimated_severity:
// "bogus_sev", confidence:"bogus_conf"})` raises `3 validation errors for
// RawFinding`. Go's enums are plain string types with no strict UnmarshalJSON,
// so afx.Bind alone marshalled the bogus strings straight through — and a bogus
// severity then added an extra key to SecurityAuditResult.by_severity, which
// Python's five-member Severity enum makes impossible.
func TestBindRawFinding_RejectsOutOfVocabularyEnums(t *testing.T) {
	for _, tc := range []struct{ field, value string }{
		{"finding_type", "bogus_type"},
		{"estimated_severity", "bogus_sev"},
		{"confidence", "bogus_conf"},
	} {
		t.Run(tc.field, func(t *testing.T) {
			_, err := BindRawFinding(withKey(validRawFinding(), tc.field, tc.value))
			if err == nil {
				t.Fatalf("want a ValidationError for %s=%q", tc.field, tc.value)
			}
			if !strings.Contains(err.Error(), tc.field+": ") {
				t.Errorf("error = %q, want it to name %s", err.Error(), tc.field)
			}
		})
	}

	// The control: every enum value is a member.
	if _, err := BindRawFinding(validRawFinding()); err != nil {
		t.Fatalf("the valid payload must bind: %v", err)
	}

	// RawFinding.data_flow carries recon's DataFlowStep, whose four fields are
	// all required. VERIFIED: `data_flow=[{"file_path": "a"}]` -> 3 errors.
	_, err := BindRawFinding(withKey(validRawFinding(), "data_flow", []any{map[string]any{"file_path": "a"}}))
	if err == nil || !strings.Contains(err.Error(), "data_flow.0.line: field required") {
		t.Errorf("err = %v, want the nested data_flow problems", err)
	}
}

// TestBindHuntResult_ValidatesElementsAndEnums. Python raises for both shapes
// (VERIFIED: 3 errors for the findings case, 1 for the chain case), which
// hunt_phase's per-hunter try turns into an empty batch plus a
// "Hunt strategy failed: X: ..." note and prove_phase lets fail the phase.
func TestBindHuntResult_ValidatesElementsAndEnums(t *testing.T) {
	bogus := withKey(withKey(withKey(validRawFinding(),
		"finding_type", "bogus_type"), "estimated_severity", "bogus_sev"), "confidence", "bogus_conf")

	_, err := BindHuntResult(map[string]any{"findings": []any{bogus}})
	if err == nil {
		t.Fatal("want a ValidationError for a finding with out-of-vocabulary enums")
	}
	for _, want := range []string{
		"findings.0.finding_type: ", "findings.0.estimated_severity: ", "findings.0.confidence: ",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error = %q, want it to mention %q", err.Error(), want)
		}
	}

	_, err = BindHuntResult(map[string]any{"chains": []any{map[string]any{
		"title": "t", "combined_impact": "i", "estimated_severity": "nope",
	}}})
	if err == nil || !strings.Contains(err.Error(), "chains.0.estimated_severity: ") {
		t.Errorf("err = %v, want the chain severity problem", err)
	}

	// The control: a well-formed hunt result still binds, defaults seeded.
	got, err := BindHuntResult(map[string]any{"findings": []any{validRawFinding()}})
	if err != nil {
		t.Fatalf("BindHuntResult: %v", err)
	}
	if len(got.Findings) != 1 || got.Findings[0].EstimatedSeverity != schemas.SeverityHigh {
		t.Errorf("bound hunt result = %+v", got)
	}
}

func asValidationError(err error, dest **ValidationError) bool {
	v, ok := err.(*ValidationError)
	if ok {
		*dest = v
	}
	return ok
}
