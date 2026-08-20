package output

import (
	"encoding/json"
	"math"
	"strconv"
	"strings"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file ports tests/test_json_output.py — which also carries the one
// generate_report test the Python suite has. Extra report coverage lives in
// report_test.go.

// jsonDoc parses a generated JSON document into an untyped tree.
func jsonDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("generated JSON is invalid: %v", err)
	}
	return payload
}

// TestGenerateJSONPrettyContainsFullFindingPayload ports
// test_generate_json_pretty_contains_full_finding_payload.
func TestGenerateJSONPrettyContainsFullFindingPayload(t *testing.T) {
	result := loadFixture(t, "audit_result")
	payload := jsonDoc(t, GenerateJSON(result, true))
	findings := sliceAt(t, payload["findings"], "findings")
	chains := sliceAt(t, payload["attack_chains"], "attack_chains")

	if len(findings) != 3 {
		t.Fatalf("want 3 findings, got %d", len(findings))
	}
	if got := mapAt(t, findings[0], "findings[0]")["id"]; got != "finding-confirmed" {
		t.Errorf("findings[0].id = %v", got)
	}
	if got := mapAt(t, findings[1], "findings[1]")["verdict"]; got != "likely" {
		t.Errorf("findings[1].verdict = %v", got)
	}
	if got := mapAt(t, findings[2], "findings[2]")["verdict"]; got != "not_exploitable" {
		t.Errorf("findings[2].verdict = %v", got)
	}
	if got := mapAt(t, chains[0], "attack_chains[0]")["chain_id"]; got != "chain-1" {
		t.Errorf("attack_chains[0].chain_id = %v", got)
	}
	// The "full" payload keeps the heavy sub-objects the summary drops.
	if _, ok := mapAt(t, findings[0], "findings[0]")["proof"].(map[string]any); !ok {
		t.Error("findings[0].proof is missing from the full payload")
	}
}

// TestGenerateJSONCompactHasNoWhitespaceNewlines ports
// test_generate_json_compact_has_no_whitespace_newlines.
func TestGenerateJSONCompactHasNoWhitespaceNewlines(t *testing.T) {
	output := GenerateJSON(loadFixture(t, "audit_result"), false)

	if strings.Contains(output, "\n") {
		t.Error("compact output contains a newline")
	}
	if !strings.HasPrefix(output, "{") {
		t.Error("compact output does not start with {")
	}
	if !strings.HasSuffix(output, "}") {
		t.Error("compact output does not end with }")
	}
	// Python parity: pydantic's compact separators carry no space at all,
	// unlike json.dumps' default ", " / ": ".
	if strings.Contains(output, `", "`) || strings.Contains(output, `": "`) {
		t.Error("compact output uses json.dumps separators, not pydantic's")
	}
}

// TestGenerateSummaryJSONOmitsProofAndContainsStatistics ports
// test_generate_summary_json_omits_proof_and_contains_statistics.
func TestGenerateSummaryJSONOmitsProofAndContainsStatistics(t *testing.T) {
	result := loadFixture(t, "audit_result")
	payload := jsonDoc(t, GenerateSummaryJSON(result))
	summary := mapAt(t, payload["summary"], "summary")
	findings := sliceAt(t, payload["findings"], "findings")
	chains := sliceAt(t, payload["attack_chains"], "attack_chains")
	performance := mapAt(t, payload["performance"], "performance")

	if summary["total_findings"] != float64(3) {
		t.Errorf("summary.total_findings = %v", summary["total_findings"])
	}
	if summary["confirmed"] != float64(1) {
		t.Errorf("summary.confirmed = %v", summary["confirmed"])
	}
	if summary["likely"] != float64(1) {
		t.Errorf("summary.likely = %v", summary["likely"])
	}
	if summary["not_exploitable"] != float64(1) {
		t.Errorf("summary.not_exploitable = %v", summary["not_exploitable"])
	}
	if _, present := mapAt(t, findings[0], "findings[0]")["proof"]; present {
		t.Error("the summary view leaked the proof object")
	}
	firstSteps := sliceAt(t, mapAt(t, chains[0], "attack_chains[0]")["steps"], "steps")
	if got := mapAt(t, firstSteps[0], "steps[0]")["step"]; got != float64(1) {
		t.Errorf("steps[0].step = %v, want 1", got)
	}
	if performance["cost_usd"] != 3.21 {
		t.Errorf("performance.cost_usd = %v, want 3.21", performance["cost_usd"])
	}
}

// TestRenderJSONReturnsDecodedDictionary ports
// test_render_json_returns_decoded_dictionary.
func TestRenderJSONReturnsDecodedDictionary(t *testing.T) {
	payload, err := RenderJSON(loadFixture(t, "audit_result"))
	if err != nil {
		t.Fatalf("RenderJSON: %v", err)
	}
	if payload["repository"] != "Agent-Field/sec-af" {
		t.Errorf("repository = %v", payload["repository"])
	}
	if got := sliceAt(t, payload["findings"], "findings"); len(got) != 3 {
		t.Errorf("want 3 findings, got %d", len(got))
	}
}

// TestGenerateReportIncludesFindingsChainsComplianceAndCost ports
// test_generate_report_includes_findings_chains_compliance_and_cost (which
// lives in tests/test_json_output.py).
func TestGenerateReportIncludesFindingsChainsComplianceAndCost(t *testing.T) {
	report := GenerateReport(loadFixture(t, "audit_result"))

	for _, want := range []string{
		"# SEC-AF Security Audit Report",
		"## Summary",
		"## Findings",
		"SQL Injection",
		"Missing Authentication",
		"## Attack Chains",
		"Input to DB read",
		"## Compliance Gaps",
		"PCI-DSS Req 6.2.4",
		"## Performance & Cost",
	} {
		if !strings.Contains(report, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

// ---------------------------------------------------------------------------
// behaviours the Python suite does not cover but the port must not drift on
// ---------------------------------------------------------------------------

// TestBuildChainStepsFallbacks pins _build_chain_steps' two quirks: a chain
// step of 0 is falsy and falls back to the enumeration index, and a chain
// naming an unknown finding id still yields a step with null detail fields.
func TestBuildChainStepsFallbacks(t *testing.T) {
	payload := jsonDoc(t, GenerateSummaryJSON(loadFixture(t, "audit_result_edge")))
	chains := sliceAt(t, payload["attack_chains"], "attack_chains")
	steps := sliceAt(t, mapAt(t, chains[0], "attack_chains[0]")["steps"], "steps")

	if len(steps) != 2 {
		t.Fatalf("want 2 steps, got %d", len(steps))
	}
	// dup-a carries chain_step 0 -> falls back to index 1.
	first := mapAt(t, steps[0], "steps[0]")
	if first["step"] != float64(1) {
		t.Errorf("steps[0].step = %v, want the 1-based index", first["step"])
	}
	if first["finding_id"] != "dup-a" {
		t.Errorf("steps[0].finding_id = %v", first["finding_id"])
	}
	// "not-in-result" is not among the findings -> index and null details.
	second := mapAt(t, steps[1], "steps[1]")
	if second["step"] != float64(2) {
		t.Errorf("steps[1].step = %v, want 2", second["step"])
	}
	for _, key := range []string{"title", "verdict", "severity", "location"} {
		value, present := second[key]
		if !present {
			t.Errorf("steps[1].%s is absent; Python emits it as null", key)
		}
		if value != nil {
			t.Errorf("steps[1].%s = %v, want null", key, value)
		}
	}
}

// TestBuildAttackChainsNullMitreBecomesEmptyList pins
// `chain.mitre_attack_mapping or []`.
func TestBuildAttackChainsNullMitreBecomesEmptyList(t *testing.T) {
	payload := jsonDoc(t, GenerateSummaryJSON(loadFixture(t, "audit_result_edge")))
	chains := sliceAt(t, payload["attack_chains"], "attack_chains")
	mitre, present := mapAt(t, chains[0], "attack_chains[0]")["mitre_attack_mapping"]
	if !present {
		t.Fatal("mitre_attack_mapping is absent")
	}
	list, ok := mitre.([]any)
	if !ok {
		t.Fatalf("mitre_attack_mapping = %v (%T), want an empty array", mitre, mitre)
	}
	if len(list) != 0 {
		t.Errorf("mitre_attack_mapping = %v, want []", list)
	}
}

// TestGenerateJSONTimestampSpellings pins the one place the two datetime
// spellings meet: the pydantic dump says "Z", the summary says "+00:00".
func TestGenerateJSONTimestampSpellings(t *testing.T) {
	result := loadFixture(t, "audit_result")

	full := jsonDoc(t, GenerateJSON(result, true))
	if full["timestamp"] != "2026-03-04T10:30:00Z" {
		t.Errorf("generate_json timestamp = %v, want the pydantic \"Z\" form", full["timestamp"])
	}
	summary := jsonDoc(t, GenerateSummaryJSON(result))
	if summary["timestamp"] != "2026-03-04T10:30:00+00:00" {
		t.Errorf("generate_summary_json timestamp = %v, want the isoformat form", summary["timestamp"])
	}

	edge := jsonDoc(t, GenerateJSON(loadFixture(t, "audit_result_edge"), true))
	if edge["timestamp"] != "2026-03-04T10:30:00.123456Z" {
		t.Errorf("microsecond timestamp = %v", edge["timestamp"])
	}
}

// TestGenerateJSONFloatSpelling pins the rule the two branches of generate_json
// obey, which is NOT the same rule.
//
// Validation contract (behaviour, measured on the pinned interpreter by running
// the real `generate_json` over a real SecurityAuditResult, one value at a
// time):
//
//   - pretty=false is `result.model_dump_json()` VERBATIM — pydantic-core's
//     Rust serializer. It writes a DECIMAL form for every magnitude in
//     [1e-5, 1e16) (so 8e-05 is "0.00008" and 1e-5 is "0.00001") and an
//     exponent form otherwise with UNPADDED exponent digits ("1e-7", not
//     "1e-07");
//   - pretty=true is `json.dumps(json.loads(...))`, i.e. CPython repr(), which
//     writes "8e-05" and "1e-07" for the same values;
//   - the two agree everywhere else, including the 0.30000000000000004 repr
//     tie, -0.0, 1e15 (decimal on both), 1e+16, 1e+21 and the 5e-324 denormal.
//
// Before this, both branches used repr() and only the pretty one was right —
// undetected because no committed golden carried a float below 1e-4.
func TestGenerateJSONFloatSpelling(t *testing.T) {
	for _, tc := range []struct {
		value           float64
		compact, pretty string
	}{
		{1e-07, "1e-7", "1e-07"},
		{1e-08, "1e-8", "1e-08"},
		{1.5e-07, "1.5e-7", "1.5e-07"},
		{-1e-07, "-1e-7", "-1e-07"},
		{1e-06, "1e-6", "1e-06"},
		{1e-05, "0.00001", "1e-05"},
		{8e-05, "0.00008", "8e-05"},
		{1.23e-05, "0.0000123", "1.23e-05"},
		{9.99e-05, "0.0000999", "9.99e-05"},
		{0.0001, "0.0001", "0.0001"},
		{0.30000000000000004, "0.30000000000000004", "0.30000000000000004"},
		{0.0, "0.0", "0.0"},
		{math.Copysign(0, -1), "-0.0", "-0.0"},
		{10.0, "10.0", "10.0"},
		{1e15, "1000000000000000.0", "1000000000000000.0"},
		{1e16, "1e+16", "1e+16"},
		{1e21, "1e+21", "1e+21"},
		{5e-324, "5e-324", "5e-324"},
		{1234.5, "1234.5", "1234.5"},
	} {
		t.Run(strconv.FormatFloat(tc.value, 'g', -1, 64), func(t *testing.T) {
			result := schemas.NewSecurityAuditResult()
			result.DurationSeconds = tc.value

			if want := `"duration_seconds":` + tc.compact; !strings.Contains(GenerateJSON(result, false), want) {
				t.Errorf("compact form does not contain %s\n%s", want, GenerateJSON(result, false))
			}
			if want := `"duration_seconds": ` + tc.pretty; !strings.Contains(GenerateJSON(result, true), want) {
				t.Errorf("pretty form does not contain %s", want)
			}
		})
	}
}

// TestGenerateJSONMetadataKeepsWireIntegers pins the OTHER number rule: the
// untyped `metadata` map (pydantic `dict[str, object]`) keeps whatever the JSON
// decoder produced, and CPython's json.loads produces an `int` for an integer
// literal. Both branches of generate_json therefore print "2", not "2.0".
//
// The live path that puts a value there is app.py:205-208, which copies the
// prove_phase `drop_summary` payload verbatim; on the Go side that payload
// arrives from the SDK's own decoder, where every number is a float64, so the
// int-ness is restored by afx.WireNumbers at the boundary and by
// SecurityAuditResult.UnmarshalJSON's UseNumber when a document is read back.
func TestGenerateJSONMetadataKeepsWireIntegers(t *testing.T) {
	var result schemas.SecurityAuditResult
	document := `{"metadata":{"findings_not_verified":3,` +
		`"prove_drop_summary":{"by_reason":{"verifier_error":2},"demoted_total":2,"findings":[]},` +
		`"a_real_float":2.5}}`
	if err := json.Unmarshal([]byte(document), &result); err != nil {
		t.Fatalf("decode: %v", err)
	}

	wantCompact := `"metadata":{"a_real_float":2.5,"findings_not_verified":3,` +
		`"prove_drop_summary":{"by_reason":{"verifier_error":2},"demoted_total":2,"findings":[]}}`
	if got := GenerateJSON(result, false); !strings.Contains(got, wantCompact) {
		t.Errorf("compact metadata\n got: %s\nwant it to contain: %s", got, wantCompact)
	}
	if got := GenerateJSON(result, true); !strings.Contains(got, `"findings_not_verified": 3,`) {
		t.Errorf("pretty metadata spells the wire integer as a float:\n%s", got)
	}
	if got := GenerateJSON(result, true); !strings.Contains(got, `"a_real_float": 2.5`) {
		t.Errorf("pretty metadata lost a genuine float:\n%s", got)
	}
}
