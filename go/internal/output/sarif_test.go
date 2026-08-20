package output

import (
	"encoding/json"
	"testing"
)

// This file ports tests/test_sarif.py. The Python tests take the
// `sample_security_audit_result` conftest fixture; the Go tests load the same
// data from testdata/audit_result.json, which scripts/gen_golden.py writes from
// that very fixture.

// sarifDoc parses a generated SARIF document into an untyped tree.
func sarifDoc(t *testing.T, raw string) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("generated SARIF is not valid JSON: %v", err)
	}
	return payload
}

func mapAt(t *testing.T, value any, what string) map[string]any {
	t.Helper()
	m, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s: want an object, got %T", what, value)
	}
	return m
}

func sliceAt(t *testing.T, value any, what string) []any {
	t.Helper()
	s, ok := value.([]any)
	if !ok {
		t.Fatalf("%s: want an array, got %T", what, value)
	}
	return s
}

// sarifRun returns runs[0] of a generated document.
func sarifRun(t *testing.T, payload map[string]any) map[string]any {
	t.Helper()
	runs := sliceAt(t, payload["runs"], "runs")
	if len(runs) != 1 {
		t.Fatalf("want exactly one run, got %d", len(runs))
	}
	return mapAt(t, runs[0], "runs[0]")
}

func containsAny(list []any, want string) bool {
	for _, item := range list {
		if s, ok := item.(string); ok && s == want {
			return true
		}
	}
	return false
}

// TestGenerateSarifHasValid210Envelope ports
// test_generate_sarif_has_valid_2_1_0_envelope.
func TestGenerateSarifHasValid210Envelope(t *testing.T) {
	result := loadFixture(t, "audit_result")
	payload := sarifDoc(t, GenerateSarif(result))
	run := sarifRun(t, payload)
	tool := mapAt(t, mapAt(t, run["tool"], "tool")["driver"], "driver")

	if payload["$schema"] != "https://json.schemastore.org/sarif-2.1.0.json" {
		t.Errorf("$schema = %v", payload["$schema"])
	}
	if payload["version"] != "2.1.0" {
		t.Errorf("version = %v", payload["version"])
	}
	if tool["name"] != "SEC-AF" {
		t.Errorf("driver.name = %v", tool["name"])
	}
	if tool["informationUri"] != "https://github.com/Agent-Field/sec-af" {
		t.Errorf("driver.informationUri = %v", tool["informationUri"])
	}
	wantID := "sec-af/audit/Agent-Field/sec-af/2026-03-04T10:30:00+00:00"
	if got := mapAt(t, run["automationDetails"], "automationDetails")["id"]; got != wantID {
		t.Errorf("automationDetails.id = %v, want %q", got, wantID)
	}
}

// TestGenerateSarifFiltersNotExploitableAndMapsSeverity ports
// test_generate_sarif_filters_not_exploitable_and_maps_severity.
func TestGenerateSarifFiltersNotExploitableAndMapsSeverity(t *testing.T) {
	result := loadFixture(t, "audit_result")
	run := sarifRun(t, sarifDoc(t, GenerateSarif(result)))
	results := sliceAt(t, run["results"], "results")

	byRule := map[string]map[string]any{}
	for _, item := range results {
		entry := mapAt(t, item, "result")
		byRule[entry["ruleId"].(string)] = entry
	}

	if len(results) != 2 {
		t.Fatalf("want 2 results, got %d", len(results))
	}
	if _, present := byRule["sec-af/sast/xss"]; present {
		t.Error("the not_exploitable finding leaked into the SARIF results")
	}
	if byRule["sec-af/sast/sql-injection"]["level"] != "error" {
		t.Errorf("sql-injection level = %v, want \"error\"", byRule["sec-af/sast/sql-injection"]["level"])
	}
	if byRule["sec-af/api/missing-authentication"]["level"] != "error" {
		t.Errorf("missing-authentication level = %v, want \"error\"", byRule["sec-af/api/missing-authentication"]["level"])
	}
}

// TestGenerateSarifIncludesComplianceTagsCodeflowAndLocations ports
// test_generate_sarif_includes_compliance_tags_codeflow_and_locations.
func TestGenerateSarifIncludesComplianceTagsCodeflowAndLocations(t *testing.T) {
	result := loadFixture(t, "audit_result")
	run := sarifRun(t, sarifDoc(t, GenerateSarif(result)))

	var sql map[string]any
	for _, item := range sliceAt(t, run["results"], "results") {
		entry := mapAt(t, item, "result")
		if entry["ruleId"] == "sec-af/sast/sql-injection" {
			sql = entry
		}
	}
	if sql == nil {
		t.Fatal("no sql-injection result")
	}

	properties := mapAt(t, sql["properties"], "properties")
	locations := sliceAt(t, sql["locations"], "locations")
	physical := mapAt(t, mapAt(t, locations[0], "locations[0]")["physicalLocation"], "physicalLocation")
	region := mapAt(t, physical["region"], "region")
	related := sliceAt(t, sql["relatedLocations"], "relatedLocations")
	codeFlows := sliceAt(t, sql["codeFlows"], "codeFlows")

	if !containsAny(sliceAt(t, properties["sec-af/compliance"], "sec-af/compliance"), "PCI-DSS:Req-6.2.4") {
		t.Errorf("sec-af/compliance = %v", properties["sec-af/compliance"])
	}
	if !containsAny(sliceAt(t, properties["tags"], "tags"), "compliance:PCI-DSS:Req-6.2.4") {
		t.Errorf("tags = %v", properties["tags"])
	}
	if region["startLine"] != float64(42) {
		t.Errorf("region.startLine = %v, want 42", region["startLine"])
	}
	if region["startColumn"] != float64(9) {
		t.Errorf("region.startColumn = %v, want 9", region["startColumn"])
	}
	firstRelated := mapAt(t, related[0], "relatedLocations[0]")
	uri := mapAt(t, mapAt(t, firstRelated["physicalLocation"], "physicalLocation")["artifactLocation"], "artifactLocation")["uri"]
	if uri != "src/routes.py" {
		t.Errorf("relatedLocations[0] uri = %v", uri)
	}
	threadFlows := sliceAt(t, mapAt(t, codeFlows[0], "codeFlows[0]")["threadFlows"], "threadFlows")
	flowLocations := sliceAt(t, mapAt(t, threadFlows[0], "threadFlows[0]")["locations"], "locations")
	if len(flowLocations) != 2 {
		t.Errorf("thread flow has %d locations, want 2", len(flowLocations))
	}
}

// TestGenerateSarifRuleEntriesAggregatePrecisionAndSeverity ports
// test_generate_sarif_rule_entries_aggregate_precision_and_severity.
func TestGenerateSarifRuleEntriesAggregatePrecisionAndSeverity(t *testing.T) {
	result := loadFixture(t, "audit_result")
	run := sarifRun(t, sarifDoc(t, GenerateSarif(result)))
	driver := mapAt(t, mapAt(t, run["tool"], "tool")["driver"], "driver")

	var sqlRule map[string]any
	for _, item := range sliceAt(t, driver["rules"], "rules") {
		rule := mapAt(t, item, "rule")
		if rule["id"] == "sec-af/sast/sql-injection" {
			sqlRule = rule
		}
	}
	if sqlRule == nil {
		t.Fatal("no sql-injection rule")
	}
	properties := mapAt(t, sqlRule["properties"], "properties")

	if got := mapAt(t, sqlRule["defaultConfiguration"], "defaultConfiguration")["level"]; got != "error" {
		t.Errorf("defaultConfiguration.level = %v, want \"error\"", got)
	}
	if properties["precision"] != "very-high" {
		t.Errorf("precision = %v, want \"very-high\"", properties["precision"])
	}
	if properties["security-severity"] != "10.0" {
		t.Errorf("security-severity = %v, want \"10.0\"", properties["security-severity"])
	}
	if !containsAny(sliceAt(t, properties["tags"], "tags"), "CWE-89") {
		t.Errorf("tags = %v", properties["tags"])
	}
}

// TestGenerateSarifIsStableForSameInput ports
// test_generate_sarif_is_stable_for_same_input. It is the assertion that keeps
// Go map iteration out of the artifact.
func TestGenerateSarifIsStableForSameInput(t *testing.T) {
	result := loadFixture(t, "audit_result")
	first := GenerateSarif(result)
	for i := 0; i < 20; i++ {
		if got := GenerateSarif(result); got != first {
			t.Fatalf("run %d differs from the first", i)
		}
	}
	if RenderSarif(result) != first {
		t.Error("render_sarif differs from generate_sarif")
	}
}

// ---------------------------------------------------------------------------
// helper-level tests (no Python counterpart; they pin the helpers the goldens
// only exercise indirectly)
// ---------------------------------------------------------------------------

// TestRuleName covers _rule_name, including the "SecAfRule" fallback.
func TestRuleName(t *testing.T) {
	cases := map[string]string{
		"sec-af/sast/sql-injection":         "SqlInjection",
		"sec-af/api/missing-authentication": "MissingAuthentication",
		"sec-af/":                           "SecAfRule",
		"":                                  "SecAfRule",
		"---":                               "SecAfRule",
		"sec-af/sast/XSS":                   "Xss",
		"sec-af/sast/a--b":                  "AB",
		"noslash":                           "Noslash",
	}
	for input, want := range cases {
		if got := ruleName(input); got != want {
			t.Errorf("ruleName(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestCweNumber covers _cwe_number.
func TestCweNumber(t *testing.T) {
	cases := map[string]string{
		"CWE-89":    "89",
		"cwe-89":    "89",
		"89":        "89",
		"CWE-CWE-1": "1",
		"":          "",
	}
	for input, want := range cases {
		if got := cweNumber(input); got != want {
			t.Errorf("cweNumber(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestNormalizeControlID covers _normalize_control_id: strip, then every run of
// whitespace collapses to a single "-".
func TestNormalizeControlID(t *testing.T) {
	cases := map[string]string{
		"Req 6.2.4":    "Req-6.2.4",
		"  Req 6.2.4 ": "Req-6.2.4",
		"Req  6.2.4":   "Req-6.2.4",
		"Req\t6.2.4":   "Req-6.2.4",
		"A03:2021":     "A03:2021",
		"":             "",
		"   ":          "",
	}
	for input, want := range cases {
		if got := normalizeControlID(input); got != want {
			t.Errorf("normalizeControlID(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestFormatSecuritySeverity covers _format_security_severity: clamped to
// [0, 10] and rendered with one decimal (half-to-even, like Python's :.1f).
func TestFormatSecuritySeverity(t *testing.T) {
	cases := []struct {
		in   float64
		want string
	}{
		{9.9, "9.9"},
		{10.0, "10.0"},
		{11.5, "10.0"},
		{-1.0, "0.0"},
		{0.04, "0.0"},
		{9.25, "9.2"},
		{0.35, "0.3"},
	}
	for _, tc := range cases {
		if got := formatSecuritySeverity(tc.in); got != tc.want {
			t.Errorf("formatSecuritySeverity(%v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestSeverityToLevelOf covers _severity_to_level's default.
func TestSeverityToLevelOf(t *testing.T) {
	cases := map[string]string{
		"critical": "error",
		"high":     "error",
		"medium":   "warning",
		"low":      "note",
		"info":     "note",
		"bogus":    "warning",
		"":         "warning",
	}
	for input, want := range cases {
		if got := severityToLevelOf(input); got != want {
			t.Errorf("severityToLevelOf(%q) = %q, want %q", input, got, want)
		}
	}
}
