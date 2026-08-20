package compliance

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"sync"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// requiredCWEs ports tests/test_compliance.py::REQUIRED_CWES.
var requiredCWEs = []string{
	"CWE-78", "CWE-79", "CWE-89", "CWE-90", "CWE-91", "CWE-94", "CWE-917",
	"CWE-287", "CWE-306", "CWE-352", "CWE-862", "CWE-863", "CWE-326",
	"CWE-327", "CWE-328", "CWE-330", "CWE-916", "CWE-840", "CWE-841",
	"CWE-200", "CWE-209", "CWE-312", "CWE-319", "CWE-532", "CWE-829",
	"CWE-1104", "CWE-16", "CWE-259", "CWE-321", "CWE-798", "CWE-285",
	"CWE-346", "CWE-601", "CWE-918",
}

// fakeAIGate ports tests/test_compliance.py::_FakeAIGate.
type fakeAIGate struct {
	mu       sync.Mutex
	calls    int
	prompts  []string
	response schemas.ComplianceGate
	err      error
}

func (f *fakeAIGate) InvokeComplianceGate(_ context.Context, user string) (schemas.ComplianceGate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.prompts = append(f.prompts, user)
	if f.err != nil {
		return schemas.ComplianceGate{}, f.err
	}
	return f.response, nil
}

func (f *fakeAIGate) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

// namespaceFinding stands in for the tests' SimpleNamespace findings: an
// object (not a dict) whose attributes carry the finding fields.
type namespaceFinding struct {
	CweID    string `json:"cwe_id"`
	Severity string `json:"severity"`
}

func frameworkSet(mappings []schemas.ComplianceMapping) map[string]struct{} {
	out := map[string]struct{}{}
	for _, mapping := range mappings {
		out[mapping.Framework] = struct{}{}
	}
	return out
}

func sortedKeys(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for key := range set {
		out = append(out, key)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// static table
// ---------------------------------------------------------------------------

// TestKeyCWEsIncludeRequiredFrameworkMappings ports
// test_key_cwes_include_required_framework_mappings (parametrized).
func TestKeyCWEsIncludeRequiredFrameworkMappings(t *testing.T) {
	cases := []struct {
		cweID        string
		owaspControl string
	}{
		{"CWE-89", "A03:2021"},
		{"CWE-79", "A03:2021"},
		{"CWE-287", "A07:2021"},
		{"CWE-862", "A01:2021"},
		{"CWE-326", "A02:2021"},
		{"CWE-840", "A04:2021"},
		{"CWE-200", "A01:2021"},
		{"CWE-1104", "A06:2021"},
		{"CWE-16", "A05:2021"},
		{"CWE-918", "A10:2021"},
	}
	for _, tc := range cases {
		t.Run(tc.cweID, func(t *testing.T) {
			mappings := GetComplianceMappings(tc.cweID, nil)
			frameworks := frameworkSet(mappings)
			for _, want := range []string{"PCI-DSS", "SOC2", "OWASP"} {
				if _, ok := frameworks[want]; !ok {
					t.Fatalf("%s: framework %q missing from %v", tc.cweID, want, sortedKeys(frameworks))
				}
			}
			found := false
			for _, mapping := range mappings {
				if mapping.Framework == "OWASP" && mapping.ControlID == tc.owaspControl {
					found = true
				}
			}
			if !found {
				t.Fatalf("%s: no OWASP mapping with control id %q", tc.cweID, tc.owaspControl)
			}
		})
	}
}

// TestAllRequiredCWEsAreMapped ports test_all_required_cwes_are_mapped.
func TestAllRequiredCWEsAreMapped(t *testing.T) {
	got := make([]string, 0, len(ComplianceMap))
	for cwe := range ComplianceMap {
		got = append(got, cwe)
	}
	want := append([]string(nil), requiredCWEs...)
	sort.Strings(got)
	sort.Strings(want)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("COMPLIANCE_MAP keys mismatch\n got: %v\nwant: %v", got, want)
	}
}

// TestGetComplianceMappingsHandlesCweNormalization ports
// test_get_compliance_mappings_handles_cwe_normalization.
func TestGetComplianceMappingsHandlesCweNormalization(t *testing.T) {
	normalized := GetComplianceMappings("CWE-89", nil)
	shorthand := GetComplianceMappings("89", nil)
	mixedCase := GetComplianceMappings("cwe89", nil)

	if len(normalized) == 0 {
		t.Fatal("CWE-89 has no mappings")
	}
	if !reflect.DeepEqual(shorthand, normalized) {
		t.Fatalf("\"89\" != \"CWE-89\": %v vs %v", shorthand, normalized)
	}
	if !reflect.DeepEqual(mixedCase, normalized) {
		t.Fatalf("\"cwe89\" != \"CWE-89\": %v vs %v", mixedCase, normalized)
	}
}

// TestNormalizeCweID covers _normalize_cwe_id's three branches directly,
// including the whitespace strip Python's `.strip()` performs.
func TestNormalizeCweID(t *testing.T) {
	cases := map[string]string{
		"CWE-89":   "CWE-89",
		"cwe-89":   "CWE-89",
		" CWE-89 ": "CWE-89",
		"CWE89":    "CWE-89",
		"cwe89":    "CWE-89",
		"89":       "CWE-89",
		"\t89\n":   "CWE-89",
		"":         "CWE-",
		"CWE":      "CWE-",
		"CWE-":     "CWE-",
	}
	for input, want := range cases {
		if got := normalizeCweID(input); got != want {
			t.Errorf("normalizeCweID(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestNormalizeFramework covers _normalize_framework.
func TestNormalizeFramework(t *testing.T) {
	cases := map[string]string{
		"PCI-DSS":   "pci-dss",
		"pci_dss":   "pci-dss",
		"  SOC2  ":  "soc2",
		"ISO_27001": "iso-27001",
	}
	for input, want := range cases {
		if got := normalizeFramework(input); got != want {
			t.Errorf("normalizeFramework(%q) = %q, want %q", input, got, want)
		}
	}
}

// TestGetComplianceMappingsCanFilterFrameworks ports
// test_get_compliance_mappings_can_filter_frameworks.
func TestGetComplianceMappingsCanFilterFrameworks(t *testing.T) {
	filtered := GetComplianceMappings("CWE-319", []string{"pci-dss", "owasp"})
	got := sortedKeys(frameworkSet(filtered))
	want := []string{"OWASP", "PCI-DSS"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frameworks = %v, want %v", got, want)
	}
}

// TestGetComplianceMappingsFrameworkFilterWithUnknownFramework ports
// test_get_compliance_mappings_framework_filter_with_unknown_framework.
func TestGetComplianceMappingsFrameworkFilterWithUnknownFramework(t *testing.T) {
	filtered := GetComplianceMappings("CWE-89", []string{"owasp", "does-not-exist"})
	got := sortedKeys(frameworkSet(filtered))
	want := []string{"OWASP"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("frameworks = %v, want %v", got, want)
	}
}

// TestGetComplianceMappingsReturnsEmptyForUnmappedCwe ports
// test_get_compliance_mappings_returns_empty_for_unmapped_cwe. The Python
// assertion is `== []`, so the Go result must be empty AND non-nil.
func TestGetComplianceMappingsReturnsEmptyForUnmappedCwe(t *testing.T) {
	got := GetComplianceMappings("CWE-9999", nil)
	if got == nil {
		t.Fatal("want an empty non-nil slice (Python returns []), got nil")
	}
	if len(got) != 0 {
		t.Fatalf("want no mappings, got %v", got)
	}
}

// TestGetComplianceMappingsReturnsDeepCopies ports
// test_get_compliance_mappings_returns_deep_copies: mutating one result must
// not be visible to the next caller, nor corrupt the table.
func TestGetComplianceMappingsReturnsDeepCopies(t *testing.T) {
	first := GetComplianceMappings("CWE-89", nil)
	second := GetComplianceMappings("CWE-89", nil)

	first[0].ControlName = "mutated"

	if second[0].ControlName == "mutated" {
		t.Fatal("second call observed the first call's mutation")
	}
	if ComplianceMap["CWE-89"][0].ControlName == "mutated" {
		t.Fatal("the static table itself was mutated")
	}
}

// TestGetSupportedFrameworksReturnsExpectedSet ports
// test_get_supported_frameworks_returns_expected_set.
func TestGetSupportedFrameworksReturnsExpectedSet(t *testing.T) {
	want := []string{"HIPAA", "ISO27001", "OWASP", "PCI-DSS", "SOC2"}
	if got := GetSupportedFrameworks(); !reflect.DeepEqual(got, want) {
		t.Fatalf("GetSupportedFrameworks() = %v, want %v", got, want)
	}
}

// ---------------------------------------------------------------------------
// gap aggregation
// ---------------------------------------------------------------------------

// TestGetComplianceGapsAggregatesCountAndMaxSeverity ports
// test_get_compliance_gaps_aggregates_count_and_max_severity.
func TestGetComplianceGapsAggregatesCountAndMaxSeverity(t *testing.T) {
	findings := []map[string]any{
		{"cwe_id": "CWE-89", "severity": "high"},
		{"cwe_id": "CWE-79", "severity": "critical"},
		{"cwe_id": "CWE-918", "severity": "medium"},
	}

	gaps := GetComplianceGaps(findings)

	var pciInjection []schemas.ComplianceGap
	for _, gap := range gaps {
		if gap.Framework == "PCI-DSS" && gap.ControlID == "Req 6.2.4" {
			pciInjection = append(pciInjection, gap)
		}
	}
	if len(pciInjection) != 1 {
		t.Fatalf("want exactly one PCI-DSS Req 6.2.4 gap, got %d", len(pciInjection))
	}
	if pciInjection[0].FindingCount != 2 {
		t.Errorf("finding_count = %d, want 2", pciInjection[0].FindingCount)
	}
	if pciInjection[0].MaxSeverity != "critical" {
		t.Errorf("max_severity = %q, want \"critical\"", pciInjection[0].MaxSeverity)
	}
	if !reflect.DeepEqual(pciInjection[0].CweIDs, []string{"CWE-79", "CWE-89"}) {
		t.Errorf("cwe_ids = %v, want [CWE-79 CWE-89]", pciInjection[0].CweIDs)
	}
}

// TestGetComplianceGapsSortsByFrameworkControl asserts the documented ordering
// contract: sorted by (framework, control_id, control_name).
func TestGetComplianceGapsSortsByFrameworkControl(t *testing.T) {
	gaps := GetComplianceGaps([]map[string]any{
		{"cwe_id": "CWE-89", "severity": "high"},
		{"cwe_id": "CWE-918", "severity": "low"},
	})
	if len(gaps) == 0 {
		t.Fatal("no gaps")
	}
	for i := 1; i < len(gaps); i++ {
		prev, cur := gaps[i-1], gaps[i]
		if prev.Framework > cur.Framework ||
			(prev.Framework == cur.Framework && prev.ControlID > cur.ControlID) ||
			(prev.Framework == cur.Framework && prev.ControlID == cur.ControlID && prev.ControlName > cur.ControlName) {
			t.Fatalf("gaps not sorted at %d: %+v then %+v", i, prev, cur)
		}
	}
}

// TestGetComplianceGapsAcceptsObjectFindingsAndNormalizesCwe ports
// test_get_compliance_gaps_accepts_object_findings_and_normalizes_cwe.
func TestGetComplianceGapsAcceptsObjectFindingsAndNormalizesCwe(t *testing.T) {
	findings := []namespaceFinding{
		{CweID: "89", Severity: "high"},
		{CweID: "cwe89", Severity: "critical"},
	}

	gaps := GetComplianceGaps(findings)

	var owaspGap *schemas.ComplianceGap
	for i := range gaps {
		if gaps[i].Framework == "OWASP" && gaps[i].ControlID == "A03:2021" {
			owaspGap = &gaps[i]
			break
		}
	}
	if owaspGap == nil {
		t.Fatal("no OWASP A03:2021 gap")
	}
	if owaspGap.FindingCount != 2 {
		t.Errorf("finding_count = %d, want 2", owaspGap.FindingCount)
	}
	if owaspGap.MaxSeverity != "critical" {
		t.Errorf("max_severity = %q, want \"critical\"", owaspGap.MaxSeverity)
	}
	if !reflect.DeepEqual(owaspGap.CweIDs, []string{"CWE-89"}) {
		t.Errorf("cwe_ids = %v, want [CWE-89]", owaspGap.CweIDs)
	}
}

// TestGetComplianceGapsIgnoresEntriesWithoutValidCwe ports
// test_get_compliance_gaps_ignores_entries_without_valid_cwe.
func TestGetComplianceGapsIgnoresEntriesWithoutValidCwe(t *testing.T) {
	findings := []map[string]any{
		{"severity": "critical"},
		{"cwe_id": nil, "severity": "high"},
		{"cwe_id": "CWE-9999", "severity": "critical"},
	}

	gaps := GetComplianceGaps(findings)
	if len(gaps) != 0 {
		t.Fatalf("want no gaps, got %v", gaps)
	}
}

// TestGetComplianceGapsVerifiedFindingSeverityQuirk pins the CPython behaviour
// documented on severityKey: a real VerifiedFinding carries a
// `class Severity(str, Enum)` member, `str()` of which is "Severity.CRITICAL",
// so the lower-cased key misses _SEVERITY_RANK entirely and max_severity stays
// at its "info" seed. Ground truth captured from
// ~/.agentfield/packages/sec-af/venv/bin/python.
func TestGetComplianceGapsVerifiedFindingSeverityQuirk(t *testing.T) {
	finding := schemas.NewVerifiedFinding()
	finding.CweID = "CWE-89"
	finding.Severity = schemas.SeverityCritical

	gaps := GetComplianceGaps([]schemas.VerifiedFinding{finding})

	if len(gaps) != 5 {
		t.Fatalf("want 5 gaps for CWE-89, got %d", len(gaps))
	}
	for _, gap := range gaps {
		if gap.MaxSeverity != "info" {
			t.Errorf("%s %s: max_severity = %q, want \"info\" (Python str(Severity.CRITICAL) quirk)",
				gap.Framework, gap.ControlID, gap.MaxSeverity)
		}
		if gap.FindingCount != 1 {
			t.Errorf("%s %s: finding_count = %d, want 1", gap.Framework, gap.ControlID, gap.FindingCount)
		}
	}
	// Ground truth from Python for the same input, in result order.
	wantControls := []string{"§164.312(a)(1)", "A.8.28", "A03:2021", "Req 6.2.4", "CC6"}
	wantFrameworks := []string{"HIPAA", "ISO27001", "OWASP", "PCI-DSS", "SOC2"}
	for i, gap := range gaps {
		if gap.Framework != wantFrameworks[i] || gap.ControlID != wantControls[i] {
			t.Fatalf("gap %d = (%s, %s), want (%s, %s)", i, gap.Framework, gap.ControlID, wantFrameworks[i], wantControls[i])
		}
	}
}

// TestGetComplianceGapsPointerFindings proves readField follows pointers, the
// shape a caller holding []*VerifiedFinding would produce.
func TestGetComplianceGapsPointerFindings(t *testing.T) {
	gaps := GetComplianceGaps([]*namespaceFinding{{CweID: "CWE-89", Severity: "high"}})
	if len(gaps) != 5 {
		t.Fatalf("want 5 gaps, got %d", len(gaps))
	}
	if gaps[0].MaxSeverity != "high" {
		t.Fatalf("max_severity = %q, want \"high\"", gaps[0].MaxSeverity)
	}
}

// TestReadField covers _read_field's two branches plus the missing-key default.
func TestReadField(t *testing.T) {
	if got := readField(map[string]any{"cwe_id": "CWE-1"}, "cwe_id"); got != "CWE-1" {
		t.Errorf("dict branch: got %v", got)
	}
	if got := readField(map[string]any{}, "cwe_id"); got != nil {
		t.Errorf("dict missing key: got %v, want nil", got)
	}
	if got := readField(namespaceFinding{CweID: "CWE-2"}, "cwe_id"); got != "CWE-2" {
		t.Errorf("attribute branch: got %v", got)
	}
	if got := readField(namespaceFinding{}, "not_a_field"); got != nil {
		t.Errorf("missing attribute: got %v, want nil", got)
	}
	if got := readField(nil, "cwe_id"); got != nil {
		t.Errorf("nil finding: got %v, want nil", got)
	}
	if got := readField(map[string]string{"severity": "low"}, "severity"); got != "low" {
		t.Errorf("typed map branch: got %v", got)
	}
}

// TestSeverityKey covers `str(x or "low").lower()`.
func TestSeverityKey(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "low"},
		{"", "low"},
		{"HIGH", "high"},
		{"critical", "critical"},
		{schemas.SeverityHigh, "severity.high"},
		{schemas.SeverityInfo, "severity.info"},
	}
	for _, tc := range cases {
		if got := severityKey(tc.in); got != tc.want {
			t.Errorf("severityKey(%#v) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// hybrid / AI fallback
// ---------------------------------------------------------------------------

// TestGetComplianceMappingsHybridUsesAIFallbackForUnknownCwe ports
// test_get_compliance_mappings_hybrid_uses_ai_fallback_for_unknown_cwe.
func TestGetComplianceMappingsHybridUsesAIFallbackForUnknownCwe(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings: []schemas.ComplianceSuggestion{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Prevent injection attacks"},
		},
		Confidence: "high",
	}}

	results := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)

	if gate.callCount() != 1 {
		t.Fatalf("gate calls = %d, want 1", gate.callCount())
	}
	if len(results) != 2 {
		t.Fatalf("results = %v, want 2 mappings", results)
	}
	got := sortedKeys(frameworkSet(results))
	if !reflect.DeepEqual(got, []string{"OWASP", "PCI-DSS"}) {
		t.Fatalf("frameworks = %v, want [OWASP PCI-DSS]", got)
	}
}

// TestGetComplianceMappingsHybridUsesCacheForAIResults ports
// test_get_compliance_mappings_hybrid_uses_cache_for_ai_results.
func TestGetComplianceMappingsHybridUsesCacheForAIResults(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings: []schemas.ComplianceSuggestion{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
		},
		Confidence: "high",
	}}

	first := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)
	second := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)

	if gate.callCount() != 1 {
		t.Fatalf("gate calls = %d, want 1 (second call must hit the cache)", gate.callCount())
	}
	if !reflect.DeepEqual(first, second) {
		t.Fatalf("cached result differs: %v vs %v", first, second)
	}
}

// TestGetComplianceMappingsHybridKeepsFastPathForKnownCwe ports
// test_get_compliance_mappings_hybrid_keeps_fast_path_for_known_cwe.
func TestGetComplianceMappingsHybridKeepsFastPathForKnownCwe(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{Confidence: "low"}}

	results := GetComplianceMappingsHybrid(context.Background(), "CWE-89", nil, gate)

	if gate.callCount() != 0 {
		t.Fatalf("gate calls = %d, want 0 for a table-known CWE", gate.callCount())
	}
	if !reflect.DeepEqual(results, GetComplianceMappings("CWE-89", nil)) {
		t.Fatalf("hybrid result differs from the static lookup: %v", results)
	}
}

// TestGetComplianceMappingsHybridWithoutGate covers `ai_gate is None`.
func TestGetComplianceMappingsHybridWithoutGate(t *testing.T) {
	ClearAICache()
	got := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, nil)
	if got == nil || len(got) != 0 {
		t.Fatalf("want an empty non-nil slice, got %#v", got)
	}
}

// TestGetComplianceMappingsHybridSwallowsGateErrors covers
// `except Exception: return []` — and asserts the failure is NOT cached, so a
// later successful call still reaches the gate.
func TestGetComplianceMappingsHybridSwallowsGateErrors(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{err: errors.New("boom")}

	got := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)
	if got == nil || len(got) != 0 {
		t.Fatalf("want an empty non-nil slice, got %#v", got)
	}

	gate.err = nil
	gate.response = schemas.ComplianceGate{
		Mappings:   []schemas.ComplianceSuggestion{{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"}},
		Confidence: "high",
	}
	retry := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)
	if len(retry) != 1 {
		t.Fatalf("retry after a failure returned %v", retry)
	}
	if gate.callCount() != 2 {
		t.Fatalf("gate calls = %d, want 2 (a failure must not be cached)", gate.callCount())
	}
}

// TestGetComplianceMappingsHybridFiltersAIMappings asserts the framework filter
// is applied to the gate's answer, not just to the static table.
func TestGetComplianceMappingsHybridFiltersAIMappings(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings: []schemas.ComplianceSuggestion{
			{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"},
			{Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Prevent injection"},
		},
		Confidence: "high",
	}}

	got := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", []string{"owasp"}, gate)

	if len(got) != 1 || got[0].Framework != "OWASP" {
		t.Fatalf("want only the OWASP mapping, got %v", got)
	}
}

// TestGetComplianceMappingsHybridCacheKeyDistinguishesFrameworks pins the
// Python cache key: `(cwe, None)` and `(cwe, ("owasp",))` are distinct entries,
// so restricting the frameworks re-queries the gate.
func TestGetComplianceMappingsHybridCacheKeyDistinguishesFrameworks(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings:   []schemas.ComplianceSuggestion{{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"}},
		Confidence: "high",
	}}

	_ = GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)
	_ = GetComplianceMappingsHybrid(context.Background(), "CWE-9999", []string{"owasp"}, gate)
	if gate.callCount() != 2 {
		t.Fatalf("gate calls = %d, want 2 (None and ('owasp',) are distinct keys)", gate.callCount())
	}

	// The same framework set spelled differently normalizes to the same key.
	_ = GetComplianceMappingsHybrid(context.Background(), "CWE-9999", []string{"OWASP"}, gate)
	_ = GetComplianceMappingsHybrid(context.Background(), "CWE-9999", []string{"owasp", "owasp"}, gate)
	if gate.callCount() != 2 {
		t.Fatalf("gate calls = %d, want 2 (normalized framework sets share a key)", gate.callCount())
	}
}

// TestGetComplianceMappingsHybridCachedResultsAreCopies asserts a caller cannot
// corrupt the cache by mutating what it was handed (Python model_copy(deep=True)).
func TestGetComplianceMappingsHybridCachedResultsAreCopies(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings:   []schemas.ComplianceSuggestion{{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"}},
		Confidence: "high",
	}}

	first := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)
	first[0].ControlName = "mutated"
	second := GetComplianceMappingsHybrid(context.Background(), "CWE-9999", nil, gate)

	if second[0].ControlName != "Injection" {
		t.Fatalf("cache was corrupted by the caller: %q", second[0].ControlName)
	}
}

// TestComplianceGatePrompt pins the fallback prompt text byte-for-byte,
// including the "(Unknown CWE)" literal.
func TestComplianceGatePrompt(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{Confidence: "low"}}

	_ = GetComplianceMappingsHybrid(context.Background(), "cwe9999", nil, gate)
	want := "Map CWE-9999 (Unknown CWE) to compliance framework controls. " +
		"Frameworks: OWASP, PCI-DSS, SOC2, HIPAA, ISO27001. Return specific control IDs."
	if gate.prompts[0] != want {
		t.Fatalf("prompt =\n%q\nwant\n%q", gate.prompts[0], want)
	}

	ClearAICache()
	gate2 := &fakeAIGate{response: schemas.ComplianceGate{Confidence: "low"}}
	_ = GetComplianceMappingsHybrid(context.Background(), "CWE-9999", []string{"PCI-DSS", "owasp"}, gate2)
	want2 := "Map CWE-9999 (Unknown CWE) to compliance framework controls. " +
		"Frameworks: PCI-DSS, owasp. Return specific control IDs."
	if gate2.prompts[0] != want2 {
		t.Fatalf("prompt =\n%q\nwant\n%q", gate2.prompts[0], want2)
	}
}

// TestGetComplianceMappingsHybridConcurrent exercises the cache under -race:
// Python's dict is single-event-loop safe, the Go port must be mutex safe.
func TestGetComplianceMappingsHybridConcurrent(t *testing.T) {
	ClearAICache()
	gate := &fakeAIGate{response: schemas.ComplianceGate{
		Mappings:   []schemas.ComplianceSuggestion{{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection"}},
		Confidence: "high",
	}}

	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			cwe := "CWE-90" + string(rune('0'+i%10))
			got := GetComplianceMappingsHybrid(context.Background(), cwe, nil, gate)
			if len(got) != 1 {
				t.Errorf("%s: got %v", cwe, got)
			}
		}(i)
	}
	wg.Wait()
}

// ---------------------------------------------------------------------------
// generated-table drift guard
// ---------------------------------------------------------------------------

// TestComplianceMapMatchesPythonSnapshot compares the generated Go table
// against testdata/compliance_map.json, which scripts/gen_compliance_table.py
// writes from the live Python COMPLIANCE_MAP in the same run that writes
// table_gen.go. A hand edit to either file fails here.
func TestComplianceMapMatchesPythonSnapshot(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "compliance_map.json"))
	if err != nil {
		t.Fatalf("read snapshot: %v", err)
	}
	var snapshot map[string][]schemas.ComplianceMapping
	if err := json.Unmarshal(raw, &snapshot); err != nil {
		t.Fatalf("decode snapshot: %v", err)
	}
	if !reflect.DeepEqual(ComplianceMap, snapshot) {
		if len(ComplianceMap) != len(snapshot) {
			t.Fatalf("table has %d CWEs, snapshot has %d", len(ComplianceMap), len(snapshot))
		}
		for cwe, want := range snapshot {
			if got := ComplianceMap[cwe]; !reflect.DeepEqual(got, want) {
				t.Errorf("%s:\n got: %+v\nwant: %+v", cwe, got, want)
			}
		}
		t.FailNow()
	}
}

// TestGetComplianceGapsFullGroundTruth compares the whole result against the
// output CPython produces for the same three dict findings. Captured with:
//
//	PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python -c "
//	from sec_af.compliance.mapping import get_compliance_gaps
//	print([(g.framework, g.control_id, g.max_severity, g.finding_count, g.cwe_ids)
//	       for g in get_compliance_gaps([
//	           {'cwe_id':'CWE-89','severity':'high'},
//	           {'cwe_id':'CWE-79','severity':'critical'},
//	           {'cwe_id':'CWE-918','severity':'medium'}])])"
func TestGetComplianceGapsFullGroundTruth(t *testing.T) {
	gaps := GetComplianceGaps([]map[string]any{
		{"cwe_id": "CWE-89", "severity": "high"},
		{"cwe_id": "CWE-79", "severity": "critical"},
		{"cwe_id": "CWE-918", "severity": "medium"},
	})

	want := []schemas.ComplianceGap{
		{Framework: "HIPAA", ControlID: "\u00a7164.312(a)(1)", ControlName: "Access control", FindingCount: 1, MaxSeverity: "high", CweIDs: []string{"CWE-89"}},
		{Framework: "HIPAA", ControlID: "\u00a7164.312(c)(1)", ControlName: "Integrity", FindingCount: 1, MaxSeverity: "critical", CweIDs: []string{"CWE-79"}},
		{Framework: "HIPAA", ControlID: "\u00a7164.312(e)(1)", ControlName: "Transmission security", FindingCount: 1, MaxSeverity: "medium", CweIDs: []string{"CWE-918"}},
		{Framework: "ISO27001", ControlID: "A.8.20", ControlName: "Network security", FindingCount: 1, MaxSeverity: "medium", CweIDs: []string{"CWE-918"}},
		{Framework: "ISO27001", ControlID: "A.8.28", ControlName: "Secure coding", FindingCount: 2, MaxSeverity: "critical", CweIDs: []string{"CWE-79", "CWE-89"}},
		{Framework: "OWASP", ControlID: "A03:2021", ControlName: "Injection", FindingCount: 2, MaxSeverity: "critical", CweIDs: []string{"CWE-79", "CWE-89"}},
		{Framework: "OWASP", ControlID: "A10:2021", ControlName: "Server-Side Request Forgery", FindingCount: 1, MaxSeverity: "medium", CweIDs: []string{"CWE-918"}},
		{Framework: "PCI-DSS", ControlID: "Req 6", ControlName: "Develop and maintain secure systems and software", FindingCount: 1, MaxSeverity: "medium", CweIDs: []string{"CWE-918"}},
		{Framework: "PCI-DSS", ControlID: "Req 6.2.4", ControlName: "Custom software addresses common coding vulnerabilities", FindingCount: 2, MaxSeverity: "critical", CweIDs: []string{"CWE-79", "CWE-89"}},
		{Framework: "SOC2", ControlID: "CC6", ControlName: "Logical and physical access controls", FindingCount: 1, MaxSeverity: "high", CweIDs: []string{"CWE-89"}},
		{Framework: "SOC2", ControlID: "CC7", ControlName: "System operations", FindingCount: 2, MaxSeverity: "critical", CweIDs: []string{"CWE-79", "CWE-918"}},
	}
	if !reflect.DeepEqual(gaps, want) {
		if len(gaps) != len(want) {
			t.Fatalf("got %d gaps, want %d", len(gaps), len(want))
		}
		for i := range want {
			if !reflect.DeepEqual(gaps[i], want[i]) {
				t.Errorf("gap %d:\n got: %+v\nwant: %+v", i, gaps[i], want[i])
			}
		}
		t.FailNow()
	}
}
