package scoring

import (
	"reflect"
	"testing"

	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file ports tests/test_scoring.py. Every expected number was produced by
// running the Python functions in the sec-af venv against the same inputs
// (`PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python`).
//
// Two assertions in tests/test_scoring.py are STALE — they encode the OLD
// "missing reachability tags default to requires_auth (0.5)" behavior that
// scoring.py's own comment says was deliberately changed to
// externally_reachable (1.0):
//
//   - test_compute_exploitability_score_defaults_reachability_when_missing
//     expects 1.05; the live code returns 2.1.
//   - test_reachability_multipliers_and_default_behavior[set()] expects 2.5;
//     the live code returns 5.0.
//
// The port follows the CODE (verified against the interpreter), which is what
// the audit pipeline actually computes, and the two tests below carry a note
// where they diverge from the Python file. See the PR's parity notes.

// makeFinding ports tests/test_scoring.py::make_finding.
//
// Python parity: the fixture passes `tags` as a SET, which pydantic coerces to
// a list in an undefined order. Go takes an ordered slice; the scoring code
// lower-cases into a set, so order never matters.
func makeFinding(severity schemas.Severity, evidenceLevel schemas.EvidenceLevel, tags []string, chainID *string) schemas.VerifiedFinding {
	f := schemas.NewVerifiedFinding()
	f.Fingerprint = "abc123"
	f.Title = "Sample finding"
	f.Description = "Sample description"
	f.FindingType = schemas.FindingTypeSast
	f.CweID = "CWE-89"
	f.CweName = "SQL Injection"
	if tags != nil {
		f.Tags = tags
	}
	f.Verdict = schemas.VerdictConfirmed
	f.EvidenceLevel = evidenceLevel
	f.Rationale = "Reasonable rationale"
	f.Severity = severity
	f.ExploitabilityScore = 0.0
	f.Location = schemas.Location{FilePath: "app.py", StartLine: 10, EndLine: 10}
	f.ChainID = chainID
	f.SarifRuleID = "sec-af/sast/sql-injection"
	f.SarifSecuritySeverity = 0.0
	return f
}

func strptr(s string) *string { return &s }

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_respects_severity_weights
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreRespectsSeverityWeights(t *testing.T) {
	cases := []struct {
		severity schemas.Severity
		want     float64
	}{
		{schemas.SeverityCritical, 10.0},
		{schemas.SeverityHigh, 8.0},
		{schemas.SeverityMedium, 5.0},
		{schemas.SeverityLow, 3.0},
		{schemas.SeverityInfo, 1.0},
	}
	for _, tc := range cases {
		t.Run(string(tc.severity), func(t *testing.T) {
			f := makeFinding(tc.severity, schemas.EvidenceLevelFullExploit, []string{"externally_reachable"}, nil)
			if got := ComputeExploitabilityScore(f); got != tc.want {
				t.Errorf("= %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_applies_chain_bonus_and_clamps_to_ten
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreAppliesChainBonusAndClampsToTen(t *testing.T) {
	f := makeFinding(schemas.SeverityCritical, schemas.EvidenceLevelFullExploit,
		[]string{"externally_reachable"}, strptr("chain-1"))
	// 10 * 1.0 * 1.0 * 2.0 = 20 -> clamped to 10.
	if got := ComputeExploitabilityScore(f); got != 10.0 {
		t.Errorf("= %v, want 10.0", got)
	}
	// A chain bonus that does NOT hit the clamp is still visible.
	mid := makeFinding(schemas.SeverityMedium, schemas.EvidenceLevelFlowIdentified,
		[]string{"requires_auth"}, strptr("c1"))
	if got := ComputeExploitabilityScore(mid); got != 1.5 {
		t.Errorf("chained medium = %v, want 1.5", got)
	}
	// Python parity: `if finding.chain_id:` — an EMPTY chain_id is falsy, so
	// it earns no bonus.
	empty := makeFinding(schemas.SeverityMedium, schemas.EvidenceLevelFullExploit,
		[]string{"externally_reachable"}, strptr(""))
	if got := ComputeExploitabilityScore(empty); got != 5.0 {
		t.Errorf("empty chain_id = %v, want 5.0 (no bonus)", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_uses_partial_flow_and_internal_reachability
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreUsesPartialFlowAndInternalReachability(t *testing.T) {
	f := makeFinding(schemas.SeverityMedium, schemas.EvidenceLevelReachabilityConfirmed,
		[]string{"internally_reachable"}, nil)
	if got := ComputeExploitabilityScore(f); got != 1.75 {
		t.Errorf("= %v, want 1.75", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_uses_requires_admin_and_unverified
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreUsesRequiresAdminAndUnverified(t *testing.T) {
	f := makeFinding(schemas.SeverityHigh, schemas.EvidenceLevelStaticMatch,
		[]string{"requires_admin"}, nil)
	// 8.0 * 0.1 * 0.3 = 0.24000000000000002 -> round(,2) -> 0.24
	if got := ComputeExploitabilityScore(f); got != 0.24 {
		t.Errorf("= %v, want 0.24", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_defaults_reachability_when_missing
//
// STALE IN PYTHON: tests/test_scoring.py asserts 1.05 (the old requires_auth
// default). scoring.py now defaults an EMPTY tag set to externally_reachable
// (1.0), so the value is 3.0 * 0.7 * 1.0 = 2.1. Verified against the
// interpreter.
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreDefaultsReachabilityWhenMissing(t *testing.T) {
	f := makeFinding(schemas.SeverityLow, schemas.EvidenceLevelSanitizationBypassable, nil, nil)
	if got := ComputeExploitabilityScore(f); got != 2.1 {
		t.Errorf("= %v, want 2.1 (empty tags -> externally_reachable)", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_is_deterministic
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreIsDeterministic(t *testing.T) {
	f := makeFinding(schemas.SeverityHigh, schemas.EvidenceLevelExploitScenarioValidated,
		[]string{"requires_auth"}, nil)
	if ComputeExploitabilityScore(f) != ComputeExploitabilityScore(f) {
		t.Error("two calls disagreed")
	}
}

// ---------------------------------------------------------------------------
// test_reachability_multipliers_and_default_behavior
//
// STALE IN PYTHON for the empty-set row: the file asserts 2.5, the live code
// returns 5.0 (see the file header).
// ---------------------------------------------------------------------------

func TestReachabilityMultipliersAndDefaultBehavior(t *testing.T) {
	cases := []struct {
		name string
		tags []string
		want float64
	}{
		// Tags are lower-cased before matching.
		{"EXTERNALLY_REACHABLE", []string{"EXTERNALLY_REACHABLE"}, 5.0},
		{"internally_reachable", []string{"internally_reachable"}, 3.5},
		{"requires_auth", []string{"requires_auth"}, 2.5},
		{"requires_admin", []string{"requires_admin"}, 1.5},
		// A tag that says nothing about reachability -> requires_auth (0.5).
		{"custom_tag", []string{"custom_tag"}, 2.5},
		// NO tags at all -> externally_reachable (1.0). Python file says 2.5.
		{"empty", []string{}, 5.0},
		{"nil", nil, 5.0},
		// Probe order: externally_reachable wins over requires_admin.
		{"probe order", []string{"requires_admin", "externally_reachable"}, 5.0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := makeFinding(schemas.SeverityMedium, schemas.EvidenceLevelFullExploit, tc.tags, nil)
			if got := ComputeExploitabilityScore(f); got != tc.want {
				t.Errorf("= %v, want %v", got, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_lower_bound_is_zeroish_for_low_signal
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreLowerBoundIsZeroishForLowSignal(t *testing.T) {
	f := makeFinding(schemas.SeverityInfo, schemas.EvidenceLevelStaticMatch,
		[]string{"requires_admin"}, nil)
	// 1.0 * 0.1 * 0.3 = 0.030000000000000002 -> 0.03
	if got := ComputeExploitabilityScore(f); got != 0.03 {
		t.Errorf("= %v, want 0.03", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_exploitability_score_does_not_depend_on_optional_cvss_or_epss_fields
// ---------------------------------------------------------------------------

func TestComputeExploitabilityScoreIgnoresOptionalCvssAndEpss(t *testing.T) {
	plain := makeFinding(schemas.SeverityHigh, schemas.EvidenceLevelExploitScenarioValidated,
		[]string{"requires_auth"}, nil)
	withOptional := plain
	withOptional.CvssV4 = &schemas.CvssV4Score{
		Vector:           "CVSS:4.0/AV:N/AC:L/PR:N/UI:N/VC:H/VI:H/VA:H",
		BaseScore:        9.3,
		Severity:         "critical",
		Automatable:      true,
		SubsequentImpact: true,
	}
	withOptional.Epss = &schemas.EpssScore{Score: 0.81, Percentile: 0.95, Date: "2026-03-04"}

	// 8.0 * 0.9 * 0.5 = 3.6000000000000005 -> 3.6
	if got := ComputeExploitabilityScore(plain); got != 3.6 {
		t.Errorf("plain = %v, want 3.6", got)
	}
	if got := ComputeExploitabilityScore(withOptional); got != 3.6 {
		t.Errorf("with cvss/epss = %v, want 3.6", got)
	}
}

// ---------------------------------------------------------------------------
// test_compute_priority_rank_sorts_descending
// ---------------------------------------------------------------------------

func TestComputePriorityRankSortsDescending(t *testing.T) {
	low := makeFinding(schemas.SeverityInfo, schemas.EvidenceLevelStaticMatch, []string{"requires_admin"}, nil)
	low.ID = "low"
	medium := makeFinding(schemas.SeverityMedium, schemas.EvidenceLevelFlowIdentified, []string{"requires_auth"}, nil)
	medium.ID = "medium"
	high := makeFinding(schemas.SeverityCritical, schemas.EvidenceLevelFullExploit, []string{"externally_reachable"}, nil)
	high.ID = "high"

	input := []schemas.VerifiedFinding{medium, high, low}
	ranked := ComputePriorityRank(input)

	gotIDs := []string{ranked[0].ID, ranked[1].ID, ranked[2].ID}
	if !reflect.DeepEqual(gotIDs, []string{"high", "medium", "low"}) {
		t.Errorf("ranked = %v, want [high medium low]", gotIDs)
	}
	// Python's sorted() returns a NEW list; the input must be untouched.
	inputIDs := []string{input[0].ID, input[1].ID, input[2].ID}
	if !reflect.DeepEqual(inputIDs, []string{"medium", "high", "low"}) {
		t.Errorf("input was mutated: %v", inputIDs)
	}
}

// ---------------------------------------------------------------------------
// test_compute_priority_rank_is_stable_for_equal_scores
// ---------------------------------------------------------------------------

func TestComputePriorityRankIsStableForEqualScores(t *testing.T) {
	first := makeFinding(schemas.SeverityLow, schemas.EvidenceLevelFlowIdentified, []string{"requires_auth"}, nil)
	first.ID = "first"
	second := makeFinding(schemas.SeverityLow, schemas.EvidenceLevelFlowIdentified, []string{"requires_auth"}, nil)
	second.ID = "second"

	ranked := ComputePriorityRank([]schemas.VerifiedFinding{first, second})
	if ranked[0].ID != "first" || ranked[1].ID != "second" {
		t.Errorf("ranked = [%s %s], want [first second] (Python sorted() is stable)", ranked[0].ID, ranked[1].ID)
	}

	// A longer run of ties, to catch a non-stable sort that only shows up
	// above the insertion-sort cutoff.
	var many []schemas.VerifiedFinding
	for i := 0; i < 40; i++ {
		f := makeFinding(schemas.SeverityLow, schemas.EvidenceLevelFlowIdentified, []string{"requires_auth"}, nil)
		f.ID = string(rune('a' + i%26))
		f.Fingerprint = f.ID + "-" + string(rune('0'+i/26))
		many = append(many, f)
	}
	rankedMany := ComputePriorityRank(many)
	for i := range many {
		if rankedMany[i].Fingerprint != many[i].Fingerprint {
			t.Fatalf("tie at %d reordered: %q != %q", i, rankedMany[i].Fingerprint, many[i].Fingerprint)
		}
	}

	// An empty input returns an empty (non-nil) slice, not nil.
	if got := ComputePriorityRank(nil); got == nil || len(got) != 0 {
		t.Errorf("ComputePriorityRank(nil) = %#v, want an empty slice", got)
	}
}

// ---------------------------------------------------------------------------
// test_assign_severity_label
// ---------------------------------------------------------------------------

func TestAssignSeverityLabel(t *testing.T) {
	cases := []struct {
		score float64
		label string
	}{
		{10.0, "critical"},
		{9.0, "critical"},
		{8.9, "high"},
		{7.0, "high"},
		{6.9, "medium"},
		{4.0, "medium"},
		{3.9, "low"},
		{1.0, "low"},
		{0.9, "info"},
		{0.0, "info"},
		{-1.0, "info"},
	}
	for _, tc := range cases {
		if got := AssignSeverityLabel(tc.score); got != tc.label {
			t.Errorf("AssignSeverityLabel(%v) = %q, want %q", tc.score, got, tc.label)
		}
	}
}

// ---------------------------------------------------------------------------
// apply_cwe_severity_floor — not covered by tests/test_scoring.py, so these
// are derived from the function's contract and verified against the
// interpreter.
// ---------------------------------------------------------------------------

func TestApplyCWESeverityFloor(t *testing.T) {
	cases := []struct {
		cwe     string
		current schemas.Severity
		want    schemas.Severity
	}{
		// A floor above the current severity upgrades it.
		{"CWE-78", schemas.SeverityMedium, schemas.SeverityCritical},
		{"CWE-918", schemas.SeverityInfo, schemas.SeverityHigh},
		{"CWE-79", schemas.SeverityLow, schemas.SeverityMedium},
		// A floor at or below the current severity leaves it alone.
		{"CWE-78", schemas.SeverityCritical, schemas.SeverityCritical},
		{"CWE-79", schemas.SeverityHigh, schemas.SeverityHigh},
		{"CWE-22", schemas.SeverityCritical, schemas.SeverityCritical},
		// A CWE with no floor is untouched.
		{"CWE-9999", schemas.SeverityLow, schemas.SeverityLow},
		{"", schemas.SeverityInfo, schemas.SeverityInfo},
	}
	for _, tc := range cases {
		if got := ApplyCWESeverityFloor(tc.cwe, tc.current); got != tc.want {
			t.Errorf("ApplyCWESeverityFloor(%q, %q) = %q, want %q", tc.cwe, tc.current, got, tc.want)
		}
	}
}

func TestScoringTablesMatchPython(t *testing.T) {
	if len(CWESeverityFloor) != 18 {
		t.Errorf("CWE_SEVERITY_FLOOR has %d entries, want 18", len(CWESeverityFloor))
	}
	wantCritical := []string{"CWE-78", "CWE-77", "CWE-94", "CWE-95", "CWE-96", "CWE-89", "CWE-502"}
	for _, cwe := range wantCritical {
		if CWESeverityFloor[cwe] != schemas.SeverityCritical {
			t.Errorf("CWE_SEVERITY_FLOOR[%s] = %q, want critical", cwe, CWESeverityFloor[cwe])
		}
	}
	wantHigh := []string{"CWE-918", "CWE-287", "CWE-290", "CWE-306", "CWE-798", "CWE-22", "CWE-611", "CWE-840", "CWE-862", "CWE-863"}
	for _, cwe := range wantHigh {
		if CWESeverityFloor[cwe] != schemas.SeverityHigh {
			t.Errorf("CWE_SEVERITY_FLOOR[%s] = %q, want high", cwe, CWESeverityFloor[cwe])
		}
	}
	if CWESeverityFloor["CWE-79"] != schemas.SeverityMedium {
		t.Errorf("CWE_SEVERITY_FLOOR[CWE-79] = %q, want medium", CWESeverityFloor["CWE-79"])
	}

	wantWeights := map[schemas.Severity]float64{
		schemas.SeverityCritical: 10.0, schemas.SeverityHigh: 8.0, schemas.SeverityMedium: 5.0,
		schemas.SeverityLow: 3.0, schemas.SeverityInfo: 1.0,
	}
	if !reflect.DeepEqual(SeverityWeights, wantWeights) {
		t.Errorf("SEVERITY_WEIGHTS = %v, want %v", SeverityWeights, wantWeights)
	}
	wantEvidence := map[schemas.EvidenceLevel]float64{
		schemas.EvidenceLevelFullExploit: 1.0, schemas.EvidenceLevelExploitScenarioValidated: 0.9,
		schemas.EvidenceLevelSanitizationBypassable: 0.7, schemas.EvidenceLevelReachabilityConfirmed: 0.5,
		schemas.EvidenceLevelFlowIdentified: 0.3, schemas.EvidenceLevelStaticMatch: 0.1,
	}
	if !reflect.DeepEqual(EvidenceMultipliers, wantEvidence) {
		t.Errorf("EVIDENCE_MULTIPLIERS = %v, want %v", EvidenceMultipliers, wantEvidence)
	}
	wantReach := map[string]float64{
		"externally_reachable": 1.0, "internally_reachable": 0.7,
		"requires_auth": 0.5, "requires_admin": 0.3,
	}
	if !reflect.DeepEqual(ReachabilityMultipliers, wantReach) {
		t.Errorf("REACHABILITY_MULTIPLIERS = %v, want %v", ReachabilityMultipliers, wantReach)
	}
}

// TestEvidenceMultiplierSweep pins every (severity, evidence) pair against the
// values the Python function returns for an externally-reachable finding.
func TestEvidenceMultiplierSweep(t *testing.T) {
	want := map[schemas.EvidenceLevel]float64{
		schemas.EvidenceLevelStaticMatch:              1.0,
		schemas.EvidenceLevelFlowIdentified:           3.0,
		schemas.EvidenceLevelReachabilityConfirmed:    5.0,
		schemas.EvidenceLevelSanitizationBypassable:   7.0,
		schemas.EvidenceLevelExploitScenarioValidated: 9.0,
		schemas.EvidenceLevelFullExploit:              10.0,
	}
	for level, expected := range want {
		f := makeFinding(schemas.SeverityCritical, level, []string{"externally_reachable"}, nil)
		if got := ComputeExploitabilityScore(f); got != expected {
			t.Errorf("critical @ %s = %v, want %v", level.Name(), got, expected)
		}
	}
}

// TestRoundingMatchesPythonRound pins the rounding scoring relies on
// (pyfmt.Round) against the values Python's round(x, 2) produces, including the
// cases where naive math.Round(x*100)/100 diverges. The scoring package used to
// carry a private copy of this helper; it now delegates to internal/pyfmt, and
// this test guards the values scoring actually depends on.
func TestRoundingMatchesPythonRound(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0.24000000000000002, 0.24},
		{0.030000000000000002, 0.03},
		{3.6000000000000005, 3.6},
		{2.0999999999999996, 2.1},
		{1.75, 1.75},
		// Exact ties round to even, not away from zero: Python round(0.125, 2)
		// is 0.12 and round(0.135, 2) is 0.14 (0.135 is really 0.13500...0028).
		{0.125, 0.12},
		{0.135, 0.14},
		{10.0, 10.0},
		{0.0, 0.0},
	}
	for _, tc := range cases {
		if got := pyfmt.Round(tc.in, 2); got != tc.want {
			t.Errorf("pyfmt.Round(%v, 2) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

// TestUnknownSeverityOrEvidenceCollapsesToZero documents the ONE deliberate
// divergence from Python: Python raises KeyError (pydantic makes it
// unreachable), Go treats the missing weight as 0.
func TestUnknownSeverityOrEvidenceCollapsesToZero(t *testing.T) {
	bad := makeFinding(schemas.Severity("blocker"), schemas.EvidenceLevelFullExploit,
		[]string{"externally_reachable"}, nil)
	if got := ComputeExploitabilityScore(bad); got != 0.0 {
		t.Errorf("unknown severity = %v, want 0", got)
	}
	badLevel := makeFinding(schemas.SeverityCritical, schemas.EvidenceLevel(9),
		[]string{"externally_reachable"}, nil)
	if got := ComputeExploitabilityScore(badLevel); got != 0.0 {
		t.Errorf("unknown evidence level = %v, want 0", got)
	}
}
