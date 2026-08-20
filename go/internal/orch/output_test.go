package orch

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/appx"
	"github.com/Agent-Field/sec-af/go/internal/compliance"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
	"github.com/Agent-Field/sec-af/go/internal/scoring"
)

// verifiedWith builds a VerifiedFinding from the fixture with the given
// identity, verdict and severity.
func verifiedWith(t *testing.T, id string, verdict schemas.Verdict, severity schemas.Severity, cwe string) schemas.VerifiedFinding {
	t.Helper()
	f := readJSON[schemas.VerifiedFinding](t, "verified_fixture.json")
	f.ID = id
	f.Fingerprint = "fp-" + id
	f.Verdict = verdict
	f.Severity = severity
	f.CweID = cwe
	f.Tags = []string{}
	return f
}

// TestGenerateOutput_SeverityThreshold walks the filter, including the two
// spellings that disable it.
func TestGenerateOutput_SeverityThreshold(t *testing.T) {
	compliance.ClearAICache()

	all := []schemas.VerifiedFinding{
		verifiedWith(t, "crit", schemas.VerdictConfirmed, schemas.SeverityCritical, "CWE-79"),
		verifiedWith(t, "high", schemas.VerdictLikely, schemas.SeverityHigh, "CWE-79"),
		verifiedWith(t, "med", schemas.VerdictInconclusive, schemas.SeverityMedium, "CWE-79"),
		verifiedWith(t, "low", schemas.VerdictInconclusive, schemas.SeverityLow, "CWE-79"),
		verifiedWith(t, "info", schemas.VerdictNotExploitable, schemas.SeverityInfo, "CWE-79"),
	}

	cases := []struct {
		threshold string
		wantIDs   []string
	}{
		{"critical", []string{"crit"}},
		{"HIGH", []string{"crit", "high"}},
		{"medium", []string{"crit", "high", "med"}},
		{"low", []string{"crit", "high", "med", "low"}},
		// "info" scores 0, so the filter is skipped entirely.
		{"info", []string{"crit", "high", "med", "low", "info"}},
		// An unrecognised threshold also scores 0 — no filtering, no error.
		{"bogus", []string{"crit", "high", "med", "low", "info"}},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.threshold, func(t *testing.T) {
			o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.SeverityThreshold = tc.threshold })
			verified := append([]schemas.VerifiedFinding(nil), all...)

			result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(), verified)
			if err != nil {
				t.Fatalf("GenerateOutput: %v", err)
			}
			got := make([]string, 0, len(result.Findings))
			for _, f := range result.Findings {
				got = append(got, f.ID)
			}
			if !reflect.DeepEqual(got, tc.wantIDs) {
				t.Errorf("threshold %q kept %v, want %v", tc.threshold, got, tc.wantIDs)
			}
		})
	}
}

// TestGenerateOutput_EnrichesEveryFinding pins the four per-finding mutations.
func TestGenerateOutput_EnrichesEveryFinding(t *testing.T) {
	compliance.ClearAICache()
	o, _ := newTestOrchestrator(t)

	// CWE-89 carries a severity floor, so a "low" finding must come back raised.
	finding := verifiedWith(t, "sqli", schemas.VerdictConfirmed, schemas.SeverityLow, "CWE-89")
	before := finding

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(),
		[]schemas.VerifiedFinding{finding})
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}
	got := result.Findings[0]

	wantSeverity := scoring.ApplyCWESeverityFloor(before.CweID, before.Severity)
	if got.Severity != wantSeverity {
		t.Errorf("severity = %q, want the CWE floor %q", got.Severity, wantSeverity)
	}
	if got.ExploitabilityScore == 0 {
		t.Error("exploitability_score must be recomputed, not left at the input's 0")
	}
	if got.SarifSecuritySeverity != got.ExploitabilityScore {
		t.Errorf("sarif_security_severity = %v, want it mirrored from exploitability_score %v",
			got.SarifSecuritySeverity, got.ExploitabilityScore)
	}
	if got.Compliance == nil {
		t.Error("compliance must be replaced by the mapping lookup, never left nil")
	}
	if len(got.Compliance) == 0 {
		t.Error("CWE-89 is in the static compliance table; want at least one mapping")
	}
}

// TestGenerateOutput_CountsAndNoiseReduction pins the counters, the seeded
// by_severity map and the rounded percentage.
func TestGenerateOutput_CountsAndNoiseReduction(t *testing.T) {
	compliance.ClearAICache()
	// AuditInput's default severity_threshold is "low", which scores 1 and
	// would drop the "info" finding before the counters ever see it. "info"
	// scores 0 and disables the filter, which is what this test needs.
	o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.SeverityThreshold = "info" })

	verified := []schemas.VerifiedFinding{
		verifiedWith(t, "a", schemas.VerdictConfirmed, schemas.SeverityHigh, "CWE-79"),
		verifiedWith(t, "b", schemas.VerdictConfirmed, schemas.SeverityHigh, "CWE-79"),
		verifiedWith(t, "c", schemas.VerdictLikely, schemas.SeverityMedium, "CWE-79"),
		verifiedWith(t, "d", schemas.VerdictInconclusive, schemas.SeverityLow, "CWE-79"),
		verifiedWith(t, "e", schemas.VerdictNotExploitable, schemas.SeverityInfo, "CWE-79"),
	}
	hunt := schemas.NewHuntResult()
	hunt.TotalRaw = 7

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), hunt, verified)
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}

	if result.Confirmed != 2 || result.Likely != 1 || result.Inconclusive != 1 || result.NotExploitable != 1 {
		t.Errorf("verdict counts = %d/%d/%d/%d, want 2/1/1/1",
			result.Confirmed, result.Likely, result.Inconclusive, result.NotExploitable)
	}
	if result.TotalRawFindings != 7 {
		t.Errorf("total_raw_findings = %d, want 7 (it comes from hunt.total_raw)", result.TotalRawFindings)
	}

	// by_severity is seeded with EVERY Severity member, so a severity with no
	// findings still reports 0. The CWE-79 floor may raise some entries, so the
	// assertion is on the key set plus the total.
	if len(result.BySeverity) != len(schemas.AllSeverities) {
		t.Errorf("by_severity keys = %v, want one per Severity member", result.BySeverity)
	}
	total := 0
	for _, severity := range schemas.AllSeverities {
		count, present := result.BySeverity[string(severity)]
		if !present {
			t.Errorf("by_severity is missing %q", severity)
		}
		total += count
	}
	if total != len(verified) {
		t.Errorf("by_severity sums to %d, want %d", total, len(verified))
	}

	// 1 not_exploitable of 7 raw -> 14.285714...% -> round(x, 2) = 14.29.
	if want := pyfmt.Round(1.0/7.0*100.0, 2); result.NoiseReductionPct != want {
		t.Errorf("noise_reduction_pct = %v, want %v", result.NoiseReductionPct, want)
	}
	if want := 14.29; result.NoiseReductionPct != want {
		t.Errorf("noise_reduction_pct = %v, want %v", result.NoiseReductionPct, want)
	}
}

// TestGenerateOutput_NoiseReductionGuard: total_raw of 0 yields 0.0, not a
// division by zero.
func TestGenerateOutput_NoiseReductionGuard(t *testing.T) {
	compliance.ClearAICache()
	o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.SeverityThreshold = "info" })
	verified := []schemas.VerifiedFinding{
		verifiedWith(t, "a", schemas.VerdictNotExploitable, schemas.SeverityInfo, "CWE-79"),
	}
	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(), verified)
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}
	if result.NoiseReductionPct != 0 {
		t.Errorf("noise_reduction_pct = %v, want 0", result.NoiseReductionPct)
	}
}

// TestGenerateOutput_AttackChains pins the PotentialChain -> AttackChain
// projection, including `description = combined_impact`.
func TestGenerateOutput_AttackChains(t *testing.T) {
	compliance.ClearAICache()
	o, _ := newTestOrchestrator(t)

	hunt := schemas.NewHuntResult()
	hunt.Chains = []schemas.PotentialChain{{
		ChainID:           "chain-1",
		Title:             "SSRF to RCE",
		FindingIDs:        []string{"a", "b"},
		CombinedImpact:    "internal metadata service reachable, then RCE",
		EstimatedSeverity: schemas.SeverityCritical,
	}}

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), hunt, nil)
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}
	if len(result.AttackChains) != 1 {
		t.Fatalf("attack_chains = %d, want 1", len(result.AttackChains))
	}
	chain := result.AttackChains[0]
	if chain.ChainID != "chain-1" || chain.Title != "SSRF to RCE" {
		t.Errorf("chain identity = %+v", chain)
	}
	if chain.Description != chain.CombinedImpact {
		t.Errorf("description = %q, want it to equal combined_impact %q", chain.Description, chain.CombinedImpact)
	}
	if !reflect.DeepEqual(chain.Findings, []string{"a", "b"}) {
		t.Errorf("findings = %v", chain.Findings)
	}
	if chain.CombinedSeverity != schemas.SeverityCritical {
		t.Errorf("combined_severity = %q", chain.CombinedSeverity)
	}
	if chain.MitreAttackMapping != nil {
		t.Errorf("mitre_attack_mapping = %v, want nil (it is not passed)", chain.MitreAttackMapping)
	}
}

// TestGenerateOutput_ResultEnvelope pins the scalar fields and the metadata.
func TestGenerateOutput_ResultEnvelope(t *testing.T) {
	compliance.ClearAICache()

	base := time.Now()
	restoreMono := nowMonotonic
	nowMonotonic = func() time.Time { return base.Add(3 * time.Second) }
	defer func() { nowMonotonic = restoreMono }()

	pinned, _ := time.Parse(time.RFC3339Nano, "2026-01-02T03:04:05.123456Z")
	restoreUTC := nowUTC
	nowUTC = func() time.Time { return pinned.UTC() }
	defer func() { nowUTC = restoreUTC }()

	sha := "deadbeef"
	o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) {
		in.RepoURL = "https://example.invalid/acme/api"
		in.Branch = "release/1.2"
		in.CommitSha = &sha
		in.Depth = "thorough"
	})
	o.StartedAt = base
	o.SetAgentInvocations(17)
	o.FindingsNotVerified = 4
	o.registerCost(PhaseRecon, floatPtr(0.123456))
	o.registerCost(PhaseHunt, floatPtr(1.987654))
	o.TrackDrop(context.Background(), "dropped", nil, "verifier_error")

	hunt := schemas.NewHuntResult()
	hunt.StrategiesRun = []string{"injection", "auth"}

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), hunt, nil)
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}

	if result.Repository != "https://example.invalid/acme/api" {
		t.Errorf("repository = %q", result.Repository)
	}
	if result.CommitSha != "deadbeef" {
		t.Errorf("commit_sha = %q", result.CommitSha)
	}
	if result.Branch == nil || *result.Branch != "release/1.2" {
		t.Errorf("branch = %v", result.Branch)
	}
	if got := result.Timestamp.String(); got != "2026-01-02T03:04:05.123456+00:00" {
		t.Errorf("timestamp = %q", got)
	}
	if result.DepthProfile != "thorough" {
		t.Errorf("depth_profile = %q", result.DepthProfile)
	}
	if result.Provider != "harness" {
		t.Errorf("provider = %q, want harness", result.Provider)
	}
	if !reflect.DeepEqual(result.StrategiesUsed, []string{"injection", "auth"}) {
		t.Errorf("strategies_used = %v", result.StrategiesUsed)
	}
	if result.AgentInvocations != 17 {
		t.Errorf("agent_invocations = %d, want 17", result.AgentInvocations)
	}
	if result.DurationSeconds != 3 {
		t.Errorf("duration_seconds = %v, want 3", result.DurationSeconds)
	}
	// round(total, 4) and round(each phase, 4) — Python's banker's rounding.
	if want := pyfmt.Round(0.123456+1.987654, 4); result.CostUsd != want {
		t.Errorf("cost_usd = %v, want %v", result.CostUsd, want)
	}
	wantBreakdown := map[string]float64{
		"recon": pyfmt.Round(0.123456, 4),
		"hunt":  pyfmt.Round(1.987654, 4),
		"prove": 0,
	}
	if !reflect.DeepEqual(result.CostBreakdown, wantBreakdown) {
		t.Errorf("cost_breakdown = %v, want %v", result.CostBreakdown, wantBreakdown)
	}
	if got := result.Metadata["findings_not_verified"]; got != 4 {
		t.Errorf("metadata.findings_not_verified = %v, want 4", got)
	}
	if got, ok := result.Metadata["prove_drop_summary"].(map[string]any); !ok || got["demoted_total"] != 1 {
		t.Errorf("metadata.prove_drop_summary = %#v", result.Metadata["prove_drop_summary"])
	}
	if result.Sarif == "" {
		t.Error("sarif must be filled in by generate_sarif")
	}
	var sarif map[string]any
	if err := json.Unmarshal([]byte(result.Sarif), &sarif); err != nil {
		t.Errorf("sarif is not valid JSON: %v", err)
	}
	// policy_violations is never passed, so it keeps the pydantic default.
	if result.PolicyViolations == nil || len(result.PolicyViolations) != 0 {
		t.Errorf("policy_violations = %v, want []", result.PolicyViolations)
	}
}

// TestGenerateOutput_CommitShaFallback: an absent OR empty commit_sha becomes
// "HEAD" (Python truthiness).
func TestGenerateOutput_CommitShaFallback(t *testing.T) {
	compliance.ClearAICache()
	for _, sha := range []*string{nil, strPtr("")} {
		o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) { in.CommitSha = sha })
		result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(), nil)
		if err != nil {
			t.Fatalf("GenerateOutput: %v", err)
		}
		if result.CommitSha != "HEAD" {
			t.Errorf("commit_sha = %q, want HEAD", result.CommitSha)
		}
	}
}

// TestGenerateOutput_BudgetNote fires only when the flag latched.
func TestGenerateOutput_BudgetNote(t *testing.T) {
	compliance.ClearAICache()

	t.Run("silent when the budget held", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		if _, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(), nil); err != nil {
			t.Fatalf("GenerateOutput: %v", err)
		}
		for _, note := range fake.Notes {
			if note.Message[:6] == "Budget" {
				t.Errorf("unexpected budget note %q", note.Message)
			}
		}
	})

	t.Run("reports the unverified count when exhausted", func(t *testing.T) {
		o, fake := newTestOrchestrator(t)
		o.markBudgetExhausted()
		o.FindingsNotVerified = 12
		if _, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(), nil); err != nil {
			t.Fatalf("GenerateOutput: %v", err)
		}
		want := "Budget exhausted; unverified findings: 12"
		found := false
		for _, note := range fake.Notes {
			if note.Message == want {
				found = true
				if !reflect.DeepEqual(note.Tags, []string{"audit", "budget", "exhausted"}) {
					t.Errorf("tags = %v", note.Tags)
				}
			}
		}
		if !found {
			t.Errorf("missing %q in %q", want, fake.NoteMessages())
		}
	})
}

// TestGenerateOutput_ComplianceFrameworksHitThePythonBug reproduces
// orchestrator.py:463's TypeError — see ErrComplianceReportArity. The
// checkpoint directory IS created first, and no compliance-<framework>.md file
// is ever written.
func TestGenerateOutput_ComplianceFrameworksHitThePythonBug(t *testing.T) {
	compliance.ClearAICache()
	o, _ := newTestOrchestrator(t, func(in *schemas.AuditInput) {
		in.ComplianceFrameworks = []string{"SOC2", "PCI-DSS"}
	})

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(),
		[]schemas.VerifiedFinding{verifiedWith(t, "a", schemas.VerdictConfirmed, schemas.SeverityHigh, "CWE-89")})
	if !errors.Is(err, ErrComplianceReportArity) {
		t.Fatalf("err = %v, want ErrComplianceReportArity", err)
	}
	// The result is still built (Python gets that far too, it just cannot
	// return it).
	if result.Sarif == "" {
		t.Error("the SARIF artifact is produced before the failure")
	}
	if _, statErr := os.Stat(o.CheckpointDir); statErr != nil {
		t.Errorf("the checkpoint dir must be created before the failure: %v", statErr)
	}
	for _, framework := range []string{"SOC2", "PCI-DSS"} {
		path := filepath.Join(o.CheckpointDir, "compliance-"+framework+".md")
		if _, statErr := os.Stat(path); statErr == nil {
			t.Errorf("%s must NOT be written — Python raises on the first iteration", path)
		}
	}
}

// TestGenerateOutput_ComplianceFrameworksSelectTheMappings: a non-empty list is
// passed through to get_compliance_mappings_hybrid; an empty one becomes None
// so the default framework set applies.
func TestGenerateOutput_ComplianceFrameworksSelectTheMappings(t *testing.T) {
	compliance.ClearAICache()

	// Empty list -> None -> every framework the static table knows for CWE-89.
	o, _ := newTestOrchestrator(t)
	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(),
		[]schemas.VerifiedFinding{verifiedWith(t, "a", schemas.VerdictConfirmed, schemas.SeverityHigh, "CWE-89")})
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}
	unfiltered := result.Findings[0].Compliance
	if len(unfiltered) == 0 {
		t.Fatal("CWE-89 must map to at least one control")
	}
	want := compliance.GetComplianceMappings("CWE-89", nil)
	if !reflect.DeepEqual(unfiltered, want) {
		t.Errorf("compliance = %v, want the unfiltered table %v", unfiltered, want)
	}
}

// TestGenerateOutput_AIGateFallbackForUnknownCWE: a CWE the static table does
// not know reaches the AI gate through the orchestrator's adapter.
func TestGenerateOutput_AIGateFallbackForUnknownCWE(t *testing.T) {
	compliance.ClearAICache()
	defer compliance.ClearAICache()

	o, fake := newTestOrchestrator(t)
	fake.AIFn = appx.AIJSON(func(string) (json.RawMessage, error) {
		return json.RawMessage(`{"mappings":[{"framework":"SOC2","control_id":"CC9.9","control_name":"Invented"}],"confidence":"low"}`), nil
	})

	result, err := o.GenerateOutput(context.Background(), schemas.NewReconResult(), schemas.NewHuntResult(),
		[]schemas.VerifiedFinding{verifiedWith(t, "a", schemas.VerdictConfirmed, schemas.SeverityHigh, "CWE-999999")})
	if err != nil {
		t.Fatalf("GenerateOutput: %v", err)
	}
	got := result.Findings[0].Compliance
	if len(got) != 1 || got[0].ControlID != "CC9.9" {
		t.Errorf("compliance = %v, want the AI gate's single mapping", got)
	}
	if len(fake.AIs) == 0 {
		t.Error("the AI gate must be consulted for an unknown CWE")
	}
}
