package orch

import (
	"context"
	"errors"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/compliance"
	"github.com/Agent-Field/sec-af/go/internal/gates"
	"github.com/Agent-Field/sec-af/go/internal/output"
	"github.com/Agent-Field/sec-af/go/internal/pyfmt"
	"github.com/Agent-Field/sec-af/go/internal/schemas"
	"github.com/Agent-Field/sec-af/go/internal/scoring"
)

// severityOrder ports the local `severity_order` map `_generate_output` uses
// for the threshold filter. Note "info" scores 0, which is why a threshold of
// "info" (or an unrecognised threshold) disables filtering entirely.
var severityOrder = map[string]int{
	"critical": 4,
	"high":     3,
	"medium":   2,
	"low":      1,
	"info":     0,
}

// ErrComplianceReportArity is the TypeError orchestrator.py:463 raises.
//
// PYTHON BUG, REPRODUCED. `_generate_output` calls
//
//	compliance_report = generate_compliance_report(result, framework)
//
// but output/compliance_report.py declares
//
//	def generate_compliance_report(result: SecurityAuditResult) -> str
//
// — ONE positional parameter. VERIFIED against the repo's own interpreter:
// calling it with two arguments raises
//
//	TypeError: generate_compliance_report() takes 1 positional argument but 2 were given
//
// so any audit whose `compliance_frameworks` list is non-empty fails at the
// very end of _generate_output, after the SARIF/JSON/Markdown artifacts have
// been produced and after the checkpoint directory has been created, but before
// a single compliance-<framework>.md file is written. app.py turns that into
// HTTP 500 with `{"error": "audit execution failed: ..."}`.
//
// DESIGN.md §0.2 is explicit that a Python oddity is reproduced rather than
// improved, so GenerateOutput returns this error on the same input. Fixing it
// (dropping the second argument, or adding the parameter) is a change to the
// PYTHON tree and belongs in a separate PR against src/.
var ErrComplianceReportArity = errors.New("generate_compliance_report() takes 1 positional argument but 2 were given")

// GenerateOutput ports `_generate_output(recon, hunt, verified)`
// (orchestrator.py:365) — the tail every entry point shares. app.py calls it
// directly after its four `.call`s; run() and run_from_checkpoint() call it
// last.
//
// Steps, in Python's order:
//
//  1. THRESHOLD FILTER. `severity_order.get(self.input.severity_threshold.lower(), 0)`;
//     when that is > 0, drop every finding scoring below it. A threshold of
//     "info" or an unknown string scores 0 and filters NOTHING.
//  2. PER-FINDING ENRICHMENT, in place: the CWE severity floor, the
//     exploitability score, sarif_security_severity mirrored from it, and the
//     compliance mappings (static table, with the AI gate as fallback).
//  3. COUNTS. verdict counts over the four Verdict members; severity counts
//     seeded with every Severity member so a severity with no findings still
//     reports 0.
//  4. NOISE REDUCTION. `not_exploitable / hunt.total_raw * 100`, rounded to 2
//     with Python's banker's rounding. Guarded on total_raw > 0.
//  5. ATTACK CHAINS. PotentialChain -> AttackChain, with `description` taking
//     the chain's combined_impact (so description and combined_impact are the
//     same string) and mitre_attack_mapping left at None.
//  6. COMPLIANCE GAPS, the SecurityAuditResult, then SARIF, then the JSON and
//     Markdown reports whose return values are DISCARDED (`_ = generate_json(...)`)
//     — they are produced for their side-effect-free validation only.
//  7. The compliance-report loop, which raises (see ErrComplianceReportArity).
//
// Python parity details worth stating:
//
//   - `verified` is REBOUND by the filter, so the caller's slice is not
//     truncated — but the surviving findings are the SAME objects and step 2
//     mutates them. Go reproduces both: a new slice header, sharing elements.
//   - `self.input.compliance_frameworks or None` passes None for an EMPTY list,
//     which makes get_compliance_mappings_hybrid use its default framework set.
//   - `commit_sha=self.input.commit_sha or "HEAD"` is Python truthiness: an
//     empty string also becomes "HEAD".
//   - `timestamp=datetime.now(UTC)` is read here, not at construction.
//   - `duration_seconds` is `time.monotonic() - self.started_at`, i.e. the whole
//     orchestrator lifetime, not just this function.
//   - the budget note fires only when the flag is latched, and reports
//     findings_not_verified — which app.py copies from prove_phase's payload.
func (o *AuditOrchestrator) GenerateOutput(
	ctx context.Context,
	recon schemas.ReconResult,
	hunt schemas.HuntResult,
	verified []schemas.VerifiedFinding,
) (schemas.SecurityAuditResult, error) {
	_ = recon // Python: `_ = recon` — accepted for symmetry, never read.

	// 1. severity threshold
	thresholdValue := severityOrder[strings.ToLower(o.Input.SeverityThreshold)]
	if thresholdValue > 0 {
		filtered := make([]schemas.VerifiedFinding, 0, len(verified))
		for _, finding := range verified {
			if severityOrder[strings.ToLower(string(finding.Severity))] >= thresholdValue {
				filtered = append(filtered, finding)
			}
		}
		verified = filtered
	}

	// 2. per-finding enrichment
	frameworks := o.Input.ComplianceFrameworks
	if len(frameworks) == 0 {
		// Python: `frameworks=self.input.compliance_frameworks or None`
		frameworks = nil
	}
	gate := o.complianceGate()
	for i := range verified {
		verified[i].Severity = scoring.ApplyCWESeverityFloor(verified[i].CweID, verified[i].Severity)
		verified[i].ExploitabilityScore = scoring.ComputeExploitabilityScore(verified[i])
		verified[i].SarifSecuritySeverity = verified[i].ExploitabilityScore
		verified[i].Compliance = compliance.GetComplianceMappingsHybrid(ctx, verified[i].CweID, frameworks, gate)
	}

	// 3. counts
	verdictCounts := map[schemas.Verdict]int{
		schemas.VerdictConfirmed:      0,
		schemas.VerdictLikely:         0,
		schemas.VerdictInconclusive:   0,
		schemas.VerdictNotExploitable: 0,
	}
	severityCounts := map[string]int{}
	for _, severity := range schemas.AllSeverities {
		severityCounts[string(severity)] = 0
	}
	for _, finding := range verified {
		// Python: `verdict_counts[finding.verdict] += 1` — a dict subscript,
		// which raises KeyError for a verdict outside the four members. The
		// Verdict enum has exactly four, so the Go map write is equivalent.
		verdictCounts[finding.Verdict]++
		severityCounts[string(finding.Severity)]++
	}

	// 4. noise reduction
	totalRaw := hunt.TotalRaw
	notExploitable := verdictCounts[schemas.VerdictNotExploitable]
	noiseReduction := 0.0
	if totalRaw > 0 {
		noiseReduction = float64(notExploitable) / float64(totalRaw) * 100.0
	}

	// 5. attack chains
	chains := make([]schemas.AttackChain, 0, len(hunt.Chains))
	for _, chain := range hunt.Chains {
		chains = append(chains, schemas.AttackChain{
			ChainID:          chain.ChainID,
			Title:            chain.Title,
			Description:      chain.CombinedImpact,
			Findings:         chain.FindingIDs,
			CombinedSeverity: chain.EstimatedSeverity,
			CombinedImpact:   chain.CombinedImpact,
			// mitre_attack_mapping is not passed, so it keeps pydantic's None.
			MitreAttackMapping: nil,
		})
	}

	if o.BudgetExhausted() {
		o.App.Note(ctx,
			"Budget exhausted; unverified findings: "+strconv.Itoa(o.FindingsNotVerified),
			"audit", "budget", "exhausted")
	}

	// 6. the result
	complianceGaps := compliance.GetComplianceGaps(verified)

	commitSha := "HEAD"
	if o.Input.CommitSha != nil && *o.Input.CommitSha != "" {
		commitSha = *o.Input.CommitSha
	}
	branch := o.Input.Branch

	costBreakdown := o.CostBreakdown()
	roundedBreakdown := make(map[string]float64, len(costBreakdown))
	for phase, cost := range costBreakdown {
		roundedBreakdown[phase] = pyfmt.Round(cost, 4)
	}

	result := schemas.NewSecurityAuditResult()
	result.Repository = o.Input.RepoURL
	result.CommitSha = commitSha
	result.Branch = &branch
	result.Timestamp = schemas.NewTimestamp(nowUTC())
	result.DepthProfile = o.Input.Depth
	result.StrategiesUsed = hunt.StrategiesRun
	result.Provider = "harness"
	result.Findings = verified
	result.AttackChains = chains
	result.TotalRawFindings = totalRaw
	result.Confirmed = verdictCounts[schemas.VerdictConfirmed]
	result.Likely = verdictCounts[schemas.VerdictLikely]
	result.Inconclusive = verdictCounts[schemas.VerdictInconclusive]
	result.NotExploitable = notExploitable
	result.NoiseReductionPct = pyfmt.Round(noiseReduction, 2)
	result.BySeverity = severityCounts
	result.ComplianceGaps = complianceGaps
	result.DurationSeconds = o.elapsedSeconds()
	result.AgentInvocations = o.AgentInvocations()
	result.CostUsd = pyfmt.Round(o.TotalCostUSD(), 4)
	result.CostBreakdown = roundedBreakdown
	result.Metadata = map[string]any{
		"findings_not_verified": o.FindingsNotVerified,
		"prove_drop_summary":    o.ProveDropSummary,
	}
	result.Sarif = ""

	result.Sarif = output.GenerateSarif(result)
	// Python: `_ = generate_json(result, pretty=True)` and `_ = generate_report(result)`.
	// Both return values are discarded; the calls stay because they exercise the
	// same rendering the caller may ask for later, and because dropping them
	// would change nothing except which code runs.
	_ = output.GenerateJSON(result, true)
	_ = output.GenerateReport(result)

	// 7. per-framework compliance reports — see ErrComplianceReportArity.
	if len(o.Input.ComplianceFrameworks) > 0 {
		if err := mkdirCheckpointDir(o.CheckpointDir); err != nil {
			return result, err
		}
		// Python raises on the FIRST loop iteration, so no report file is ever
		// written. The built result is handed back alongside the error purely so
		// a Go caller can inspect it; Python has no return value on this path.
		return result, ErrComplianceReportArity
	}

	return result, nil
}

// complianceGate adapts the orchestrator's AIGateWrapper to the narrow seam
// compliance.GetComplianceMappingsHybrid needs:
//
//	suggestion = await ai_gate.invoke(user=prompt, schema=ComplianceGate)
//
// A nil AIGate yields a nil seam, which is Python's `ai_gate=None` — the static
// table then has no fallback.
func (o *AuditOrchestrator) complianceGate() compliance.AIGateLike {
	if o.AIGate == nil {
		return nil
	}
	return compliance.AIGateFunc(func(ctx context.Context, user string) (schemas.ComplianceGate, error) {
		return gates.Invoke[schemas.ComplianceGate](ctx, o.AIGate, user, "")
	})
}

// elapsedSeconds is `time.monotonic() - self.started_at`.
//
// It reads the clock through nowMonotonic (orch.go) rather than time.Since so a
// test — and scripts/gen_golden_phases.py's Python counterpart, which swaps the
// orchestrator module's `time` name — can pin the elapsed value that lands in
// the progress notes and in duration_seconds.
func (o *AuditOrchestrator) elapsedSeconds() float64 {
	return nowMonotonic().Sub(o.StartedAt).Seconds()
}
