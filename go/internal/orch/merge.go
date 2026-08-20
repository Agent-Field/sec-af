package orch

import (
	"sort"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// VerifiedFindingFallback ports the module-level `_verified_finding_fallback`
// (orchestrator.py:672) — a RawFinding promoted to an INCONCLUSIVE
// VerifiedFinding when no proof is available.
//
//	VerifiedFinding(
//	    id=finding.id, fingerprint=finding.fingerprint, title=..., description=...,
//	    finding_type=..., cwe_id=..., cwe_name=..., owasp_category=...,
//	    tags=[], verdict=Verdict.INCONCLUSIVE, evidence_level=EvidenceLevel.STATIC_MATCH,
//	    rationale="Automated proof unavailable; requires manual review.",
//	    severity=finding.estimated_severity, exploitability_score=0.0,
//	    location=Location(file_path=..., start_line=..., end_line=...,
//	                      function_name=..., code_snippet=...),
//	    sarif_rule_id=f"sec-af/{finding.finding_type.value}/{finding.cwe_id.lower()}",
//	    sarif_security_severity=0.0)
//
// Two things distinguish it from agents/prove.Fallback, which serves the same
// purpose elsewhere:
//
//   - the rationale is a FIXED string, not "Verification incomplete: <reason>";
//   - the sarif_rule_id is built from the lowercased CWE ID
//     ("sec-af/sast/cwe-89"), where prove's is built from the CWE NAME with
//     spaces turned into hyphens ("sec-af/sast/sql-injection").
//
// Python parity: nothing in the Python tree calls this function — every demotion
// path goes through agents/prove.fallback — so it is ported for completeness.
// `related_locations`, `compliance` and `reproduction_steps` keep pydantic's
// empty-list defaults; `drop_reason` stays None, which is what makes a finding
// built here invisible to the orchestrator's drop_reason sweep.
func VerifiedFindingFallback(finding schemas.RawFinding) schemas.VerifiedFinding {
	snippet := finding.CodeSnippet
	out := schemas.NewVerifiedFinding()
	out.ID = finding.ID
	out.Fingerprint = finding.Fingerprint
	out.Title = finding.Title
	out.Description = finding.Description
	out.FindingType = finding.FindingType
	out.CweID = finding.CweID
	out.CweName = finding.CweName
	out.OwaspCategory = finding.OwaspCategory
	out.Tags = []string{}
	out.Verdict = schemas.VerdictInconclusive
	out.EvidenceLevel = schemas.EvidenceLevelStaticMatch
	out.Rationale = "Automated proof unavailable; requires manual review."
	out.Severity = finding.EstimatedSeverity
	out.ExploitabilityScore = 0.0
	out.Location = schemas.Location{
		FilePath:     finding.FilePath,
		StartLine:    finding.StartLine,
		EndLine:      finding.EndLine,
		FunctionName: finding.FunctionName,
		CodeSnippet:  &snippet,
	}
	out.SarifRuleID = "sec-af/" + string(finding.FindingType) + "/" + strings.ToLower(finding.CweID)
	out.SarifSecuritySeverity = 0.0
	return out
}

// MergeReconFindingsIntoHunt ports the module-level
// `merge_recon_findings_into_hunt` (orchestrator.py:700) — how the findings
// RECON detected on its own (hardcoded secrets, misconfigs, weak TLS) join the
// hunters' output:
//
//	if not recon_findings: return hunt
//	merged_findings = [*recon_findings, *hunt.findings]
//	strategies_run = list(hunt.strategies_run)
//	if "recon" not in strategies_run: strategies_run.insert(0, "recon")
//	return HuntResult(findings=merged_findings, chains=hunt.chains,
//	                  total_raw=hunt.total_raw + len(recon_findings),
//	                  deduplicated_count=len(merged_findings),
//	                  chain_count=hunt.chain_count, strategies_run=strategies_run,
//	                  hunt_duration_seconds=hunt.hunt_duration_seconds)
//
// Behaviours tests/test_recon_findings.py::test_merge_recon_findings_prepends_and_updates_counts
// pins, all reproduced:
//
//   - recon findings are PREPENDED, so findings[0] is a recon finding;
//   - total_raw GROWS by the recon count (it is not recomputed);
//   - deduplicated_count is REPLACED by the merged length — no dedup pass runs,
//     so a recon finding that duplicates a hunter finding survives twice;
//   - "recon" is inserted at the FRONT of strategies_run, and only when absent.
//
// Python parity: an empty recon_findings list returns the hunt result
// UNCHANGED — the same value, not a copy — so a caller that mutates the result
// mutates the input. Go returns the same struct value, which copies the header
// but shares the backing arrays: identical aliasing.
func MergeReconFindingsIntoHunt(hunt schemas.HuntResult, reconFindings []schemas.RawFinding) schemas.HuntResult {
	if len(reconFindings) == 0 {
		return hunt
	}

	merged := make([]schemas.RawFinding, 0, len(reconFindings)+len(hunt.Findings))
	merged = append(merged, reconFindings...)
	merged = append(merged, hunt.Findings...)

	strategiesRun := make([]string, 0, len(hunt.StrategiesRun)+1)
	strategiesRun = append(strategiesRun, hunt.StrategiesRun...)
	found := false
	for _, s := range strategiesRun {
		if s == "recon" {
			found = true
			break
		}
	}
	if !found {
		strategiesRun = append([]string{"recon"}, strategiesRun...)
	}

	return schemas.HuntResult{
		Findings:            merged,
		Chains:              hunt.Chains,
		TotalRaw:            hunt.TotalRaw + len(reconFindings),
		DeduplicatedCount:   len(merged),
		ChainCount:          hunt.ChainCount,
		StrategiesRun:       strategiesRun,
		HuntDurationSeconds: hunt.HuntDurationSeconds,
	}
}

// sortedNonEmpty ports `sorted({item for item in values if item})` — the
// framework projection `_merge_recon` applies to
// security_context.framework_security.
//
// Python parity: the filter is TRUTHINESS, so blank entries disappear before
// the set is built; case is preserved, so "Django" and "django" are two
// distinct frameworks. The set-then-sort erases the only nondeterminism.
// reasoners/phases.py's recon_phase carries the same expression, and
// internal/phases has its own copy for the same reason SEC-AF does.
func sortedNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
