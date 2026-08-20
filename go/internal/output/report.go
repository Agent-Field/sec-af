package output

import (
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file ports src/sec_af/output/report.py — the human-readable Markdown
// audit report. Every line is byte-identical to the Python one; the golden test
// diffs the whole document.

// renderSummary ports _render_summary.
//
// Python parity: the branch line is chosen by TRUTHINESS, so an empty branch
// string renders "- Branch: n/a" exactly like a null one.
func renderSummary(result schemas.SecurityAuditResult) []string {
	branchLine := "- Branch: n/a"
	if result.Branch != nil && *result.Branch != "" {
		branchLine = fmt.Sprintf("- Branch: `%s`", *result.Branch)
	}
	return []string{
		"## Summary",
		"",
		fmt.Sprintf("- Repository: `%s`", result.Repository),
		fmt.Sprintf("- Commit: `%s`", result.CommitSha),
		branchLine,
		fmt.Sprintf("- Timestamp: `%s`", result.Timestamp.String()),
		fmt.Sprintf("- Depth profile: `%s`", result.DepthProfile),
		fmt.Sprintf("- Provider: `%s`", result.Provider),
		fmt.Sprintf("- Findings: **%d** (confirmed: %d, likely: %d, inconclusive: %d, not exploitable: %d)",
			len(result.Findings), result.Confirmed, result.Likely, result.Inconclusive, result.NotExploitable),
		fmt.Sprintf("- Noise reduction: **%.1f%%**", result.NoiseReductionPct),
		"",
	}
}

// renderFinding ports _render_finding.
func renderFinding(finding schemas.VerifiedFinding) []string {
	lines := []string{
		fmt.Sprintf("### %s", finding.Title),
		"",
		fmt.Sprintf("- ID: `%s`", finding.ID),
		fmt.Sprintf("- Verdict: `%s` (evidence level %d)", string(finding.Verdict), int(finding.EvidenceLevel)),
		fmt.Sprintf("- Severity: `%s` | Exploitability: **%.1f/10**", string(finding.Severity), finding.ExploitabilityScore),
		fmt.Sprintf("- CWE: `%s` (%s)", finding.CweID, finding.CweName),
		fmt.Sprintf("- Location: `%s:%d`", finding.Location.FilePath, finding.Location.StartLine),
	}
	if finding.ChainID != nil && *finding.ChainID != "" {
		lines = append(lines, fmt.Sprintf("- Chain: `%s` step %s", *finding.ChainID, chainStepLabel(finding.ChainStep)))
	}
	if finding.Proof != nil && len(finding.Proof.DataFlowTrace) > 0 {
		lines = append(lines, "- Data flow trace:")
		for _, step := range finding.Proof.DataFlowTrace {
			lines = append(lines, fmt.Sprintf("  - `%s:%d` - %s", step.File, step.Line, step.Description))
		}
	}
	if finding.Rationale != "" {
		lines = append(lines, fmt.Sprintf("- Rationale: %s", finding.Rationale))
	}
	return append(lines, "")
}

// chainStepLabel ports `finding.chain_step or '?'`: Python truthiness, so both
// a null step and a step of 0 render as "?".
func chainStepLabel(step *int) string {
	if step == nil || *step == 0 {
		return "?"
	}
	return strconv.Itoa(*step)
}

// renderAttackChain ports _render_attack_chain.
func renderAttackChain(chain schemas.AttackChain) []string {
	quoted := make([]string, 0, len(chain.Findings))
	for _, findingID := range chain.Findings {
		quoted = append(quoted, "`"+findingID+"`")
	}
	lines := []string{
		fmt.Sprintf("### %s", chain.Title),
		"",
		fmt.Sprintf("- Chain ID: `%s`", chain.ChainID),
		fmt.Sprintf("- Combined severity: `%s`", string(chain.CombinedSeverity)),
		fmt.Sprintf("- Combined impact: %s", chain.CombinedImpact),
		fmt.Sprintf("- Findings: %s", strings.Join(quoted, ", ")),
	}
	if len(chain.MitreAttackMapping) > 0 {
		lines = append(lines, "- MITRE ATT&CK:")
		for _, mapping := range chain.MitreAttackMapping {
			lines = append(lines, fmt.Sprintf("  - %s (%s): %s", mapping.TechniqueID, mapping.Tactic, mapping.TechniqueName))
		}
	}
	return append(lines, "")
}

// GenerateReport ports generate_report: the full Markdown audit report,
// joined with "\n" and carrying NO trailing newline (Python's `"\n".join`).
//
// Python parity divergence: the cost-breakdown section iterates a dict, whose
// order in CPython is insertion order; a Go map carries none, so the phases are
// listed in SORTED key order. Same deviation as the JSON writer's — see
// pyjson_local.go encodeMap.
func GenerateReport(result schemas.SecurityAuditResult) string {
	lines := []string{
		"# SEC-AF Security Audit Report",
		"",
	}
	lines = append(lines, renderSummary(result)...)
	lines = append(lines, "## Findings", "")

	if len(result.Findings) > 0 {
		for _, finding := range result.Findings {
			lines = append(lines, renderFinding(finding)...)
		}
	} else {
		lines = append(lines, "No findings.", "")
	}

	lines = append(lines, "## Attack Chains", "")
	if len(result.AttackChains) > 0 {
		for _, chain := range result.AttackChains {
			lines = append(lines, renderAttackChain(chain)...)
		}
	} else {
		lines = append(lines, "No attack chains.", "")
	}

	lines = append(lines, "## Compliance Gaps", "")
	if len(result.ComplianceGaps) > 0 {
		for _, gap := range result.ComplianceGaps {
			lines = append(lines, fmt.Sprintf("- %s %s: %s (findings: %d, max severity: %s)",
				gap.Framework, gap.ControlID, gap.ControlName, gap.FindingCount, gap.MaxSeverity))
		}
		lines = append(lines, "")
	} else {
		lines = append(lines, "No compliance gaps.", "")
	}

	lines = append(lines,
		"## Performance & Cost",
		"",
		fmt.Sprintf("- Duration: %.1fs", result.DurationSeconds),
		fmt.Sprintf("- Agent invocations: %d", result.AgentInvocations),
		fmt.Sprintf("- Cost: $%.2f", result.CostUsd),
		"- Cost breakdown:",
	)
	if len(result.CostBreakdown) > 0 {
		phases := make([]string, 0, len(result.CostBreakdown))
		for phase := range result.CostBreakdown {
			phases = append(phases, phase)
		}
		sort.Strings(phases)
		for _, phase := range phases {
			lines = append(lines, fmt.Sprintf("  - %s: $%.2f", phase, result.CostBreakdown[phase]))
		}
	} else {
		lines = append(lines, "  - n/a")
	}

	return strings.Join(lines, "\n")
}

// RenderReport ports render_report, the alias generate_report is exported under.
func RenderReport(auditResult schemas.SecurityAuditResult) string {
	return GenerateReport(auditResult)
}
