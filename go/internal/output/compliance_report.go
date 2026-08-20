package output

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Agent-Field/sec-af/go/internal/schemas"
)

// This file ports src/sec_af/output/compliance_report.py — the
// framework-organised Markdown report meant for PDF conversion.

// severityIconTable ports the literal dict inside _severity_icon.
var severityIconTable = map[string]string{
	"critical": "CRITICAL",
	"high":     "HIGH",
	"medium":   "MEDIUM",
	"low":      "LOW",
}

// verdictLabelTable ports the literal dict inside _verdict_label.
var verdictLabelTable = map[string]string{
	"confirmed":       "Confirmed",
	"likely":          "Likely",
	"inconclusive":    "Inconclusive",
	"not_exploitable": "Not Exploitable",
}

// severityOrder is the fixed iteration order of _render_executive_summary's
// severity table.
var severityOrder = []string{"critical", "high", "medium", "low", "info"}

// severityIcon ports _severity_icon: note the default is "INFO", so "info" and
// any unknown severity share a label.
func severityIcon(severity string) string {
	if icon, ok := severityIconTable[strings.ToLower(severity)]; ok {
		return icon
	}
	return "INFO"
}

// verdictLabel ports _verdict_label: an unknown verdict is echoed back
// verbatim (`dict.get(v, v)`).
func verdictLabel(verdictValue string) string {
	if label, ok := verdictLabelTable[verdictValue]; ok {
		return label
	}
	return verdictValue
}

// renderComplianceHeader ports _render_header.
//
// `now` is the value Python reads from `datetime.now(UTC)`; it is a parameter
// rather than a call so the golden test can pin it — see
// GenerateComplianceReportAt.
func renderComplianceHeader(result schemas.SecurityAuditResult, now time.Time) []string {
	branch := "N/A"
	if result.Branch != nil && *result.Branch != "" {
		branch = *result.Branch
	}
	return []string{
		"# SEC-AF Compliance Report",
		"",
		fmt.Sprintf("**Generated:** %s", now.UTC().Format("2006-01-02 15:04")+" UTC"),
		fmt.Sprintf("**Repository:** %s", result.Repository),
		fmt.Sprintf("**Commit:** %s", result.CommitSha),
		fmt.Sprintf("**Branch:** %s", branch),
		fmt.Sprintf("**Scan Depth:** %s", result.DepthProfile),
		fmt.Sprintf("**Total Findings:** %d", len(result.Findings)),
		"",
		"---",
		"",
	}
}

// renderExecutiveSummary ports _render_executive_summary.
func renderExecutiveSummary(result schemas.SecurityAuditResult) []string {
	summaryLine := fmt.Sprintf(
		"This report covers a security audit of `%s` at commit `%s`. "+
			"The scan identified **%d** findings, of which **%d** are confirmed exploitable.",
		result.Repository, headRunes(result.CommitSha, 8), len(result.Findings), result.Confirmed)

	lines := []string{
		"## Executive Summary",
		"",
		summaryLine,
		"",
		"### Verdict Distribution",
		"",
		"| Verdict | Count |",
		"|---------|-------|",
		fmt.Sprintf("| Confirmed | %d |", result.Confirmed),
		fmt.Sprintf("| Likely | %d |", result.Likely),
		fmt.Sprintf("| Inconclusive | %d |", result.Inconclusive),
		fmt.Sprintf("| Not Exploitable | %d |", result.NotExploitable),
		"",
		fmt.Sprintf("**Noise Reduction:** %.1f%%", result.NoiseReductionPct),
		"",
	}

	if len(result.BySeverity) > 0 {
		lines = append(lines,
			"### Severity Distribution",
			"",
			"| Severity | Count |",
			"|----------|-------|",
		)
		for _, severity := range severityOrder {
			count := result.BySeverity[severity]
			if count > 0 {
				lines = append(lines, fmt.Sprintf("| %s | %d |", severityIcon(severity), count))
			}
		}
		lines = append(lines, "")
	}
	return lines
}

// renderComplianceSection ports _render_compliance_section: gaps grouped by
// framework (frameworks sorted, gaps within a framework sorted by control id),
// with the CWE column truncated at five entries.
func renderComplianceSection(result schemas.SecurityAuditResult) []string {
	if len(result.ComplianceGaps) == 0 {
		return []string{"## Compliance Status", "", "No compliance gaps identified.", ""}
	}

	byFramework := map[string][]schemas.ComplianceGap{}
	frameworks := make([]string, 0)
	for _, gap := range result.ComplianceGaps {
		if _, seen := byFramework[gap.Framework]; !seen {
			frameworks = append(frameworks, gap.Framework)
		}
		byFramework[gap.Framework] = append(byFramework[gap.Framework], gap)
	}
	sort.Strings(frameworks)

	lines := []string{"## Compliance Gap Analysis", ""}
	for _, framework := range frameworks {
		gaps := append([]schemas.ComplianceGap(nil), byFramework[framework]...)
		// Python parity: `sorted(gaps, key=lambda g: g.control_id)` is a STABLE
		// sort on the control id alone, so equal control ids keep the order they
		// had in result.compliance_gaps.
		sort.SliceStable(gaps, func(i, j int) bool { return gaps[i].ControlID < gaps[j].ControlID })

		lines = append(lines,
			fmt.Sprintf("### %s", framework),
			"",
			"| Control ID | Control Name | Findings | Max Severity | CWEs |",
			"|-----------|-------------|----------|-------------|------|",
		)
		for _, gap := range gaps {
			shown := gap.CweIDs
			if len(shown) > 5 {
				shown = shown[:5]
			}
			cweStr := strings.Join(shown, ", ")
			if len(gap.CweIDs) > 5 {
				cweStr += fmt.Sprintf(" (+%d more)", len(gap.CweIDs)-5)
			}
			lines = append(lines, fmt.Sprintf("| %s | %s | %d | %s | %s |",
				gap.ControlID, gap.ControlName, gap.FindingCount, severityIcon(gap.MaxSeverity), cweStr))
		}
		lines = append(lines, "")
	}
	return lines
}

// renderFindingsByFramework ports _render_findings_by_framework.
//
// Python parity: a finding is listed once per DISTINCT framework among its
// compliance mappings (the `seen_frameworks` set), and findings with no
// mappings at all land in the trailing "Uncategorized Findings" section.
func renderFindingsByFramework(result schemas.SecurityAuditResult) []string {
	if len(result.Findings) == 0 {
		return []string{"## Detailed Findings", "", "No findings to report.", ""}
	}

	frameworkFindings := map[string][]schemas.VerifiedFinding{}
	frameworks := make([]string, 0)
	uncategorized := make([]schemas.VerifiedFinding, 0)

	for _, finding := range result.Findings {
		if len(finding.Compliance) == 0 {
			uncategorized = append(uncategorized, finding)
			continue
		}
		seen := map[string]struct{}{}
		for _, mapping := range finding.Compliance {
			if _, ok := seen[mapping.Framework]; ok {
				continue
			}
			if _, known := frameworkFindings[mapping.Framework]; !known {
				frameworks = append(frameworks, mapping.Framework)
			}
			frameworkFindings[mapping.Framework] = append(frameworkFindings[mapping.Framework], finding)
			seen[mapping.Framework] = struct{}{}
		}
	}
	sort.Strings(frameworks)

	lines := []string{"## Detailed Findings by Framework", ""}
	for _, framework := range frameworks {
		lines = append(lines, fmt.Sprintf("### %s", framework), "")
		for _, finding := range frameworkFindings[framework] {
			lines = append(lines,
				fmt.Sprintf("#### %s", finding.Title),
				"",
				fmt.Sprintf("- **Verdict:** %s", verdictLabel(string(finding.Verdict))),
				fmt.Sprintf("- **Severity:** %s", severityIcon(string(finding.Severity))),
				fmt.Sprintf("- **CWE:** %s (%s)", finding.CweID, finding.CweName),
				fmt.Sprintf("- **Location:** `%s:%d`", finding.Location.FilePath, finding.Location.StartLine),
				fmt.Sprintf("- **Evidence Level:** %d/6", int(finding.EvidenceLevel)),
				fmt.Sprintf("- **Exploitability Score:** %.1f/10", finding.ExploitabilityScore),
				"",
			)
			if finding.Rationale != "" {
				lines = append(lines, fmt.Sprintf("**Rationale:** %s", finding.Rationale), "")
			}
			complianceLines := make([]string, 0, len(finding.Compliance))
			for _, mapping := range finding.Compliance {
				complianceLines = append(complianceLines,
					fmt.Sprintf("  - %s %s: %s", mapping.Framework, mapping.ControlID, mapping.ControlName))
			}
			if len(complianceLines) > 0 {
				lines = append(lines, "**Compliance Mappings:**")
				lines = append(lines, complianceLines...)
				lines = append(lines, "")
			}
		}
	}

	if len(uncategorized) > 0 {
		lines = append(lines, "### Uncategorized Findings", "")
		for _, finding := range uncategorized {
			lines = append(lines,
				fmt.Sprintf("#### %s", finding.Title),
				"",
				fmt.Sprintf("- **Verdict:** %s", verdictLabel(string(finding.Verdict))),
				fmt.Sprintf("- **Severity:** %s", severityIcon(string(finding.Severity))),
				fmt.Sprintf("- **CWE:** %s", finding.CweID),
				fmt.Sprintf("- **Location:** `%s:%d`", finding.Location.FilePath, finding.Location.StartLine),
				"",
			)
		}
	}
	return lines
}

// renderComplianceFooter ports _render_footer.
func renderComplianceFooter(result schemas.SecurityAuditResult) []string {
	return []string{
		"---",
		"",
		"## Audit Metadata",
		"",
		fmt.Sprintf("- **Duration:** %.1fs", result.DurationSeconds),
		fmt.Sprintf("- **Agent Invocations:** %d", result.AgentInvocations),
		fmt.Sprintf("- **Cost:** $%.2f", result.CostUsd),
		fmt.Sprintf("- **Strategies Used:** %s", strings.Join(result.StrategiesUsed, ", ")),
		"",
		"*Report generated by SEC-AF -- Composite Intelligence Security Auditor*",
	}
}

// GenerateComplianceReport ports generate_compliance_report: a
// compliance-focused Markdown report, structured for direct PDF conversion via
// pandoc/weasyprint.
//
// The header stamps the CURRENT time, exactly as the Python function does
// (`datetime.now(UTC)`), so two calls a minute apart differ. Tests and any
// caller that needs a reproducible document use GenerateComplianceReportAt.
func GenerateComplianceReport(result schemas.SecurityAuditResult) string {
	return GenerateComplianceReportAt(result, time.Now().UTC())
}

// GenerateComplianceReportAt is GenerateComplianceReport with the "Generated:"
// timestamp supplied by the caller.
//
// This seam is Go-only: Python reads the clock inline, so pinning it there
// takes monkeypatching (which is what scripts/gen_golden.py does to produce the
// committed golden). Nothing about the rest of the document depends on it.
func GenerateComplianceReportAt(result schemas.SecurityAuditResult, now time.Time) string {
	sections := [][]string{
		renderComplianceHeader(result, now),
		renderExecutiveSummary(result),
		renderComplianceSection(result),
		renderFindingsByFramework(result),
		renderComplianceFooter(result),
	}
	lines := make([]string, 0, 64)
	for _, section := range sections {
		lines = append(lines, section...)
	}
	return strings.Join(lines, "\n")
}

// headRunes ports Python's `s[:n]` string slice: it counts CHARACTERS, and a
// string shorter than n is returned whole rather than panicking (which
// s[:n] on a Go string would do).
func headRunes(s string, n int) string {
	count := 0
	for i := range s {
		if count == n {
			return s[:i]
		}
		count++
	}
	return s
}
