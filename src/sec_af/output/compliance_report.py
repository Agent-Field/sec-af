"""Compliance report generator for SEC-AF.

Generates compliance-focused reports organized by framework (OWASP, PCI-DSS,
SOC2, HIPAA, ISO27001) with evidence sections, finding details, and
remediation status. Output is structured Markdown suitable for PDF conversion.
"""

from __future__ import annotations

from collections import defaultdict
from datetime import UTC, datetime
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.compliance import ComplianceGap
    from ..schemas.output import SecurityAuditResult
    from ..schemas.prove import VerifiedFinding


def _severity_icon(severity: str) -> str:
    return {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}.get(severity.lower(), "INFO")


def _verdict_label(verdict_value: str) -> str:
    return {
        "confirmed": "Confirmed",
        "likely": "Likely",
        "inconclusive": "Inconclusive",
        "not_exploitable": "Not Exploitable",
    }.get(verdict_value, verdict_value)


def _render_header(result: SecurityAuditResult) -> list[str]:
    now = datetime.now(UTC).strftime("%Y-%m-%d %H:%M UTC")
    return [
        "# SEC-AF Compliance Report",
        "",
        f"**Generated:** {now}",
        f"**Repository:** {result.repository}",
        f"**Commit:** {result.commit_sha}",
        f"**Branch:** {result.branch or 'N/A'}",
        f"**Scan Depth:** {result.depth_profile}",
        f"**Total Findings:** {len(result.findings)}",
        "",
        "---",
        "",
    ]


def _render_executive_summary(result: SecurityAuditResult) -> list[str]:
    summary_line = f"This report covers a security audit of `{result.repository}` at commit `{result.commit_sha[:8]}`. The scan identified **{len(result.findings)}** findings, of which **{result.confirmed}** are confirmed exploitable."
    lines = [
        "## Executive Summary",
        "",
        summary_line,
        "",
        "### Verdict Distribution",
        "",
        "| Verdict | Count |",
        "|---------|-------|",
        f"| Confirmed | {result.confirmed} |",
        f"| Likely | {result.likely} |",
        f"| Inconclusive | {result.inconclusive} |",
        f"| Not Exploitable | {result.not_exploitable} |",
        "",
        f"**Noise Reduction:** {result.noise_reduction_pct:.1f}%",
        "",
    ]
    if result.by_severity:
        lines.extend(
            [
                "### Severity Distribution",
                "",
                "| Severity | Count |",
                "|----------|-------|",
            ]
        )
        for severity in ["critical", "high", "medium", "low", "info"]:
            count = result.by_severity.get(severity, 0)
            if count > 0:
                lines.append(f"| {_severity_icon(severity)} | {count} |")
        lines.append("")
    return lines


def _render_compliance_section(result: SecurityAuditResult) -> list[str]:
    if not result.compliance_gaps:
        return ["## Compliance Status", "", "No compliance gaps identified.", ""]

    by_framework: dict[str, list[ComplianceGap]] = defaultdict(list)
    for gap in result.compliance_gaps:
        by_framework[gap.framework].append(gap)

    lines = ["## Compliance Gap Analysis", ""]
    for framework, gaps in sorted(by_framework.items()):
        lines.extend(
            [
                f"### {framework}",
                "",
                "| Control ID | Control Name | Findings | Max Severity | CWEs |",
                "|-----------|-------------|----------|-------------|------|",
            ]
        )
        for gap in sorted(gaps, key=lambda g: g.control_id):
            cwe_str = ", ".join(gap.cwe_ids[:5])
            if len(gap.cwe_ids) > 5:
                cwe_str += f" (+{len(gap.cwe_ids) - 5} more)"
            lines.append(
                f"| {gap.control_id} | {gap.control_name} | {gap.finding_count} | {_severity_icon(gap.max_severity)} | {cwe_str} |"
            )
        lines.append("")
    return lines


def _render_findings_by_framework(result: SecurityAuditResult) -> list[str]:
    if not result.findings:
        return ["## Detailed Findings", "", "No findings to report.", ""]

    framework_findings: dict[str, list[VerifiedFinding]] = defaultdict(list)
    uncategorized: list[VerifiedFinding] = []

    for finding in result.findings:
        if finding.compliance:
            seen_frameworks: set[str] = set()
            for mapping in finding.compliance:
                if mapping.framework not in seen_frameworks:
                    framework_findings[mapping.framework].append(finding)
                    seen_frameworks.add(mapping.framework)
        else:
            uncategorized.append(finding)

    lines = ["## Detailed Findings by Framework", ""]
    for framework, findings in sorted(framework_findings.items()):
        lines.extend([f"### {framework}", ""])
        for finding in findings:
            lines.extend(
                [
                    f"#### {finding.title}",
                    "",
                    f"- **Verdict:** {_verdict_label(finding.verdict.value)}",
                    f"- **Severity:** {_severity_icon(finding.severity.value)}",
                    f"- **CWE:** {finding.cwe_id} ({finding.cwe_name})",
                    f"- **Location:** `{finding.location.file_path}:{finding.location.start_line}`",
                    f"- **Evidence Level:** {int(finding.evidence_level)}/6",
                    f"- **Exploitability Score:** {finding.exploitability_score:.1f}/10",
                    "",
                ]
            )
            if finding.rationale:
                lines.extend([f"**Rationale:** {finding.rationale}", ""])
            compliance_lines = [f"  - {m.framework} {m.control_id}: {m.control_name}" for m in finding.compliance]
            if compliance_lines:
                lines.extend(["**Compliance Mappings:**", *compliance_lines, ""])
    if uncategorized:
        lines.extend(["### Uncategorized Findings", ""])
        for finding in uncategorized:
            lines.extend(
                [
                    f"#### {finding.title}",
                    "",
                    f"- **Verdict:** {_verdict_label(finding.verdict.value)}",
                    f"- **Severity:** {_severity_icon(finding.severity.value)}",
                    f"- **CWE:** {finding.cwe_id}",
                    f"- **Location:** `{finding.location.file_path}:{finding.location.start_line}`",
                    "",
                ]
            )
    return lines


def _render_footer(result: SecurityAuditResult) -> list[str]:
    return [
        "---",
        "",
        "## Audit Metadata",
        "",
        f"- **Duration:** {result.duration_seconds:.1f}s",
        f"- **Agent Invocations:** {result.agent_invocations}",
        f"- **Cost:** ${result.cost_usd:.2f}",
        f"- **Strategies Used:** {', '.join(result.strategies_used)}",
        "",
        "*Report generated by SEC-AF -- Composite Intelligence Security Auditor*",
    ]


def generate_compliance_report(result: SecurityAuditResult) -> str:
    """Generate a compliance-focused report in Markdown format.

    The output is structured for direct PDF conversion via tools like
    pandoc, weasyprint, or similar Markdown-to-PDF converters.
    """
    sections = [
        _render_header(result),
        _render_executive_summary(result),
        _render_compliance_section(result),
        _render_findings_by_framework(result),
        _render_footer(result),
    ]
    return "\n".join(line for section in sections for line in section)
