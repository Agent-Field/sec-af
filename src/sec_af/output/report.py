from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.output import AttackChain, SecurityAuditResult
    from ..schemas.prove import VerifiedFinding


def _render_summary(result: SecurityAuditResult) -> list[str]:
    return [
        "## Summary",
        "",
        f"- Repository: `{result.repository}`",
        f"- Commit: `{result.commit_sha}`",
        f"- Branch: `{result.branch}`" if result.branch else "- Branch: n/a",
        f"- Timestamp: `{result.timestamp.isoformat()}`",
        f"- Depth profile: `{result.depth_profile}`",
        f"- Provider: `{result.provider}`",
        (
            f"- Findings: **{len(result.findings)}** (confirmed: {result.confirmed}, "
            f"likely: {result.likely}, inconclusive: {result.inconclusive}, "
            f"not exploitable: {result.not_exploitable})"
        ),
        f"- Noise reduction: **{result.noise_reduction_pct:.1f}%**",
        "",
    ]


def _render_finding(finding: VerifiedFinding) -> list[str]:
    lines = [
        f"### {finding.title}",
        "",
        f"- ID: `{finding.id}`",
        f"- Verdict: `{finding.verdict.value}` (evidence level {int(finding.evidence_level)})",
        f"- Severity: `{finding.severity.value}` | Exploitability: **{finding.exploitability_score:.1f}/10**",
        f"- CWE: `{finding.cwe_id}` ({finding.cwe_name})",
        f"- Location: `{finding.location.file_path}:{finding.location.start_line}`",
    ]
    if finding.chain_id:
        lines.append(f"- Chain: `{finding.chain_id}` step {finding.chain_step or '?'}")
    if finding.proof and finding.proof.data_flow_trace:
        lines.append("- Data flow trace:")
        for step in finding.proof.data_flow_trace:
            lines.append(f"  - `{step.file}:{step.line}` - {step.description}")
    if finding.rationale:
        lines.append(f"- Rationale: {finding.rationale}")
    lines.append("")
    return lines


def _render_attack_chain(chain: AttackChain) -> list[str]:
    lines = [
        f"### {chain.title}",
        "",
        f"- Chain ID: `{chain.chain_id}`",
        f"- Combined severity: `{chain.combined_severity.value}`",
        f"- Combined impact: {chain.combined_impact}",
        f"- Findings: {', '.join(f'`{finding_id}`' for finding_id in chain.findings)}",
    ]
    if chain.mitre_attack_mapping:
        lines.append("- MITRE ATT&CK:")
        for mapping in chain.mitre_attack_mapping:
            lines.append(f"  - {mapping.technique_id} ({mapping.tactic}): {mapping.technique_name}")
    lines.append("")
    return lines


def generate_report(result: SecurityAuditResult) -> str:
    lines = [
        "# SEC-AF Security Audit Report",
        "",
        *_render_summary(result),
        "## Findings",
        "",
    ]
    if result.findings:
        for finding in result.findings:
            lines.extend(_render_finding(finding))
    else:
        lines.extend(["No findings.", ""])

    lines.extend(["## Attack Chains", ""])
    if result.attack_chains:
        for chain in result.attack_chains:
            lines.extend(_render_attack_chain(chain))
    else:
        lines.extend(["No attack chains.", ""])

    lines.extend(["## Compliance Gaps", ""])
    if result.compliance_gaps:
        for gap in result.compliance_gaps:
            gap_line = (
                f"- {gap.framework} {gap.control_id}: {gap.control_name} "
                + f"(findings: {gap.finding_count}, max severity: {gap.max_severity})"
            )
            lines.append(gap_line)
        lines.append("")
    else:
        lines.extend(["No compliance gaps.", ""])

    lines.extend(
        [
            "## Performance & Cost",
            "",
            f"- Duration: {result.duration_seconds:.1f}s",
            f"- Agent invocations: {result.agent_invocations}",
            f"- Cost: ${result.cost_usd:.2f}",
            "- Cost breakdown:",
        ]
    )
    if result.cost_breakdown:
        for phase, cost in result.cost_breakdown.items():
            lines.append(f"  - {phase}: ${cost:.2f}")
    else:
        lines.append("  - n/a")

    return "\n".join(lines)


def render_report(audit_result: SecurityAuditResult) -> str:
    return generate_report(audit_result)
