from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

if TYPE_CHECKING:
    from ..schemas.output import AttackChain, SecurityAuditResult
    from ..schemas.prove import VerifiedFinding


def generate_json(result: SecurityAuditResult, pretty: bool = True) -> str:
    full_json = result.model_dump_json()
    if not pretty:
        return full_json
    return json.dumps(json.loads(full_json), indent=2)


def _build_summary_statistics(result: SecurityAuditResult) -> dict[str, object]:
    return {
        "total_findings": len(result.findings),
        "confirmed": result.confirmed,
        "likely": result.likely,
        "inconclusive": result.inconclusive,
        "not_exploitable": result.not_exploitable,
        "noise_reduction_pct": result.noise_reduction_pct,
        "by_severity": result.by_severity,
    }


def _build_summary_findings(result: SecurityAuditResult) -> list[dict[str, object]]:
    return [
        {
            "id": finding.id,
            "title": finding.title,
            "severity": finding.severity.value,
            "verdict": finding.verdict.value,
            "evidence_level": int(finding.evidence_level),
            "exploitability_score": finding.exploitability_score,
            "cwe_id": finding.cwe_id,
            "location": {
                "file": finding.location.file_path,
                "line": finding.location.start_line,
            },
            "chain_id": finding.chain_id,
        }
        for finding in result.findings
    ]


def _findings_by_id(result: SecurityAuditResult) -> dict[str, VerifiedFinding]:
    return {finding.id: finding for finding in result.findings}


def _build_chain_steps(chain: AttackChain, findings: dict[str, VerifiedFinding]) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    for index, finding_id in enumerate(chain.findings, start=1):
        finding = findings.get(finding_id)
        steps.append(
            {
                "step": finding.chain_step or index if finding else index,
                "finding_id": finding_id,
                "title": finding.title if finding else None,
                "verdict": finding.verdict.value if finding else None,
                "severity": finding.severity.value if finding else None,
                "location": (
                    {
                        "file": finding.location.file_path,
                        "line": finding.location.start_line,
                    }
                    if finding
                    else None
                ),
            }
        )
    return steps


def _build_attack_chains(result: SecurityAuditResult) -> list[dict[str, object]]:
    findings = _findings_by_id(result)
    return [
        {
            "chain_id": chain.chain_id,
            "title": chain.title,
            "description": chain.description,
            "combined_severity": chain.combined_severity.value,
            "combined_impact": chain.combined_impact,
            "findings": chain.findings,
            "steps": _build_chain_steps(chain, findings),
            "mitre_attack_mapping": [
                {
                    "tactic": mapping.tactic,
                    "technique_id": mapping.technique_id,
                    "technique_name": mapping.technique_name,
                }
                for mapping in chain.mitre_attack_mapping or []
            ],
        }
        for chain in result.attack_chains
    ]


def generate_summary_json(result: SecurityAuditResult) -> str:
    summary: dict[str, object] = {
        "repository": result.repository,
        "commit_sha": result.commit_sha,
        "timestamp": result.timestamp.isoformat(),
        "depth_profile": result.depth_profile,
        "summary": _build_summary_statistics(result),
        "findings": _build_summary_findings(result),
        "attack_chains": _build_attack_chains(result),
        "compliance_gaps": [gap.model_dump() for gap in result.compliance_gaps],
        "performance": {
            "duration_seconds": result.duration_seconds,
            "cost_usd": result.cost_usd,
            "cost_breakdown": result.cost_breakdown,
            "agent_invocations": result.agent_invocations,
        },
    }
    return json.dumps(summary, indent=2)


def render_json(audit_result: SecurityAuditResult) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(generate_json(audit_result, pretty=True)))
