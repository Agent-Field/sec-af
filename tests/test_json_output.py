from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from sec_af.output.json_output import generate_json, generate_summary_json
from sec_af.output.report import generate_report
from sec_af.schemas.compliance import ComplianceGap, ComplianceMapping
from sec_af.schemas.hunt import FindingType, Severity
from sec_af.schemas.output import AttackChain, MitreMapping, SecurityAuditResult
from sec_af.schemas.prove import (
    DataFlowStep,
    EvidenceLevel,
    Proof,
    Verdict,
    VerifiedFinding,
)


def _build_audit_result() -> SecurityAuditResult:
    rebuild = getattr(SecurityAuditResult, "model_rebuild", None)
    if callable(rebuild):
        _ = rebuild(_types_namespace={"VerifiedFinding": VerifiedFinding})

    confirmed_finding = VerifiedFinding(
        id="finding-confirmed",
        fingerprint="fp-confirmed",
        title="SQL Injection in lookup endpoint",
        description="User input reaches SQL execution without sanitization.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category="A03:2021 Injection",
        tags={"REACHABLE", "INTERNET_FACING"},
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        rationale="Path from request body to sink is confirmed.",
        severity=Severity.CRITICAL,
        exploitability_score=9.2,
        proof=Proof(
            exploit_hypothesis="Attacker injects payload through id field.",
            verification_method="Static trace + manual code review",
            evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
            data_flow_trace=[
                DataFlowStep(
                    file="src/routes.py",
                    line=15,
                    description="Input source",
                    tainted=True,
                ),
                DataFlowStep(
                    file="src/users.py",
                    line=42,
                    description="Sink call",
                    tainted=True,
                ),
            ],
            vulnerable_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            exploit_payload='{"id": "1 OR 1=1"}',
            expected_outcome="Unauthorized row disclosure",
        ),
        location={
            "file_path": "src/users.py",
            "start_line": 42,
            "end_line": 42,
            "start_column": 9,
            "end_column": 66,
            "function_name": "lookup_user",
        },
        chain_id="chain-1",
        chain_step=1,
        enables=["finding-likely"],
        compliance=[
            ComplianceMapping(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Prevent injection attacks",
            )
        ],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=9.0,
    )

    not_exploitable_finding = VerifiedFinding(
        id="finding-noise",
        fingerprint="fp-noise",
        title="Potential reflected XSS in docs preview",
        description="Escaped output prevents execution.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        tags={"POTENTIAL"},
        verdict=Verdict.NOT_EXPLOITABLE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Templating layer auto-escapes sink.",
        severity=Severity.LOW,
        exploitability_score=1.2,
        location={
            "file_path": "src/views.py",
            "start_line": 88,
            "end_line": 89,
        },
        sarif_rule_id="sec-af/sast/xss",
        sarif_security_severity=2.1,
    )

    return SecurityAuditResult(
        repository="Agent-Field/sec-af",
        commit_sha="abc123",
        branch="main",
        timestamp=datetime(2026, 3, 4, 10, 30, 0, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=["injection", "api_security"],
        provider="codex",
        findings=[confirmed_finding, not_exploitable_finding],
        attack_chains=[
            AttackChain(
                chain_id="chain-1",
                title="Input injection to DB read",
                description="Unsanitized path from request id to SQL sink",
                findings=["finding-confirmed"],
                combined_severity=Severity.CRITICAL,
                combined_impact="Database read access",
                mitre_attack_mapping=[
                    MitreMapping(
                        tactic="Initial Access",
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application",
                    )
                ],
            )
        ],
        total_raw_findings=5,
        confirmed=1,
        likely=0,
        inconclusive=0,
        not_exploitable=1,
        noise_reduction_pct=80.0,
        by_severity={"critical": 1, "low": 1},
        compliance_gaps=[
            ComplianceGap(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Prevent injection attacks",
                finding_count=1,
                max_severity="critical",
                cwe_ids=["CWE-89"],
            )
        ],
        duration_seconds=180.5,
        agent_invocations=28,
        cost_usd=3.42,
        cost_breakdown={"recon": 0.4, "hunt": 1.0, "prove": 2.02},
        sarif="{}",
    )


def test_generate_json_serializes_all_findings_with_full_proof_data() -> None:
    result = _build_audit_result()

    output = generate_json(result, pretty=True)
    payload = cast("dict[str, object]", json.loads(output))
    findings = cast("list[dict[str, object]]", payload["findings"])
    attack_chains = cast("list[dict[str, object]]", payload["attack_chains"])
    compliance_gaps = cast("list[dict[str, object]]", payload["compliance_gaps"])
    cost_breakdown = cast("dict[str, float]", payload["cost_breakdown"])

    assert len(findings) == 2
    assert findings[1]["verdict"] == "not_exploitable"
    confirmed_proof = cast("dict[str, object]", findings[0]["proof"])
    trace = cast("list[dict[str, object]]", confirmed_proof["data_flow_trace"])
    assert trace[0]["file"] == "src/routes.py"
    assert trace[1]["line"] == 42
    mitre = cast("list[dict[str, object]]", attack_chains[0]["mitre_attack_mapping"])
    assert mitre[0]["technique_id"] == "T1190"
    assert compliance_gaps[0]["control_id"] == "Req 6.2.4"
    assert cost_breakdown["prove"] == 2.02


def test_generate_json_compact_mode_has_no_pretty_indent() -> None:
    result = _build_audit_result()

    output = generate_json(result, pretty=False)

    assert "\n" not in output


def test_generate_summary_json_omits_proof_and_returns_statistics() -> None:
    result = _build_audit_result()

    output = generate_summary_json(result)
    payload = cast("dict[str, object]", json.loads(output))
    summary = cast("dict[str, object]", payload["summary"])
    findings = cast("list[dict[str, object]]", payload["findings"])
    performance = cast("dict[str, object]", payload["performance"])

    assert summary["total_findings"] == 2
    assert summary["confirmed"] == 1
    assert summary["not_exploitable"] == 1
    assert findings[0]["id"] == "finding-confirmed"
    assert "proof" not in findings[0]
    assert performance["cost_usd"] == 3.42


def test_generate_report_includes_attack_chain_compliance_and_performance() -> None:
    result = _build_audit_result()

    report = generate_report(result)

    assert "# SEC-AF Security Audit Report" in report
    assert "## Summary" in report
    assert "SQL Injection in lookup endpoint" in report
    assert "Potential reflected XSS in docs preview" in report
    assert "## Attack Chains" in report
    assert "Input injection to DB read" in report
    assert "## Compliance Gaps" in report
    assert "PCI-DSS Req 6.2.4" in report
    assert "## Performance & Cost" in report
