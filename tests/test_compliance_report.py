"""Tests for compliance report generation."""

from datetime import UTC, datetime

from sec_af.output.compliance_report import generate_compliance_report
from sec_af.schemas.compliance import ComplianceGap, ComplianceMapping
from sec_af.schemas.hunt import FindingType, Severity
from sec_af.schemas.output import SecurityAuditResult
from sec_af.schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding


def _make_finding(
    title: str = "Test Finding",
    verdict: Verdict = Verdict.CONFIRMED,
    severity: Severity = Severity.HIGH,
    cwe_id: str = "CWE-89",
) -> VerifiedFinding:
    return VerifiedFinding(
        fingerprint="test-fp",
        title=title,
        description="Test description",
        finding_type=FindingType.SAST,
        cwe_id=cwe_id,
        cwe_name="SQL Injection",
        verdict=verdict,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        rationale="Test rationale",
        severity=severity,
        exploitability_score=7.5,
        location=Location(file_path="app.py", start_line=10, end_line=15),
        compliance=[
            ComplianceMapping(
                framework="OWASP",
                control_id="A03:2021",
                control_name="Injection",
            ),
            ComplianceMapping(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Secure coding",
            ),
        ],
        sarif_rule_id="sec-af/sast/cwe-89",
        sarif_security_severity=7.5,
    )


def _make_result(findings: list[VerifiedFinding] | None = None) -> SecurityAuditResult:
    if findings is None:
        findings = [_make_finding()]
    return SecurityAuditResult(
        repository="https://github.com/test/repo",
        commit_sha="abc123def456",
        branch="main",
        timestamp=datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=["injection", "auth"],
        provider="harness",
        findings=findings,
        attack_chains=[],
        total_raw_findings=5,
        confirmed=1,
        likely=0,
        inconclusive=0,
        not_exploitable=4,
        noise_reduction_pct=80.0,
        by_severity={"critical": 0, "high": 1, "medium": 0, "low": 0, "info": 0},
        compliance_gaps=[
            ComplianceGap(
                framework="OWASP",
                control_id="A03:2021",
                control_name="Injection",
                finding_count=1,
                max_severity="high",
                cwe_ids=["CWE-89"],
            ),
        ],
        duration_seconds=45.2,
        agent_invocations=12,
        cost_usd=0.15,
        cost_breakdown={"recon": 0.03, "hunt": 0.07, "prove": 0.05},
        sarif="",
    )


def test_compliance_report_contains_header() -> None:
    report = generate_compliance_report(_make_result())
    assert "# SEC-AF Compliance Report" in report
    assert "https://github.com/test/repo" in report


def test_compliance_report_contains_executive_summary() -> None:
    report = generate_compliance_report(_make_result())
    assert "Executive Summary" in report
    assert "Confirmed" in report


def test_compliance_report_contains_compliance_gaps() -> None:
    report = generate_compliance_report(_make_result())
    assert "Compliance Gap Analysis" in report
    assert "OWASP" in report
    assert "A03:2021" in report


def test_compliance_report_contains_findings() -> None:
    report = generate_compliance_report(_make_result())
    assert "Test Finding" in report
    assert "CWE-89" in report


def test_compliance_report_empty_findings() -> None:
    result = _make_result(findings=[])
    report = generate_compliance_report(result)
    assert "No findings to report" in report


def test_compliance_report_contains_metadata() -> None:
    report = generate_compliance_report(_make_result())
    assert "Audit Metadata" in report
    assert "45.2s" in report
