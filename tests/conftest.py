from __future__ import annotations

from datetime import UTC, datetime

import pytest

from sec_af.schemas.compliance import ComplianceGap, ComplianceMapping
from sec_af.schemas.hunt import Confidence, FindingType, RawFinding, Severity
from sec_af.schemas.input import AuditInput
from sec_af.schemas.output import AttackChain, MitreMapping, SecurityAuditResult
from sec_af.schemas.prove import (
    DataFlowStep,
    EvidenceLevel,
    Location,
    Proof,
    Verdict,
    VerifiedFinding,
)


@pytest.fixture(scope="session", autouse=True)
def rebuild_output_model() -> None:
    rebuild = getattr(SecurityAuditResult, "model_rebuild", None)
    if callable(rebuild):
        _ = rebuild(_types_namespace={"VerifiedFinding": VerifiedFinding})


@pytest.fixture
def sample_repo_url() -> str:
    return "https://github.com/Agent-Field/sec-af"


@pytest.fixture
def sample_audit_input(sample_repo_url: str) -> AuditInput:
    return AuditInput(
        repo_url=sample_repo_url,
        branch="main",
        depth="standard",
        severity_threshold="low",
        scan_types=["sast", "secrets", "config"],
        output_formats=["json", "sarif", "markdown"],
        compliance_frameworks=["PCI-DSS", "SOC2", "OWASP"],
        max_cost_usd=10.0,
        max_provers=4,
        max_duration_seconds=900,
        include_paths=["src/"],
        exclude_paths=["tests/", "vendor/", ".git/"],
        is_pr=True,
        pr_id="123",
        post_pr_comments=True,
        fail_on_findings=False,
    )


@pytest.fixture
def sample_raw_findings() -> list[RawFinding]:
    return [
        RawFinding(
            id="raw-1",
            hunter_strategy="injection",
            title="Potential SQL injection in user lookup",
            description="Unsanitized query string reaches SQL execution.",
            finding_type=FindingType.SAST,
            cwe_id="CWE-89",
            cwe_name="SQL Injection",
            owasp_category="A03:2021",
            file_path="src/users.py",
            start_line=42,
            end_line=42,
            function_name="lookup_user",
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            estimated_severity=Severity.CRITICAL,
            confidence=Confidence.HIGH,
            data_flow=[
                DataFlowStep(
                    file="src/routes.py",
                    line=15,
                    description="Request body input",
                    tainted=True,
                ),
                DataFlowStep(
                    file="src/users.py",
                    line=42,
                    description="SQL sink",
                    tainted=True,
                ),
            ],
            related_files=["src/routes.py"],
            fingerprint="fp-sql-raw",
        ),
        RawFinding(
            id="raw-2",
            hunter_strategy="config_secrets",
            title="Hardcoded API key",
            description="Static API key value committed in source.",
            finding_type=FindingType.SECRETS,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            owasp_category="A07:2021",
            file_path="src/config.py",
            start_line=7,
            end_line=7,
            function_name=None,
            code_snippet='API_KEY = "sk-real-key-here-12345"',
            estimated_severity=Severity.HIGH,
            confidence=Confidence.HIGH,
            related_files=[],
            fingerprint="fp-secret-raw",
        ),
    ]


@pytest.fixture
def sample_verified_findings() -> list[VerifiedFinding]:
    sql = VerifiedFinding(
        id="finding-confirmed",
        fingerprint="fp-sql-1",
        title="SQL Injection",
        description="Unsanitized user input reaches SQL query execution.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category="A03:2021",
        tags={"externally_reachable", "user-input"},
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        rationale="Source-to-sink path is confirmed and exploitable.",
        severity=Severity.CRITICAL,
        exploitability_score=10.0,
        proof=Proof(
            exploit_hypothesis="Inject through id parameter.",
            verification_method="manual-review+trace",
            evidence_level=EvidenceLevel.FULL_EXPLOIT,
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
                    description="SQL sink",
                    tainted=True,
                ),
            ],
            vulnerable_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            exploit_payload='{"id": "1 OR 1=1"}',
            expected_outcome="Unauthorized data access",
        ),
        location=Location(
            file_path="src/users.py",
            start_line=42,
            end_line=42,
            start_column=9,
            end_column=66,
            function_name="lookup_user",
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        ),
        related_locations=[
            Location(
                file_path="src/routes.py",
                start_line=15,
                end_line=15,
                code_snippet="user_id = request.json['id']",
            )
        ],
        chain_id="chain-1",
        chain_step=1,
        enables=["finding-likely"],
        compliance=[
            ComplianceMapping(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Prevent injection",
            )
        ],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=9.9,
    )
    likely = VerifiedFinding(
        id="finding-likely",
        fingerprint="fp-auth-1",
        title="Missing Authentication",
        description="Admin endpoint can be accessed without auth.",
        finding_type=FindingType.API,
        cwe_id="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        owasp_category="A07:2021",
        tags={"requires_auth"},
        verdict=Verdict.LIKELY,
        evidence_level=EvidenceLevel.FLOW_IDENTIFIED,
        rationale="Guard checks appear absent on route.",
        severity=Severity.HIGH,
        exploitability_score=4.8,
        location=Location(file_path="src/api/admin.py", start_line=11, end_line=11),
        sarif_rule_id="sec-af/api/missing-authentication",
        sarif_security_severity=7.6,
    )
    not_exploitable = VerifiedFinding(
        id="finding-noise",
        fingerprint="fp-noise-1",
        title="Potential XSS",
        description="Output is escaped by template engine.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        verdict=Verdict.NOT_EXPLOITABLE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Sink auto-escapes output.",
        severity=Severity.LOW,
        exploitability_score=0.6,
        location=Location(file_path="src/views.py", start_line=88, end_line=89),
        sarif_rule_id="sec-af/sast/xss",
        sarif_security_severity=1.9,
    )
    return [sql, likely, not_exploitable]


@pytest.fixture
def sample_security_audit_result(sample_verified_findings: list[VerifiedFinding]) -> SecurityAuditResult:
    return SecurityAuditResult(
        repository="Agent-Field/sec-af",
        commit_sha="a" * 40,
        branch="issue-23-tests",
        timestamp=datetime(2026, 3, 4, 10, 30, 0, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=["injection", "auth"],
        provider="opencode",
        findings=sample_verified_findings,
        attack_chains=[
            AttackChain(
                chain_id="chain-1",
                title="Input to DB read",
                description="Untrusted input reaches SQL sink",
                findings=["finding-confirmed", "finding-likely"],
                combined_severity=Severity.CRITICAL,
                combined_impact="Unauthorized DB disclosure",
                mitre_attack_mapping=[
                    MitreMapping(
                        tactic="Initial Access",
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application",
                    )
                ],
            )
        ],
        total_raw_findings=6,
        confirmed=1,
        likely=1,
        inconclusive=0,
        not_exploitable=1,
        noise_reduction_pct=66.7,
        by_severity={"critical": 1, "high": 1, "low": 1},
        compliance_gaps=[
            ComplianceGap(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Prevent injection",
                finding_count=1,
                max_severity="critical",
                cwe_ids=["CWE-89"],
            )
        ],
        duration_seconds=182.4,
        agent_invocations=24,
        cost_usd=3.21,
        cost_breakdown={"recon": 0.5, "hunt": 1.2, "prove": 1.51},
        sarif="{}",
    )
