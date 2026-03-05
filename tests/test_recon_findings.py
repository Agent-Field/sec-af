from __future__ import annotations

from sec_af.agents.recon import extract_recon_findings
from sec_af.orchestrator import merge_recon_findings_into_hunt
from sec_af.schemas.hunt import Confidence, FindingType, HuntResult, RawFinding, Severity
from sec_af.schemas.recon import (
    ConfigReport,
    CryptoUsage,
    MisconfigFinding,
    ReconResult,
    SecurityContext,
    SecretFinding,
)


def _minimal_recon_result() -> ReconResult:
    return ReconResult.model_validate(
        {
            "architecture": {},
            "data_flows": {},
            "dependencies": {},
            "config": {},
            "security_context": {
                "auth_model": "jwt",
                "auth_details": "Bearer token",
                "crypto_usage": [
                    {
                        "algorithm": "TLSv1.0",
                        "usage_context": "legacy tls terminator",
                        "is_weak": True,
                    }
                ],
            },
        }
    )


def test_extract_recon_findings_builds_raw_findings_from_recon_detections() -> None:
    recon = _minimal_recon_result()
    recon.config = ConfigReport(
        secrets=[
            SecretFinding(
                secret_type="api_key",
                file_path="src/config.py",
                line=7,
                match='API_KEY = "sk-live-123"',
                confidence="high",
            )
        ],
        misconfigs=[
            MisconfigFinding(
                category="dangerous_config",
                file_path="deploy/prod.yaml",
                line=22,
                key="DEBUG",
                value="true",
                risk="Debug mode enabled in production",
            )
        ],
    )
    recon.security_context = SecurityContext(
        auth_model="jwt",
        auth_details="Bearer token",
        crypto_usage=[CryptoUsage(algorithm="TLSv1.0", usage_context="public edge", is_weak=True)],
    )

    findings = extract_recon_findings(recon)

    assert len(findings) == 3
    assert {finding.hunter_strategy for finding in findings} == {"recon"}
    assert {finding.confidence for finding in findings} == {Confidence.HIGH}
    assert {finding.finding_type for finding in findings} == {FindingType.SECRETS, FindingType.CONFIG}
    assert any(finding.cwe_id == "CWE-798" and finding.estimated_severity == Severity.HIGH for finding in findings)
    assert any(finding.cwe_id == "CWE-16" and finding.estimated_severity == Severity.MEDIUM for finding in findings)
    assert any(finding.cwe_id == "CWE-327" and finding.file_path == "security_context" for finding in findings)


def test_merge_recon_findings_prepends_and_updates_counts() -> None:
    hunt = HuntResult(
        findings=[
            RawFinding(
                hunter_strategy="injection",
                title="Potential SQLi",
                description="Candidate",
                finding_type=FindingType.SAST,
                cwe_id="CWE-89",
                cwe_name="SQL Injection",
                file_path="src/users.py",
                start_line=42,
                end_line=42,
                code_snippet="cursor.execute(query)",
                estimated_severity=Severity.HIGH,
                confidence=Confidence.MEDIUM,
            )
        ],
        chains=[],
        total_raw=1,
        deduplicated_count=1,
        chain_count=0,
        strategies_run=["injection"],
    )
    recon_findings = [
        RawFinding(
            hunter_strategy="recon",
            title="Hardcoded secret in config.py",
            description="Detected static credential.",
            finding_type=FindingType.SECRETS,
            cwe_id="CWE-798",
            cwe_name="Use of Hard-coded Credentials",
            file_path="src/config.py",
            start_line=7,
            end_line=7,
            code_snippet='API_KEY = "sk-live-123"',
            estimated_severity=Severity.HIGH,
            confidence=Confidence.HIGH,
        )
    ]

    merged = merge_recon_findings_into_hunt(hunt, recon_findings)

    assert len(merged.findings) == 2
    assert merged.findings[0].hunter_strategy == "recon"
    assert merged.total_raw == 2
    assert merged.deduplicated_count == 2
    assert merged.strategies_run[0] == "recon"
