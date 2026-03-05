from __future__ import annotations

from dataclasses import dataclass

import pytest

from sec_af.agents.dedup import deduplicate_and_correlate
from sec_af.schemas.hunt import ChainCorrelationResult, Confidence, FindingType, RawFinding, Severity
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)


def _recon() -> ReconResult:
    return ReconResult(
        architecture=ArchitectureMap(),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(),
        config=ConfigReport(),
        security_context=SecurityContext(auth_model="session", auth_details="standard"),
        languages=["python"],
    )


def _finding(*, finding_id: str, cwe_id: str, cwe_name: str, severity: Severity = Severity.HIGH) -> RawFinding:
    return RawFinding(
        id=finding_id,
        hunter_strategy="injection",
        title=f"Finding {finding_id}",
        description=f"Description for {finding_id}",
        finding_type=FindingType.SAST,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        file_path=f"src/{finding_id.lower()}.py",
        start_line=10,
        end_line=10,
        code_snippet="dangerous_call(user_input)",
        estimated_severity=severity,
        confidence=Confidence.HIGH,
        related_files=[],
        fingerprint=f"fp-{finding_id}",
    )


@dataclass
class _HarnessResult:
    parsed: object
    is_error: bool = False


@dataclass
class _HarnessApp:
    response: ChainCorrelationResult
    prompt: str = ""

    async def harness(self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object) -> object:
        _ = (schema, cwd, kwargs)
        self.prompt = prompt
        return _HarnessResult(parsed=self.response)


@pytest.mark.asyncio
async def test_dedup_prompt_includes_seed_chain_candidates() -> None:
    findings = [
        _finding(finding_id="F1", cwe_id="CWE-918", cwe_name="Server-Side Request Forgery (SSRF)"),
        _finding(finding_id="F3", cwe_id="CWE-798", cwe_name="Use of Hard-coded Credentials"),
    ]
    app = _HarnessApp(response=ChainCorrelationResult(chains=[], duplicate_ids=[]))

    _ = await deduplicate_and_correlate(findings, _recon(), app, repo_path=".")

    assert "Seed chain candidates (validate and expand these):" in app.prompt
    assert (
        "Potential chain: Server-Side Request Forgery (SSRF) -> Use of Hard-coded Credentials (findings F1, F3)"
        in app.prompt
    )
    assert "Look for additional multi-step attack chains beyond these seeds." in app.prompt


@pytest.mark.asyncio
async def test_seed_chains_are_used_when_ai_returns_no_chains() -> None:
    findings = [
        _finding(finding_id="F1", cwe_id="CWE-89", cwe_name="SQL Injection", severity=Severity.CRITICAL),
        _finding(
            finding_id="F2", cwe_id="CWE-200", cwe_name="Exposure of Sensitive Information", severity=Severity.HIGH
        ),
    ]
    app = _HarnessApp(response=ChainCorrelationResult(chains=[], duplicate_ids=[]))

    result = await deduplicate_and_correlate(findings, _recon(), app, repo_path=".")

    assert len(result.chains) == 1
    assert result.chains[0].finding_ids == ["F1", "F2"]
    assert result.chains[0].title == "Potential attack chain: CWE-89 -> CWE-200"


@pytest.mark.asyncio
async def test_ai_discovered_chains_take_priority_over_seed_chains() -> None:
    findings = [
        _finding(
            finding_id="F1", cwe_id="CWE-918", cwe_name="Server-Side Request Forgery (SSRF)", severity=Severity.HIGH
        ),
        _finding(
            finding_id="F2", cwe_id="CWE-200", cwe_name="Exposure of Sensitive Information", severity=Severity.MEDIUM
        ),
        _finding(finding_id="F3", cwe_id="CWE-798", cwe_name="Use of Hard-coded Credentials", severity=Severity.HIGH),
    ]
    app = _HarnessApp(
        response=ChainCorrelationResult(
            chains=[
                "AI-discovered chain: SSRF to data exfiltration|F1,F2,F3|SSRF reaches metadata; stolen secret enables privileged API access and data exfiltration.|critical"
            ],
            duplicate_ids=[],
        )
    )

    result = await deduplicate_and_correlate(findings, _recon(), app, repo_path=".")

    assert len(result.chains) == 1
    assert result.chains[0].title == "AI-discovered chain: SSRF to data exfiltration"
    assert result.chains[0].finding_ids == ["F1", "F2", "F3"]
