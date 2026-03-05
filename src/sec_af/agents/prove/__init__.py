from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol

from sec_af.compliance.mapping import get_compliance_mappings
from sec_af.config import DepthProfile
from sec_af.schemas.hunt import Confidence, HuntResult, RawFinding, Severity
from sec_af.scoring import compute_exploitability_score

from .chain_builder import run_chain_builder
from .verifier import fallback as verifier_fallback
from .verifier import run_verifier

if TYPE_CHECKING:
    from collections.abc import Awaitable

    from sec_af.schemas.prove import VerifiedFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_CONFIDENCE_RANK: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}


def _normalize_depth(depth: str) -> DepthProfile:
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def _priority_sort(findings: list[RawFinding]) -> list[RawFinding]:
    return sorted(
        findings,
        key=lambda finding: (
            _SEVERITY_RANK.get(finding.estimated_severity, 0),
            _CONFIDENCE_RANK.get(finding.confidence, 0),
        ),
        reverse=True,
    )


def _apply_metadata(finding: VerifiedFinding) -> VerifiedFinding:
    finding.compliance = get_compliance_mappings(finding.cwe_id)
    finding.exploitability_score = compute_exploitability_score(finding)
    finding.sarif_security_severity = finding.exploitability_score
    if not finding.sarif_rule_id:
        cwe_slug = finding.cwe_name.lower().replace(" ", "-").replace("/", "-")
        finding.sarif_rule_id = f"sec-af/{finding.finding_type.value}/{cwe_slug}"
    return finding


async def _run_parallel_verification(
    app: HarnessCapable,
    repo_path: str,
    findings: list[RawFinding],
    depth: str,
    max_concurrent_provers: int,
) -> list[VerifiedFinding]:
    if not findings:
        return []

    concurrency_limit = max(1, min(max_concurrent_provers, len(findings)))
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _verify(finding: RawFinding) -> VerifiedFinding:
        async with semaphore:
            try:
                return await run_verifier(app, repo_path, finding, depth)
            except BaseException as exc:
                return verifier_fallback(finding, str(exc))

    jobs: list[Awaitable[VerifiedFinding]] = [_verify(finding) for finding in findings]
    return await asyncio.gather(*jobs)


async def run_prove(
    app: HarnessCapable,
    repo_path: str,
    hunt_result: HuntResult,
    depth: str,
    max_concurrent_provers: int = 3,
) -> list[VerifiedFinding]:
    profile = _normalize_depth(depth)
    prioritized = _priority_sort(hunt_result.findings)

    verified_findings = await _run_parallel_verification(
        app,
        repo_path,
        prioritized,
        profile.value,
        max_concurrent_provers,
    )

    verified_findings = [_apply_metadata(finding) for finding in verified_findings]

    if hunt_result.chains:
        verified_findings = await run_chain_builder(
            app=app,
            repo_path=repo_path,
            potential_chains=hunt_result.chains,
            findings=verified_findings,
            depth=profile.value,
        )
        verified_findings = [_apply_metadata(finding) for finding in verified_findings]

    verified_findings.sort(
        key=lambda finding: (
            finding.exploitability_score,
            finding.evidence_level,
        ),
        reverse=True,
    )
    return verified_findings


__all__ = ["run_prove"]
