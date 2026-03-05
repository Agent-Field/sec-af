from __future__ import annotations

import asyncio
from typing import TYPE_CHECKING, Protocol

from sec_af.schemas.prove import DataFlowTrace, EvidenceLevel, Location, ReproductionStep, Verdict, VerifiedFinding

from .assembler import assemble_verified_finding
from .exploit import run_exploit_hypothesizer
from .sanitization import run_sanitization_analyzer
from .tracer import run_tracer
from .verdict import run_verdict_agent

if TYPE_CHECKING:
    from sec_af.schemas.hunt import RawFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


def _sarif_rule_id(finding: RawFinding) -> str:
    cwe_slug = finding.cwe_name.lower().replace(" ", "-").replace("/", "-")
    return f"sec-af/{finding.finding_type.value}/{cwe_slug}"


def fallback(
    finding: RawFinding,
    reason: str,
    *,
    drop_reason: str | None = None,
    original_verdict: str | None = None,
) -> VerifiedFinding:
    rationale = f"Verification incomplete: {reason}"
    if original_verdict:
        rationale = f"{rationale} (original verdict: {original_verdict})"
    tags = ["low_confidence"] if drop_reason else []
    return VerifiedFinding(
        id=finding.id,
        fingerprint=finding.fingerprint,
        title=finding.title,
        description=finding.description,
        finding_type=finding.finding_type,
        cwe_id=finding.cwe_id,
        cwe_name=finding.cwe_name,
        owasp_category=finding.owasp_category,
        verdict=Verdict.INCONCLUSIVE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale=rationale,
        severity=finding.estimated_severity,
        tags=tags,
        exploitability_score=0.0,
        location=Location(
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            function_name=finding.function_name,
            code_snippet=finding.code_snippet,
        ),
        reproduction_steps=[],
        sarif_rule_id=_sarif_rule_id(finding),
        sarif_security_severity=0.0,
        drop_reason=drop_reason,
    )


async def run_verifier(app: HarnessCapable, repo_path: str, finding: RawFinding, depth: str) -> VerifiedFinding:
    tracer_task = run_tracer(app=app, repo_path=repo_path, finding=finding, depth=depth)
    seed_trace = DataFlowTrace(
        source=f"{finding.file_path}:{finding.start_line}",
        sink=finding.function_name or finding.file_path,
        steps=[f"{step.file_path}:{step.line} {step.operation}" for step in finding.data_flow]
        if finding.data_flow
        else [],
        sink_reached=False,
    )
    sanitization_task = run_sanitization_analyzer(
        app=app,
        repo_path=repo_path,
        finding=finding,
        data_flow_trace=seed_trace,
        depth=depth,
    )
    data_flow_trace, sanitization = await asyncio.gather(tracer_task, sanitization_task)

    exploit = await run_exploit_hypothesizer(
        app=app,
        repo_path=repo_path,
        finding=finding,
        data_flow_trace=data_flow_trace,
        sanitization=sanitization,
        depth=depth,
    )
    verdict = await run_verdict_agent(
        app=app,
        repo_path=repo_path,
        finding=finding,
        data_flow=data_flow_trace,
        sanitization=sanitization,
        exploit=exploit,
    )
    verified = assemble_verified_finding(finding, data_flow_trace, sanitization, exploit, verdict)

    if not verified.sarif_rule_id:
        verified.sarif_rule_id = _sarif_rule_id(finding)
    if not verified.reproduction_steps and verified.verdict != Verdict.NOT_EXPLOITABLE:
        verified.reproduction_steps = [
            ReproductionStep(
                step=1,
                description="Review vulnerable code location and trace data flow to sink.",
                command=None,
                expected_output="Flow reaches sensitive sink without sufficient mitigation.",
            ),
            ReproductionStep(
                step=2,
                description="Craft payload from exploit_hypothesis and execute against target path.",
                command=None,
                expected_output="Observed effect aligns with expected exploit outcome.",
            ),
        ]
    return verified
