from __future__ import annotations

from typing import TYPE_CHECKING

from sec_af.schemas.prove import (
    DataFlowEvidence,
    DataFlowStep,
    DataFlowTrace,
    EvidenceLevel,
    ExploitHypothesis,
    Location,
    Proof,
    ReproductionStep,
    SanitizationAnalysis,
    SanitizationResult,
    Verdict,
    VerdictDecision,
    VerifiedFinding,
)

if TYPE_CHECKING:
    from sec_af.schemas.hunt import RawFinding


_VERDICT_MAP: dict[str, Verdict] = {
    "confirmed": Verdict.CONFIRMED,
    "likely": Verdict.LIKELY,
    "inconclusive": Verdict.INCONCLUSIVE,
    "not_exploitable": Verdict.NOT_EXPLOITABLE,
}


def _sarif_rule_id(finding: RawFinding) -> str:
    cwe_slug = finding.cwe_name.lower().replace(" ", "-").replace("/", "-")
    return f"sec-af/{finding.finding_type.value}/{cwe_slug}"


def _to_evidence_level(level: int) -> EvidenceLevel:
    bounded = max(1, min(6, level))
    return EvidenceLevel(bounded)


def _to_data_flow_steps(trace: DataFlowTrace) -> list[DataFlowStep]:
    rows: list[DataFlowStep] = []
    for index, step in enumerate(trace.steps, start=1):
        rows.append(DataFlowStep(file=f"trace_step_{index}", line=index, description=step, tainted=True))
    return rows


def _reproduction_steps(verdict: Verdict, exploit: ExploitHypothesis) -> list[ReproductionStep]:
    if verdict == Verdict.NOT_EXPLOITABLE:
        return []
    return [
        ReproductionStep(
            step=1,
            description="Trace attacker-controlled input from source to sink in target code path.",
            command=None,
            expected_output="Input reaches a sensitive sink.",
        ),
        ReproductionStep(
            step=2,
            description=exploit.hypothesis,
            command=exploit.payload,
            expected_output=exploit.expected_outcome,
        ),
    ]


def assemble_verified_finding(
    finding: RawFinding,
    data_flow_trace: DataFlowTrace,
    sanitization: SanitizationResult,
    exploit: ExploitHypothesis,
    verdict_decision: VerdictDecision,
) -> VerifiedFinding:
    verdict = _VERDICT_MAP.get(verdict_decision.verdict, Verdict.INCONCLUSIVE)
    evidence_level = _to_evidence_level(verdict_decision.evidence_level)
    data_flow_steps = _to_data_flow_steps(data_flow_trace)

    proof = Proof(
        exploit_hypothesis=exploit.hypothesis,
        verification_method=f"composite_subagent_chain:{finding.finding_type.value}",
        evidence_level=evidence_level,
        data_flow_trace=data_flow_steps,
        data_flow_evidence=DataFlowEvidence(
            steps=data_flow_steps,
            source=data_flow_trace.source,
            sink=data_flow_trace.sink,
            sink_reached=data_flow_trace.sink_reached,
        ),
        sanitization_analysis=SanitizationAnalysis(
            sanitization_found=sanitization.found,
            sanitization_type=sanitization.type,
            sanitization_sufficient=sanitization.sufficient,
            bypass_possible=bool(sanitization.bypass_method),
            bypass_method=sanitization.bypass_method,
        ),
        exploit_payload=exploit.payload,
        expected_outcome=exploit.expected_outcome,
    )

    return VerifiedFinding(
        id=finding.id,
        fingerprint=finding.fingerprint,
        title=finding.title,
        description=finding.description,
        finding_type=finding.finding_type,
        cwe_id=finding.cwe_id,
        cwe_name=finding.cwe_name,
        owasp_category=finding.owasp_category,
        verdict=verdict,
        evidence_level=evidence_level,
        rationale=verdict_decision.rationale,
        severity=finding.estimated_severity,
        tags=[],
        exploitability_score=0.0,
        proof=proof,
        location=Location(
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            function_name=finding.function_name,
            code_snippet=finding.code_snippet,
        ),
        reproduction_steps=_reproduction_steps(verdict, exploit),
        sarif_rule_id=_sarif_rule_id(finding),
        sarif_security_severity=0.0,
        drop_reason=None,
    )
