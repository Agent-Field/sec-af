from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from sec_af.schemas.prove import EvidenceLevel, Location, ReproductionStep, Verdict, VerifiedFinding

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


@runtime_checkable
class HarnessResultLike(Protocol):
    parsed: object | None


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "verifier.txt"

_VERIFICATION_METHODS: dict[str, str] = {
    "sast": "Trace source-to-sink flow, validate sanitization, and construct exploit scenario.",
    "api": "Trace request lifecycle and authorization checks, then validate abuse path.",
    "sca": "Confirm vulnerable version and reachability of vulnerable call chain.",
    "secrets": "Validate secret format/context and determine whether credential is likely real and actionable.",
    "config": "Verify active runtime config and whether secure overrides or mitigations apply.",
    "logic": "Reason through state transitions and attacker-controlled sequencing.",
}


def _extract_parsed(result: object) -> VerifiedFinding:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, VerifiedFinding):
            return parsed
        if isinstance(parsed, dict):
            return VerifiedFinding(**cast("dict[str, object]", parsed))
    if isinstance(result, VerifiedFinding):
        return result
    raise TypeError("Verifier did not return a valid VerifiedFinding")


def _sarif_rule_id(finding: RawFinding) -> str:
    cwe_slug = finding.cwe_name.lower().replace(" ", "-").replace("/", "-")
    return f"sec-af/{finding.finding_type.value}/{cwe_slug}"


def _finding_data_flow(finding: RawFinding) -> str:
    if not finding.data_flow:
        return "[]"
    rows = [
        {
            "file_path": step.file_path,
            "line": step.line,
            "component": step.component,
            "operation": step.operation,
        }
        for step in finding.data_flow
    ]
    return json.dumps(rows, indent=2)


def _build_prompt(template: str, finding: RawFinding, depth: str) -> str:
    verification_method = _VERIFICATION_METHODS.get(
        finding.finding_type.value,
        "Trace data/control flow and verify exploitability with evidence.",
    )
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{CWE_ID}}": finding.cwe_id,
        "{{CWE_NAME}}": finding.cwe_name,
        "{{FILE_PATH}}": finding.file_path,
        "{{START_LINE}}": str(finding.start_line),
        "{{CODE_SNIPPET}}": finding.code_snippet,
        "{{FINDING_TYPE}}": finding.finding_type.value,
        "{{VERIFICATION_METHOD}}": verification_method,
        "{{RELATED_FILES}}": json.dumps(finding.related_files, indent=2),
        "{{DATA_FLOW_JSON}}": _finding_data_flow(finding),
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


def fallback(finding: RawFinding, reason: str) -> VerifiedFinding:
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
        rationale=f"Verification incomplete: {reason}",
        severity=finding.estimated_severity,
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
    )


async def run_verifier(app: HarnessCapable, repo_path: str, finding: RawFinding, depth: str) -> VerifiedFinding:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(prompt_template, finding, depth)
    result = await app.harness(prompt=prompt, schema=VerifiedFinding, cwd=repo_path)
    verified = _extract_parsed(result)

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
