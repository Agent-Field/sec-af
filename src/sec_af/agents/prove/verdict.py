from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from sec_af.schemas.prove import DataFlowTrace, ExploitHypothesis, SanitizationResult, VerdictDecision

if TYPE_CHECKING:
    from sec_af.schemas.hunt import RawFinding


class AICapable(Protocol):
    async def ai(
        self,
        *,
        user: str,
        schema: type,
        system: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "prove" / "verdict.txt"


def _build_context(data_flow: DataFlowTrace, sanitization: SanitizationResult, exploit: ExploitHypothesis) -> str:
    trace_steps = "\n".join(f"- {step}" for step in data_flow.steps) if data_flow.steps else "- (none)"
    return (
        "Tracer output:\n"
        f"- source: {data_flow.source}\n"
        f"- sink: {data_flow.sink}\n"
        f"- sink_reached: {data_flow.sink_reached}\n"
        f"- steps:\n{trace_steps}\n\n"
        "Sanitization output:\n"
        f"- found: {sanitization.found}\n"
        f"- type: {sanitization.type or 'none'}\n"
        f"- sufficient: {sanitization.sufficient}\n"
        f"- bypass_method: {sanitization.bypass_method or 'none'}\n\n"
        "Exploit output:\n"
        f"- hypothesis: {exploit.hypothesis}\n"
        f"- payload: {exploit.payload or 'none'}\n"
        f"- expected_outcome: {exploit.expected_outcome}"
    )


def _build_prompt(
    template: str,
    finding: RawFinding,
    data_flow: DataFlowTrace,
    sanitization: SanitizationResult,
    exploit: ExploitHypothesis,
) -> str:
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{CWE_ID}}": finding.cwe_id,
        "{{CWE_NAME}}": finding.cwe_name,
        "{{FILE_PATH}}": finding.file_path,
        "{{START_LINE}}": str(finding.start_line),
        "{{CODE_SNIPPET}}": finding.code_snippet,
        "{{FINDING_TYPE}}": finding.finding_type.value,
        "{{RELATED_FILES}}": json.dumps(finding.related_files, indent=2),
        "{{SUBAGENT_CONTEXT}}": _build_context(data_flow, sanitization, exploit),
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


def _extract_ai_result(result: object, agent_name: str) -> VerdictDecision:
    """Extract VerdictDecision from .ai() result."""
    if isinstance(result, VerdictDecision):
        return result
    if isinstance(result, dict):
        return VerdictDecision.model_validate(result)
    parsed: Any = getattr(result, "parsed", None)
    if isinstance(parsed, VerdictDecision):
        return parsed
    if isinstance(parsed, dict):
        return VerdictDecision.model_validate(parsed)
    raise TypeError(f"{agent_name} .ai() did not return a valid VerdictDecision: {type(result).__name__}")


async def run_verdict_agent(
    app: AICapable,
    repo_path: str,
    finding: RawFinding,
    data_flow: DataFlowTrace,
    sanitization: SanitizationResult,
    exploit: ExploitHypothesis,
) -> VerdictDecision:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(prompt_template, finding, data_flow, sanitization, exploit)

    # VerdictAgent is a pure judgment task — no file access needed.
    # Uses .ai() (single structured LLM call) instead of .harness() (multi-turn session).
    result = await app.ai(
        user=prompt,
        schema=VerdictDecision,
    )
    return _extract_ai_result(result, "VerdictAgent")
