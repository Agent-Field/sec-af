from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import DataFlowTrace, ExploitHypothesis, SanitizationResult, VerdictDecision

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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "verdict.txt"


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


async def run_verdict_agent(
    app: HarnessCapable,
    repo_path: str,
    finding: RawFinding,
    data_flow: DataFlowTrace,
    sanitization: SanitizationResult,
    exploit: ExploitHypothesis,
) -> VerdictDecision:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, data_flow, sanitization, exploit)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Focus on judgment quality; inspect files only if required for tie-break decisions."
    )
    agent_name = "prove-verdict"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=VerdictDecision, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, VerdictDecision, "VerdictAgent")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
