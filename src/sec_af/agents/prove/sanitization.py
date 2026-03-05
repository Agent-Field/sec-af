from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import DataFlowTrace, SanitizationResult

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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "sanitization.txt"


def _trace_context(trace: DataFlowTrace) -> str:
    steps = "\n".join(f"- {step}" for step in trace.steps) if trace.steps else "- (no concrete trace steps)"
    sink_reached = "yes" if trace.sink_reached else "no"
    return f"Source: {trace.source}\nSink: {trace.sink}\nSink reached: {sink_reached}\nTrace steps:\n{steps}"


def _build_prompt(template: str, finding: RawFinding, trace: DataFlowTrace, depth: str) -> str:
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
        "{{TRACE_CONTEXT}}": _trace_context(trace),
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_sanitization_analyzer(
    app: HarnessCapable,
    repo_path: str,
    finding: RawFinding,
    data_flow_trace: DataFlowTrace,
    depth: str,
) -> SanitizationResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, data_flow_trace, depth)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path above for file inspection during sanitization analysis."
    )
    agent_name = "prove-sanitization"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=SanitizationResult, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, SanitizationResult, "SanitizationAnalyzer")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
