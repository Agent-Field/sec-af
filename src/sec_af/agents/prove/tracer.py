from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import DataFlowTrace

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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "tracer.txt"


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
        "{{DATA_FLOW_JSON}}": _finding_data_flow(finding),
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_tracer(app: HarnessCapable, repo_path: str, finding: RawFinding, depth: str) -> DataFlowTrace:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, depth)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path above for file inspection during source-to-sink tracing."
    )
    agent_name = "prove-tracer"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=DataFlowTrace, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, DataFlowTrace, "DataFlowTracer")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
