from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.output import CrossServiceFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "cross_service.txt"


def _build_prompt(template: str, services: list[str], findings_summary: str, depth: str) -> str:
    replacements = {
        "{{SERVICES}}": json.dumps(services, indent=2),
        "{{FINDINGS_SUMMARY}}": findings_summary,
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_cross_service_analyzer(
    app: HarnessCapable,
    repo_path: str,
    services: list[str],
    findings_summary: str,
    depth: str,
) -> CrossServiceFinding:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, services, findings_summary, depth)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path above for cross-service inspection."
    )
    agent_name = "prove-cross-service"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=CrossServiceFinding,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, CrossServiceFinding, "CrossServiceAnalyzer")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
