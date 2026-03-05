from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol
from sec_af.agents._utils import extract_harness_result
from sec_af.agents.recon._parsers import parse_dependency_report_raw

from sec_af.schemas.recon import DependencyReport, DependencyReportRaw


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "dependencies.txt"


async def run_dependency_auditor(app: HarnessCapable, repo_path: str) -> DependencyReport:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Start by listing files in the repository path above.\n"
        + "- After gathering evidence, write the JSON output file using your Write tool."
    )
    agent_name = "recon-dependencies"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=DependencyReportRaw, cwd=harness_cwd, project_dir=repo_path)
        raw = extract_harness_result(result, DependencyReportRaw, "Dependency auditor")
        return parse_dependency_report_raw(raw)
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
