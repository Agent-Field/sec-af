from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol
from sec_af.agents._utils import extract_harness_result
from sec_af.agents.recon._parsers import parse_config_report_raw

from sec_af.schemas.recon import ConfigReport, ConfigReportRaw


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "config_scanner.txt"


async def run_config_scanner(app: HarnessCapable, repo_path: str) -> ConfigReport:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Start by listing files in the repository path above.\n"
        + "- After gathering evidence, write the JSON output file using your Write tool."
    )
    agent_name = "recon-config-scanner"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=ConfigReportRaw, cwd=harness_cwd, project_dir=repo_path)
        raw = extract_harness_result(result, ConfigReportRaw, "Config scanner")
        return parse_config_report_raw(raw)
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
