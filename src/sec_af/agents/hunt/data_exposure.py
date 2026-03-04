from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from sec_af.agents._utils import extract_harness_result

from sec_af.schemas.hunt import HuntResult

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "data_exposure.txt"


def _recon_context_block(recon: ReconResult) -> str:
    return json.dumps(recon.model_dump(), indent=2)


async def run_data_exposure_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{RECON_RESULT_JSON}}", _recon_context_block(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Strategy: data_exposure\n"
        + "- Use multiple turns: inspect files first, then produce findings.\n"
        + "- Return final JSON only when analysis is complete."
    )
    agent_name = "hunt-data-exposure"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        parsed = extract_harness_result(result, HuntResult, "Data Exposure Hunter")
        if not parsed.strategies_run:
            parsed.strategies_run = ["data_exposure"]
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
