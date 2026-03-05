from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.context import recon_context_for_api_security
from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "api_security.txt"


async def run_api_security_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    if not recon.architecture.api_surface:
        return HuntResult(strategies_run=[HuntStrategy.API_SECURITY.value])

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context_for_api_security(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Focus only on API-relevant code paths and endpoint handlers surfaced by RECON.\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible API issues, "
        + "stop and return empty findings.\n"
        + "- Take multiple turns: inspect handlers/middleware first, then generate findings.\n"
        + "- Write final JSON only when analysis is complete."
    )
    agent_name = "hunt-api-security"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        parsed = extract_harness_result(result, HuntResult, "API security hunter")

        if not parsed.strategies_run:
            parsed.strategies_run = [HuntStrategy.API_SECURITY.value]
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
