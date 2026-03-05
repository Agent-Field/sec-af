from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol
from sec_af.agents._utils import extract_harness_result
from sec_af.agents.recon._parsers import parse_security_context_raw

from sec_af.schemas.recon import ArchitectureMap, SecurityContext, SecurityContextRaw

from .architecture import architecture_context_block


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "security_context.txt"


async def run_security_context_profiler(
    app: HarnessCapable,
    repo_path: str,
    architecture: ArchitectureMap,
) -> SecurityContext:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{ARCHITECTURE_MAP_JSON}}", architecture_context_block(architecture))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Take multiple turns to explore the codebase first, then build your analysis.\n"
        + "- Write final JSON only when analysis is complete."
    )
    agent_name = "recon-security-context"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=SecurityContextRaw, cwd=harness_cwd, project_dir=repo_path)
        raw = extract_harness_result(result, SecurityContextRaw, "Security context profiler")
        return parse_security_context_raw(raw)
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
