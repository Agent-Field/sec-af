from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol
from sec_af.agents._utils import extract_harness_result

from sec_af.schemas.recon import ArchitectureMap


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "architecture.txt"


async def run_architecture_mapper(app: HarnessCapable, repo_path: str) -> ArchitectureMap:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Take multiple turns to explore the codebase first, then build your analysis.\n"
        + "- Write final JSON only when analysis is complete."
    )
    agent_name = "recon-architecture"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=ArchitectureMap, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, ArchitectureMap, "Architecture mapper")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


def architecture_context_block(architecture: ArchitectureMap) -> str:
    return json.dumps(architecture.model_dump(), indent=2)
