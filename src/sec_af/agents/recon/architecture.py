from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Protocol
from sec_af.agents._utils import extract_harness_result
from sec_af.agents.recon._parsers import parse_architecture_raw

from sec_af.schemas.recon import ArchitectureMap, ArchitectureMapRaw


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
        + "- Start by listing files in the repository path above.\n"
        + "- After gathering evidence, write the JSON output file using your Write tool."
    )
    agent_name = "recon-architecture"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=ArchitectureMapRaw, cwd=harness_cwd, project_dir=repo_path)
        raw = extract_harness_result(result, ArchitectureMapRaw, "Architecture mapper")
        return parse_architecture_raw(raw)
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


def architecture_context_block(architecture: ArchitectureMap) -> str:
    return json.dumps(architecture.model_dump(), indent=2)
