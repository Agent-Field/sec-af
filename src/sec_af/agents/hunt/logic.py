from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from sec_af.agents._utils import extract_harness_result

from sec_af.config import DepthProfile
from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "logic.txt"


def _normalize_depth(depth: str | DepthProfile) -> DepthProfile:
    if isinstance(depth, DepthProfile):
        return depth
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def is_logic_hunter_enabled(depth: str | DepthProfile) -> bool:
    profile = _normalize_depth(depth)
    return profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}


def _build_prompt(prompt_template: str, recon: ReconResult, repo_path: str) -> str:
    recon_json = json.dumps(recon.model_dump(), indent=2)
    return (
        prompt_template.replace("{{RECON_RESULT_JSON}}", recon_json)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Strategy: logic_bugs\n"
        + "- Focus CWEs: CWE-840 (Business Logic Errors), CWE-841 (Behavioral Workflow)\n"
        + "- Take multiple turns: inspect workflows, validate state transitions, and build findings incrementally.\n"
        + "- Write final JSON only when complete."
    )


async def run_logic_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    depth: str | DepthProfile,
) -> HuntResult:
    if not is_logic_hunter_enabled(depth):
        return HuntResult(findings=[], strategies_run=[])

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(prompt_template, recon, repo_path)
    agent_name = "hunt-logic"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd)
        parsed = extract_harness_result(result, HuntResult, "Business logic hunter")
        if not parsed.strategies_run:
            parsed.strategies_run = [HuntStrategy.LOGIC_BUGS.value]
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
