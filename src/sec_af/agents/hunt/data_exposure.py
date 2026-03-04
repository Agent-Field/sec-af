from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from sec_af.schemas.hunt import HuntResult

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


@runtime_checkable
class HarnessResultLike(Protocol):
    parsed: object | None


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "data_exposure.txt"


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Data Exposure Hunter did not return a valid HuntResult")


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
    result = await app.harness(prompt=prompt, schema=HuntResult, cwd=repo_path)
    parsed = _extract_parsed(result, HuntResult)
    if not parsed.strategies_run:
        parsed.strategies_run = ["data_exposure"]
    return parsed
