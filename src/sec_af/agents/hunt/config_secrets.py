from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


@runtime_checkable
class HarnessResultLike(Protocol):
    parsed: object | None


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "config_secrets.txt"


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Config/Secrets hunter did not return a valid HuntResult")


def _recon_context_block(recon: ReconResult) -> str:
    return json.dumps(recon.model_dump(), indent=2)


async def run_config_secrets_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Hunt strategy: {HuntStrategy.CONFIG_SECRETS.value} (CWE-798, CWE-259, CWE-321, CWE-16).\n"
        + "- Use RECON ConfigReport and SecurityContext to prioritize likely real findings.\n"
        + "- Take multiple turns: inspect files, validate exploitability signal, then build findings.\n"
        + "- ReconResult JSON:\n"
        + _recon_context_block(recon)
    )
    result = await app.harness(prompt=prompt, schema=HuntResult, cwd=repo_path)
    parsed = _extract_parsed(result, HuntResult)
    if not parsed.strategies_run:
        parsed.strategies_run = [HuntStrategy.CONFIG_SECRETS.value]
    if parsed.total_raw <= 0:
        parsed.total_raw = len(parsed.findings)
    if parsed.deduplicated_count <= 0:
        parsed.deduplicated_count = len(parsed.findings)
    if parsed.chain_count <= 0:
        parsed.chain_count = len(parsed.chains)
    return parsed
