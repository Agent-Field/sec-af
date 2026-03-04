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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "api_security.txt"


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("API security hunter did not return a valid HuntResult")


def _api_context_block(recon: ReconResult) -> str:
    context = {
        "api_surface": [endpoint.model_dump() for endpoint in recon.architecture.api_surface],
        "entry_points": [
            entry.model_dump()
            for entry in recon.architecture.entry_points
            if entry.kind.lower() in {"http", "api", "graphql", "rpc", "route"}
        ],
        "security_context": recon.security_context.model_dump(),
        "trust_boundaries": [boundary.model_dump() for boundary in recon.architecture.trust_boundaries],
    }
    return json.dumps(context, indent=2)


async def run_api_security_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
) -> HuntResult:
    if not recon.architecture.api_surface:
        return HuntResult(strategies_run=[HuntStrategy.API_SECURITY.value])

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{API_SECURITY_CONTEXT_JSON}}", _api_context_block(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Focus only on API-relevant code paths and endpoint handlers surfaced by RECON.\n"
        + "- Take multiple turns: inspect handlers/middleware first, then generate findings.\n"
        + "- Write final JSON only when analysis is complete."
    )

    result = await app.harness(prompt=prompt, schema=HuntResult, cwd=repo_path)
    parsed = _extract_parsed(result, HuntResult)

    if not parsed.strategies_run:
        parsed.strategies_run = [HuntStrategy.API_SECURITY.value]
    return parsed
