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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "injection.txt"


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Injection hunter did not return a valid HuntResult")


def _recon_context_block(recon_result: ReconResult) -> str:
    entry_points = [entry.model_dump() for entry in recon_result.architecture.entry_points[:10]]
    data_flows = [flow.model_dump() for flow in recon_result.data_flows.flows[:10]]
    context = {
        "app_type": recon_result.architecture.app_type,
        "auth_model": recon_result.security_context.auth_model,
        "frameworks": recon_result.frameworks,
        "languages": recon_result.languages,
        "entry_points": entry_points,
        "data_flows": data_flows,
    }
    return json.dumps(context, indent=2)


async def run_injection_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{RECON_CONTEXT_JSON}}", _recon_context_block(recon_result))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Depth profile: {depth}\n"
        + "- Focus on RECON entry points and data flows as primary source-to-sink paths.\n"
        + "- Explore the codebase, trace data flows from sources to sinks, and identify injection points.\n"
        + "- Take multiple turns to build findings incrementally and write final JSON only when complete."
    )
    result = await app.harness(prompt=prompt, schema=HuntResult, cwd=repo_path)
    return _extract_parsed(result, HuntResult)
