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


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "supply_chain.txt"


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Supply Chain Hunter did not return a valid HuntResult")


def should_run_supply_chain_hunter(recon: ReconResult) -> bool:
    return recon.dependencies.direct_count > 0


def _empty_supply_chain_result() -> HuntResult:
    return HuntResult(findings=[], chains=[], strategies_run=[])


async def run_supply_chain_hunter(app: HarnessCapable, repo_path: str, recon: ReconResult) -> HuntResult:
    if not should_run_supply_chain_hunter(recon):
        return _empty_supply_chain_result()

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Hunt strategy: supply_chain (CWE-1104, CWE-829).\n"
        + "- Focus manifests/lockfiles (package.json, requirements.txt, go.mod, Pipfile, "
        + "poetry.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.toml).\n"
        + f"- Recon dependency report: {json.dumps(recon.dependencies.model_dump(), indent=2)}\n"
        + "- Take multiple turns: inspect manifests/lockfiles, validate dependency risks, "
        + "then produce final structured findings.\n"
        + "- Write final JSON only when analysis is complete.\n"
    )
    result = await app.harness(prompt=prompt, schema=HuntResult, cwd=repo_path)
    hunt_result = _extract_parsed(result, HuntResult)

    if not hunt_result.strategies_run:
        hunt_result.strategies_run = ["supply_chain"]
    if hunt_result.total_raw <= 0:
        hunt_result.total_raw = len(hunt_result.findings)
    if hunt_result.deduplicated_count <= 0:
        hunt_result.deduplicated_count = len(hunt_result.findings)
    hunt_result.chain_count = len(hunt_result.chains)

    return hunt_result
