from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_supply_chain
from sec_af.schemas.hunt import HuntResult

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "supply_chain.txt"


def should_run_supply_chain_hunter(recon: ReconResult) -> bool:
    return recon.dependencies.direct_count > 0


def _empty_supply_chain_result() -> HuntResult:
    return HuntResult(findings=[], chains=[], strategies_run=[])


async def run_supply_chain_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    if not should_run_supply_chain_hunter(recon):
        return _empty_supply_chain_result()

    recon_context = recon_context_for_supply_chain(recon)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Hunt strategy: supply_chain (CWE-1104, CWE-829).\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} manifests/files without credible dependency risk, "
        + "stop and return empty findings.\n"
        + "- Focus manifests/lockfiles (package.json, requirements.txt, go.mod, Pipfile, "
        + "poetry.lock, package-lock.json, yarn.lock, pnpm-lock.yaml, Cargo.toml).\n"
        + "- Take multiple turns: inspect manifests/lockfiles, validate dependency risks, "
        + "then produce final structured findings.\n"
        + "- Write final JSON only when analysis is complete.\n"
    )

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult(strategies_run=["supply_chain"])

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="sca",
        strategy="supply_chain",
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(location=location, enriched=enriched, finding_type="sca", strategy="supply_chain")
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=["supply_chain"],
    )
