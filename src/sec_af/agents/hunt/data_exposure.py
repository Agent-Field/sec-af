from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_data_exposure
from sec_af.schemas.hunt import HuntResult

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "data_exposure.txt"


async def run_data_exposure_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    recon_context = recon_context_for_data_exposure(recon)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Strategy: data_exposure\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible exposure risk, "
        + "stop and return empty findings.\n"
        + "- Use multiple turns: inspect files first, then produce findings.\n"
        + "- Return final JSON only when analysis is complete."
    )

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult(strategies_run=["data_exposure"])

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="sast",
        strategy="data_exposure",
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(location=location, enriched=enriched, finding_type="sast", strategy="data_exposure")
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=["data_exposure"],
    )
