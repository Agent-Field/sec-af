from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_api_security
from sec_af.schemas.hunt import HuntResult, HuntStrategy

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "api_security.txt"


async def run_api_security_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    if not recon.architecture.api_surface:
        return HuntResult(strategies_run=[HuntStrategy.API_SECURITY.value])

    recon_context = recon_context_for_api_security(recon)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Focus only on API-relevant code paths and endpoint handlers surfaced by RECON.\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible API issues, "
        + "stop and return empty findings.\n"
        + "- Read the handler files first, then generate findings.\n"
        + "- After gathering evidence, write the JSON output file using your Write tool."
    )

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult(strategies_run=[HuntStrategy.API_SECURITY.value])

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="api",
        strategy=HuntStrategy.API_SECURITY.value,
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(
            location=location,
            enriched=enriched,
            finding_type="api",
            strategy=HuntStrategy.API_SECURITY.value,
        )
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=[HuntStrategy.API_SECURITY.value],
    )
