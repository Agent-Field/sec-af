from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_injection
from sec_af.schemas.hunt import HuntResult

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "injection.txt"


async def run_injection_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
    max_files_without_signal: int = 30,
) -> HuntResult:
    recon_context = recon_context_for_injection(recon_result)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon_result))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon_result))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Depth profile: {depth}\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible signal, "
        + "stop and return empty findings.\n"
        + "- Focus on RECON entry points and data flows as primary source-to-sink paths.\n"
        + "- Explore the codebase, trace data flows from sources to sinks, and identify injection points.\n"
        + "- Take multiple turns to build findings incrementally and write final JSON only when complete."
    )

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult()

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="sast",
        strategy="injection",
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(location=location, enriched=enriched, finding_type="sast", strategy="injection")
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=["injection"],
    )
