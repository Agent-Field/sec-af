from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context
from sec_af.schemas.hunt import HuntResult

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "xss.txt"


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


async def run_xss_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
    max_files_without_signal: int = 30,
) -> HuntResult:
    recon_context = _recon_context_block(recon_result)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT_JSON}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon_result))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon_result))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Depth profile: {depth}\n"
        + f"- Early stop rule: if you inspect {max_files_without_signal} files without credible signal, stop and return empty findings.\n"
        + "- Focus on RECON entry points and data flows as primary source-to-sink paths.\n"
        + "- Explore the codebase, trace user-controlled data into rendering sinks, and identify XSS/client-side injection points.\n"
        + "- Target CWEs: CWE-79, CWE-80, CWE-87, CWE-116.\n"
        + "- Take multiple turns to build findings incrementally and write final JSON only when complete."
    )

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult()

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="sast",
        strategy="xss",
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(location=location, enriched=enriched, finding_type="sast", strategy="xss")
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=["xss"],
    )
