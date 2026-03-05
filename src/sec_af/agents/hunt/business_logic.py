from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.config import DepthProfile
from sec_af.context import framework_hints_for_context, language_hints_for_context
from sec_af.schemas.hunt import HuntResult, HuntStrategy

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "business_logic.txt"


def _normalize_depth(depth: str | DepthProfile) -> DepthProfile:
    if isinstance(depth, DepthProfile):
        return depth
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def is_business_logic_hunter_enabled(depth: str | DepthProfile) -> bool:
    profile = _normalize_depth(depth)
    return profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}


def _recon_context_block(recon_result: ReconResult) -> str:
    entry_points = [entry.model_dump() for entry in recon_result.architecture.entry_points[:15]]
    api_surface = [endpoint.model_dump() for endpoint in recon_result.architecture.api_surface[:20]]
    data_flows = [flow.model_dump() for flow in recon_result.data_flows.flows[:20]]
    context = {
        "app_type": recon_result.architecture.app_type,
        "frameworks": recon_result.frameworks,
        "languages": recon_result.languages,
        "auth_model": recon_result.security_context.auth_model,
        "auth_details": recon_result.security_context.auth_details,
        "entry_points": entry_points,
        "api_surface": api_surface,
        "data_flows": data_flows,
    }
    return json.dumps(context, indent=2)


async def run_business_logic_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str | DepthProfile,
    max_files_without_signal: int = 30,
    depth_prompt: str = "",
) -> HuntResult:
    if not is_business_logic_hunter_enabled(depth):
        return HuntResult(findings=[], strategies_run=[])

    recon_context = _recon_context_block(recon_result)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT_JSON}}", recon_context)
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon_result))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon_result))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Depth profile: {_normalize_depth(depth).value}\n"
        + f"- Early stop rule: if you inspect {max_files_without_signal} files without credible business-logic signal, stop and return empty findings.\n"
        + "- Strategy: business_logic\n"
        + "- Focus CWEs: CWE-840, CWE-841, CWE-362, CWE-367, CWE-639.\n"
        + "- Reason about intended business behavior versus exploitable implementation behavior.\n"
        + "- Take multiple turns, trace complete workflows, and return final JSON only when complete."
    )
    if depth_prompt:
        scan_prompt += f"\n- Additional depth guidance: {depth_prompt}"

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult(strategies_run=[HuntStrategy.BUSINESS_LOGIC.value])

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="logic",
        strategy=HuntStrategy.BUSINESS_LOGIC.value,
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(
            location=location,
            enriched=enriched,
            finding_type="logic",
            strategy=HuntStrategy.BUSINESS_LOGIC.value,
        )
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=[HuntStrategy.BUSINESS_LOGIC.value],
    )
