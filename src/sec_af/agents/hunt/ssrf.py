from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.context import framework_hints_for_context, language_hints_for_context
from sec_af.schemas.hunt import HuntResult

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "ssrf.txt"


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


async def run_ssrf_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
    max_files_without_signal: int = 30,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{RECON_CONTEXT_JSON}}", _recon_context_block(recon_result))
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon_result))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon_result))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Depth profile: {depth}\n"
        + f"- Early stop rule: if you inspect {max_files_without_signal} files without credible signal, stop and return empty findings.\n"
        + "- Focus on RECON entry points and data flows as primary source-to-sink paths.\n"
        + "- Explore the codebase, trace data flows from sources to sinks, and identify SSRF points.\n"
        + "- Take multiple turns to build findings incrementally and write final JSON only when complete."
    )
    agent_name = "hunt-ssrf"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, HuntResult, "SSRF hunter")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
