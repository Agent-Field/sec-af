from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_auth
from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult

PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "auth.txt"
_TARGET_CWES = ["CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-352"]


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


def _depth_label(depth: str) -> str:
    normalized = depth.lower().strip()
    return normalized if normalized in {"quick", "standard", "thorough"} else "standard"


def _build_prompt(template: str, repo_path: str, recon_result: ReconResult, depth: str) -> str:
    return (
        template.replace("{{REPO_PATH}}", repo_path)
        .replace("{{DEPTH}}", _depth_label(depth))
        .replace("{{TARGET_CWES}}", ", ".join(_TARGET_CWES))
        .replace("{{RECON_CONTEXT}}", recon_context_for_auth(recon_result))
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon_result))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon_result))
    )


async def run_auth_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
    max_files_without_signal: int = 30,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    depth_label = _depth_label(depth)
    prompt = (
        _build_prompt(prompt_template, repo_path, recon_result, depth_label)
        + "\n\nEXECUTION CONSTRAINTS:\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible auth issues, "
        + "stop and return empty findings.\n"
    )
    agent_name = "hunt-auth"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=HuntResult,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        parsed = extract_harness_result(result, HuntResult, "Auth hunter")

        return HuntResult(
            findings=parsed.findings,
            total_raw=len(parsed.findings),
            deduplicated_count=len(parsed.findings),
            chain_count=0,
            strategies_run=[HuntStrategy.AUTH.value],
        )
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
