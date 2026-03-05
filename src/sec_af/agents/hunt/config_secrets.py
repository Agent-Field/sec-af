from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_config_secrets
from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "config_secrets.txt"


async def run_config_secrets_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context_for_config_secrets(recon))
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + f"- Hunt strategy: {HuntStrategy.CONFIG_SECRETS.value} (CWE-798, CWE-259, CWE-321, CWE-16).\n"
        + "- Early stop rule: if you inspect "
        + f"{max_files_without_signal} files without credible secrets/config issues, "
        + "stop and return empty findings.\n"
        + "- Use RECON ConfigReport and SecurityContext to prioritize likely real findings.\n"
        + "- Take multiple turns: inspect files, validate exploitability signal, then build findings.\n"
    )
    agent_name = "hunt-config-secrets"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        parsed = extract_harness_result(result, HuntResult, "Config/Secrets hunter")
        if not parsed.strategies_run:
            parsed.strategies_run = [HuntStrategy.CONFIG_SECRETS.value]
        if parsed.total_raw <= 0:
            parsed.total_raw = len(parsed.findings)
        if parsed.deduplicated_count <= 0:
            parsed.deduplicated_count = len(parsed.findings)
        if parsed.chain_count <= 0:
            parsed.chain_count = len(parsed.chains)
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
