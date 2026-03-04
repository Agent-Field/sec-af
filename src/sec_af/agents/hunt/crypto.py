from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol
from sec_af.agents._utils import extract_harness_result

from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "crypto.txt"


def should_run_crypto_hunter(recon: ReconResult) -> bool:
    return bool(recon.security_context.crypto_usage)


def _crypto_usage_context_block(recon: ReconResult) -> str:
    return json.dumps([usage.model_dump() for usage in recon.security_context.crypto_usage], indent=2)


async def run_crypto_hunter(app: HarnessCapable, repo_path: str, recon: ReconResult) -> HuntResult:
    if not should_run_crypto_hunter(recon):
        return HuntResult()

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template.replace("{{CRYPTO_USAGE_JSON}}", _crypto_usage_context_block(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Hunt strategy: crypto\n"
        + "- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916\n"
        + "- Take multiple turns to explore relevant files before finalizing findings.\n"
        + "- Write final JSON only when analysis is complete."
    )
    agent_name = "hunt-crypto"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=HuntResult, cwd=harness_cwd, project_dir=repo_path)
        parsed = extract_harness_result(result, HuntResult, "Crypto hunter")

        if not parsed.strategies_run:
            parsed.strategies_run = [HuntStrategy.CRYPTO.value]
        if parsed.total_raw == 0 and parsed.findings:
            parsed.total_raw = len(parsed.findings)
        if parsed.deduplicated_count == 0 and parsed.findings:
            parsed.deduplicated_count = len(parsed.findings)
        if parsed.chain_count == 0 and parsed.chains:
            parsed.chain_count = len(parsed.chains)
        return parsed
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
