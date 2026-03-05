from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_crypto
from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "crypto.txt"

_SECURITY_CRITICAL_TERMS = (
    "password",
    "passwd",
    "credential",
    "auth",
    "token",
    "session",
    "encrypt",
    "decrypt",
    "signature",
    "sign",
    "verify",
    "jwt",
    "tls",
    "ssl",
    "key",
)

_NON_SECURITY_TERMS = (
    "checksum",
    "etag",
    "cache",
    "fingerprint",
    "dedup",
    "integrity",
)


def _usage_contexts(recon: ReconResult) -> list[str]:
    return [usage.usage_context for usage in recon.security_context.crypto_usage if usage.usage_context]


def _filter_contexts_by_terms(contexts: list[str], terms: tuple[str, ...]) -> list[str]:
    filtered: list[str] = []
    for context in contexts:
        lowered = context.lower()
        if any(term in lowered for term in terms):
            filtered.append(context)
    return filtered


def should_run_crypto_hunter(recon: ReconResult) -> bool:
    return bool(recon.security_context.crypto_usage)


async def run_crypto_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon: ReconResult,
    max_files_without_signal: int = 30,
) -> HuntResult:
    if not should_run_crypto_hunter(recon):
        return HuntResult()

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    usage_contexts = _usage_contexts(recon)
    security_critical_candidates = _filter_contexts_by_terms(usage_contexts, _SECURITY_CRITICAL_TERMS)
    non_security_candidates = _filter_contexts_by_terms(usage_contexts, _NON_SECURITY_TERMS)
    prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context_for_crypto(recon))
        .replace("{{LANGUAGE_HINTS}}", language_hints_for_context(recon))
        .replace("{{FRAMEWORK_HINTS}}", framework_hints_for_context(recon))
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Hunt strategy: crypto\n"
        + f"- Early stop rule: if you inspect {max_files_without_signal} files without credible crypto misuse, stop and return empty findings.\n"
        + "- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916, CWE-259, CWE-321, CWE-798\n"
        + "- Security-critical usage candidates: "
        + (", ".join(security_critical_candidates) if security_critical_candidates else "none")
        + "\n"
        + "- Non-security usage candidates: "
        + (", ".join(non_security_candidates) if non_security_candidates else "none")
        + "\n"
        + "- Prioritize weak crypto findings only when used in security-sensitive contexts; avoid checksum/cache-only noise.\n"
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
