from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.context import framework_hints_for_context, language_hints_for_context, recon_context_for_crypto
from sec_af.schemas.hunt import HuntResult, HuntStrategy

from ._scan_enrich import assemble_finding, enrich_locations_parallel, scan_locations

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

    recon_context = recon_context_for_crypto(recon)
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    usage_contexts = _usage_contexts(recon)
    security_critical_candidates = _filter_contexts_by_terms(usage_contexts, _SECURITY_CRITICAL_TERMS)
    non_security_candidates = _filter_contexts_by_terms(usage_contexts, _NON_SECURITY_TERMS)
    scan_prompt = (
        prompt_template.replace("{{RECON_CONTEXT}}", recon_context)
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

    locations = await scan_locations(app=app, prompt=scan_prompt, repo_path=repo_path)
    if not locations:
        return HuntResult(strategies_run=[HuntStrategy.CRYPTO.value])

    enriched_findings = await enrich_locations_parallel(
        app=app,
        locations=locations,
        finding_type="sast",
        strategy=HuntStrategy.CRYPTO.value,
        recon_context=recon_context,
        repo_path=repo_path,
    )
    findings = [
        assemble_finding(
            location=location,
            enriched=enriched,
            finding_type="sast",
            strategy=HuntStrategy.CRYPTO.value,
        )
        for location, enriched in zip(locations, enriched_findings)
    ]
    return HuntResult(
        findings=findings,
        total_raw=len(findings),
        deduplicated_count=len(findings),
        chain_count=0,
        strategies_run=[HuntStrategy.CRYPTO.value],
    )
