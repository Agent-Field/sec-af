from __future__ import annotations

import asyncio
import os
from typing import Any, cast

from sec_af.context import recon_context_generic
from sec_af.agents.prove.verifier import fallback as verifier_fallback
from sec_af.schemas.hunt import (
    Confidence,
    HuntResult,
    HuntStrategy,
    RawFinding,
    Severity,
)
from sec_af.schemas.prove import RemediationSuggestion, Verdict, VerifiedFinding
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)
from sec_af.agents.recon import _repo_metrics
from sec_af.config import DepthProfile

from . import router

_runtime_router: Any = router
NODE_ID = os.getenv("NODE_ID", "sec-af")


def _unwrap(result: object, name: str) -> object:
    if isinstance(result, dict):
        if "error" in result and isinstance(result["error"], dict):
            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
            raise RuntimeError(f"{name} failed: {message}")
        if "output" in result:
            return result["output"]
        if "result" in result:
            return result["result"]
    return result


def _as_dict(payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
    return payload


def _normalize_depth(depth: str) -> DepthProfile:
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def _recon_summary_string(recon: ReconResult) -> str:
    """Build a natural-language summary of recon context for AI strategy selection.

    Returns a focused string like:
    "Python/Django app, 5000 LOC, JWT auth, PostgreSQL, 5 direct dependencies..."
    """
    parts: list[str] = []

    # Languages and frameworks
    if recon.languages:
        lang_str = "/".join(recon.languages)
        if recon.frameworks:
            framework_str = "/".join(recon.frameworks)
            parts.append(f"{lang_str} ({framework_str})")
        else:
            parts.append(lang_str)

    # Code metrics
    if recon.lines_of_code > 0:
        parts.append(f"{recon.lines_of_code} LOC")
    if recon.file_count > 0:
        parts.append(f"{recon.file_count} files")

    # Authentication
    if recon.security_context.auth_model:
        parts.append(f"{recon.security_context.auth_model} auth")

    # Cryptography
    if recon.security_context.crypto_usage:
        parts.append(f"{len(recon.security_context.crypto_usage)} crypto algorithms")

    # Dependencies
    if recon.dependencies.direct_count > 0:
        parts.append(f"{recon.dependencies.direct_count} direct dependencies")
    if recon.dependencies.known_cves:
        parts.append(f"{len(recon.dependencies.known_cves)} known CVEs")

    # API surface
    if recon.architecture.api_surface:
        parts.append(f"{len(recon.architecture.api_surface)} API endpoints")

    # Secrets and config issues
    if recon.config.secrets:
        parts.append(f"{len(recon.config.secrets)} secrets found")
    if recon.config.misconfigs:
        parts.append(f"{len(recon.config.misconfigs)} misconfigs")

    return ", ".join(parts) if parts else "Unknown application"


async def expand_cwes_for_hunt(
    recon_summary: str,
    strategies: list[str],
) -> list[str]:
    """Use AI gate to suggest additional CWEs based on recon context."""
    from sec_af.schemas.gates import CWEExpansion

    runtime_router_local: Any = _runtime_router
    prompt = (
        "Based on this codebase recon context, suggest additional CWE IDs that hunters should look for "
        "beyond their hardcoded baselines. Only suggest CWEs that are specifically relevant to "
        "the detected languages, frameworks, and architecture patterns.\n\n"
        f"Active strategies: {', '.join(strategies)}\n\n"
        f"Recon context:\n{recon_summary}"
    )
    try:
        result = await runtime_router_local.ai(
            user=prompt,
            schema=CWEExpansion,
        )
        if isinstance(result, CWEExpansion):
            return result.additional_cwes
        if isinstance(result, dict):
            expansion = CWEExpansion(**result)
            return expansion.additional_cwes
        return []
    except Exception:
        return []  # Graceful fallback - AI expansion is additive, not critical


@router.reasoner()
async def run_cwe_expansion(
    recon_summary: str,
    strategies: list[str],
) -> dict[str, Any]:
    additional = await expand_cwes_for_hunt(recon_summary, strategies)
    return {"additional_cwes": additional}


# ---------------------------------------------------------------------------
# RECON PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def recon_phase(repo_path: str, depth: str = "standard") -> dict[str, Any]:
    _runtime_router.note("RECON phase starting", tags=["phase", "recon"])

    arch_raw, deps_raw, config_raw = await asyncio.gather(
        _runtime_router.call(f"{NODE_ID}.run_architecture_mapper", repo_path=repo_path),
        _runtime_router.call(f"{NODE_ID}.run_dependency_auditor", repo_path=repo_path),
        _runtime_router.call(f"{NODE_ID}.run_config_scanner", repo_path=repo_path),
    )

    architecture = ArchitectureMap.model_validate(
        _as_dict(_unwrap(arch_raw, "run_architecture_mapper"), "run_architecture_mapper")
    )
    dependencies = DependencyReport.model_validate(
        _as_dict(_unwrap(deps_raw, "run_dependency_auditor"), "run_dependency_auditor")
    )
    config = ConfigReport.model_validate(_as_dict(_unwrap(config_raw, "run_config_scanner"), "run_config_scanner"))

    if _normalize_depth(depth) == DepthProfile.QUICK:
        data_flows = DataFlowMap()
        security_context = SecurityContext(auth_model="unknown", auth_details="unknown")
    else:
        flow_raw, sec_raw = await asyncio.gather(
            _runtime_router.call(
                f"{NODE_ID}.run_data_flow_mapper", repo_path=repo_path, architecture=architecture.model_dump()
            ),
            _runtime_router.call(
                f"{NODE_ID}.run_security_context_profiler", repo_path=repo_path, architecture=architecture.model_dump()
            ),
        )
        data_flows = DataFlowMap.model_validate(
            _as_dict(_unwrap(flow_raw, "run_data_flow_mapper"), "run_data_flow_mapper")
        )
        security_context = SecurityContext.model_validate(
            _as_dict(_unwrap(sec_raw, "run_security_context_profiler"), "run_security_context_profiler")
        )

    languages = sorted({m.language.lower() for m in architecture.modules if getattr(m, "language", None)})
    frameworks = sorted({item for item in security_context.framework_security if item})
    lines_of_code, file_count = _repo_metrics(repo_path)

    recon = ReconResult(
        architecture=architecture,
        data_flows=data_flows,
        dependencies=dependencies,
        config=config,
        security_context=security_context,
        languages=languages,
        frameworks=frameworks,
        lines_of_code=lines_of_code,
        file_count=file_count,
    )
    _runtime_router.note("RECON phase complete", tags=["phase", "recon", "done"])
    return recon.model_dump()


# ---------------------------------------------------------------------------
# HUNT PHASE
# ---------------------------------------------------------------------------


def _default_strategies(recon: ReconResult, depth: str) -> list[HuntStrategy]:
    strategies: list[HuntStrategy] = [
        HuntStrategy.INJECTION,
        HuntStrategy.DOS,
        HuntStrategy.SSRF,
        HuntStrategy.AUTH,
        HuntStrategy.DATA_EXPOSURE,
        HuntStrategy.CONFIG_SECRETS,
    ]
    profile = _normalize_depth(depth)
    if profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}:
        strategies.append(HuntStrategy.XSS)
    if recon.security_context.crypto_usage:
        strategies.append(HuntStrategy.CRYPTO)
    if recon.dependencies.direct_count > 0:
        strategies.append(HuntStrategy.SUPPLY_CHAIN)
    if recon.architecture.api_surface:
        strategies.append(HuntStrategy.API_SECURITY)

    if profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}:
        strategies.append(HuntStrategy.BUSINESS_LOGIC)

    ordered: list[HuntStrategy] = []
    for s in strategies:
        if s not in ordered:
            ordered.append(s)
    return ordered


@router.reasoner()
async def hunt_phase(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str = "standard",
    ai_gate: Any | None = None,
    max_concurrent_hunters: int = 4,
    early_stop_file_threshold: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("HUNT phase starting", tags=["phase", "hunt"])
    recon = ReconResult(**recon_context)

    default_candidates = _default_strategies(recon, depth)
    default_strategy_names = [s.value for s in default_candidates]

    strategies = default_candidates
    if ai_gate is not None:
        try:
            recon_summary = _recon_summary_string(recon)
            selection = await ai_gate.select_strategy(
                recon_summary=recon_summary,
                depth=depth,
                default_candidates=default_strategy_names,
            )
            selected_names = selection.strategies
            strategy_map = {s.value: s for s in default_candidates}
            strategies = [strategy_map[name] for name in selected_names if name in strategy_map]
            if not strategies:
                strategies = default_candidates
                _runtime_router.note("AI gate returned no valid strategies, using defaults", tags=["hunt", "ai_gate"])
        except Exception as e:
            _runtime_router.note(f"AI gate failed: {e}, using default strategies", tags=["hunt", "ai_gate", "error"])
            strategies = default_candidates

    recon_summary = recon_context_generic(recon)
    additional_cwes = await expand_cwes_for_hunt(recon_summary, [s.value for s in strategies])
    if additional_cwes:
        _runtime_router.note(
            f"CWE expansion suggested {len(additional_cwes)} additional CWEs",
            tags=["hunt", "ai_gate", "cwe_expansion"],
        )

    concurrency_limit = max(1, min(max_concurrent_hunters, len(strategies)))
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _run_strategy(strategy: HuntStrategy) -> object:
        async with semaphore:
            return await _runtime_router.call(
                f"{NODE_ID}.run_{strategy.value}_hunter",
                repo_path=repo_path,
                recon_context=recon_context,
                depth=depth,
                max_files_without_signal=early_stop_file_threshold,
            )

    hunt_calls = [_run_strategy(strategy) for strategy in strategies]
    hunt_results = await asyncio.gather(*hunt_calls, return_exceptions=True)

    all_findings: list[RawFinding] = []
    for idx, raw in enumerate(hunt_results):
        if isinstance(raw, Exception):
            _runtime_router.note(f"Hunt strategy failed: {strategies[idx].value}: {raw}", tags=["hunt", "error"])
            continue
        payload = HuntResult.model_validate(
            _as_dict(_unwrap(raw, f"run_{strategies[idx].value}_hunter"), f"run_{strategies[idx].value}_hunter")
        )
        all_findings.extend(payload.findings)

    _runtime_router.note(f"HUNT found {len(all_findings)} raw findings, deduplicating", tags=["hunt", "dedup"])
    dedup_raw = await _runtime_router.call(
        f"{NODE_ID}.run_deduplicator",
        findings=[f.model_dump() for f in all_findings],
        recon_context=recon_context,
        repo_path=repo_path,
    )
    dedup = HuntResult.model_validate(_as_dict(_unwrap(dedup_raw, "run_deduplicator"), "run_deduplicator"))
    dedup.strategies_run = [s.value for s in strategies]

    _runtime_router.note("HUNT phase complete", tags=["phase", "hunt", "done"])
    return dedup.model_dump()


# ---------------------------------------------------------------------------
# PROVE PHASE
# ---------------------------------------------------------------------------


def _prioritize_findings(findings: list[RawFinding]) -> list[RawFinding]:
    sev = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
    conf = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
    return sorted(findings, key=lambda f: (sev.get(f.estimated_severity, 0), conf.get(f.confidence, 0)), reverse=True)


def _prover_cap(depth: str, max_provers: int | None) -> int:
    defaults = {DepthProfile.QUICK: 10, DepthProfile.STANDARD: 30, DepthProfile.THOROUGH: 10_000}
    cap = defaults[_normalize_depth(depth)]
    return max(0, min(max_provers, cap)) if max_provers is not None else cap


def _track_drop(
    *,
    summary: dict[str, Any],
    finding_title: str,
    original_verdict: str | None,
    reason: str,
) -> None:
    summary["demoted_total"] = int(summary.get("demoted_total", 0)) + 1
    by_reason = cast("dict[str, int]", summary.setdefault("by_reason", {}))
    by_reason[reason] = by_reason.get(reason, 0) + 1
    findings = cast("list[dict[str, str | None]]", summary.setdefault("findings", []))
    findings.append(
        {
            "title": finding_title,
            "original_verdict": original_verdict,
            "reason": reason,
        }
    )
    _runtime_router.note(
        f"Demoted finding '{finding_title}' (verdict={original_verdict or 'unknown'}): {reason}",
        tags=["prove", "drop", "demotion"],
    )


@router.reasoner()
async def prove_phase(
    repo_path: str,
    hunt_result: dict[str, Any],
    depth: str = "standard",
    max_provers: int | None = None,
    max_concurrent_provers: int = 3,
) -> dict[str, Any]:
    _runtime_router.note("PROVE phase starting", tags=["phase", "prove"])
    hunt = HuntResult.model_validate(hunt_result)

    prioritized = _prioritize_findings(hunt.findings)
    cap = _prover_cap(depth, max_provers)
    selected = prioritized[:cap]

    concurrency_limit = max(1, min(max_concurrent_provers, len(selected))) if selected else 1
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _run_verifier(finding: RawFinding) -> object:
        async with semaphore:
            return await _runtime_router.call(
                f"{NODE_ID}.run_verifier",
                repo_path=repo_path,
                finding=finding.model_dump(),
                depth=depth,
            )

    verify_calls = [_run_verifier(finding) for finding in selected]
    prove_results = await asyncio.gather(*verify_calls, return_exceptions=True)

    verified: list[VerifiedFinding] = []
    drop_summary: dict[str, Any] = {"demoted_total": 0, "by_reason": {}, "findings": []}
    for idx, raw in enumerate(prove_results):
        finding = selected[idx]
        if isinstance(raw, Exception):
            _track_drop(
                summary=drop_summary,
                finding_title=finding.title,
                original_verdict=None,
                reason="verifier_error",
            )
            verified.append(verifier_fallback(finding, str(raw), drop_reason="verifier_error"))
            continue
        try:
            payload = _as_dict(_unwrap(raw, "run_verifier"), "run_verifier")
        except Exception as exc:
            _track_drop(
                summary=drop_summary,
                finding_title=finding.title,
                original_verdict=None,
                reason="schema_parse_failure",
            )
            verified.append(
                verifier_fallback(
                    finding,
                    f"Schema parse failed: {exc}",
                    drop_reason="schema_parse_failure",
                )
            )
            continue

        verdict_value = payload.get("verdict")
        if isinstance(verdict_value, str) and verdict_value.lower() == "unverified":
            _track_drop(
                summary=drop_summary,
                finding_title=finding.title,
                original_verdict=verdict_value,
                reason="verdict_unverified",
            )
            verified.append(
                verifier_fallback(
                    finding,
                    "Verifier returned unverified verdict; demoted for manual review",
                    drop_reason="verdict_unverified",
                    original_verdict=verdict_value,
                )
            )
            continue

        try:
            verified.append(VerifiedFinding.model_validate(payload))
        except Exception as exc:
            original_verdict = str(verdict_value) if verdict_value is not None else None
            _track_drop(
                summary=drop_summary,
                finding_title=finding.title,
                original_verdict=original_verdict,
                reason="schema_parse_failure",
            )
            verified.append(
                verifier_fallback(
                    finding,
                    f"Schema parse failed: {exc}",
                    drop_reason="schema_parse_failure",
                    original_verdict=original_verdict,
                )
            )

    _runtime_router.note(f"PROVE phase complete: {len(verified)} verified", tags=["phase", "prove", "done"])
    return {
        "verified": [v.model_dump() for v in verified],
        "total_selected": len(selected),
        "total_findings": len(hunt.findings),
        "not_verified": max(0, len(hunt.findings) - len(selected)),
        "drop_summary": drop_summary,
    }


# ---------------------------------------------------------------------------
# REMEDIATION PHASE
# ---------------------------------------------------------------------------


@router.reasoner()
async def remediation_phase(
    repo_path: str,
    verified_findings: list[dict[str, Any]],
    max_concurrent_remediations: int = 3,
) -> dict[str, Any]:
    """Run remediation for confirmed/likely findings in parallel via app.call()."""
    _runtime_router.note("REMEDIATION phase starting", tags=["phase", "remediation"])

    findings = [VerifiedFinding.model_validate(v) for v in verified_findings]
    needs_remediation = [
        (idx, f)
        for idx, f in enumerate(findings)
        if f.verdict in {Verdict.CONFIRMED, Verdict.LIKELY} and f.remediation is None
    ]

    if not needs_remediation:
        _runtime_router.note("No findings need remediation", tags=["phase", "remediation", "done"])
        return {"verified": [f.model_dump() for f in findings]}

    semaphore = asyncio.Semaphore(max(1, min(max_concurrent_remediations, len(needs_remediation))))

    async def _call_remediation(idx: int, finding: VerifiedFinding) -> tuple[int, dict[str, Any] | None]:
        async with semaphore:
            try:
                raw = await _runtime_router.call(
                    f"{NODE_ID}.run_remediation",
                    repo_path=repo_path,
                    finding=finding.model_dump(),
                )
                payload = _as_dict(_unwrap(raw, "run_remediation"), "run_remediation")
                return (idx, payload)
            except Exception:
                return (idx, None)

    results = await asyncio.gather(*[_call_remediation(idx, f) for idx, f in needs_remediation])

    generated = 0
    for idx, payload in results:
        if payload is not None:
            try:
                findings[idx].remediation = RemediationSuggestion.model_validate(payload)
                generated += 1
            except Exception:
                pass

    _runtime_router.note(
        f"REMEDIATION phase complete: {generated}/{len(needs_remediation)} generated",
        tags=["phase", "remediation", "done"],
    )
    return {"verified": [f.model_dump() for f in findings]}
