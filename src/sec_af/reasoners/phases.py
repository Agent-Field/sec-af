from __future__ import annotations

import asyncio
import os
from typing import Any, cast

from sec_af.agents.prove.verifier import fallback as verifier_fallback
from sec_af.schemas.hunt import (
    Confidence,
    HuntResult,
    HuntStrategy,
    RawFinding,
    Severity,
)
from sec_af.schemas.prove import VerifiedFinding
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
        HuntStrategy.AUTH,
        HuntStrategy.DATA_EXPOSURE,
        HuntStrategy.CONFIG_SECRETS,
    ]
    if recon.security_context.crypto_usage:
        strategies.append(HuntStrategy.CRYPTO)
    if recon.dependencies.direct_count > 0:
        strategies.append(HuntStrategy.SUPPLY_CHAIN)
    if recon.architecture.api_surface:
        strategies.append(HuntStrategy.API_SECURITY)

    profile = _normalize_depth(depth)
    if profile in {DepthProfile.STANDARD, DepthProfile.THOROUGH}:
        strategies.append(HuntStrategy.LOGIC_BUGS)

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
    max_concurrent_hunters: int = 4,
    early_stop_file_threshold: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("HUNT phase starting", tags=["phase", "hunt"])
    recon = ReconResult(**recon_context)
    strategies = _default_strategies(recon, depth)

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
    for idx, raw in enumerate(prove_results):
        if isinstance(raw, Exception):
            verified.append(verifier_fallback(selected[idx], str(raw)))
            continue
        verified.append(VerifiedFinding.model_validate(_as_dict(_unwrap(raw, "run_verifier"), "run_verifier")))

    _runtime_router.note(f"PROVE phase complete: {len(verified)} verified", tags=["phase", "prove", "done"])
    return {
        "verified": [v.model_dump() for v in verified],
        "total_selected": len(selected),
        "total_findings": len(hunt.findings),
        "not_verified": max(0, len(hunt.findings) - len(selected)),
    }
