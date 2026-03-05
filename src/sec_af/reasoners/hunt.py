from __future__ import annotations

from typing import Any

from sec_af.agents.dedup import deduplicate_and_correlate as _deduplicate_and_correlate
from sec_af.agents.hunt.api_security import run_api_security_hunter as _run_api_security_hunter
from sec_af.agents.hunt.auth import run_auth_hunter as _run_auth_hunter
from sec_af.agents.hunt.config_secrets import run_config_secrets_hunter as _run_config_secrets_hunter
from sec_af.agents.hunt.crypto import run_crypto_hunter as _run_crypto_hunter
from sec_af.agents.hunt.data_exposure import run_data_exposure_hunter as _run_data_exposure_hunter
from sec_af.agents.hunt.injection import run_injection_hunter as _run_injection_hunter
from sec_af.agents.hunt.logic import run_logic_hunter as _run_logic_hunter
from sec_af.agents.hunt.supply_chain import run_supply_chain_hunter as _run_supply_chain_hunter
from sec_af.schemas.hunt import RawFinding
from sec_af.schemas.recon import ReconResult

from . import router

_runtime_router: Any = router


def _recon_model(recon_context: dict[str, Any]) -> ReconResult:
    return ReconResult(**recon_context)


async def _run_hunter(
    runner: Any,
    *,
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    recon_model = _recon_model(recon_context)
    runtime_router = _runtime_router
    try:
        result = await runner(
            app=runtime_router,
            repo_path=repo_path,
            recon_result=recon_model,
            depth=depth,
            max_files_without_signal=max_files_without_signal,
        )
    except TypeError:
        try:
            result = await runner(
                app=runtime_router,
                repo_path=repo_path,
                recon=recon_model,
                depth=depth,
                max_files_without_signal=max_files_without_signal,
            )
        except TypeError:
            try:
                result = await runner(app=runtime_router, repo_path=repo_path, recon=recon_model)
            except TypeError:
                result = await runner(runtime_router, repo_path, recon_model, depth)
    return result.model_dump()


@router.reasoner()
async def run_injection_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Injection hunter starting", tags=["hunt", "injection"])
    return await _run_hunter(
        _run_injection_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_auth_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Auth hunter starting", tags=["hunt", "auth"])
    return await _run_hunter(
        _run_auth_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_crypto_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Crypto hunter starting", tags=["hunt", "crypto"])
    return await _run_hunter(
        _run_crypto_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_logic_bugs_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Logic bugs hunter starting", tags=["hunt", "logic-bugs"])
    return await _run_hunter(
        _run_logic_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_data_exposure_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Data exposure hunter starting", tags=["hunt", "data-exposure"])
    return await _run_hunter(
        _run_data_exposure_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_supply_chain_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Supply chain hunter starting", tags=["hunt", "supply-chain"])
    return await _run_hunter(
        _run_supply_chain_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_config_secrets_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("Config secrets hunter starting", tags=["hunt", "config-secrets"])
    return await _run_hunter(
        _run_config_secrets_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_api_security_hunter(
    repo_path: str,
    recon_context: dict[str, Any],
    depth: str,
    max_files_without_signal: int = 30,
) -> dict[str, Any]:
    _runtime_router.note("API security hunter starting", tags=["hunt", "api-security"])
    return await _run_hunter(
        _run_api_security_hunter,
        repo_path=repo_path,
        recon_context=recon_context,
        depth=depth,
        max_files_without_signal=max_files_without_signal,
    )


@router.reasoner()
async def run_deduplicator(
    findings: list[dict[str, Any]],
    recon_context: dict[str, Any],
    repo_path: str,
) -> dict[str, Any]:
    _runtime_router.note("Deduplicator starting", tags=["hunt", "dedup"])
    raw_findings = [RawFinding(**f) for f in findings]
    recon = ReconResult(**recon_context)
    result = await _deduplicate_and_correlate(raw_findings, recon, _runtime_router, repo_path)
    return result.model_dump()
