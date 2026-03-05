from __future__ import annotations

import asyncio
import importlib
import time
from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, Protocol, cast

from sec_af.config import DepthProfile
from sec_af.schemas.hunt import HuntResult, HuntStrategy, RawFinding

from ..dedup import deduplicate_and_correlate

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


HunterRunner = Callable[..., Awaitable[object]]


def _missing_hunter(strategy: HuntStrategy) -> HunterRunner:
    async def _runner(*_args: object, **_kwargs: object) -> list[RawFinding]:
        return []

    _runner.__name__ = f"missing_{strategy.value}_hunter"
    return _runner


def _load_hunter(module_name: str, func_name: str, strategy: HuntStrategy) -> HunterRunner:
    try:
        module = importlib.import_module(module_name, package=__package__)
    except ImportError:
        return _missing_hunter(strategy)
    func = getattr(module, func_name, None)
    if callable(func):
        return cast("HunterRunner", func)
    return _missing_hunter(strategy)


_STRATEGY_RUNNERS: dict[HuntStrategy, HunterRunner] = {
    HuntStrategy.INJECTION: _load_hunter(".injection", "run_injection_hunter", HuntStrategy.INJECTION),
    HuntStrategy.AUTH: _load_hunter(".auth", "run_auth_hunter", HuntStrategy.AUTH),
    HuntStrategy.CRYPTO: _load_hunter(".crypto", "run_crypto_hunter", HuntStrategy.CRYPTO),
    HuntStrategy.LOGIC_BUGS: _load_hunter(".logic", "run_logic_hunter", HuntStrategy.LOGIC_BUGS),
    HuntStrategy.DATA_EXPOSURE: _load_hunter(".data_exposure", "run_data_exposure_hunter", HuntStrategy.DATA_EXPOSURE),
    HuntStrategy.SUPPLY_CHAIN: _load_hunter(".supply_chain", "run_supply_chain_hunter", HuntStrategy.SUPPLY_CHAIN),
    HuntStrategy.CONFIG_SECRETS: _load_hunter(
        ".config_secrets", "run_config_secrets_hunter", HuntStrategy.CONFIG_SECRETS
    ),
    HuntStrategy.API_SECURITY: _load_hunter(".api_security", "run_api_security_hunter", HuntStrategy.API_SECURITY),
}

_QUICK_STRATEGIES: tuple[HuntStrategy, ...] = (
    HuntStrategy.INJECTION,
    HuntStrategy.AUTH,
    HuntStrategy.DATA_EXPOSURE,
)


def _normalize_depth(depth: str) -> DepthProfile:
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def _select_strategies(depth: DepthProfile) -> list[HuntStrategy]:
    if depth == DepthProfile.QUICK:
        return list(_QUICK_STRATEGIES)
    return list(_STRATEGY_RUNNERS)


def _extract_findings(payload: object) -> list[RawFinding]:
    if isinstance(payload, HuntResult):
        return payload.findings
    if isinstance(payload, list):
        payload_items = cast("list[object]", payload)
        return [item for item in payload_items if isinstance(item, RawFinding)]

    parsed = getattr(payload, "parsed", None)
    if isinstance(parsed, HuntResult):
        return parsed.findings
    if isinstance(parsed, list):
        parsed_items = cast("list[object]", parsed)
        return [item for item in parsed_items if isinstance(item, RawFinding)]

    candidates_obj = getattr(payload, "findings", None)
    if isinstance(candidates_obj, list):
        candidates = cast("list[object]", candidates_obj)
        return [item for item in candidates if isinstance(item, RawFinding)]

    return []


async def _run_single_hunter(
    runner: HunterRunner,
    *,
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: DepthProfile,
    early_stop_file_threshold: int,
) -> list[RawFinding]:
    depth_prompt = (
        "Use deep, multi-turn analysis. Trace cross-file flows and hunt secondary pivots."
        if depth == DepthProfile.THOROUGH
        else ""
    )

    try:
        result = await runner(
            app=app,
            repo_path=repo_path,
            recon_result=recon_result,
            depth=depth.value,
            depth_prompt=depth_prompt,
            max_files_without_signal=early_stop_file_threshold,
        )
    except TypeError:
        try:
            result = await runner(
                app=app,
                repo_path=repo_path,
                recon_result=recon_result,
                depth=depth.value,
            )
        except TypeError:
            try:
                result = await runner(
                    app=app,
                    repo_path=repo_path,
                    recon_result=recon_result,
                    max_files_without_signal=early_stop_file_threshold,
                )
            except TypeError:
                try:
                    result = await runner(app, repo_path, recon_result, depth.value)
                except TypeError:
                    result = await runner(app, repo_path, recon_result)

    return _extract_findings(result)


async def run_hunt(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
    max_concurrent_hunters: int = 4,
    early_stop_file_threshold: int = 30,
) -> HuntResult:
    started = time.monotonic()
    profile = _normalize_depth(depth)
    strategies = _select_strategies(profile)

    concurrency_limit = max(1, min(max_concurrent_hunters, len(strategies)))
    semaphore = asyncio.Semaphore(concurrency_limit)

    async def _run_strategy(strategy: HuntStrategy) -> list[RawFinding]:
        async with semaphore:
            return await _run_single_hunter(
                _STRATEGY_RUNNERS[strategy],
                app=app,
                repo_path=repo_path,
                recon_result=recon_result,
                depth=profile,
                early_stop_file_threshold=early_stop_file_threshold,
            )

    hunter_tasks = [_run_strategy(strategy) for strategy in strategies]
    hunter_results = await asyncio.gather(*hunter_tasks, return_exceptions=True)

    all_findings: list[RawFinding] = []
    for result in hunter_results:
        if isinstance(result, Exception):
            continue
        if isinstance(result, list):
            all_findings.extend(result)

    deduplicated = await deduplicate_and_correlate(all_findings, recon_result, app, repo_path)
    deduplicated.total_raw = len(all_findings)
    deduplicated.deduplicated_count = len(deduplicated.findings)
    deduplicated.chain_count = len(deduplicated.chains)
    deduplicated.strategies_run = [strategy.value for strategy in strategies]
    deduplicated.hunt_duration_seconds = time.monotonic() - started
    return deduplicated


__all__ = ["run_hunt"]
