from __future__ import annotations

from typing import Any, cast

from sec_af.agents.recon.architecture import run_architecture_mapper as _run_architecture_mapper
from sec_af.agents.recon.config_scanner import run_config_scanner as _run_config_scanner
from sec_af.agents.recon.data_flow import run_data_flow_mapper as _run_data_flow_mapper
from sec_af.agents.recon.dependencies import run_dependency_auditor as _run_dependency_auditor
from sec_af.agents.recon.security_context import run_security_context_profiler as _run_security_context_profiler
from sec_af.schemas.recon import ArchitectureMap

from . import router


@router.reasoner()
async def run_architecture_mapper(repo_path: str) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    runtime_router.note("Architecture mapper starting", tags=["recon", "architecture"])
    result = await _run_architecture_mapper(runtime_router, repo_path)
    return result.model_dump()


@router.reasoner()
async def run_dependency_auditor(repo_path: str) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    runtime_router.note("Dependency auditor starting", tags=["recon", "dependencies"])
    result = await _run_dependency_auditor(runtime_router, repo_path)
    return result.model_dump()


@router.reasoner()
async def run_config_scanner(repo_path: str) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    runtime_router.note("Config scanner starting", tags=["recon", "config"])
    result = await _run_config_scanner(runtime_router, repo_path)
    return result.model_dump()


@router.reasoner()
async def run_data_flow_mapper(repo_path: str, architecture: dict[str, Any]) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    runtime_router.note("Data flow mapper starting", tags=["recon", "data-flow"])
    architecture_model = ArchitectureMap(**architecture)
    result = await _run_data_flow_mapper(runtime_router, repo_path, architecture_model)
    return result.model_dump()


@router.reasoner()
async def run_security_context_profiler(repo_path: str, architecture: dict[str, Any]) -> dict[str, Any]:
    runtime_router = cast(Any, router)
    runtime_router.note("Security context profiler starting", tags=["recon", "security-context"])
    architecture_model = ArchitectureMap(**architecture)
    result = await _run_security_context_profiler(runtime_router, repo_path, architecture_model)
    return result.model_dump()
