from __future__ import annotations

from importlib import import_module
from typing import Any

from sec_af.agents.prove.dep_reachability import run_dep_reachability as _run_dep_reachability
from sec_af.agents.prove.exploit import run_exploit_hypothesizer as _run_exploit_hypothesizer
from sec_af.agents.prove.sanitization import run_sanitization_analyzer as _run_sanitization_analyzer
from sec_af.agents.prove.tracer import run_tracer as _run_tracer
from sec_af.agents.prove.verifier import run_verifier as _run_verifier
from sec_af.agents.prove.verdict import run_verdict_agent as _run_verdict_agent
from sec_af.schemas.hunt import RawFinding
from sec_af.schemas.prove import (
    DataFlowTrace,
    ExploitHypothesis,
    RemediationSuggestion,
    SanitizationResult,
    VerifiedFinding,
)

from . import router

_runtime_router: Any = router


@router.reasoner()
async def run_dep_reachability(repo_path: str, finding: dict[str, Any], depth: str) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Dependency reachability analyzer starting", tags=["prove", "dep-reachability"])
    result = await _run_dep_reachability(runtime_router, repo_path, finding, depth)
    return result.model_dump()


@router.reasoner()
async def run_verifier(repo_path: str, finding: dict[str, Any], depth: str) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Verifier starting", tags=["prove", "verifier"])
    finding_model = RawFinding(**finding)
    result = await _run_verifier(runtime_router, repo_path, finding_model, depth)
    return result.model_dump()


@router.reasoner()
async def run_tracer(repo_path: str, finding: dict[str, Any], depth: str) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Tracer starting", tags=["prove", "tracer"])
    finding_model = RawFinding(**finding)
    result = await _run_tracer(runtime_router, repo_path, finding_model, depth)
    return result.model_dump()


@router.reasoner()
async def run_sanitization_analyzer(
    repo_path: str,
    finding: dict[str, Any],
    data_flow: dict[str, Any],
    depth: str,
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Sanitization analyzer starting", tags=["prove", "sanitization"])
    finding_model = RawFinding(**finding)
    flow_model = DataFlowTrace(**data_flow)
    result = await _run_sanitization_analyzer(runtime_router, repo_path, finding_model, flow_model, depth)
    return result.model_dump()


@router.reasoner()
async def run_exploit_hypothesizer(
    repo_path: str,
    finding: dict[str, Any],
    data_flow: dict[str, Any],
    sanitization: dict[str, Any],
    depth: str,
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Exploit hypothesizer starting", tags=["prove", "exploit"])
    finding_model = RawFinding(**finding)
    flow_model = DataFlowTrace(**data_flow)
    sanitization_model = SanitizationResult(**sanitization)
    result = await _run_exploit_hypothesizer(
        runtime_router, repo_path, finding_model, flow_model, sanitization_model, depth
    )
    return result.model_dump()


@router.reasoner()
async def run_verdict_agent(
    finding: dict[str, Any],
    data_flow: dict[str, Any],
    sanitization: dict[str, Any],
    exploit: dict[str, Any],
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Verdict agent starting", tags=["prove", "verdict"])
    finding_model = RawFinding(**finding)
    flow_model = DataFlowTrace(**data_flow)
    sanitization_model = SanitizationResult(**sanitization)
    exploit_model = ExploitHypothesis(**exploit)
    result = await _run_verdict_agent(
        app=runtime_router,
        repo_path=".",
        finding=finding_model,
        data_flow=flow_model,
        sanitization=sanitization_model,
        exploit=exploit_model,
    )
    return result.model_dump()


@router.reasoner()
async def run_remediation(repo_path: str, finding: dict[str, Any]) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Remediation agent starting", tags=["prove", "remediation"])
    finding_model = VerifiedFinding(**finding)
    remediation_module = import_module("sec_af.agents.remediation")
    generate_remediation = getattr(remediation_module, "generate_remediation")
    result = await generate_remediation(runtime_router, repo_path, finding_model)
    return RemediationSuggestion.model_validate(result).model_dump()


@router.reasoner()
async def run_remediation_agent(
    repo_path: str, finding: dict[str, Any], verdict: str, rationale: str
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Remediation agent starting", tags=["prove", "remediation"])
    finding_model = RawFinding(**finding)
    from sec_af.agents.remediation import run_remediation as _run_remediation  # pyright: ignore[reportMissingImports]

    result = await _run_remediation(runtime_router, repo_path, finding_model, verdict, rationale)
    return result.model_dump()


@router.reasoner()
async def run_dast_verifier(
    repo_path: str, finding: dict[str, Any], exploit_payload: str, depth: str
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("DAST verifier starting", tags=["prove", "dast"])
    finding_model = RawFinding(**finding)
    _run_dast = import_module("sec_af.agents.prove.dast_verifier").run_dast_verifier
    result = await _run_dast(runtime_router, repo_path, finding_model, exploit_payload, depth)
    return result.model_dump()


@router.reasoner()
async def run_cross_service_analyzer(
    repo_path: str, services: list[str], findings_summary: str, depth: str
) -> dict[str, Any]:
    runtime_router = _runtime_router
    runtime_router.note("Cross-service analyzer starting", tags=["prove", "cross-service"])
    _run_cross = import_module("sec_af.agents.prove.cross_service").run_cross_service_analyzer
    result = await _run_cross(runtime_router, repo_path, services, findings_summary, depth)
    return result.model_dump()
