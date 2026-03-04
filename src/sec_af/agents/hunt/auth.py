from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, cast, runtime_checkable

from sec_af.schemas.hunt import HuntResult, HuntStrategy

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult

PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "hunt" / "auth.txt"
_AUTH_HINT_KEYWORDS = (
    "auth",
    "jwt",
    "session",
    "middleware",
    "guard",
    "csrf",
    "role",
    "permission",
    "rbac",
    "scope",
)
_TARGET_CWES = ["CWE-287", "CWE-306", "CWE-862", "CWE-863", "CWE-352"]
_MAX_TURNS_BY_DEPTH = {
    "quick": 6,
    "standard": 10,
    "thorough": 14,
}


@runtime_checkable
class HarnessResultLike(Protocol):
    parsed: object | None


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


def _extract_parsed(result: object, schema: type[HuntResult]) -> HuntResult:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Auth hunter did not return valid findings")


def _depth_label(depth: str) -> str:
    normalized = depth.lower().strip()
    return normalized if normalized in _MAX_TURNS_BY_DEPTH else "standard"


def _keyword_match(value: str) -> bool:
    lowered = value.lower()
    return any(keyword in lowered for keyword in _AUTH_HINT_KEYWORDS)


def _auth_hints(recon_result: ReconResult) -> dict[str, list[str]]:
    middleware_hints: set[str] = set()
    session_hints: set[str] = set()
    rbac_hints: set[str] = set()

    for module in recon_result.architecture.modules:
        candidates = [module.name, module.path, module.description or "", *module.dependencies]
        if any(_keyword_match(item) for item in candidates if item):
            middleware_hints.add(f"module:{module.path}")

    for endpoint in recon_result.architecture.api_surface:
        candidate = " ".join([endpoint.path, endpoint.handler, endpoint.file_path]).lower()
        if any(token in candidate for token in ("auth", "login", "token", "session", "guard", "middleware")):
            middleware_hints.add(f"endpoint:{endpoint.method} {endpoint.path} -> {endpoint.handler}")
        if any(token in candidate for token in ("role", "permission", "admin", "scope")):
            rbac_hints.add(f"endpoint:{endpoint.method} {endpoint.path} -> {endpoint.handler}")

    auth_details = recon_result.security_context.auth_details
    if auth_details:
        lowered = auth_details.lower()
        if any(token in lowered for token in ("session", "cookie", "csrf", "samesite")):
            session_hints.add(auth_details)
        if any(token in lowered for token in ("role", "permission", "rbac", "scope", "acl")):
            rbac_hints.add(auth_details)
        if _keyword_match(lowered):
            middleware_hints.add(auth_details)

    for header in recon_result.security_context.security_headers:
        if "csrf" in header.lower() or "samesite" in header.lower():
            session_hints.add(f"header:{header}")

    for misconfig in recon_result.config.misconfigs:
        row = " ".join(
            [
                misconfig.category,
                misconfig.file_path,
                misconfig.key or "",
                misconfig.value or "",
                misconfig.risk,
            ]
        ).lower()
        if any(token in row for token in ("session", "csrf", "cookie", "samesite")):
            session_hints.add(f"config:{misconfig.file_path}:{misconfig.line or 0}")
        if any(token in row for token in ("role", "permission", "rbac", "acl", "scope")):
            rbac_hints.add(f"config:{misconfig.file_path}:{misconfig.line or 0}")

    for flow in recon_result.data_flows.flows:
        flow_text = " ".join([flow.source, flow.sink, *flow.files]).lower()
        if any(token in flow_text for token in ("session", "cookie", "csrf", "token", "jwt")):
            session_hints.add(f"flow:{flow.source}->{flow.sink}")
        if any(token in flow_text for token in ("role", "permission", "scope", "account", "user_id")):
            rbac_hints.add(f"flow:{flow.source}->{flow.sink}")

    return {
        "middleware": sorted(middleware_hints),
        "session": sorted(session_hints),
        "rbac": sorted(rbac_hints),
    }


def _build_prompt(template: str, repo_path: str, recon_result: ReconResult, depth: str) -> str:
    hints = _auth_hints(recon_result)
    entry_points = [entry.model_dump() for entry in recon_result.architecture.entry_points]
    api_surface = [endpoint.model_dump() for endpoint in recon_result.architecture.api_surface]
    return (
        template.replace("{{REPO_PATH}}", repo_path)
        .replace("{{DEPTH}}", _depth_label(depth))
        .replace("{{TARGET_CWES}}", ", ".join(_TARGET_CWES))
        .replace("{{AUTH_MODEL}}", recon_result.security_context.auth_model)
        .replace("{{AUTH_DETAILS}}", recon_result.security_context.auth_details)
        .replace("{{AUTH_MIDDLEWARE_HINTS_JSON}}", json.dumps(hints["middleware"], indent=2))
        .replace("{{SESSION_HINTS_JSON}}", json.dumps(hints["session"], indent=2))
        .replace("{{RBAC_HINTS_JSON}}", json.dumps(hints["rbac"], indent=2))
        .replace("{{ENTRY_POINTS_JSON}}", json.dumps(entry_points, indent=2))
        .replace("{{API_SURFACE_JSON}}", json.dumps(api_surface, indent=2))
        .replace(
            "{{SECURITY_CONTEXT_JSON}}",
            json.dumps(recon_result.security_context.model_dump(), indent=2),
        )
        .replace("{{RECON_RESULT_JSON}}", json.dumps(recon_result.model_dump(), indent=2))
    )


async def run_auth_hunter(
    app: HarnessCapable,
    repo_path: str,
    recon_result: ReconResult,
    depth: str,
) -> HuntResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    depth_label = _depth_label(depth)
    prompt = _build_prompt(prompt_template, repo_path, recon_result, depth_label)

    result = await app.harness(
        prompt=prompt, schema=HuntResult, cwd=repo_path, max_turns=_MAX_TURNS_BY_DEPTH[depth_label]
    )
    parsed = _extract_parsed(result, HuntResult)

    return HuntResult(
        findings=parsed.findings,
        total_raw=len(parsed.findings),
        deduplicated_count=len(parsed.findings),
        chain_count=0,
        strategies_run=[HuntStrategy.AUTH.value],
    )
