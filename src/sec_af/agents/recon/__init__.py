from __future__ import annotations

import asyncio
import time
from pathlib import Path
from typing import Protocol

from sec_af.config import DepthProfile
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)

from .architecture import run_architecture_mapper
from .config_scanner import run_config_scanner
from .data_flow import run_data_flow_mapper
from .dependencies import run_dependency_auditor
from .security_context import run_security_context_profiler

_SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", "vendor", ".venv", "venv", "__pycache__"}
_CODE_EXTS = {
    ".py",
    ".go",
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".java",
    ".kt",
    ".swift",
    ".rs",
    ".c",
    ".cc",
    ".cpp",
    ".h",
    ".hpp",
    ".cs",
    ".rb",
    ".php",
    ".scala",
    ".sql",
    ".sh",
    ".yaml",
    ".yml",
    ".json",
    ".toml",
}


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


def _normalize_depth(depth: str) -> DepthProfile:
    try:
        return DepthProfile(depth.lower())
    except ValueError:
        return DepthProfile.STANDARD


def _repo_metrics(repo_path: str) -> tuple[int, int]:
    root = Path(repo_path)
    if not root.exists():
        return 0, 0

    file_count = 0
    line_count = 0
    for path in root.rglob("*"):
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        if not path.is_file():
            continue
        file_count += 1
        if path.suffix.lower() not in _CODE_EXTS:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                for _ in handle:
                    line_count += 1
        except OSError:
            continue
    return line_count, file_count


def _quick_defaults() -> tuple[DataFlowMap, SecurityContext]:
    return DataFlowMap(), SecurityContext(auth_model="unknown", auth_details="unknown")


async def run_recon(app: HarnessCapable, repo_path: str, depth: str) -> ReconResult:
    started = time.monotonic()
    profile = _normalize_depth(depth)

    architecture, dependencies, config = await asyncio.gather(
        run_architecture_mapper(app, repo_path),
        run_dependency_auditor(app, repo_path),
        run_config_scanner(app, repo_path),
    )

    data_flows: DataFlowMap
    security_context: SecurityContext
    if profile == DepthProfile.QUICK:
        data_flows, security_context = _quick_defaults()
    else:
        data_flows, security_context = await asyncio.gather(
            run_data_flow_mapper(app, repo_path, architecture),
            run_security_context_profiler(app, repo_path, architecture),
        )

    languages = sorted(
        {module.language.lower() for module in architecture.modules if getattr(module, "language", None)}
    )
    frameworks = sorted({item for item in security_context.framework_security if item})
    lines_of_code, file_count = _repo_metrics(repo_path)

    return ReconResult(
        architecture=architecture,
        data_flows=data_flows,
        dependencies=dependencies,
        config=config,
        security_context=security_context,
        languages=languages,
        frameworks=frameworks,
        lines_of_code=lines_of_code,
        file_count=file_count,
        recon_duration_seconds=time.monotonic() - started,
    )


__all__ = [
    "run_recon",
    "run_architecture_mapper",
    "run_data_flow_mapper",
    "run_dependency_auditor",
    "run_config_scanner",
    "run_security_context_profiler",
    "ArchitectureMap",
    "DataFlowMap",
    "DependencyReport",
    "ConfigReport",
    "SecurityContext",
    "ReconResult",
]
