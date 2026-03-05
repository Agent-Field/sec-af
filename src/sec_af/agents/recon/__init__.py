from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping
from pathlib import Path
from typing import Protocol, cast

from sec_af.config import DepthProfile
from sec_af.schemas.hunt import Confidence, FindingType, RawFinding, Severity
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


def _safe_line(value: object, default: int = 1) -> int:
    if isinstance(value, int) and value > 0:
        return value
    return default


def _safe_path(value: object, default: str = "security_context") -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _to_recon_finding(
    *,
    title: str,
    description: str,
    finding_type: FindingType,
    cwe_id: str,
    cwe_name: str,
    owasp_category: str,
    severity: Severity,
    file_path: str,
    start_line: int,
    code_snippet: str,
) -> RawFinding:
    return RawFinding(
        hunter_strategy="recon",
        title=title,
        description=description,
        finding_type=finding_type,
        cwe_id=cwe_id,
        cwe_name=cwe_name,
        owasp_category=owasp_category,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line,
        code_snippet=code_snippet,
        estimated_severity=severity,
        confidence=Confidence.HIGH,
    )


def _extract_from_config(config: ConfigReport) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for secret in config.secrets:
        line = _safe_line(secret.line)
        location = f"{secret.file_path}:{line}"
        findings.append(
            _to_recon_finding(
                title=f"Hardcoded secret in {secret.file_path}",
                description=(
                    f"Detected {secret.secret_type} secret at {location}. "
                    f"Data flow summary: hardcoded credential from source file can be reused by an attacker."
                ),
                finding_type=FindingType.SECRETS,
                cwe_id="CWE-798",
                cwe_name="Use of Hard-coded Credentials",
                owasp_category="A07:2021",
                severity=Severity.HIGH,
                file_path=secret.file_path,
                start_line=line,
                code_snippet=secret.match,
            )
        )

    for misconfig in config.misconfigs:
        line = _safe_line(misconfig.line)
        details = ", ".join(item for item in [misconfig.key, misconfig.value] if item)
        snippet = details or misconfig.risk
        findings.append(
            _to_recon_finding(
                title=f"Insecure configuration in {misconfig.file_path}",
                description=(
                    f"Detected {misconfig.category} with risk: {misconfig.risk}. "
                    "Data flow summary: insecure runtime configuration weakens application security controls."
                ),
                finding_type=FindingType.CONFIG,
                cwe_id="CWE-16",
                cwe_name="Configuration",
                owasp_category="A05:2021",
                severity=Severity.MEDIUM,
                file_path=misconfig.file_path,
                start_line=line,
                code_snippet=snippet,
            )
        )
    return findings


def _extract_weak_tls(context: SecurityContext) -> list[RawFinding]:
    findings: list[RawFinding] = []
    for usage in context.crypto_usage:
        if usage.is_weak is not True:
            continue
        algorithm = usage.algorithm.strip() if usage.algorithm else "unknown"
        usage_context = usage.usage_context or "security context"
        if "tls" not in algorithm.lower() and "ssl" not in algorithm.lower() and "tls" not in usage_context.lower():
            continue
        findings.append(
            _to_recon_finding(
                title=f"Weak TLS configuration: {algorithm}",
                description=(
                    f"Detected weak transport crypto usage in {usage_context}. "
                    "Data flow summary: clients may negotiate weak encryption for in-transit data."
                ),
                finding_type=FindingType.CONFIG,
                cwe_id="CWE-327",
                cwe_name="Use of a Broken or Risky Cryptographic Algorithm",
                owasp_category="A02:2021",
                severity=Severity.MEDIUM,
                file_path="security_context",
                start_line=1,
                code_snippet=f"algorithm={algorithm}; context={usage_context}",
            )
        )
    return findings


def _extract_structured_security_items(context: SecurityContext) -> list[RawFinding]:
    findings: list[RawFinding] = []
    category_specs: tuple[tuple[str, FindingType, str, str, str, Severity, str, str], ...] = (
        (
            "hardcoded_secrets",
            FindingType.SECRETS,
            "CWE-798",
            "Use of Hard-coded Credentials",
            "A07:2021",
            Severity.HIGH,
            "Hardcoded secret",
            "hardcoded credential from source file can be reused by an attacker",
        ),
        (
            "dangerous_configs",
            FindingType.CONFIG,
            "CWE-16",
            "Configuration",
            "A05:2021",
            Severity.MEDIUM,
            "Dangerous configuration",
            "insecure runtime configuration weakens application security controls",
        ),
        (
            "weak_tls",
            FindingType.CONFIG,
            "CWE-327",
            "Use of a Broken or Risky Cryptographic Algorithm",
            "A02:2021",
            Severity.MEDIUM,
            "Weak TLS setting",
            "clients may negotiate weak encryption for in-transit data",
        ),
        (
            "exposed_endpoints",
            FindingType.API,
            "CWE-489",
            "Active Debug Code",
            "A05:2021",
            Severity.MEDIUM,
            "Exposed debug endpoint",
            "publicly reachable debug endpoint may expose internal application state",
        ),
    )

    for category, finding_type, cwe_id, cwe_name, owasp, severity, title, summary in category_specs:
        items_obj = getattr(context, category, None)
        if not isinstance(items_obj, list):
            continue
        items = cast(list[object], items_obj)

        for raw_item in items:
            if isinstance(raw_item, Mapping):
                mapping_item = cast(Mapping[object, object], raw_item)
                row_data = {str(k): v for k, v in mapping_item.items()}
            elif isinstance(raw_item, str):
                row_data = {"description": raw_item}
            else:
                continue

            file_path = _safe_path(row_data.get("file_path"), "security_context")
            line = _safe_line(row_data.get("line"))
            evidence = str(row_data.get("match") or row_data.get("value") or row_data.get("description") or row_data)
            findings.append(
                _to_recon_finding(
                    title=f"{title} in {file_path}",
                    description=(f"Detected {category} at {file_path}:{line}. Data flow summary: {summary}."),
                    finding_type=finding_type,
                    cwe_id=cwe_id,
                    cwe_name=cwe_name,
                    owasp_category=owasp,
                    severity=severity,
                    file_path=file_path,
                    start_line=line,
                    code_snippet=evidence,
                )
            )
    return findings


def extract_recon_findings(recon: ReconResult) -> list[RawFinding]:
    findings: list[RawFinding] = []
    findings.extend(_extract_from_config(recon.config))
    findings.extend(_extract_structured_security_items(recon.security_context))
    findings.extend(_extract_weak_tls(recon.security_context))
    return findings


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


async def run_fast_recon(app: HarnessCapable, repo_path: str) -> ReconResult:
    architecture, dependencies, config = await asyncio.gather(
        run_architecture_mapper(app, repo_path),
        run_dependency_auditor(app, repo_path),
        run_config_scanner(app, repo_path),
    )

    data_flows, security_context = _quick_defaults()
    languages = sorted(
        {module.language.lower() for module in architecture.modules if getattr(module, "language", None)}
    )
    frameworks: list[str] = []
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
    )


async def run_deep_recon(
    app: HarnessCapable,
    repo_path: str,
    architecture: ArchitectureMap,
) -> tuple[DataFlowMap, SecurityContext]:
    data_flows, security_context = await asyncio.gather(
        run_data_flow_mapper(app, repo_path, architecture),
        run_security_context_profiler(app, repo_path, architecture),
    )
    return data_flows, security_context


__all__ = [
    "run_recon",
    "run_fast_recon",
    "run_deep_recon",
    "run_architecture_mapper",
    "run_data_flow_mapper",
    "run_dependency_auditor",
    "run_config_scanner",
    "run_security_context_profiler",
    "extract_recon_findings",
    "ArchitectureMap",
    "DataFlowMap",
    "DependencyReport",
    "ConfigReport",
    "SecurityContext",
    "ReconResult",
]
