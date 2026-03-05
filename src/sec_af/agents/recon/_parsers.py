from __future__ import annotations

from sec_af.schemas.recon import (
    APIEndpoint,
    ArchitectureMap,
    ArchitectureMapRaw,
    ConfigReport,
    ConfigReportRaw,
    CryptoUsage,
    DataFlow,
    DataFlowMap,
    DataFlowMapRaw,
    Dependency,
    DependencyReport,
    DependencyReportRaw,
    EntryPoint,
    KnownCVE,
    MisconfigFinding,
    Module,
    OutdatedDep,
    SanitizationPoint,
    SecretFinding,
    SecurityContext,
    SecurityContextRaw,
    Service,
    Sink,
    TrustBoundary,
)


def _split_pipe(s: str, expected: int) -> list[str]:
    parts = [p.strip() for p in s.split("|", maxsplit=expected - 1)]
    while len(parts) < expected:
        parts.append("")
    return parts


def _parse_bool(s: str) -> bool | None:
    s = s.lower().strip()
    if s in ("true", "yes", "1"):
        return True
    if s in ("false", "no", "0"):
        return False
    return None


def _parse_int(s: str, default: int = 0) -> int:
    try:
        return int(s.strip())
    except (ValueError, TypeError):
        return default


def _parse_float(s: str) -> float | None:
    try:
        return float(s.strip())
    except (ValueError, TypeError):
        return None


def _parse_file_line(s: str) -> tuple[str, int]:
    s = s.strip()
    if ":" in s:
        idx = s.rfind(":")
        path = s[:idx]
        line = _parse_int(s[idx + 1 :], 0)
        if line > 0:
            return path, line
    return s, 0


def _is_na(s: str) -> bool:
    return s.lower().strip() in ("", "na", "n/a", "none", "unknown")


def parse_architecture_raw(raw: ArchitectureMapRaw) -> ArchitectureMap:
    modules = []
    for entry in raw.modules:
        parts = _split_pipe(entry, 4)
        modules.append(
            Module(
                name=parts[0],
                path=parts[1],
                language=parts[2],
                description=parts[3] or None,
            )
        )

    entry_points = []
    for entry in raw.entry_points:
        parts = _split_pipe(entry, 4)
        file_path, line = _parse_file_line(parts[2])
        ident = parts[1]
        route = ident if "/" in ident else None
        entry_points.append(
            EntryPoint(
                kind=parts[0],
                identifier=ident,
                file_path=file_path,
                line=line,
                route=route,
                auth_required=_parse_bool(parts[3]),
            )
        )

    trust_boundaries = []
    for entry in raw.trust_boundaries:
        parts = _split_pipe(entry, 4)
        trust_boundaries.append(
            TrustBoundary(
                name=parts[0],
                source_zone=parts[1],
                target_zone=parts[2],
                description=parts[3],
            )
        )

    services = []
    for entry in raw.services:
        parts = _split_pipe(entry, 4)
        services.append(
            Service(
                name=parts[0],
                service_type=parts[1],
                endpoint=None if _is_na(parts[2]) else parts[2],
                auth_mechanism=None if _is_na(parts[3]) else parts[3],
            )
        )

    api_endpoints = []
    for entry in raw.api_endpoints:
        parts = _split_pipe(entry, 6)
        file_path, line = _parse_file_line(parts[3])
        api_endpoints.append(
            APIEndpoint(
                method=parts[0],
                path=parts[1],
                handler=parts[2],
                file_path=file_path,
                line=line,
                auth_required=_parse_bool(parts[4]),
                rate_limited=_parse_bool(parts[5]),
            )
        )

    return ArchitectureMap(
        app_type=raw.app_type,
        modules=modules,
        entry_points=entry_points,
        trust_boundaries=trust_boundaries,
        services=services,
        api_surface=api_endpoints,
    )


def parse_data_flow_raw(raw: DataFlowMapRaw) -> DataFlowMap:
    flows = []
    for entry in raw.flows:
        parts = _split_pipe(entry, 4)
        files = [f.strip() for f in parts[3].split(",") if f.strip()]
        flows.append(
            DataFlow(
                source=parts[0],
                sink=parts[1],
                sanitized=_parse_bool(parts[2]) or False,
                files=files,
            )
        )

    sanitization_points = []
    for entry in raw.sanitization_points:
        parts = _split_pipe(entry, 4)
        file_path, line = _parse_file_line(parts[0])
        protects = [p.strip() for p in parts[3].split(",") if p.strip()]
        sanitization_points.append(
            SanitizationPoint(
                file_path=file_path,
                line=line,
                function_name=parts[1] or None,
                sanitization_type=parts[2],
                protects_against=protects,
            )
        )

    sinks = []
    for entry in raw.sinks:
        parts = _split_pipe(entry, 4)
        file_path, line = _parse_file_line(parts[1])
        sinks.append(
            Sink(
                sink_type=parts[0],
                file_path=file_path,
                line=line,
                function_name=parts[2] or None,
                exploitability_notes=parts[3] or None,
            )
        )

    return DataFlowMap(flows=flows, sanitization_points=sanitization_points, sinks=sinks)


def parse_dependency_report_raw(raw: DependencyReportRaw) -> DependencyReport:
    sbom = []
    direct_count = 0
    transitive_count = 0
    for entry in raw.sbom:
        parts = _split_pipe(entry, 5)
        is_direct = _parse_bool(parts[3]) or False
        if is_direct:
            direct_count += 1
        else:
            transitive_count += 1
        sbom.append(
            Dependency(
                name=parts[0],
                version=parts[1],
                ecosystem=parts[2],
                direct=is_direct,
                license=None if _is_na(parts[4]) else parts[4],
            )
        )

    known_cves = []
    for entry in raw.known_cves:
        parts = _split_pipe(entry, 7)
        known_cves.append(
            KnownCVE(
                cve_id=parts[0],
                package=parts[1],
                installed_version=parts[2],
                fixed_version=None if _is_na(parts[3]) else parts[3],
                cvss_v4_score=_parse_float(parts[4]),
                direct=_parse_bool(parts[5]) or False,
                reachable=_parse_bool(parts[6]),
            )
        )

    outdated = []
    for entry in raw.outdated:
        parts = _split_pipe(entry, 4)
        outdated.append(
            OutdatedDep(
                package=parts[0],
                current_version=parts[1],
                latest_version=parts[2],
                direct=_parse_bool(parts[3]) or False,
            )
        )

    return DependencyReport(
        sbom=sbom,
        known_cves=known_cves,
        outdated=outdated,
        direct_count=direct_count,
        transitive_count=transitive_count,
    )


def parse_config_report_raw(raw: ConfigReportRaw) -> ConfigReport:
    secrets = []
    for entry in raw.secrets:
        parts = _split_pipe(entry, 5)
        file_path, line = _parse_file_line(parts[1])
        secrets.append(
            SecretFinding(
                secret_type=parts[0],
                file_path=file_path,
                line=line,
                match=parts[2],
                confidence=parts[3] or "medium",
                is_test_value=_parse_bool(parts[4]),
            )
        )

    misconfigs = []
    for entry in raw.misconfigs:
        parts = _split_pipe(entry, 5)
        file_path, line = _parse_file_line(parts[1])
        misconfigs.append(
            MisconfigFinding(
                category=parts[0],
                file_path=file_path,
                line=line if line > 0 else None,
                key=None if _is_na(parts[2]) else parts[2],
                risk=parts[3],
                remediation=None if _is_na(parts[4]) else parts[4],
            )
        )

    return ConfigReport(secrets=secrets, misconfigs=misconfigs)


_HEADER_TERMS = ("header", "csp", "hsts", "x-frame", "x-content-type", "cors")
_DEPLOY_TERMS = ("deploy", "docker", "kubernetes", "cloud", "ssl", "tls", "https", "container", "k8s")


def parse_security_context_raw(raw: SecurityContextRaw) -> SecurityContext:
    crypto_usage = []
    for entry in raw.crypto_usage:
        parts = _split_pipe(entry, 5)
        crypto_usage.append(
            CryptoUsage(
                algorithm=parts[0],
                key_size=_parse_int(parts[1]) if not _is_na(parts[1]) else None,
                mode=None if _is_na(parts[2]) else parts[2],
                usage_context=None if _is_na(parts[3]) else parts[3],
                is_weak=_parse_bool(parts[4]),
            )
        )

    framework_security: list[str] = []
    security_headers: list[str] = []
    deployment_signals: list[str] = []
    for signal in raw.security_signals:
        lowered = signal.lower()
        if any(term in lowered for term in _HEADER_TERMS):
            security_headers.append(signal)
        elif any(term in lowered for term in _DEPLOY_TERMS):
            deployment_signals.append(signal)
        else:
            framework_security.append(signal)

    return SecurityContext(
        auth_model=raw.auth_model,
        auth_details=raw.auth_details,
        crypto_usage=crypto_usage,
        framework_security=framework_security,
        security_headers=security_headers,
        deployment_signals=deployment_signals,
    )
