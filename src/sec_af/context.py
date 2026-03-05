from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any

from sec_af.agents.hunt._framework_hints import get_framework_hints
from sec_af.agents.hunt._language_hints import get_language_hints
from sec_af.schemas.hunt import HuntStrategy
from sec_af.schemas.recon import KnownCVE, ReconResult

_MAX_PRIMARY_ITEMS = 15
_MAX_SECONDARY_ITEMS = 10

_BASE_RECON_FIELDS = ("languages", "frameworks", "lines_of_code", "file_count")

STRATEGY_CONTEXT_MAP: dict[str, list[str]] = {
    "injection": ["architecture", "data_flows", "security_context"],
    "xss": ["architecture", "data_flows", "security_context"],
    "ssrf": ["architecture", "data_flows", "security_context"],
    "auth": ["architecture", "security_context"],
    "crypto": ["security_context"],
    "dos": ["architecture", "data_flows"],
    "data_exposure": ["architecture", "data_flows", "config"],
    "supply_chain": ["dependencies"],
    "config_secrets": ["config", "architecture"],
    "api_security": ["architecture", "security_context", "data_flows"],
    "business_logic": ["architecture", "data_flows", "security_context"],
}


def prune_recon_for_strategy(recon: ReconResult, strategy: str) -> dict[str, Any]:
    required_fields = STRATEGY_CONTEXT_MAP.get(strategy)
    if required_fields is None:
        return recon.model_dump()

    include_fields = set(_BASE_RECON_FIELDS)
    include_fields.update(required_fields)
    return recon.model_dump(include=include_fields)


def _limit(items: Iterable[str], max_items: int) -> tuple[list[str], int]:
    rows = [item for item in items if item]
    return rows[:max_items], len(rows)


def _render_list(title: str, items: Iterable[str], *, max_items: int) -> str:
    trimmed, total = _limit(items, max_items)
    if total == 0:
        return f"{title}: none identified in recon."
    lines = [f"{title}: {total} total, showing top {len(trimmed)}:"]
    lines.extend(f"- {item}" for item in trimmed)
    return "\n".join(lines)


def _endpoint_rank_key(endpoint_auth_required: bool | None, endpoint_rate_limited: bool | None) -> tuple[int, int]:
    return (
        0 if endpoint_auth_required is False else 1,
        0 if endpoint_rate_limited is False else 1,
    )


def _cve_priority(cve: KnownCVE) -> tuple[int, float, float, int]:
    reachable_rank = 0 if cve.reachable else 1
    cvss = cve.cvss_v4_score if cve.cvss_v4_score is not None else -1.0
    epss = cve.epss_score if cve.epss_score is not None else -1.0
    direct_rank = 0 if cve.direct else 1
    return (reachable_rank, -cvss, -epss, direct_rank)


def recon_context_for_injection(recon: ReconResult) -> str:
    unsanitized_flows = [flow for flow in recon.data_flows.flows if not flow.sanitized]
    flow_candidates = unsanitized_flows if unsanitized_flows else recon.data_flows.flows

    entry_point_rows = (
        f"{entry.kind} {entry.route or entry.identifier} ({entry.file_path}:{entry.line})"
        for entry in recon.architecture.entry_points
    )
    sink_rows = (
        f"{sink.sink_type} at {sink.file_path}:{sink.line}" + (f" ({sink.function_name})" if sink.function_name else "")
        for sink in recon.data_flows.sinks
    )
    flow_rows = (
        f"{flow.source} -> {flow.sink}; sanitized={flow.sanitized}; files={', '.join(flow.files[:3])}"
        for flow in flow_candidates
    )

    return "\n\n".join(
        [
            "Injection-focused recon summary.",
            f"Codebase profile: {recon.file_count} files, {recon.lines_of_code} LOC, languages={', '.join(recon.languages) or 'unknown'}, frameworks={', '.join(recon.frameworks) or 'unknown'}.",
            _render_list(
                "Entry points likely to receive untrusted input", entry_point_rows, max_items=_MAX_PRIMARY_ITEMS
            ),
            _render_list("High-value sinks", sink_rows, max_items=_MAX_PRIMARY_ITEMS),
            _render_list("Source-to-sink flow candidates (unsanitized first)", flow_rows, max_items=_MAX_PRIMARY_ITEMS),
            _render_list(
                "Known sanitization points",
                (
                    f"{point.file_path}:{point.line} type={point.sanitization_type} protects={', '.join(point.protects_against) or 'unspecified'}"
                    for point in recon.data_flows.sanitization_points
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_auth(recon: ReconResult) -> str:
    ranked_endpoints = sorted(
        recon.architecture.api_surface,
        key=lambda endpoint: _endpoint_rank_key(endpoint.auth_required, endpoint.rate_limited),
    )
    auth_related_modules = [
        module
        for module in recon.architecture.modules
        if any(
            token in f"{module.name} {module.path} {(module.description or '')}".lower()
            for token in ("auth", "session", "rbac", "permission", "role", "guard", "middleware", "csrf", "jwt")
        )
    ]

    endpoint_rows = (
        f"{endpoint.method} {endpoint.path} -> {endpoint.handler} ({endpoint.file_path}:{endpoint.line}, auth_required={endpoint.auth_required}, rate_limited={endpoint.rate_limited})"
        for endpoint in ranked_endpoints
    )

    return "\n\n".join(
        [
            "Authentication/authorization-focused recon summary.",
            f"Auth model: {recon.security_context.auth_model}. Details: {recon.security_context.auth_details or 'none provided'}.",
            _render_list(
                "Auth/session/RBAC modules and middleware candidates",
                (
                    f"{module.path} ({module.language})" + (f" - {module.description}" if module.description else "")
                    for module in auth_related_modules
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "API endpoints to validate for auth/authz coverage", endpoint_rows, max_items=_MAX_PRIMARY_ITEMS
            ),
            _render_list(
                "Auth/session-relevant data flows",
                (
                    f"{flow.source} -> {flow.sink} (files={', '.join(flow.files[:3])}, sanitized={flow.sanitized})"
                    for flow in recon.data_flows.flows
                    if any(
                        token in f"{flow.source} {flow.sink} {' '.join(flow.files)}".lower()
                        for token in (
                            "auth",
                            "token",
                            "jwt",
                            "session",
                            "cookie",
                            "csrf",
                            "role",
                            "permission",
                            "scope",
                        )
                    )
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Security headers and framework security signals",
                [*recon.security_context.security_headers, *recon.security_context.framework_security],
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_crypto(recon: ReconResult) -> str:
    weak_first = sorted(
        recon.security_context.crypto_usage,
        key=lambda usage: 0 if usage.is_weak else 1,
    )
    return "\n\n".join(
        [
            "Cryptography-focused recon summary.",
            f"Crypto usage entries: {len(recon.security_context.crypto_usage)} total.",
            _render_list(
                "Algorithms and key handling (weak entries first)",
                (
                    f"algorithm={usage.algorithm}, key_size={usage.key_size}, mode={usage.mode}, context={usage.usage_context or 'unspecified'}, is_weak={usage.is_weak}"
                    for usage in weak_first
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Potential secret/key findings from config scan",
                (
                    f"{secret.secret_type} at {secret.file_path}:{secret.line} (confidence={secret.confidence})"
                    for secret in recon.config.secrets
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Deployment/TLS/security header signals",
                [*recon.security_context.deployment_signals, *recon.security_context.security_headers],
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_data_exposure(recon: ReconResult) -> str:
    return "\n\n".join(
        [
            "Data exposure-focused recon summary.",
            _render_list(
                "Data flows touching likely sensitive domains",
                (
                    f"{flow.source} -> {flow.sink}; sanitized={flow.sanitized}; files={', '.join(flow.files[:3])}"
                    for flow in recon.data_flows.flows
                    if any(
                        token in f"{flow.source} {flow.sink} {' '.join(flow.files)}".lower()
                        for token in (
                            "password",
                            "token",
                            "secret",
                            "credential",
                            "session",
                            "cookie",
                            "email",
                            "phone",
                            "pii",
                            "ssn",
                            "card",
                            "auth",
                            "user",
                        )
                    )
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Logging/exposure-related misconfig signals",
                (
                    f"{misconfig.category} at {misconfig.file_path}:{misconfig.line or 0}; risk={misconfig.risk}; key={misconfig.key or 'n/a'}"
                    for misconfig in recon.config.misconfigs
                    if any(
                        token
                        in f"{misconfig.category} {misconfig.key or ''} {misconfig.value or ''} {misconfig.risk}".lower()
                        for token in ("log", "debug", "trace", "error", "verbose", "tls", "http", "exposure")
                    )
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Entry points and API surface with exposure risk",
                (
                    f"{endpoint.method} {endpoint.path} ({endpoint.file_path}:{endpoint.line}, auth_required={endpoint.auth_required})"
                    for endpoint in recon.architecture.api_surface
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_config_secrets(recon: ReconResult) -> str:
    return "\n\n".join(
        [
            "Config and secrets-focused recon summary.",
            _render_list(
                "Detected secret-like findings",
                (
                    f"{secret.secret_type} at {secret.file_path}:{secret.line}; confidence={secret.confidence}; is_test_value={secret.is_test_value}"
                    for secret in recon.config.secrets
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Configuration weaknesses from recon",
                (
                    f"{misconfig.category} at {misconfig.file_path}:{misconfig.line or 0}; risk={misconfig.risk}; key={misconfig.key or 'n/a'}"
                    for misconfig in recon.config.misconfigs
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Security/deployment context affecting config risk",
                [*recon.security_context.deployment_signals, *recon.security_context.framework_security],
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_supply_chain(recon: ReconResult) -> str:
    prioritized_cves = sorted(recon.dependencies.known_cves, key=_cve_priority)
    return "\n\n".join(
        [
            "Supply-chain-focused recon summary.",
            f"Dependency inventory: direct={recon.dependencies.direct_count}, transitive={recon.dependencies.transitive_count}, SBOM entries={len(recon.dependencies.sbom)}.",
            _render_list(
                "Known CVE exposure (reachable/high severity first)",
                (
                    f"{cve.cve_id} in {cve.package} {cve.installed_version} (fixed={cve.fixed_version or 'unknown'}, cvss={cve.cvss_v4_score}, epss={cve.epss_score}, direct={cve.direct}, reachable={cve.reachable})"
                    for cve in prioritized_cves
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Outdated dependencies",
                (
                    f"{dep.package}: {dep.current_version} -> {dep.latest_version} (direct={dep.direct})"
                    for dep in recon.dependencies.outdated
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Primary dependency ecosystems in this repo",
                sorted({f"{dep.ecosystem}: {dep.name}@{dep.version}" for dep in recon.dependencies.sbom}),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_api_security(recon: ReconResult) -> str:
    ranked_endpoints = sorted(
        recon.architecture.api_surface,
        key=lambda endpoint: _endpoint_rank_key(endpoint.auth_required, endpoint.rate_limited),
    )
    return "\n\n".join(
        [
            "API security-focused recon summary.",
            _render_list(
                "API endpoints prioritized by missing auth/rate-limits",
                (
                    f"{endpoint.method} {endpoint.path} -> {endpoint.handler} ({endpoint.file_path}:{endpoint.line}, auth_required={endpoint.auth_required}, rate_limited={endpoint.rate_limited})"
                    for endpoint in ranked_endpoints
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "HTTP/API entry points",
                (
                    f"{entry.kind} {entry.route or entry.identifier} ({entry.file_path}:{entry.line}, auth_required={entry.auth_required})"
                    for entry in recon.architecture.entry_points
                    if entry.kind.lower() in {"http", "api", "graphql", "rpc", "route"}
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Trust boundaries relevant to API calls",
                (
                    f"{boundary.name}: {boundary.source_zone} -> {boundary.target_zone}; enforcement={', '.join(boundary.enforcement) or 'none'}"
                    for boundary in recon.architecture.trust_boundaries
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Framework/deployment API security signals",
                [*recon.security_context.framework_security, *recon.security_context.deployment_signals],
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_for_logic(recon: ReconResult) -> str:
    return "\n\n".join(
        [
            "Business-logic-focused recon summary.",
            _render_list(
                "Core modules likely to implement workflows and state transitions",
                (
                    f"{module.path} ({module.language})" + (f" - {module.description}" if module.description else "")
                    for module in recon.architecture.modules
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Workflow entry points",
                (
                    f"{entry.kind} {entry.route or entry.identifier} ({entry.file_path}:{entry.line})"
                    for entry in recon.architecture.entry_points
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Cross-file data/control flow candidates",
                (
                    f"{flow.source} -> {flow.sink}; files={', '.join(flow.files[:5])}; sanitized={flow.sanitized}"
                    for flow in recon.data_flows.flows
                ),
                max_items=_MAX_PRIMARY_ITEMS,
            ),
            _render_list(
                "Trust boundaries and external service transitions",
                [
                    *(
                        f"boundary {boundary.name}: {boundary.source_zone}->{boundary.target_zone}"
                        for boundary in recon.architecture.trust_boundaries
                    ),
                    *(
                        f"service {service.name}: type={service.service_type}, endpoint={service.endpoint or 'n/a'}, auth={service.auth_mechanism or 'n/a'}"
                        for service in recon.architecture.services
                    ),
                ],
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def recon_context_generic(recon: ReconResult) -> str:
    return "\n\n".join(
        [
            "General recon summary.",
            f"Profile: {recon.file_count} files, {recon.lines_of_code} LOC, languages={', '.join(recon.languages) or 'unknown'}, frameworks={', '.join(recon.frameworks) or 'unknown'}.",
            _render_list(
                "Top entry points",
                (
                    f"{entry.kind} {entry.route or entry.identifier} ({entry.file_path}:{entry.line})"
                    for entry in recon.architecture.entry_points
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Top API endpoints",
                (
                    f"{endpoint.method} {endpoint.path} ({endpoint.file_path}:{endpoint.line})"
                    for endpoint in recon.architecture.api_surface
                ),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
            _render_list(
                "Top data-flow candidates",
                (f"{flow.source} -> {flow.sink}; sanitized={flow.sanitized}" for flow in recon.data_flows.flows),
                max_items=_MAX_SECONDARY_ITEMS,
            ),
        ]
    )


def language_hints_for_context(recon: ReconResult) -> str:
    """Build language-specific hints from recon-detected languages."""
    return get_language_hints(recon.languages)


def framework_hints_for_context(recon: ReconResult) -> str:
    """Build framework-specific hints from recon-detected frameworks."""
    return get_framework_hints(recon.frameworks)


def get_context_for_strategy(strategy: HuntStrategy, recon: ReconResult) -> str:
    builders: dict[HuntStrategy, Callable[[ReconResult], str]] = {
        HuntStrategy.INJECTION: recon_context_for_injection,
        HuntStrategy.AUTH: recon_context_for_auth,
        HuntStrategy.CRYPTO: recon_context_for_crypto,
        HuntStrategy.DATA_EXPOSURE: recon_context_for_data_exposure,
        HuntStrategy.CONFIG_SECRETS: recon_context_for_config_secrets,
        HuntStrategy.SUPPLY_CHAIN: recon_context_for_supply_chain,
        HuntStrategy.API_SECURITY: recon_context_for_api_security,
        HuntStrategy.LOGIC_BUGS: recon_context_for_logic,
    }
    builder = builders.get(strategy, recon_context_generic)
    return builder(recon)
