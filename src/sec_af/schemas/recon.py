"""RECON phase schemas.

These are complex `.harness()` schemas from DESIGN.md §4.3.
"""

from uuid import uuid4

from pydantic import BaseModel, Field


class Module(BaseModel):
    """DESIGN.md §4.3 module-level architecture element."""

    name: str
    path: str
    language: str
    description: str | None = None
    dependencies: list[str] = Field(default_factory=list)


class EntryPoint(BaseModel):
    """DESIGN.md §4.3 executable entry point (HTTP, CLI, event)."""

    kind: str
    identifier: str
    file_path: str
    line: int
    method: str | None = None
    route: str | None = None
    auth_required: bool | None = None


class TrustBoundary(BaseModel):
    """DESIGN.md §4.3 trust transition location."""

    name: str
    source_zone: str
    target_zone: str
    description: str
    enforcement: list[str] = Field(default_factory=list)


class Service(BaseModel):
    """DESIGN.md §4.3 service dependency or external integration."""

    name: str
    service_type: str
    endpoint: str | None = None
    purpose: str | None = None
    auth_mechanism: str | None = None


class APIEndpoint(BaseModel):
    """DESIGN.md §4.3 exposed API surface entry."""

    method: str
    path: str
    handler: str
    file_path: str
    line: int
    auth_required: bool | None = None
    rate_limited: bool | None = None


class ArchitectureMap(BaseModel):
    """DESIGN.md §4.3 architecture mapper output."""

    app_type: str | None = None
    modules: list[Module] = Field(default_factory=list)
    entry_points: list[EntryPoint] = Field(default_factory=list)
    trust_boundaries: list[TrustBoundary] = Field(default_factory=list)
    services: list[Service] = Field(default_factory=list)
    api_surface: list[APIEndpoint] = Field(default_factory=list)


class DataFlowStep(BaseModel):
    """DESIGN.md §4.3 intermediate transformation step in a data flow."""

    file_path: str
    line: int
    component: str
    operation: str


class SanitizationPoint(BaseModel):
    """DESIGN.md §4.3 location where tainted data is sanitized."""

    file_path: str
    line: int
    function_name: str | None = None
    sanitization_type: str
    protects_against: list[str] = Field(default_factory=list)


class Sink(BaseModel):
    """DESIGN.md §4.3 security-critical sink reached by application data."""

    sink_type: str
    file_path: str
    line: int
    function_name: str | None = None
    exploitability_notes: str | None = None


class DataFlow(BaseModel):
    """DESIGN.md §4.3 input-to-sink path."""

    source: str
    path: list[DataFlowStep] = Field(default_factory=list)
    sink: str
    sanitized: bool
    files: list[str] = Field(default_factory=list)


class DataFlowMap(BaseModel):
    """DESIGN.md §4.3 aggregated data flow analysis output."""

    flows: list[DataFlow] = Field(default_factory=list)
    sanitization_points: list[SanitizationPoint] = Field(default_factory=list)
    sinks: list[Sink] = Field(default_factory=list)


class Dependency(BaseModel):
    """DESIGN.md §4.3 software bill-of-materials entry."""

    name: str
    version: str
    ecosystem: str
    direct: bool
    license: str | None = None


class KnownCVE(BaseModel):
    """DESIGN.md §4.3 known CVE affecting a dependency."""

    cve_id: str
    package: str
    installed_version: str
    fixed_version: str | None = None
    cvss_v4_score: float | None = None
    epss_score: float | None = None
    direct: bool
    reachable: bool | None = None


class OutdatedDep(BaseModel):
    """DESIGN.md §4.3 dependency that lags behind latest available version."""

    package: str
    current_version: str
    latest_version: str
    direct: bool


class DependencyReport(BaseModel):
    """DESIGN.md §4.3 dependency auditor output."""

    sbom: list[Dependency] = Field(default_factory=list)
    known_cves: list[KnownCVE] = Field(default_factory=list)
    outdated: list[OutdatedDep] = Field(default_factory=list)
    direct_count: int = 0
    transitive_count: int = 0


class SecretFinding(BaseModel):
    """DESIGN.md §4.3 discovered hardcoded secret or credential."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    secret_type: str
    file_path: str
    line: int
    match: str
    confidence: str
    is_test_value: bool | None = None


class MisconfigFinding(BaseModel):
    """DESIGN.md §4.3 insecure configuration finding."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    category: str
    file_path: str
    line: int | None = None
    key: str | None = None
    value: str | None = None
    risk: str
    remediation: str | None = None


class ConfigReport(BaseModel):
    """DESIGN.md §4.3 config scanner output."""

    secrets: list[SecretFinding] = Field(default_factory=list)
    misconfigs: list[MisconfigFinding] = Field(default_factory=list)


class CryptoUsage(BaseModel):
    """DESIGN.md §4.3 cryptography usage profile entry."""

    algorithm: str
    key_size: int | None = None
    mode: str | None = None
    usage_context: str | None = None
    is_weak: bool | None = None


class SecurityContext(BaseModel):
    """DESIGN.md §4.3 security context profiler output."""

    auth_model: str
    auth_details: str
    crypto_usage: list[CryptoUsage] = Field(default_factory=list)
    framework_security: list[str] = Field(default_factory=list)
    security_headers: list[str] = Field(default_factory=list)
    deployment_signals: list[str] = Field(default_factory=list)


class ReconResult(BaseModel):
    """DESIGN.md §4.3 comprehensive RECON context."""

    architecture: ArchitectureMap
    data_flows: DataFlowMap
    dependencies: DependencyReport
    config: ConfigReport
    security_context: SecurityContext
    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    lines_of_code: int = 0
    file_count: int = 0
    recon_duration_seconds: float = 0.0


# ---------------------------------------------------------------------------
# Flat harness schemas for RECON agents
# ---------------------------------------------------------------------------
# These schemas are what the LLM actually produces via .harness() calls.
# They use only flat fields (str, list[str]) — no nested models.
# Parser functions in agents/recon/_parsers.py convert these to the
# structured schemas above for downstream use (context.py, etc.).
# ---------------------------------------------------------------------------


class ArchitectureMapRaw(BaseModel):
    """Flat harness output for architecture mapper. All list[str], no nesting."""

    app_type: str = Field(
        default="unknown",
        description="Application type: web_api, cli_tool, library, microservice, monolith",
    )
    modules: list[str] = Field(
        default_factory=list,
        description=(
            "One string per module. Format: 'name | path | language | description'. "
            "Example: 'auth | src/auth/ | python | Authentication and session management'"
        ),
    )
    entry_points: list[str] = Field(
        default_factory=list,
        description=(
            "One string per entry point. Format: 'kind | route_or_id | file_path:line | auth_required'. "
            "Example: 'http | POST /api/login | src/routes.py:42 | false'"
        ),
    )
    trust_boundaries: list[str] = Field(
        default_factory=list,
        description=(
            "One string per boundary. Format: 'name | source_zone | target_zone | description'. "
            "Example: 'API Gateway | external | internal | Rate limiting and auth'"
        ),
    )
    services: list[str] = Field(
        default_factory=list,
        description=(
            "One string per external service. Format: 'name | type | endpoint | auth_mechanism'. "
            "Example: 'PostgreSQL | database | localhost:5432 | password'"
        ),
    )
    api_endpoints: list[str] = Field(
        default_factory=list,
        description=(
            "One string per API endpoint. Format: 'method | path | handler | file_path:line | auth_required | rate_limited'. "
            "Example: 'GET | /api/users | get_users | src/api.py:15 | true | false'"
        ),
    )


class DataFlowMapRaw(BaseModel):
    """Flat harness output for data flow mapper. All list[str], no nesting."""

    flows: list[str] = Field(
        default_factory=list,
        description=(
            "One string per data flow. Format: 'source | sink | sanitized(true/false) | file1, file2, ...'. "
            "Example: 'request.body | sql.execute | false | src/db.py, src/routes.py'"
        ),
    )
    sanitization_points: list[str] = Field(
        default_factory=list,
        description=(
            "One string per sanitization point. Format: 'file_path:line | function_name | type | protects_against'. "
            "Example: 'src/utils.py:42 | sanitize_html | html_encoding | CWE-79'"
        ),
    )
    sinks: list[str] = Field(
        default_factory=list,
        description=(
            "One string per security-critical sink. Format: 'sink_type | file_path:line | function_name | notes'. "
            "Example: 'sql_execute | src/db.py:55 | run_query | Direct string concatenation'"
        ),
    )


class DependencyReportRaw(BaseModel):
    """Flat harness output for dependency auditor. All list[str], no nesting."""

    sbom: list[str] = Field(
        default_factory=list,
        description=(
            "One string per dependency. Format: 'name | version | ecosystem | direct(true/false) | license'. "
            "Example: 'express | 4.18.2 | npm | true | MIT'"
        ),
    )
    known_cves: list[str] = Field(
        default_factory=list,
        description=(
            "One string per CVE. Format: 'cve_id | package | installed_version | fixed_version | cvss_score | direct | reachable'. "
            "Example: 'CVE-2023-1234 | lodash | 4.17.15 | 4.17.21 | 7.5 | true | unknown'"
        ),
    )
    outdated: list[str] = Field(
        default_factory=list,
        description=(
            "One string per outdated dep. Format: 'package | current_version | latest_version | direct(true/false)'. "
            "Example: 'express | 4.17.0 | 4.18.2 | true'"
        ),
    )


class ConfigReportRaw(BaseModel):
    """Flat harness output for config scanner. All list[str], no nesting."""

    secrets: list[str] = Field(
        default_factory=list,
        description=(
            "One string per secret finding. Format: 'type | file_path:line | match_preview | confidence | is_test(true/false)'. "
            "Example: 'aws_access_key | .env:3 | AKIA... | high | false'"
        ),
    )
    misconfigs: list[str] = Field(
        default_factory=list,
        description=(
            "One string per misconfiguration. Format: 'category | file_path:line | key | risk | remediation'. "
            "Example: 'debug_mode | config.py:15 | DEBUG=True | Exposes stack traces | Set DEBUG=False'"
        ),
    )


class SecurityContextRaw(BaseModel):
    """Flat harness output for security context profiler. All flat, no nesting."""

    auth_model: str = Field(
        description="Authentication model: jwt, session_cookie, oauth2, api_key, none, or other",
    )
    auth_details: str = Field(
        default="",
        description="Brief description of auth implementation details",
    )
    crypto_usage: list[str] = Field(
        default_factory=list,
        description=(
            "One string per crypto usage. Format: 'algorithm | key_size | mode | usage_context | is_weak(true/false)'. "
            "Example: 'AES | 256 | GCM | data encryption | false'"
        ),
    )
    security_signals: list[str] = Field(
        default_factory=list,
        description=(
            "Framework security features, security headers, and deployment signals. "
            "One signal per entry. Examples: 'CSRF protection enabled', 'HSTS header present', 'Runs in Docker'"
        ),
    )
