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
