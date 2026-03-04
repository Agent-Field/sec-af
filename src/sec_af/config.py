"""Configuration schemas for SEC-AF.

See DESIGN.md §9 for depth profiles and budget controls.
"""

from enum import Enum

from pydantic import BaseModel, Field

from .schemas.input import AuditInput


class DepthProfile(str, Enum):
    """DESIGN.md §9 available depth profiles for pipeline execution."""

    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


class BudgetConfig(BaseModel):
    """DESIGN.md §9.1 budget enforcement thresholds."""

    max_cost_usd: float | None = None
    max_provers: int | None = None
    max_duration_seconds: int | None = None
    recon_budget_pct: float = 0.15
    hunt_budget_pct: float = 0.35
    prove_budget_pct: float = 0.50


class AuditConfig(BaseModel):
    """DESIGN.md §3 and §9 runtime config consumed by orchestrator phases."""

    repo_path: str
    depth: DepthProfile = DepthProfile.STANDARD
    severity_threshold: str = "low"
    scan_types: list[str] = Field(
        default_factory=lambda: ["sast", "sca", "secrets", "config"]
    )
    output_formats: list[str] = Field(default_factory=lambda: ["json"])
    compliance_frameworks: list[str] = Field(default_factory=list)
    include_paths: list[str] | None = None
    exclude_paths: list[str] = Field(
        default_factory=lambda: ["tests/", "vendor/", "node_modules/", ".git/"],
    )
    provider: str = "opencode"
    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    @classmethod
    def from_input(cls, audit_input: AuditInput, repo_path: str) -> "AuditConfig":
        """DESIGN.md §8.2 maps API input into orchestrator config."""

        depth = DepthProfile(audit_input.depth)
        return cls(
            repo_path=repo_path,
            depth=depth,
            severity_threshold=audit_input.severity_threshold,
            scan_types=audit_input.scan_types,
            output_formats=audit_input.output_formats,
            compliance_frameworks=audit_input.compliance_frameworks,
            include_paths=audit_input.include_paths,
            exclude_paths=audit_input.exclude_paths,
            budget=BudgetConfig(
                max_cost_usd=audit_input.max_cost_usd,
                max_provers=audit_input.max_provers,
                max_duration_seconds=audit_input.max_duration_seconds,
            ),
        )
