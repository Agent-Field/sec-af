"""Configuration schemas for SEC-AF.

See DESIGN.md §9 for depth profiles and budget controls.
"""

import os
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

    repo_path: str = Field(...)
    depth: DepthProfile = DepthProfile.STANDARD
    severity_threshold: str = "low"
    scan_types: list[str] = Field(default_factory=lambda: ["sast", "sca", "secrets", "config"])
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


class AIIntegrationConfig(BaseModel):
    provider: str = Field(
        default_factory=lambda: os.getenv("SEC_AF_PROVIDER", os.getenv("HARNESS_PROVIDER", "opencode"))
    )
    harness_model: str = Field(
        default_factory=lambda: os.getenv(
            "SEC_AF_MODEL",
            os.getenv("HARNESS_MODEL", "minimax/minimax-m2.5"),
        )
    )
    ai_model: str = Field(
        default_factory=lambda: os.getenv(
            "SEC_AF_AI_MODEL",
            os.getenv("AI_MODEL", os.getenv("SEC_AF_MODEL", "minimax/minimax-m2.5")),
        )
    )
    max_turns: int = Field(default_factory=lambda: int(os.getenv("SEC_AF_MAX_TURNS", "50")))
    max_retries: int = Field(default_factory=lambda: int(os.getenv("SEC_AF_AI_MAX_RETRIES", "3")))
    initial_backoff_seconds: float = Field(
        default_factory=lambda: float(os.getenv("SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "2.0"))
    )
    max_backoff_seconds: float = Field(default_factory=lambda: float(os.getenv("SEC_AF_AI_MAX_BACKOFF_SECONDS", "8.0")))
    opencode_bin: str = Field(default_factory=lambda: os.getenv("SEC_AF_OPENCODE_BIN", "opencode"))

    @classmethod
    def from_env(cls) -> "AIIntegrationConfig":
        return cls()

    def provider_env(self) -> dict[str, str]:
        env_keys = (
            "OPENROUTER_API_KEY",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "GOOGLE_API_KEY",
            "GITHUB_TOKEN",
            "GH_TOKEN",
        )
        return {key: value for key in env_keys if (value := os.getenv(key))}
