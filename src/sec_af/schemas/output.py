"""Output and orchestration schemas.

See DESIGN.md §7 and §12.3 for output payloads and progress reporting.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field

from .compliance import ComplianceGap
from .hunt import Severity
from .prove import VerifiedFinding  # noqa: F401 — needed for Pydantic forward ref resolution


class Location(BaseModel):
    """DESIGN.md §7.1 location metadata for finding references."""

    file_path: str
    start_line: int
    end_line: int
    start_column: int | None = None
    end_column: int | None = None
    function_name: str | None = None
    code_snippet: str | None = None


class CvssV4Score(BaseModel):
    """DESIGN.md §7.1 CVSS v4 scoring object."""

    vector: str
    base_score: float
    severity: str
    automatable: bool
    subsequent_impact: bool


class EpssScore(BaseModel):
    """DESIGN.md §7.1 EPSS score object for CVE findings."""

    score: float
    percentile: float
    date: str


class MitreMapping(BaseModel):
    """DESIGN.md §7.2 MITRE ATT&CK mapping for attack chains."""

    tactic: str
    technique_id: str
    technique_name: str


class AttackChain(BaseModel):
    """DESIGN.md §7.2 verified multi-step exploit chain."""

    chain_id: str
    title: str
    description: str
    findings: list[str] = Field(default_factory=list)
    combined_severity: Severity
    combined_impact: str
    mitre_attack_mapping: list[MitreMapping] | None = None


class ReproductionStep(BaseModel):
    """DESIGN.md §7.1 reproduction instructions in output payload."""

    step: int
    description: str
    command: str | None = None
    expected_output: str | None = None


class PolicyViolation(BaseModel):
    """A violation of an org-specific security policy."""

    policy: str = Field(description="The policy rule that was violated")
    violation_description: str = Field(description="How the code violates this policy")
    file_path: str = Field(description="File where violation was found")
    severity: str = Field(default="medium", description="Severity of the violation")


class SecurityAuditResult(BaseModel):
    """DESIGN.md §7.3 top-level SEC-AF audit output."""

    repository: str
    commit_sha: str
    branch: str | None = None
    timestamp: datetime
    depth_profile: str
    strategies_used: list[str] = Field(default_factory=list)
    provider: str
    findings: list["VerifiedFinding"] = Field(default_factory=list)
    attack_chains: list[AttackChain] = Field(default_factory=list)
    total_raw_findings: int = 0
    confirmed: int = 0
    likely: int = 0
    inconclusive: int = 0
    not_exploitable: int = 0
    noise_reduction_pct: float = 0.0
    by_severity: dict[str, int] = Field(default_factory=dict)
    compliance_gaps: list[ComplianceGap] = Field(default_factory=list)
    policy_violations: list[PolicyViolation] = Field(default_factory=list)
    duration_seconds: float = 0.0
    agent_invocations: int = 0
    cost_usd: float = 0.0
    cost_breakdown: dict[str, float] = Field(default_factory=dict)
    metadata: dict[str, object] = Field(default_factory=dict)
    sarif: str


# Resolve forward references now that VerifiedFinding is available
_ = SecurityAuditResult.model_rebuild()


class AuditProgress(BaseModel):
    """DESIGN.md §12.3 orchestrator phase progress event."""

    phase: str
    phase_progress: float
    agents_total: int
    agents_completed: int
    agents_running: int
    findings_so_far: int
    elapsed_seconds: float
    estimated_remaining_seconds: float
    cost_so_far_usd: float


class AuditMetrics(BaseModel):
    """DESIGN.md §7.3 and §9.1 run-level performance and budget metrics."""

    duration_seconds: float
    agent_invocations: int
    cost_usd: float
    cost_breakdown: dict[str, float] = Field(default_factory=dict)
    budget_exhausted: bool = False
    findings_not_verified: int = 0
