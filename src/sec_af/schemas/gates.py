"""Flat schemas for .ai() gate calls.

See DESIGN.md §2.4 and §2.5 for .ai() vs .harness() routing constraints.
"""

from pydantic import BaseModel, Field


class SeverityClassification(BaseModel):
    """DESIGN.md §2.4: quick severity classification gate used in scoring."""

    severity: str = Field(description='One of: "critical", "high", "medium", "low".')
    confidence: float
    rationale: str


class DuplicateCheck(BaseModel):
    """DESIGN.md §5.5: quick duplicate check gate for dedup decisions."""

    is_duplicate: bool
    duplicate_of: str | None = None
    reason: str


class StrategySelection(BaseModel):
    """DESIGN.md §5.3: strategy selection gate for HUNT routing."""

    strategies: list[str]
    rationale: str


class RelevanceGate(BaseModel):
    """DESIGN.md §2.4: relevance/noise filter gate for candidate findings."""

    is_relevant: bool
    confidence: float
    reason: str


class VerdictGate(BaseModel):
    """DESIGN.md §2.4 and §6.3: binary verdict gate for simple cases."""

    confirmed: bool
    confidence: float
    reason: str


class ComplianceSuggestion(BaseModel):
    framework: str
    control_id: str
    control_name: str


class ComplianceGate(BaseModel):
    mappings: list[ComplianceSuggestion]
    confidence: str


class ReachabilityGate(BaseModel):
    """Reachability assessment for findings without explicit reachability tags."""

    reachability: str = Field(
        description='One of: "externally_reachable", "requires_auth", "internal_only", "unreachable".'
    )
    rationale: str
    confidence: str = Field(description='One of: "high", "medium", "low".')
