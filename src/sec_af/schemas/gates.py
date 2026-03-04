"""Flat gate schemas scaffold from DESIGN.md §2.4 and §2.5."""

from __future__ import annotations

from pydantic import BaseModel, Field


class SeverityGate(BaseModel):
    """Simple `.ai()` severity gate schema from DESIGN.md §2.4."""

    severity: str = Field(default="medium")
    confidence: float = Field(default=0.0)
    rationale: str = Field(default="not_implemented")


class StrategySelection(BaseModel):
    """Simple strategy selection schema from DESIGN.md §5.6."""

    strategies: list[str] = Field(default_factory=list)
    rationale: str = Field(default="not_implemented")
