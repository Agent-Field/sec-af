"""Output schema scaffold from DESIGN.md §7."""

from __future__ import annotations

from typing import TYPE_CHECKING

from pydantic import BaseModel, Field

if TYPE_CHECKING:
    from .prove import Proof


class VerifiedFinding(BaseModel):
    """Verified finding stub from DESIGN.md §7.1."""

    id: str = ""
    title: str = ""
    verdict: str = "inconclusive"
    proof: Proof | None = None


class SecurityAuditResult(BaseModel):
    """Top-level audit result stub from DESIGN.md §7.3."""

    repository: str = ""
    findings: list[VerifiedFinding] = Field(default_factory=list)
    duration_seconds: float = 0.0
