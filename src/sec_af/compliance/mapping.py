"""Compliance mapping stub from DESIGN.md §7.1 and §7.3."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.compliance import ComplianceMapping
    from ..schemas.output import VerifiedFinding


def map_compliance(findings: list[VerifiedFinding]) -> list[ComplianceMapping]:
    """Map findings to compliance controls (stub)."""
    _ = findings
    raise NotImplementedError("Implemented in a future issue")
