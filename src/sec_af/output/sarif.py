"""SARIF output stub from DESIGN.md §7.5."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.output import SecurityAuditResult


def render_sarif(audit_result: SecurityAuditResult) -> str:
    """Render SARIF 2.1.0 output (stub)."""
    _ = audit_result
    raise NotImplementedError("Implemented in a future issue")
