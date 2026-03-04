"""Report output stub from DESIGN.md §7.3."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.output import SecurityAuditResult


def render_report(audit_result: SecurityAuditResult) -> str:
    """Render summary report output (stub)."""
    _ = audit_result
    raise NotImplementedError("Implemented in a future issue")
