"""JSON output stub from DESIGN.md §7.3."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.output import SecurityAuditResult


def render_json(audit_result: SecurityAuditResult) -> dict[str, object]:
    """Render rich JSON output (stub)."""
    _ = audit_result
    raise NotImplementedError("Implemented in a future issue")
