"""Compliance schema scaffold from DESIGN.md §7.1 and §7.3."""

from __future__ import annotations

from pydantic import BaseModel


class ComplianceMapping(BaseModel):
    """Compliance mapping stub from DESIGN.md §7.1."""

    framework: str = ""
    control_id: str = ""
    control_name: str = ""
