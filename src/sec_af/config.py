"""Configuration scaffold from DESIGN.md §5.3 and §7.3."""

from __future__ import annotations

from enum import StrEnum

from pydantic import BaseModel


class DepthProfile(StrEnum):
    """Depth profile enum from DESIGN.md §5.3 and §7.3."""

    QUICK = "quick"
    STANDARD = "standard"
    THOROUGH = "thorough"


class AuditConfig(BaseModel):
    """Audit configuration stub from DESIGN.md §7.3."""

    depth: DepthProfile = DepthProfile.STANDARD
    max_provers: int | None = None
    provider: str = "opencode"
