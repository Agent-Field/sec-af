"""Input schema scaffold from DESIGN.md §3 and §7.3."""

from __future__ import annotations

from pydantic import BaseModel, Field


class AuditInput(BaseModel):
    """REST API audit request schema from DESIGN.md §3."""

    repo_url: str = Field(default="")
    branch: str | None = Field(default=None)
    depth: str = Field(default="standard")
    severity_threshold: str = Field(default="medium")
    output_formats: list[str] = Field(default_factory=lambda: ["json"])
