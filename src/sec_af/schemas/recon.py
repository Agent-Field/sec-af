"""RECON schema scaffold from DESIGN.md §4."""

from __future__ import annotations

from pydantic import BaseModel, Field


class ReconResult(BaseModel):
    """Top-level RECON output stub from DESIGN.md §4.3."""

    languages: list[str] = Field(default_factory=list)
    frameworks: list[str] = Field(default_factory=list)
    lines_of_code: int = 0
    file_count: int = 0
    recon_duration_seconds: float = 0.0
