"""HUNT schema scaffold from DESIGN.md §5."""

from __future__ import annotations

from pydantic import BaseModel, Field


class RawFinding(BaseModel):
    """Potential vulnerability finding stub from DESIGN.md §5.4."""

    id: str = ""
    title: str = ""
    cwe_id: str = ""
    file_path: str = ""
    start_line: int = 0


class HuntResult(BaseModel):
    """Deduplicated/correlated hunt output stub from DESIGN.md §5.5."""

    findings: list[RawFinding] = Field(default_factory=list)
    total_raw: int = 0
    deduplicated_count: int = 0
    chain_count: int = 0
