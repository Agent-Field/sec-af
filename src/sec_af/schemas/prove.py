"""PROVE schema scaffold from DESIGN.md §6."""

from __future__ import annotations

from pydantic import BaseModel


class Proof(BaseModel):
    """Evidence container stub from DESIGN.md §6.4."""

    exploit_hypothesis: str = "not_implemented"
    verification_method: str = "not_implemented"
    evidence_level: int = 0
