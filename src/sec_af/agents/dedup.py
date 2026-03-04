"""Dedup/correlation stub from DESIGN.md §5.5."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..schemas.hunt import HuntResult


class Deduplicator:
    """Stub deduplicator/correlator from DESIGN.md §5.5."""

    async def run(self, hunt_result: HuntResult) -> HuntResult:
        """Return deduplicated and correlated findings (stub)."""
        _ = hunt_result
        raise NotImplementedError("Implemented in a future issue")
