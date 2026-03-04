"""Harness integration scaffold from DESIGN.md §2.3 and §2.4."""

from __future__ import annotations

from typing import Any


class HarnessClient:
    """Stub wrappers for `.harness()`/`.ai()` routing from DESIGN.md §2.4."""

    async def run_harness(self, prompt: str, schema: type[Any], cwd: str) -> Any:
        """Run a complex harness task (stub)."""
        _ = (prompt, schema, cwd)
        raise NotImplementedError("Implemented in a future issue")

    async def run_ai_gate(self, prompt: str, schema: type[Any]) -> Any:
        """Run a simple AI gate call (stub)."""
        _ = (prompt, schema)
        raise NotImplementedError("Implemented in a future issue")
