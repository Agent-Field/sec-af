"""Shared fixture stubs from DESIGN.md §3 (pipeline stages)."""

from __future__ import annotations

import pytest


@pytest.fixture
def sample_repo_url() -> str:
    """Fixture stub for repository URL inputs from DESIGN.md §3."""
    return "https://example.com/repo.git"
