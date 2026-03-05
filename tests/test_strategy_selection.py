"""Tests for AI-driven strategy selection in hunt phase."""

from __future__ import annotations

import pytest

from sec_af.schemas.gates import StrategySelection
from sec_af.schemas.hunt import HuntStrategy
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)


@pytest.fixture
def sample_recon() -> ReconResult:
    """Create a sample recon result for testing."""
    return ReconResult(
        architecture=ArchitectureMap(modules=[], api_surface=[]),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(
            direct_count=5,
            transitive_count=20,
        ),
        config=ConfigReport(),
        security_context=SecurityContext(
            auth_model="jwt",
            auth_details="JWT with RS256",
            crypto_usage=[],
            framework_security=["django-rest-framework"],
        ),
        languages=["python"],
        frameworks=["django"],
        lines_of_code=5000,
        file_count=42,
    )


class MockAIGate:
    """Mock AIGateWrapper for testing."""

    async def select_strategy(
        self,
        *,
        recon_summary: str,
        depth: str,
        default_candidates: list[str],
    ) -> StrategySelection:
        """Mock strategy selection that returns a subset of candidates."""
        # Simulate AI selecting strategies based on recon
        selected = default_candidates[:2]  # Simple mock: select first 2
        return StrategySelection(
            strategies=selected,
            rationale="Selected based on recon context",
        )


@pytest.mark.asyncio
async def test_ai_gate_select_strategy_with_mock() -> None:
    """Test strategy selection with mock AI gate."""
    gate = MockAIGate()

    default_candidates = [
        HuntStrategy.INJECTION.value,
        HuntStrategy.AUTH.value,
        HuntStrategy.DATA_EXPOSURE.value,
        HuntStrategy.CONFIG_SECRETS.value,
    ]

    result = await gate.select_strategy(
        recon_summary="Python/Django app, 5000 LOC, JWT auth, PostgreSQL",
        depth="standard",
        default_candidates=default_candidates,
    )

    assert isinstance(result, StrategySelection)
    assert isinstance(result.strategies, list)
    assert len(result.strategies) > 0
    assert all(isinstance(s, str) for s in result.strategies)
    assert isinstance(result.rationale, str)


def test_recon_summary_string_format(sample_recon: ReconResult) -> None:
    """Test that _recon_summary_string produces a natural language summary."""
    # This test will fail until _recon_summary_string is implemented
    from sec_af.reasoners.phases import _recon_summary_string

    summary = _recon_summary_string(sample_recon)

    # Verify it's a string
    assert isinstance(summary, str)
    # Verify it contains key information
    assert "python" in summary.lower()
    assert "django" in summary.lower()
    assert "jwt" in summary.lower()
    # Verify it's not empty
    assert len(summary) > 0


def test_default_strategies_include_dos(sample_recon: ReconResult) -> None:
    from sec_af.reasoners.phases import _default_strategies

    strategies = _default_strategies(sample_recon, "standard")

    assert HuntStrategy.DOS in strategies
