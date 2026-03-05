from __future__ import annotations

from dataclasses import dataclass

import pytest

from sec_af.agents.hunt.crypto import run_crypto_hunter
from sec_af.schemas.hunt import HuntResult
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    CryptoUsage,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)


@dataclass
class _HarnessResult:
    parsed: HuntResult
    is_error: bool = False


@dataclass
class _HarnessApp:
    response: HuntResult
    prompt: str = ""

    async def harness(self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object) -> object:
        _ = (schema, cwd, kwargs)
        self.prompt = prompt
        return _HarnessResult(parsed=self.response)


def _recon_with_crypto_usage() -> ReconResult:
    return ReconResult(
        architecture=ArchitectureMap(),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(),
        config=ConfigReport(),
        security_context=SecurityContext(
            auth_model="session",
            auth_details="cookie",
            crypto_usage=[
                CryptoUsage(algorithm="MD5", usage_context="file integrity checksum", is_weak=True),
                CryptoUsage(algorithm="SHA1", usage_context="password hashing", is_weak=True),
            ],
        ),
    )


@pytest.mark.asyncio
async def test_crypto_hunter_prompt_includes_context_aware_risk_gating() -> None:
    app = _HarnessApp(response=HuntResult())

    _ = await run_crypto_hunter(app=app, repo_path=".", recon=_recon_with_crypto_usage())

    assert "- Focus CWEs: CWE-326, CWE-327, CWE-328, CWE-330, CWE-916, CWE-259, CWE-321, CWE-798" in app.prompt
    assert "Security-critical usage candidates" in app.prompt
    assert "Non-security usage candidates" in app.prompt
    assert "file integrity checksum" in app.prompt
    assert "password hashing" in app.prompt


@pytest.mark.asyncio
async def test_crypto_hunter_skips_when_recon_has_no_crypto_usage() -> None:
    recon = ReconResult(
        architecture=ArchitectureMap(),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(),
        config=ConfigReport(),
        security_context=SecurityContext(auth_model="session", auth_details="cookie", crypto_usage=[]),
    )

    app = _HarnessApp(response=HuntResult())
    result = await run_crypto_hunter(app=app, repo_path=".", recon=recon)

    assert result == HuntResult()
    assert app.prompt == ""
