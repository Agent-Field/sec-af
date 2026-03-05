from __future__ import annotations

import os
from typing import Any, cast

import pytest

from sec_af.config import AIIntegrationConfig, AuditConfig, BudgetConfig, DepthProfile
from sec_af.schemas.input import AuditInput


def test_depth_profile_values_are_stable() -> None:
    assert DepthProfile.QUICK.value == "quick"
    assert DepthProfile.STANDARD.value == "standard"
    assert DepthProfile.THOROUGH.value == "thorough"


def test_budget_config_defaults_sum_to_100_percent() -> None:
    budget = BudgetConfig()
    assert budget.recon_budget_pct + budget.hunt_budget_pct + budget.prove_budget_pct == pytest.approx(1.0)
    assert budget.max_cost_usd is None
    assert budget.max_provers is None
    assert budget.max_duration_seconds is None


def test_audit_config_from_input_maps_fields_and_budget(sample_audit_input: AuditInput) -> None:
    config = AuditConfig.from_input(sample_audit_input, repo_path="/tmp/sec-af-repo")

    assert config.repo_path == "/tmp/sec-af-repo"
    assert config.depth == DepthProfile.STANDARD
    assert config.scan_types == ["sast", "secrets", "config"]
    assert config.output_formats == ["json", "sarif", "markdown"]
    assert config.budget.max_cost_usd == 10.0
    assert config.budget.max_provers == 4
    assert config.budget.max_duration_seconds == 900


def test_audit_config_rejects_invalid_depth(sample_audit_input: AuditInput) -> None:
    dump_method = getattr(sample_audit_input, "model_dump", None)
    if callable(dump_method):
        payload = cast("dict[str, Any]", dump_method())
    else:
        dict_method = cast("Any", cast("Any", sample_audit_input).dict)
        payload = cast("dict[str, Any]", dict_method())
    payload["depth"] = "invalid"
    validate = getattr(AuditInput, "model_validate", None)
    parse_obj = cast("Any", cast("Any", AuditInput).parse_obj)
    invalid = cast("AuditInput", validate(payload) if callable(validate) else parse_obj(payload))

    with pytest.raises(ValueError):
        _ = AuditConfig.from_input(invalid, repo_path="/tmp/sec-af-repo")


def test_ai_integration_config_uses_sec_af_env_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SEC_AF_PROVIDER", "custom-provider")
    monkeypatch.setenv("HARNESS_PROVIDER", "fallback-provider")
    monkeypatch.setenv("SEC_AF_MODEL", "provider/model-a")
    monkeypatch.setenv("HARNESS_MODEL", "provider/model-b")
    monkeypatch.setenv("SEC_AF_AI_MODEL", "provider/model-c")
    monkeypatch.setenv("SEC_AF_MAX_TURNS", "75")
    monkeypatch.setenv("SEC_AF_AI_MAX_RETRIES", "6")
    monkeypatch.setenv("SEC_AF_AI_INITIAL_BACKOFF_SECONDS", "1.5")
    monkeypatch.setenv("SEC_AF_AI_MAX_BACKOFF_SECONDS", "12")
    monkeypatch.setenv("SEC_AF_OPENCODE_BIN", "/usr/local/bin/opencode")

    config = AIIntegrationConfig.from_env()

    assert config.provider == "custom-provider"
    assert config.harness_model == "provider/model-a"
    assert config.ai_model == "provider/model-c"
    assert config.max_turns == 75
    assert config.max_retries == 6
    assert config.initial_backoff_seconds == 1.5
    assert config.max_backoff_seconds == 12
    assert config.opencode_bin == "/usr/local/bin/opencode"


def test_ai_integration_config_falls_back_to_harness_and_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "SEC_AF_PROVIDER",
        "HARNESS_PROVIDER",
        "SEC_AF_MODEL",
        "HARNESS_MODEL",
        "SEC_AF_AI_MODEL",
        "AI_MODEL",
        "SEC_AF_MAX_TURNS",
        "SEC_AF_AI_MAX_RETRIES",
        "SEC_AF_AI_INITIAL_BACKOFF_SECONDS",
        "SEC_AF_AI_MAX_BACKOFF_SECONDS",
        "SEC_AF_OPENCODE_BIN",
    ):
        monkeypatch.delenv(key, raising=False)

    config = AIIntegrationConfig.from_env()

    assert config.provider == "opencode"
    assert config.harness_model == "minimax/minimax-m2.5"
    assert config.ai_model == "minimax/minimax-m2.5"
    assert config.max_turns == 50
    assert config.max_retries == 3
    assert config.initial_backoff_seconds == 2.0
    assert config.max_backoff_seconds == 8.0
    assert config.opencode_bin == "opencode"


def test_provider_env_only_includes_present_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "test-openai")
    monkeypatch.setenv("GITHUB_TOKEN", "test-gh")
    monkeypatch.delenv("OPENROUTER_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("GOOGLE_API_KEY", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)

    env = AIIntegrationConfig.from_env().provider_env()

    assert env["OPENAI_API_KEY"] == "test-openai"
    assert env["GITHUB_TOKEN"] == "test-gh"
    assert "OPENROUTER_API_KEY" not in env
    assert "XDG_DATA_HOME" in env
