"""Tests for custom security policy schemas and evaluation logic."""

import sec_af.policies as policies
from sec_af.policies import PolicyEvalResult, build_prompt


def test_policy_eval_result_schema():
    result = PolicyEvalResult(
        violated=True,
        description="No authentication middleware found on /api/admin endpoints",
        file_path="src/routes/admin.py",
        severity="high",
    )
    assert result.violated is True
    assert "admin" in result.description


def test_policy_eval_result_compliant():
    result = PolicyEvalResult(
        violated=False,
        description="No violation found",
        file_path="N/A",
        severity="low",
    )
    assert result.violated is False


def test_build_prompt_substitution():
    template = "Policy: {{POLICY}}\nRecon: {{RECON_SUMMARY}}"
    result = build_prompt(template, "All endpoints must require auth", "5 files, 3 endpoints")
    assert "All endpoints must require auth" in result
    assert "5 files, 3 endpoints" in result


def test_prompt_file_exists():
    assert policies.PROMPT_PATH.exists(), f"Prompt file not found at {policies.PROMPT_PATH}"
