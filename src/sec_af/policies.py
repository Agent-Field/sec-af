"""Custom security policy evaluation.

Evaluates org-specific security policies against scan results
using AI to determine violations.
"""

from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel, Field


PROMPT_PATH = Path(__file__).resolve().parents[2] / "prompts" / "policy_eval.txt"


class PolicyEvalResult(BaseModel):
    """Flat schema for AI policy evaluation. 4 fields."""

    violated: bool = Field(description="Whether the policy is violated")
    description: str = Field(description="How the policy is violated, or 'No violation' if compliant")
    file_path: str = Field(description="Primary file where violation occurs, or 'N/A'")
    severity: str = Field(description='Severity: "high", "medium", or "low"')


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


def _build_prompt(template: str, policy: str, recon_summary: str) -> str:
    return template.replace("{{POLICY}}", policy).replace("{{RECON_SUMMARY}}", recon_summary)


def build_prompt(template: str, policy: str, recon_summary: str) -> str:
    return _build_prompt(template, policy, recon_summary)


async def evaluate_policy(
    app: HarnessCapable,
    repo_path: str,
    policy: str,
    recon_summary: str,
) -> PolicyEvalResult:
    """Evaluate a single custom policy against the codebase."""
    from sec_af.agents._utils import extract_harness_result

    template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(template, policy, recon_summary)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Inspect the codebase to determine if this policy is violated.\n"
    )
    harness_cwd = tempfile.mkdtemp(prefix="secaf-policy-")
    try:
        result = await app.harness(prompt=prompt, schema=PolicyEvalResult, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, PolicyEvalResult, "PolicyEvaluator")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


async def evaluate_policies(
    app: HarnessCapable,
    repo_path: str,
    policies: list[str],
    recon_summary: str,
) -> list[PolicyEvalResult]:
    """Evaluate multiple custom policies sequentially."""
    results: list[PolicyEvalResult] = []
    for policy in policies:
        result = await evaluate_policy(app, repo_path, policy, recon_summary)
        results.append(result)
    return results
