from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import Any, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import ReachabilityProof


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "dep_reachability.txt"


def _build_prompt(template: str, finding: dict[str, Any], depth: str) -> str:
    replacements = {
        "{{CVE}}": str(finding.get("cve", "")),
        "{{PACKAGE}}": str(finding.get("package", "")),
        "{{VULNERABLE_FUNCTION}}": str(finding.get("vulnerable_function", "")),
        "{{VERSION}}": str(finding.get("version", "")),
        "{{EVIDENCE}}": json.dumps(finding.get("evidence", {}), indent=2),
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_dep_reachability(
    app: HarnessCapable,
    repo_path: str,
    finding: dict[str, Any],
    depth: str,
) -> ReachabilityProof:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, depth)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path above for file inspection during dependency reachability analysis."
    )
    agent_name = "prove-dep-reachability"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=ReachabilityProof, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, ReachabilityProof, "DependencyReachabilityAnalyzer")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
