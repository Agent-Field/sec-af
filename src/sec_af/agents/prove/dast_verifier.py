from __future__ import annotations

import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import DastVerificationResult

if TYPE_CHECKING:
    from sec_af.schemas.hunt import RawFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "dast_verifier.txt"


def _build_prompt(template: str, finding: RawFinding, exploit_payload: str, depth: str) -> str:
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{CWE_ID}}": finding.cwe_id,
        "{{FILE_PATH}}": finding.file_path,
        "{{EXPLOIT_PAYLOAD}}": exploit_payload,
        "{{DEPTH}}": depth,
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_dast_verifier(
    app: HarnessCapable,
    repo_path: str,
    finding: RawFinding,
    exploit_payload: str,
    depth: str,
) -> DastVerificationResult:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, exploit_payload, depth)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path above for file inspection during DAST-style verification."
    )
    agent_name = "prove-dast"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=DastVerificationResult,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, DastVerificationResult, "DastVerifier")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
