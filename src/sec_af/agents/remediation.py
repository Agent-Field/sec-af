from __future__ import annotations

import json
import shutil
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING, Any, Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.prove import RemediationSuggestion

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


PROMPT_PATH = Path(__file__).resolve().parents[3] / "prompts" / "remediation.txt"


def _build_prompt(template: str, finding: RawFinding, verdict: str, rationale: str) -> str:
    replacements = {
        "{{TITLE}}": finding.title,
        "{{DESCRIPTION}}": finding.description,
        "{{CWE_ID}}": finding.cwe_id,
        "{{CWE_NAME}}": finding.cwe_name,
        "{{FILE_PATH}}": finding.file_path,
        "{{START_LINE}}": str(finding.start_line),
        "{{CODE_SNIPPET}}": finding.code_snippet,
        "{{FINDING_TYPE}}": finding.finding_type.value,
        "{{VERDICT}}": verdict,
        "{{RATIONALE}}": rationale,
        "{{RELATED_FILES}}": json.dumps(finding.related_files, indent=2),
    }
    prompt = template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)
    return prompt


async def run_remediation(
    app: HarnessCapable,
    repo_path: str,
    finding: RawFinding,
    verdict: str,
    rationale: str,
) -> RemediationSuggestion:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        _build_prompt(prompt_template, finding, verdict, rationale)
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Use the repository path to inspect the actual source code for accurate patch generation."
    )
    agent_name = "remediation"
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-{agent_name}-")
    try:
        result = await app.harness(prompt=prompt, schema=RemediationSuggestion, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, RemediationSuggestion, "RemediationAgent")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


async def generate_remediation(
    app: HarnessCapable,
    repo_path: str,
    finding: Any,
) -> RemediationSuggestion:
    """Adapts VerifiedFinding (location-based) to the prompt template expected by run_remediation."""
    location = getattr(finding, "location", None)
    file_path: str = getattr(location, "file_path", "") if location else getattr(finding, "file_path", "")
    start_line: int = getattr(location, "start_line", 0) if location else getattr(finding, "start_line", 0)

    proof = getattr(finding, "proof", None)
    code_snippet: str = (getattr(proof, "vulnerable_code", "") or "") if proof else ""

    related_locs: list[Any] = getattr(finding, "related_locations", [])
    related_files: list[str] = [loc.file_path for loc in related_locs] if related_locs else []

    verdict_val: Any = getattr(finding, "verdict", "confirmed")
    verdict_str: str = str(verdict_val.value) if hasattr(verdict_val, "value") else str(verdict_val)
    rationale: str = getattr(finding, "rationale", "")

    finding_type_val: Any = getattr(finding, "finding_type", None)
    finding_type_str: str = (
        str(finding_type_val.value) if hasattr(finding_type_val, "value") else str(finding_type_val or "")
    )

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    replacements: dict[str, str] = {
        "{{TITLE}}": getattr(finding, "title", ""),
        "{{DESCRIPTION}}": getattr(finding, "description", ""),
        "{{CWE_ID}}": getattr(finding, "cwe_id", ""),
        "{{CWE_NAME}}": getattr(finding, "cwe_name", ""),
        "{{FILE_PATH}}": file_path,
        "{{START_LINE}}": str(start_line),
        "{{CODE_SNIPPET}}": code_snippet,
        "{{FINDING_TYPE}}": finding_type_str,
        "{{VERDICT}}": verdict_str,
        "{{RATIONALE}}": rationale,
        "{{RELATED_FILES}}": json.dumps(related_files, indent=2),
    }
    prompt = prompt_template
    for needle, value in replacements.items():
        prompt = prompt.replace(needle, value)

    prompt += (
        "\n\nCONTEXT:\n"
        f"- Repository path: {repo_path}\n"
        "- Use the repository path to inspect the actual source code for accurate patch generation."
    )

    harness_cwd = tempfile.mkdtemp(prefix="secaf-remediation-")
    try:
        result = await app.harness(
            prompt=prompt,
            schema=RemediationSuggestion,
            cwd=harness_cwd,
            project_dir=repo_path,
        )
        return extract_harness_result(result, RemediationSuggestion, "RemediationAgent")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)
