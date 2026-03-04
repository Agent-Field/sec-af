from __future__ import annotations

from pathlib import Path
from typing import Protocol, cast, runtime_checkable

from sec_af.schemas.recon import DependencyReport


@runtime_checkable
class HarnessResultLike(Protocol):
    parsed: object | None


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "recon" / "dependencies.txt"


def _extract_parsed(result: object, schema: type[DependencyReport]) -> DependencyReport:
    if isinstance(result, HarnessResultLike):
        parsed = result.parsed
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**cast("dict[str, object]", parsed))
    if isinstance(result, schema):
        return result
    raise TypeError("Dependency auditor did not return a valid DependencyReport")


async def run_dependency_auditor(app: HarnessCapable, repo_path: str) -> DependencyReport:
    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = (
        prompt_template
        + "\n\nCONTEXT:\n"
        + f"- Repository path: {repo_path}\n"
        + "- Take multiple turns to explore the codebase first, then build your analysis.\n"
        + "- Write final JSON only when analysis is complete."
    )
    result = await app.harness(prompt=prompt, schema=DependencyReport, cwd=repo_path)
    return _extract_parsed(result, DependencyReport)
