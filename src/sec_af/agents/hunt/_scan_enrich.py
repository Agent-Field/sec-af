from __future__ import annotations

import asyncio
import shutil
import tempfile
from pathlib import Path
from typing import Protocol

from sec_af.agents._utils import extract_harness_result
from sec_af.schemas.hunt import (
    Confidence,
    EnrichedFinding,
    FindingType,
    RawFinding,
    ScanLocationsResult,
    Severity,
    VulnLocation,
)
from sec_af.schemas.recon import DataFlowStep


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


PROMPTS_DIR = Path(__file__).resolve().parents[4] / "prompts" / "hunt"
SCAN_PROMPT_PATH = PROMPTS_DIR / "scan_locations.txt"
ENRICH_PROMPT_PATH = PROMPTS_DIR / "enrich_finding.txt"


def _to_finding_type(value: str) -> FindingType:
    try:
        return FindingType(value.lower())
    except ValueError:
        return FindingType.SAST


def _to_severity(value: str) -> Severity:
    try:
        return Severity(value.lower())
    except ValueError:
        return Severity.MEDIUM


def _to_confidence(value: str) -> Confidence:
    try:
        return Confidence(value.lower())
    except ValueError:
        return Confidence.MEDIUM


async def scan_locations(app: HarnessCapable, prompt: str, repo_path: str) -> list[VulnLocation]:
    scan_template = SCAN_PROMPT_PATH.read_text(encoding="utf-8")
    scan_prompt = scan_template.replace("{{HUNTER_PROMPT}}", prompt)
    harness_cwd = tempfile.mkdtemp(prefix="secaf-hunt-scan-")
    try:
        result = await app.harness(
            prompt=scan_prompt, schema=ScanLocationsResult, cwd=harness_cwd, project_dir=repo_path
        )
        parsed = extract_harness_result(result, ScanLocationsResult, "Hunt location scanner")
        return parsed.locations
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


async def enrich_location(
    app: HarnessCapable,
    location: VulnLocation,
    finding_type: str,
    strategy: str,
    recon_context: str,
    repo_path: str,
) -> EnrichedFinding:
    enrich_template = ENRICH_PROMPT_PATH.read_text(encoding="utf-8")
    enrich_prompt = (
        enrich_template.replace("{{FINDING_TYPE}}", finding_type)
        .replace("{{STRATEGY}}", strategy)
        .replace("{{RECON_CONTEXT}}", recon_context)
        .replace("{{FILE_PATH}}", location.file_path)
        .replace("{{START_LINE}}", str(location.start_line))
        .replace("{{CODE_SNIPPET}}", location.code_snippet)
        .replace("{{PATTERN_TYPE}}", location.pattern_type)
    )
    harness_cwd = tempfile.mkdtemp(prefix=f"secaf-hunt-enrich-{strategy}-")
    try:
        result = await app.harness(prompt=enrich_prompt, schema=EnrichedFinding, cwd=harness_cwd, project_dir=repo_path)
        return extract_harness_result(result, EnrichedFinding, "Hunt finding enricher")
    finally:
        shutil.rmtree(harness_cwd, ignore_errors=True)


async def enrich_locations_parallel(
    app: HarnessCapable,
    locations: list[VulnLocation],
    finding_type: str,
    strategy: str,
    recon_context: str,
    repo_path: str,
    max_concurrent: int = 5,
) -> list[EnrichedFinding]:
    if not locations:
        return []

    semaphore = asyncio.Semaphore(max(1, max_concurrent))

    async def _run(location: VulnLocation) -> EnrichedFinding:
        async with semaphore:
            return await enrich_location(
                app=app,
                location=location,
                finding_type=finding_type,
                strategy=strategy,
                recon_context=recon_context,
                repo_path=repo_path,
            )

    return await asyncio.gather(*[_run(location) for location in locations])


def assemble_finding(location: VulnLocation, enriched: EnrichedFinding, finding_type: str, strategy: str) -> RawFinding:
    snippet_line_count = max(1, location.code_snippet.count("\n") + 1)
    data_flow = None
    summary = enriched.data_flow_summary.strip()
    if summary:
        data_flow = [
            DataFlowStep(
                file_path=location.file_path,
                line=location.start_line,
                component=strategy,
                operation=summary,
            )
        ]

    return RawFinding(
        hunter_strategy=strategy,
        title=enriched.title,
        description=enriched.description,
        finding_type=_to_finding_type(finding_type),
        cwe_id=enriched.cwe_id,
        cwe_name=enriched.cwe_id,
        file_path=location.file_path,
        start_line=location.start_line,
        end_line=location.start_line + snippet_line_count - 1,
        code_snippet=location.code_snippet,
        estimated_severity=_to_severity(enriched.severity),
        confidence=_to_confidence(enriched.confidence),
        data_flow=data_flow,
    )
