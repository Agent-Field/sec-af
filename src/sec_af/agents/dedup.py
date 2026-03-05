from __future__ import annotations

import asyncio
import hashlib
from collections import defaultdict
from typing import TYPE_CHECKING, Protocol, cast

from sec_af.schemas.hunt import (
    ChainCorrelationResult,
    Confidence,
    HuntResult,
    PotentialChain,
    RawFinding,
    Severity,
)

if TYPE_CHECKING:
    from sec_af.schemas.recon import ReconResult


class HarnessCapable(Protocol):
    async def harness(
        self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object
    ) -> object: ...


class AICapable(Protocol):
    async def ai(
        self,
        *,
        user: str,
        schema: object,
        system: str | None = None,
        **kwargs: object,
    ) -> object: ...


_SEVERITY_SCORE: dict[Severity, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

_CONFIDENCE_SCORE: dict[Confidence, int] = {
    Confidence.HIGH: 3,
    Confidence.MEDIUM: 2,
    Confidence.LOW: 1,
}

_CHAIN_PATTERNS: tuple[tuple[str, ...], ...] = (
    ("CWE-918", "CWE-798"),
    ("CWE-862", "CWE-285"),
    ("CWE-89", "CWE-200"),
    ("CWE-16", "CWE-798"),
)


def compute_fingerprint(finding: RawFinding) -> str:
    key = f"{finding.file_path}:{finding.start_line}:{finding.cwe_id}"
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]


def _confidence_value(finding: RawFinding) -> int:
    return _CONFIDENCE_SCORE.get(finding.confidence, 0)


def _severity_confidence_sort_key(finding: RawFinding) -> tuple[int, int]:
    return (_SEVERITY_SCORE.get(finding.estimated_severity, 0), _CONFIDENCE_SCORE.get(finding.confidence, 0))


def _merge_duplicate(existing: RawFinding, incoming: RawFinding) -> RawFinding:
    winner = existing
    loser = incoming
    if _confidence_value(incoming) > _confidence_value(existing):
        winner = incoming
        loser = existing

    if len(loser.description) > len(winner.description):
        winner.description = loser.description

    winner.related_files = sorted(set(winner.related_files) | set(loser.related_files))
    if winner.data_flow is None and loser.data_flow is not None:
        winner.data_flow = loser.data_flow
    winner.fingerprint = winner.fingerprint or compute_fingerprint(winner)
    return winner


async def _ai_check_duplicate(
    app: AICapable,
    candidate: RawFinding,
    existing: RawFinding,
    timeout_seconds: float = 60.0,
) -> bool:
    from sec_af.schemas.gates import DuplicateCheck

    prompt = (
        "Determine if these two security findings are duplicates (same root cause).\n\n"
        f"Finding A:\n"
        f"- Title: {candidate.title}\n"
        f"- CWE: {candidate.cwe_id} ({candidate.cwe_name})\n"
        f"- File: {candidate.file_path}:{candidate.start_line}\n"
        f"- Description: {candidate.description[:200]}\n\n"
        f"Finding B:\n"
        f"- Title: {existing.title}\n"
        f"- CWE: {existing.cwe_id} ({existing.cwe_name})\n"
        f"- File: {existing.file_path}:{existing.start_line}\n"
        f"- Description: {existing.description[:200]}"
    )
    try:
        result = await asyncio.wait_for(
            app.ai(user=prompt, schema=DuplicateCheck),
            timeout=timeout_seconds,
        )
        if isinstance(result, DuplicateCheck):
            return result.is_duplicate
        if isinstance(result, dict):
            payload = cast("dict[str, object]", result)
            return DuplicateCheck.model_validate(payload).is_duplicate
        return False
    except Exception:
        return False


async def _deduplicate_with_ai(
    findings: list[RawFinding],
    app: object,
) -> list[RawFinding]:
    by_fingerprint: dict[str, RawFinding] = {}
    for finding in findings:
        finding.fingerprint = finding.fingerprint or compute_fingerprint(finding)
        existing = by_fingerprint.get(finding.fingerprint)
        if existing is None:
            by_fingerprint[finding.fingerprint] = finding
            continue
        by_fingerprint[finding.fingerprint] = _merge_duplicate(existing, finding)

    deduped = list(by_fingerprint.values())

    by_file: dict[str, list[RawFinding]] = defaultdict(list)
    for finding in deduped:
        by_file[finding.file_path].append(finding)

    to_remove: set[str] = set()
    has_ai = hasattr(app, "ai") and callable(getattr(app, "ai", None))
    if has_ai:
        ai_app = cast("AICapable", app)

        # Collect all candidate pairs up front so we can check them in parallel.
        pairs: list[tuple[RawFinding, RawFinding]] = []
        for file_findings in by_file.values():
            if len(file_findings) < 2:
                continue
            for i, candidate in enumerate(file_findings):
                for existing in file_findings[i + 1 :]:
                    if candidate.cwe_id == existing.cwe_id:
                        pairs.append((candidate, existing))

        if pairs:
            results = await asyncio.gather(*[_ai_check_duplicate(ai_app, a, b) for a, b in pairs])
            for (candidate, existing), is_dup in zip(pairs, results):
                if not is_dup:
                    continue
                # Skip if either side was already removed by an earlier pair result.
                if candidate.fingerprint in to_remove or existing.fingerprint in to_remove:
                    continue
                if _confidence_value(candidate) >= _confidence_value(existing):
                    to_remove.add(existing.fingerprint)
                    by_fingerprint[candidate.fingerprint] = _merge_duplicate(candidate, existing)
                else:
                    to_remove.add(candidate.fingerprint)
                    by_fingerprint[existing.fingerprint] = _merge_duplicate(existing, candidate)

    final = [f for f in deduped if f.fingerprint not in to_remove]
    final.sort(key=_severity_confidence_sort_key, reverse=True)
    return final


def _fallback_correlate(findings: list[RawFinding]) -> list[PotentialChain]:
    findings_by_cwe: dict[str, list[RawFinding]] = defaultdict(list)
    for finding in findings:
        findings_by_cwe[finding.cwe_id.upper()].append(finding)

    chains: list[PotentialChain] = []
    for first_cwe, second_cwe in _CHAIN_PATTERNS:
        first_candidates = findings_by_cwe.get(first_cwe, [])
        second_candidates = findings_by_cwe.get(second_cwe, [])
        if not first_candidates or not second_candidates:
            continue

        first = first_candidates[0]
        second = second_candidates[0]
        chains.append(
            PotentialChain(
                title=f"Potential attack chain: {first_cwe} -> {second_cwe}",
                finding_ids=[first.id, second.id],
                combined_impact=(
                    "Combined exploitation path discovered by correlation heuristics; verify chain during PROVE phase."
                ),
                estimated_severity=max(
                    first.estimated_severity,
                    second.estimated_severity,
                    key=lambda severity: _SEVERITY_SCORE.get(severity, 0),
                ),
            )
        )
    return chains


def _seed_chain_context(seed_chains: list[PotentialChain], findings: list[RawFinding]) -> str:
    by_id = {finding.id: finding for finding in findings}
    lines = ["Seed chain candidates (validate and expand these):"]
    if not seed_chains:
        lines.append("- No heuristic seed chains were detected from hardcoded CWE pairs.")
    else:
        for chain in seed_chains:
            ordered_labels: list[str] = []
            for finding_id in chain.finding_ids:
                finding = by_id.get(finding_id)
                if finding is None:
                    continue
                ordered_labels.append(finding.cwe_name)

            label = " -> ".join(ordered_labels) if ordered_labels else chain.title
            lines.append(f"- Potential chain: {label} (findings {', '.join(chain.finding_ids)})")

    lines.append("Look for additional multi-step attack chains beyond these seeds.")
    return "\n".join(lines)


def _split_pipe(s: str, expected: int) -> list[str]:
    parts = [p.strip() for p in s.split("|", maxsplit=expected - 1)]
    while len(parts) < expected:
        parts.append("")
    return parts


def _parse_chain_from_str(entry: str, available_ids: set[str]) -> PotentialChain | None:
    parts = _split_pipe(entry, 4)
    title = parts[0]
    raw_ids = [fid.strip() for fid in parts[1].split(",") if fid.strip()]
    valid_ids = [fid for fid in raw_ids if fid in available_ids]
    if len(valid_ids) < 2:
        return None
    impact = parts[2] or "Combined exploitation path"
    severity_str = parts[3].lower().strip()
    severity_map = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
    }
    severity = severity_map.get(severity_str, Severity.HIGH)
    return PotentialChain(title=title, finding_ids=valid_ids, combined_impact=impact, estimated_severity=severity)


def _extract_chain_correlation(result: object) -> ChainCorrelationResult | None:
    if isinstance(result, ChainCorrelationResult):
        return result
    parsed = getattr(result, "parsed", None)
    if isinstance(parsed, ChainCorrelationResult):
        return parsed
    if isinstance(parsed, dict):
        try:
            return ChainCorrelationResult.model_validate(cast("dict[str, object]", parsed))
        except Exception:
            return None
    return None


async def deduplicate_and_correlate(
    findings: list[RawFinding],
    recon: ReconResult,
    app: HarnessCapable,
    repo_path: str,
) -> HuntResult:
    deduplicated = await _deduplicate_with_ai(findings, app)
    chains: list[PotentialChain] = []
    seed_chains = _fallback_correlate(deduplicated)
    seed_context = _seed_chain_context(seed_chains, deduplicated)

    if deduplicated:
        import shutil
        import tempfile

        findings_summary = "\n".join(
            f"- id={f.id} cwe={f.cwe_id} file={f.file_path}:{f.start_line} "
            f"title={f.title} severity={f.estimated_severity.value}"
            for f in deduplicated
        )
        prompt = (
            "You are SEC-AF's chain correlator.\n"
            "Identify multi-step attack chains across the findings below.\n"
            "A chain means one vulnerability enables exploitation of another.\n"
            "Also flag any remaining duplicate IDs that should be dropped.\n\n"
            f"Findings:\n{findings_summary}\n\n"
            f"{seed_context}"
        )
        harness_cwd = tempfile.mkdtemp(prefix="secaf-dedup-")
        try:
            harness_result = await asyncio.wait_for(
                app.harness(prompt, schema=ChainCorrelationResult, cwd=harness_cwd, project_dir=repo_path),
                timeout=600.0,
            )
            parsed = _extract_chain_correlation(harness_result)
            if parsed is not None:
                available_ids = {f.id for f in deduplicated}
                for chain_str in parsed.chains:
                    chain = _parse_chain_from_str(chain_str, available_ids)
                    if chain:
                        chains.append(chain)
                if parsed.duplicate_ids:
                    drop_set = set(parsed.duplicate_ids)
                    deduplicated = [f for f in deduplicated if f.id not in drop_set]
        except Exception:
            chains = []
        finally:
            shutil.rmtree(harness_cwd, ignore_errors=True)

    if not chains:
        chains = seed_chains

    deduplicated.sort(key=_severity_confidence_sort_key, reverse=True)
    return HuntResult(
        findings=deduplicated,
        chains=chains,
        total_raw=len(findings),
        deduplicated_count=len(deduplicated),
        chain_count=len(chains),
    )


class Deduplicator:
    def __init__(self, app: HarnessCapable, repo_path: str):
        self._app: HarnessCapable
        self._repo_path: str
        self._app = app
        self._repo_path = repo_path

    async def run(self, findings: list[RawFinding], recon: ReconResult) -> HuntResult:
        return await deduplicate_and_correlate(findings, recon, self._app, self._repo_path)


__all__ = ["Deduplicator", "compute_fingerprint", "deduplicate_and_correlate"]
