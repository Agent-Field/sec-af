from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from typing import TYPE_CHECKING, Protocol, cast

from sec_af.schemas.hunt import Confidence, DeduplicatedResult, HuntResult, PotentialChain, RawFinding, Severity

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
        result = await app.ai(user=prompt, schema=DuplicateCheck)
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
        for file_findings in by_file.values():
            if len(file_findings) < 2:
                continue
            for i, candidate in enumerate(file_findings):
                if candidate.fingerprint in to_remove:
                    continue
                for existing in file_findings[i + 1 :]:
                    if existing.fingerprint in to_remove:
                        continue
                    if candidate.cwe_id == existing.cwe_id:
                        is_dup = await _ai_check_duplicate(ai_app, candidate, existing)
                        if is_dup:
                            if _confidence_value(candidate) >= _confidence_value(existing):
                                to_remove.add(existing.fingerprint)
                                by_fingerprint[candidate.fingerprint] = _merge_duplicate(candidate, existing)
                            else:
                                to_remove.add(candidate.fingerprint)
                                by_fingerprint[existing.fingerprint] = _merge_duplicate(existing, candidate)
                            break

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


def _extract_dedup_payload(result: object) -> DeduplicatedResult | None:
    if isinstance(result, DeduplicatedResult):
        return result

    parsed = getattr(result, "parsed", None)
    if isinstance(parsed, DeduplicatedResult):
        return parsed
    if isinstance(parsed, dict):
        try:
            parsed_payload = cast("dict[str, object]", parsed)
            return DeduplicatedResult.model_validate(parsed_payload)
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

        prompt = (
            "You are SEC-AF's deduplicator/correlator.\n"
            "Take multiple turns:\n"
            "1) Validate duplicate groups and tighten merged findings.\n"
            "2) Validate seed chain candidates and identify multi-step attack chains across findings.\n"
            "   A multi-step attack chain means one vulnerability enables exploitation of another step.\n"
            "   You are not limited to the provided seeds; discover additional chains when justified.\n"
            "3) Return final JSON matching DeduplicatedResult.\n\n"
            f"Recon context:\n{recon.model_dump_json()}\n\n"
            f"Deduplicated candidate findings:\n{json.dumps([f.model_dump() for f in deduplicated])}\n\n"
            f"{seed_context}"
        )
        harness_cwd = tempfile.mkdtemp(prefix="secaf-dedup-")
        try:
            harness_result = await app.harness(
                prompt, schema=DeduplicatedResult, cwd=harness_cwd, project_dir=repo_path
            )
            parsed = _extract_dedup_payload(harness_result)
            if parsed is not None:
                deduplicated = parsed.findings or deduplicated
                chains = parsed.chains
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
