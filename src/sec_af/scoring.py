from __future__ import annotations

from sec_af.schemas.prove import EvidenceLevel, VerifiedFinding

SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 8.0,
    "medium": 5.0,
    "low": 3.0,
    "info": 1.0,
}

EVIDENCE_MULTIPLIERS: dict[EvidenceLevel, float] = {
    EvidenceLevel.FULL_EXPLOIT: 1.0,
    EvidenceLevel.EXPLOIT_SCENARIO_VALIDATED: 0.9,
    EvidenceLevel.SANITIZATION_BYPASSABLE: 0.7,
    EvidenceLevel.REACHABILITY_CONFIRMED: 0.5,
    EvidenceLevel.FLOW_IDENTIFIED: 0.3,
    EvidenceLevel.STATIC_MATCH: 0.1,
}

REACHABILITY_MULTIPLIERS: dict[str, float] = {
    "externally_reachable": 1.0,
    "internally_reachable": 0.7,
    "requires_auth": 0.5,
    "requires_admin": 0.3,
}


def _reachability_multiplier(finding: VerifiedFinding) -> float:
    normalized_tags = {tag.lower() for tag in finding.tags}
    for key in (
        "externally_reachable",
        "internally_reachable",
        "requires_auth",
        "requires_admin",
    ):
        if key in normalized_tags:
            return REACHABILITY_MULTIPLIERS[key]
    return REACHABILITY_MULTIPLIERS["requires_auth"]


def compute_exploitability_score(finding: VerifiedFinding) -> float:
    severity_weight = SEVERITY_WEIGHTS[finding.severity.value]
    evidence_multiplier = EVIDENCE_MULTIPLIERS[finding.evidence_level]
    reachability = _reachability_multiplier(finding)
    chain_bonus = 2.0 if finding.chain_id else 1.0

    score = severity_weight * evidence_multiplier * reachability * chain_bonus
    return round(min(max(score, 0.0), 10.0), 2)


def compute_priority_rank(findings: list[VerifiedFinding]) -> list[VerifiedFinding]:
    return sorted(findings, key=compute_exploitability_score, reverse=True)


def assign_severity_label(score: float) -> str:
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score >= 1.0:
        return "low"
    return "info"
