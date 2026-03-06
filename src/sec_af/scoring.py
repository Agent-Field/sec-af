from __future__ import annotations

from sec_af.schemas.hunt import Severity
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

# CWE families with minimum severity floors.
# LLMs often underestimate severity for well-known vulnerability classes.
# This ensures critical CWEs are never reported below a sane minimum.
_SEVERITY_ORDER: dict[str, int] = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

CWE_SEVERITY_FLOOR: dict[str, str] = {
    # Remote Code Execution / Command Injection — always critical
    "CWE-78": "critical",
    "CWE-77": "critical",
    "CWE-94": "critical",
    "CWE-95": "critical",
    "CWE-96": "critical",
    # SQL Injection — always critical
    "CWE-89": "critical",
    # Deserialization — always critical
    "CWE-502": "critical",
    # SSRF — at least high
    "CWE-918": "high",
    # Authentication Bypass — at least high
    "CWE-287": "high",
    "CWE-290": "high",
    "CWE-306": "high",
    # Hardcoded Credentials — at least high
    "CWE-798": "high",
    # Path Traversal — at least high
    "CWE-22": "high",
    # XXE — at least high
    "CWE-611": "high",
    # XSS — at least medium (already is, but explicit)
    "CWE-79": "medium",
    # Broken Access Control — at least high
    "CWE-840": "high",
    "CWE-862": "high",
    "CWE-863": "high",
}


def apply_cwe_severity_floor(cwe_id: str, current_severity: Severity) -> Severity:
    """Upgrade severity if the CWE has a known minimum floor.

    LLMs consistently underrate severity for injection and RCE classes.
    This provides a hard floor so CWE-78 can never be reported as "medium".
    """
    floor_label = CWE_SEVERITY_FLOOR.get(cwe_id)
    if floor_label is None:
        return current_severity
    if _SEVERITY_ORDER.get(floor_label, 0) > _SEVERITY_ORDER.get(current_severity.value, 0):
        return Severity(floor_label)
    return current_severity


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
    # Default: assume externally reachable when tags are empty (no reachability
    # data available).  The previous default of "requires_auth" (0.5) severely
    # penalised every finding when reachability assessment is not wired into the
    # DAG path — causing critical CWEs to score 2.5/10.
    if not normalized_tags:
        return REACHABILITY_MULTIPLIERS["externally_reachable"]
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
