from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from sec_af.scoring import (
    assign_severity_label,
    compute_exploitability_score,
    compute_priority_rank,
)
from sec_af.schemas.hunt import FindingType, Severity
from sec_af.schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding


def make_finding(
    *,
    severity: Severity = Severity.MEDIUM,
    evidence_level: EvidenceLevel = EvidenceLevel.FLOW_IDENTIFIED,
    tags: set[str] | None = None,
    chain_id: str | None = None,
) -> VerifiedFinding:
    return VerifiedFinding(
        fingerprint="abc123",
        title="Sample finding",
        description="Sample description",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        tags=tags or set(),
        verdict=Verdict.CONFIRMED,
        evidence_level=evidence_level,
        rationale="Reasonable rationale",
        severity=severity,
        exploitability_score=0.0,
        location=Location(file_path="app.py", start_line=10, end_line=10),
        chain_id=chain_id,
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=0.0,
    )


@pytest.mark.parametrize(
    ("severity", "expected"),
    [
        (Severity.CRITICAL, 10.0),
        (Severity.HIGH, 8.0),
        (Severity.MEDIUM, 5.0),
        (Severity.LOW, 3.0),
        (Severity.INFO, 1.0),
    ],
)
def test_compute_exploitability_score_respects_severity_weights(severity: Severity, expected: float) -> None:
    finding = make_finding(
        severity=severity,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        tags={"externally_reachable"},
    )
    assert compute_exploitability_score(finding) == expected


def test_compute_exploitability_score_applies_chain_bonus_and_clamps_to_ten() -> None:
    finding = make_finding(
        severity=Severity.CRITICAL,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        tags={"externally_reachable"},
        chain_id="chain-1",
    )
    assert compute_exploitability_score(finding) == 10.0


def test_compute_exploitability_score_uses_partial_flow_and_internal_reachability() -> None:
    finding = make_finding(
        severity=Severity.MEDIUM,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        tags={"internally_reachable"},
    )
    assert compute_exploitability_score(finding) == 1.75


def test_compute_exploitability_score_uses_requires_admin_and_unverified() -> None:
    finding = make_finding(
        severity=Severity.HIGH,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        tags={"requires_admin"},
    )
    assert compute_exploitability_score(finding) == 0.24


def test_compute_exploitability_score_defaults_reachability_when_missing() -> None:
    finding = make_finding(
        severity=Severity.LOW,
        evidence_level=EvidenceLevel.SANITIZATION_BYPASSABLE,
    )
    assert compute_exploitability_score(finding) == 1.05


def test_compute_exploitability_score_is_deterministic() -> None:
    finding = make_finding(
        severity=Severity.HIGH,
        evidence_level=EvidenceLevel.EXPLOIT_SCENARIO_VALIDATED,
        tags={"requires_auth"},
    )
    assert compute_exploitability_score(finding) == compute_exploitability_score(finding)


def test_compute_priority_rank_sorts_descending() -> None:
    low = make_finding(
        severity=Severity.INFO,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        tags={"requires_admin"},
    )
    medium = make_finding(
        severity=Severity.MEDIUM,
        evidence_level=EvidenceLevel.FLOW_IDENTIFIED,
        tags={"requires_auth"},
    )
    high = make_finding(
        severity=Severity.CRITICAL,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        tags={"externally_reachable"},
    )

    ranked = compute_priority_rank([medium, high, low])
    assert ranked == [high, medium, low]


@pytest.mark.parametrize(
    ("score", "label"),
    [
        (10.0, "critical"),
        (9.0, "critical"),
        (8.9, "high"),
        (7.0, "high"),
        (6.9, "medium"),
        (4.0, "medium"),
        (3.9, "low"),
        (1.0, "low"),
        (0.9, "info"),
        (0.0, "info"),
    ],
)
def test_assign_severity_label(score: float, label: str) -> None:
    assert assign_severity_label(score) == label
