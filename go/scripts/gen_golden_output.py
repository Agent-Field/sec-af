#!/usr/bin/env python3
"""Committed golden generator for internal/output (SARIF, JSON, reports).

Standalone sibling of ``gen_golden.py``: ``gen_golden.py`` calls ``gen_output()``
from here, and this file also runs on its own.

REPRODUCE (from the repo root of the worktree):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python \
        go/scripts/gen_golden_output.py

Every golden is written by CALLING THE REAL PYTHON FUNCTION — a generator that
re-implemented the formatting would happily agree with a broken port.
Deterministic and idempotent: every input is a fixed literal and the one clock
read (compliance_report's "Generated:" header) is frozen, so rerunning
overwrites the goldens with identical bytes unless src/sec_af/output/ changed.
"""

from __future__ import annotations

import json
import os
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Make `sec_af` importable when run from the repo root without an install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

_GO_ROOT = os.path.join(_REPO_ROOT, "go")


def _write(rel_path: str, text: str) -> None:
    """Write text under go/ and report it, creating parent directories."""
    dest = Path(_GO_ROOT) / rel_path
    dest.parent.mkdir(parents=True, exist_ok=True)
    _ = dest.write_text(text, encoding="utf-8")
    print(f"wrote {rel_path} ({len(text.encode('utf-8'))} bytes)")


# ---------------------------------------------------------------------------
# S8 - internal/output: SARIF, full/summary JSON, Markdown report, compliance
# report.
#
# These four generators are the only place SEC-AF emits bytes a third party
# reads (a SARIF uploader, a PDF converter, a reviewer), so the Go port has to
# match them exactly - down to Python's float repr ("10.0", not "10"), its
# ensure_ascii escaping ("§", not a raw section sign) and its dict
# insertion order.
#
# Rather than hand-authoring a golden per function, this section writes THREE
# result fixtures to internal/output/testdata/*.json and then, for each one,
# the five artifacts Python produces from it. The Go golden test loads the SAME
# fixture file, runs its own generators and diffs the bytes - so the fixture is
# the shared input and neither side re-implements the other.
#
# Fixture keys are dumped with sort_keys=True on purpose: the three dict-typed
# fields of SecurityAuditResult (by_severity, cost_breakdown, metadata) keep
# their file order once parsed, and a Go map cannot carry insertion order, so
# the port emits them sorted. Sorted-in, sorted-out makes the two agree.
# ---------------------------------------------------------------------------

_S8_TESTDATA = "internal/output/testdata"
_S8_GOLDEN = "internal/output/testdata/golden"

# The instant compliance_report._render_header would read off the clock. Pinned
# here (and passed explicitly to the Go GenerateComplianceReportAt) so the
# report is reproducible.
_S8_GENERATED_AT = datetime(2026, 5, 6, 7, 8, 9, tzinfo=UTC)


class _S8FrozenDatetime:
    """Stand-in for the `datetime` name inside compliance_report."""

    @staticmethod
    def now(tz: Any = None) -> Any:
        _ = tz
        return _S8_GENERATED_AT


def _s8_location(
    file_path: str,
    start_line: int,
    end_line: int,
    **kw: Any,
) -> Any:
    from sec_af.schemas.prove import Location

    return Location(file_path=file_path, start_line=start_line, end_line=end_line, **kw)


def _s8_mapping(framework: str, control_id: str, control_name: str) -> Any:
    from sec_af.schemas.compliance import ComplianceMapping

    return ComplianceMapping(framework=framework, control_id=control_id, control_name=control_name)


def _s8_sample_result() -> Any:
    """The tests/conftest.py::sample_security_audit_result fixture.

    Reproduced field for field, with the one change that `tags` is a sorted
    LIST instead of a set - a Python set has no stable iteration order, and the
    fixture file has to be byte-stable across regenerations.
    """
    from sec_af.schemas.compliance import ComplianceGap
    from sec_af.schemas.hunt import FindingType, Severity
    from sec_af.schemas.output import AttackChain, MitreMapping, SecurityAuditResult
    from sec_af.schemas.prove import DataFlowStep, EvidenceLevel, Proof, Verdict, VerifiedFinding

    sql = VerifiedFinding(
        id="finding-confirmed",
        fingerprint="fp-sql-1",
        title="SQL Injection",
        description="Unsanitized user input reaches SQL query execution.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category="A03:2021",
        tags=["externally_reachable", "user-input"],
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        rationale="Source-to-sink path is confirmed and exploitable.",
        severity=Severity.CRITICAL,
        exploitability_score=10.0,
        proof=Proof(
            exploit_hypothesis="Inject through id parameter.",
            verification_method="manual-review+trace",
            evidence_level=EvidenceLevel.FULL_EXPLOIT,
            data_flow_trace=[
                DataFlowStep(file="src/routes.py", line=15, description="Input source", tainted=True),
                DataFlowStep(file="src/users.py", line=42, description="SQL sink", tainted=True),
            ],
            vulnerable_code='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
            exploit_payload='{"id": "1 OR 1=1"}',
            expected_outcome="Unauthorized data access",
        ),
        location=_s8_location(
            "src/users.py",
            42,
            42,
            start_column=9,
            end_column=66,
            function_name="lookup_user",
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        ),
        related_locations=[
            _s8_location("src/routes.py", 15, 15, code_snippet="user_id = request.json['id']"),
        ],
        chain_id="chain-1",
        chain_step=1,
        enables=["finding-likely"],
        compliance=[_s8_mapping("PCI-DSS", "Req 6.2.4", "Prevent injection")],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=9.9,
    )
    likely = VerifiedFinding(
        id="finding-likely",
        fingerprint="fp-auth-1",
        title="Missing Authentication",
        description="Admin endpoint can be accessed without auth.",
        finding_type=FindingType.API,
        cwe_id="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        owasp_category="A07:2021",
        tags=["requires_auth"],
        verdict=Verdict.LIKELY,
        evidence_level=EvidenceLevel.FLOW_IDENTIFIED,
        rationale="Guard checks appear absent on route.",
        severity=Severity.HIGH,
        exploitability_score=4.8,
        location=_s8_location("src/api/admin.py", 11, 11),
        sarif_rule_id="sec-af/api/missing-authentication",
        sarif_security_severity=7.6,
    )
    not_exploitable = VerifiedFinding(
        id="finding-noise",
        fingerprint="fp-noise-1",
        title="Potential XSS",
        description="Output is escaped by template engine.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-79",
        cwe_name="Cross-site Scripting",
        verdict=Verdict.NOT_EXPLOITABLE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Sink auto-escapes output.",
        severity=Severity.LOW,
        exploitability_score=0.6,
        location=_s8_location("src/views.py", 88, 89),
        sarif_rule_id="sec-af/sast/xss",
        sarif_security_severity=1.9,
    )
    return SecurityAuditResult(
        repository="Agent-Field/sec-af",
        commit_sha="a" * 40,
        branch="issue-23-tests",
        timestamp=datetime(2026, 3, 4, 10, 30, 0, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=["injection", "auth"],
        provider="opencode",
        findings=[sql, likely, not_exploitable],
        attack_chains=[
            AttackChain(
                chain_id="chain-1",
                title="Input to DB read",
                description="Untrusted input reaches SQL sink",
                findings=["finding-confirmed", "finding-likely"],
                combined_severity=Severity.CRITICAL,
                combined_impact="Unauthorized DB disclosure",
                mitre_attack_mapping=[
                    MitreMapping(
                        tactic="Initial Access",
                        technique_id="T1190",
                        technique_name="Exploit Public-Facing Application",
                    )
                ],
            )
        ],
        total_raw_findings=6,
        confirmed=1,
        likely=1,
        inconclusive=0,
        not_exploitable=1,
        noise_reduction_pct=66.7,
        by_severity={"critical": 1, "high": 1, "low": 1},
        compliance_gaps=[
            ComplianceGap(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Prevent injection",
                finding_count=1,
                max_severity="critical",
                cwe_ids=["CWE-89"],
            )
        ],
        duration_seconds=182.4,
        agent_invocations=24,
        cost_usd=3.21,
        cost_breakdown={"hunt": 1.2, "prove": 1.51, "recon": 0.5},
        sarif="{}",
    )


def _s8_empty_result() -> Any:
    """Every "nothing to report" branch of all four generators at once."""
    from sec_af.schemas.output import SecurityAuditResult

    return SecurityAuditResult(
        repository="Agent-Field/empty",
        commit_sha="0" * 40,
        branch=None,
        timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        depth_profile="quick",
        strategies_used=[],
        provider="aforge",
        findings=[],
        attack_chains=[],
        total_raw_findings=0,
        confirmed=0,
        likely=0,
        inconclusive=0,
        not_exploitable=0,
        noise_reduction_pct=0.0,
        by_severity={},
        compliance_gaps=[],
        duration_seconds=0.0,
        agent_invocations=0,
        cost_usd=0.0,
        cost_breakdown={},
        sarif="",
    )


def _s8_edge_result() -> Any:
    """The nasty fixture: escaping, rounding and every truthiness branch.

    Packed in deliberately:

    * non-ASCII, quotes, backslashes and angle brackets in strings that reach
      both the JSON writers (ensure_ascii) and the Markdown ones (raw);
    * a microsecond timestamp (isoformat keeps six digits, model_dump_json
      spells the zone "Z");
    * two findings sharing one sarif_rule_id, so the rule aggregates level,
      precision and security-severity (9.25 -> "9.2", a half-to-even tie);
    * a rule id whose last segment is empty -> _rule_name's "SecAfRule"
      fallback, and a lower-case cwe id -> _cwe_number / _base_tags upper-casing;
    * a finding with NO compliance mappings -> the "Uncategorized Findings"
      section, and one with two mappings in the same framework -> the
      seen_frameworks de-duplication;
    * chain_step 0 and a chain naming a finding id that does not exist ->
      both `chain_step or index` fallbacks;
    * an empty branch and an empty code_snippet -> the truthiness (not
      None-ness) guards;
    * a compliance gap with seven CWEs -> the "(+2 more)" truncation;
    * a commit_sha shorter than the eight characters the executive summary
      slices.
    """
    from sec_af.schemas.compliance import ComplianceGap
    from sec_af.schemas.hunt import FindingType, Severity
    from sec_af.schemas.output import AttackChain, PolicyViolation, SecurityAuditResult
    from sec_af.schemas.prove import DataFlowStep, EvidenceLevel, Proof, Verdict, VerifiedFinding

    shared_a = VerifiedFinding(
        id="dup-a",
        fingerprint="fp-dup-a",
        title='Naïve "quote" & <tag> handling',
        description="Backslash \\ and tab\tand newline stay in one line.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category=None,
        tags=["zeta", "alpha"],
        verdict=Verdict.LIKELY,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        rationale="",
        severity=Severity.MEDIUM,
        exploitability_score=4.5,
        location=_s8_location("src/naïve.py", 3, 3, start_column=1, code_snippet=""),
        chain_id="chain-x",
        chain_step=0,
        compliance=[
            _s8_mapping("OWASP", "A03:2021", "Injection"),
            _s8_mapping("OWASP", "A01:2021", "Broken Access Control"),
            _s8_mapping("PCI-DSS", "Req  6.2.4", "Custom software"),
        ],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=11.5,
    )
    shared_b = VerifiedFinding(
        id="dup-b",
        fingerprint="fp-dup-b",
        title="Second finding on the same rule",
        description="Aggregates into the same SARIF rule as dup-a.",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category="A03:2021",
        tags=[],
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.FULL_EXPLOIT,
        rationale="Confirmed by trace.",
        severity=Severity.CRITICAL,
        exploitability_score=9.25,
        proof=Proof(
            exploit_hypothesis="h",
            verification_method="trace",
            evidence_level=EvidenceLevel.FULL_EXPLOIT,
            data_flow_trace=[DataFlowStep(file="src/§.py", line=1, description="source → sink", tainted=True)],
        ),
        location=_s8_location("src/dup.py", 7, 9, end_column=4),
        related_locations=[_s8_location("src/other.py", 2, 2)],
        compliance=[],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=-1.0,
    )
    fallback_rule = VerifiedFinding(
        id="rule-fallback",
        fingerprint="fp-fallback",
        title="Rule id with an empty last segment",
        description="Exercises the _rule_name fallback.",
        finding_type=FindingType.CONFIG,
        cwe_id="cwe-79",
        cwe_name="Cross-site Scripting",
        tags=["b", "a"],
        verdict=Verdict.INCONCLUSIVE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Unclear.",
        severity=Severity.INFO,
        exploitability_score=0.0,
        location=_s8_location("src/views.py", 1, 1),
        compliance=[_s8_mapping("ISO27001", "A.8.28", "Secure coding")],
        sarif_rule_id="sec-af/",
        sarif_security_severity=0.04,
    )
    dropped = VerifiedFinding(
        id="dropped",
        fingerprint="fp-dropped",
        title="Filtered out of SARIF",
        description="not_exploitable findings never reach the SARIF document.",
        finding_type=FindingType.SECRETS,
        cwe_id="CWE-798",
        cwe_name="Hard-coded Credentials",
        verdict=Verdict.NOT_EXPLOITABLE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="False positive.",
        severity=Severity.LOW,
        exploitability_score=1.0,
        location=_s8_location("src/config.py", 5, 5),
        sarif_rule_id="sec-af/secrets/hardcoded",
        sarif_security_severity=2.0,
    )

    return SecurityAuditResult(
        repository="Agent-Field/sec-af—naïve",
        commit_sha="abc123",
        branch="",
        timestamp=datetime(2026, 3, 4, 10, 30, 0, 123456, tzinfo=UTC),
        depth_profile="thorough",
        strategies_used=["injection", "auth", "xss"],
        provider="aforge",
        findings=[shared_a, shared_b, fallback_rule, dropped],
        attack_chains=[
            AttackChain(
                chain_id="chain-x",
                title="Chain naming a missing finding",
                description="The second id is not in result.findings.",
                findings=["dup-a", "not-in-result"],
                combined_severity=Severity.HIGH,
                combined_impact="Impact <script> & co.",
                mitre_attack_mapping=None,
            )
        ],
        total_raw_findings=9,
        confirmed=1,
        likely=1,
        inconclusive=1,
        not_exploitable=1,
        noise_reduction_pct=0.0,
        by_severity={"critical": 1, "info": 1, "low": 1, "medium": 1},
        compliance_gaps=[
            ComplianceGap(
                framework="OWASP",
                control_id="A03:2021",
                control_name="Injection",
                finding_count=7,
                max_severity="info",
                cwe_ids=[
                    "CWE-78",
                    "CWE-79",
                    "CWE-89",
                    "CWE-90",
                    "CWE-91",
                    "CWE-94",
                    "CWE-917",
                ],
            ),
            ComplianceGap(
                framework="OWASP",
                control_id="A01:2021",
                control_name="Broken Access Control",
                finding_count=1,
                max_severity="unknown-severity",
                cwe_ids=["CWE-862"],
            ),
        ],
        policy_violations=[
            PolicyViolation(
                policy="no-eval",
                violation_description="eval() on request data",
                file_path="src/naïve.py",
                severity="high",
            )
        ],
        duration_seconds=0.05,
        agent_invocations=3,
        cost_usd=1.005,
        cost_breakdown={"hunt": 1.0, "prove": 0.0},
        metadata={"flag": True, "note": 'quote" backslash\\ <tag> & ünïcode', "nested": {"b": "2", "a": "1"}},
        sarif="",
    )


def _s8_compliance_report_result() -> Any:
    """tests/test_compliance_report.py::_make_result().

    Its `_make_finding` leaves `id` to the uuid4 default; the fixture pins it so
    regenerating produces identical bytes.
    """
    from sec_af.schemas.compliance import ComplianceGap
    from sec_af.schemas.hunt import FindingType, Severity
    from sec_af.schemas.output import SecurityAuditResult
    from sec_af.schemas.prove import EvidenceLevel, Verdict, VerifiedFinding

    finding = VerifiedFinding(
        id="compliance-report-finding",
        fingerprint="test-fp",
        title="Test Finding",
        description="Test description",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        rationale="Test rationale",
        severity=Severity.HIGH,
        exploitability_score=7.5,
        location=_s8_location("app.py", 10, 15),
        compliance=[
            _s8_mapping("OWASP", "A03:2021", "Injection"),
            _s8_mapping("PCI-DSS", "Req 6.2.4", "Secure coding"),
        ],
        sarif_rule_id="sec-af/sast/cwe-89",
        sarif_security_severity=7.5,
    )
    return SecurityAuditResult(
        repository="https://github.com/test/repo",
        commit_sha="abc123def456",
        branch="main",
        timestamp=datetime(2025, 1, 15, 10, 30, 0, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=["injection", "auth"],
        provider="harness",
        findings=[finding],
        attack_chains=[],
        total_raw_findings=5,
        confirmed=1,
        likely=0,
        inconclusive=0,
        not_exploitable=4,
        noise_reduction_pct=80.0,
        by_severity={"critical": 0, "high": 1, "info": 0, "low": 0, "medium": 0},
        compliance_gaps=[
            ComplianceGap(
                framework="OWASP",
                control_id="A03:2021",
                control_name="Injection",
                finding_count=1,
                max_severity="high",
                cwe_ids=["CWE-89"],
            ),
        ],
        duration_seconds=45.2,
        agent_invocations=12,
        cost_usd=0.15,
        cost_breakdown={"hunt": 0.07, "prove": 0.05, "recon": 0.03},
        sarif="",
    )


def _s8_float_edge_result() -> Any:
    """The FLOAT fixture: magnitudes the other four never reach.

    ``generate_json(result, pretty=False)`` returns ``model_dump_json()``
    VERBATIM, i.e. pydantic-core's own serializer -- which is NOT CPython's
    ``repr()``.  The two disagree for every |x| < 1e-4::

        value       repr() / json.dumps      model_dump_json()
        1e-7        1e-07                    1e-7
        8e-05       8e-05                    0.00008
        1e-5        1e-05                    0.00001

    The pretty branch re-serialises through ``json.dumps(json.loads(...))`` and
    therefore legitimately wants the repr spelling, so ONE fixture pins both
    rules at once.  None of the other four fixtures carries a float outside
    plain decimal range, which is exactly why a Go writer that spelled the
    compact form with repr() stayed green.

    ``metadata`` additionally carries the shape app.py stores there: the
    prove_phase ``drop_summary``, whose counts are INTs after ``json.loads``.
    Python spells them "2"; a Go writer that kept the SDK's float64 decode would
    spell them "2.0".
    """
    from sec_af.schemas.output import SecurityAuditResult

    return SecurityAuditResult(
        repository="Agent-Field/floats",
        commit_sha="f" * 40,
        branch="main",
        timestamp=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
        depth_profile="standard",
        strategies_used=[],
        provider="aforge",
        findings=[],
        attack_chains=[],
        total_raw_findings=0,
        confirmed=0,
        likely=0,
        inconclusive=0,
        not_exploitable=0,
        # 8e-05 is a normal EPSS-scale probability: decimal for pydantic,
        # exponent for repr.
        noise_reduction_pct=8e-05,
        by_severity={},
        compliance_gaps=[],
        # Sub-microsecond duration: exponent on BOTH sides, but pydantic drops
        # the exponent's zero padding.
        duration_seconds=1e-07,
        agent_invocations=0,
        cost_usd=1.23e-05,
        cost_breakdown={
            "denormal": 5e-324,
            "exponent_low": 1e-06,
            "huge": 1e16,
            "integral": 10.0,
            "repr_tie": 0.30000000000000004,
            "threshold": 1e-05,
        },
        metadata={
            "findings_not_verified": 3,
            "prove_drop_summary": {
                "by_reason": {"verifier_error": 2},
                "demoted_total": 2,
                "findings": [],
            },
        },
        sarif="",
    )


def _s8_emit_fixture(name: str, result: Any) -> Any:
    """Write the fixture both implementations load, then re-read it.

    Returning the RE-PARSED model (not the one just built) guarantees the
    goldens describe exactly the document the Go side will see: any lossy field
    in the dump would show up here rather than as a mystery diff later.
    """
    from sec_af.schemas.output import SecurityAuditResult

    payload = json.dumps(result.model_dump(mode="json"), indent=2, sort_keys=True, ensure_ascii=False) + "\n"
    _write(f"{_S8_TESTDATA}/{name}.json", payload)
    return SecurityAuditResult.model_validate(json.loads(payload))


def _s8_emit_artifacts(name: str, result: Any) -> None:
    """Write the five Python artifacts for one fixture."""
    from sec_af.output import compliance_report as compliance_report_mod
    from sec_af.output.compliance_report import generate_compliance_report
    from sec_af.output.json_output import generate_json, generate_summary_json
    from sec_af.output.report import generate_report
    from sec_af.output.sarif import generate_sarif

    _write(f"{_S8_GOLDEN}/{name}.sarif.json", generate_sarif(result))
    _write(f"{_S8_GOLDEN}/{name}.full.json", generate_json(result, pretty=True))
    _write(f"{_S8_GOLDEN}/{name}.full_compact.json", generate_json(result, pretty=False))
    _write(f"{_S8_GOLDEN}/{name}.summary.json", generate_summary_json(result))
    _write(f"{_S8_GOLDEN}/{name}.report.md", generate_report(result))

    # generate_compliance_report stamps datetime.now(UTC) into its header, so
    # the module-level `datetime` name is swapped for a frozen stand-in just
    # long enough to render. The Go port takes the same instant as an argument.
    original = compliance_report_mod.datetime
    compliance_report_mod.datetime = _S8FrozenDatetime  # pyright: ignore[reportAttributeAccessIssue]
    try:
        _write(f"{_S8_GOLDEN}/{name}.compliance_report.md", generate_compliance_report(result))
    finally:
        compliance_report_mod.datetime = original  # pyright: ignore[reportAttributeAccessIssue]


def s8_emit_goldens() -> None:
    """internal/output: three result fixtures x five artifacts each."""
    for name, build in (
        ("audit_result", _s8_sample_result),
        ("audit_result_empty", _s8_empty_result),
        ("audit_result_edge", _s8_edge_result),
        ("audit_result_report", _s8_compliance_report_result),
        ("audit_result_floats", _s8_float_edge_result),
    ):
        _s8_emit_artifacts(name, _s8_emit_fixture(name, build()))


def gen_output() -> None:
    """Entry point ``gen_golden.py`` calls."""
    s8_emit_goldens()


if __name__ == "__main__":
    gen_output()
