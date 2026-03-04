from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from sec_af.output.json_output import generate_json, generate_summary_json, render_json
from sec_af.output.report import generate_report

if TYPE_CHECKING:
    from sec_af.schemas.output import SecurityAuditResult


def test_generate_json_pretty_contains_full_finding_payload(sample_security_audit_result: SecurityAuditResult) -> None:
    payload = cast("dict[str, object]", json.loads(generate_json(sample_security_audit_result, pretty=True)))
    findings = cast("list[dict[str, object]]", payload["findings"])
    chains = cast("list[dict[str, object]]", payload["attack_chains"])

    assert len(findings) == 3
    assert findings[0]["id"] == "finding-confirmed"
    assert findings[1]["verdict"] == "likely"
    assert findings[2]["verdict"] == "not_exploitable"
    assert chains[0]["chain_id"] == "chain-1"


def test_generate_json_compact_has_no_whitespace_newlines(sample_security_audit_result: SecurityAuditResult) -> None:
    output = generate_json(sample_security_audit_result, pretty=False)

    assert "\n" not in output
    assert output.startswith("{")
    assert output.endswith("}")


def test_generate_summary_json_omits_proof_and_contains_statistics(
    sample_security_audit_result: SecurityAuditResult,
) -> None:
    payload = cast("dict[str, object]", json.loads(generate_summary_json(sample_security_audit_result)))
    summary = cast("dict[str, object]", payload["summary"])
    findings = cast("list[dict[str, object]]", payload["findings"])
    chains = cast("list[dict[str, object]]", payload["attack_chains"])
    performance = cast("dict[str, object]", payload["performance"])

    assert summary["total_findings"] == 3
    assert summary["confirmed"] == 1
    assert summary["likely"] == 1
    assert summary["not_exploitable"] == 1
    assert "proof" not in findings[0]
    first_chain = cast("dict[str, object]", chains[0])
    first_steps = cast("list[dict[str, object]]", first_chain["steps"])
    assert first_steps[0]["step"] == 1
    assert performance["cost_usd"] == 3.21


def test_render_json_returns_decoded_dictionary(sample_security_audit_result: SecurityAuditResult) -> None:
    payload = render_json(sample_security_audit_result)

    assert payload["repository"] == "Agent-Field/sec-af"
    assert len(cast("list[dict[str, object]]", payload["findings"])) == 3


def test_generate_report_includes_findings_chains_compliance_and_cost(
    sample_security_audit_result: SecurityAuditResult,
) -> None:
    report = generate_report(sample_security_audit_result)

    assert "# SEC-AF Security Audit Report" in report
    assert "## Summary" in report
    assert "## Findings" in report
    assert "SQL Injection" in report
    assert "Missing Authentication" in report
    assert "## Attack Chains" in report
    assert "Input to DB read" in report
    assert "## Compliance Gaps" in report
    assert "PCI-DSS Req 6.2.4" in report
    assert "## Performance & Cost" in report
