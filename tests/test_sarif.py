from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

import pytest

from sec_af.output.sarif import generate_sarif
from sec_af.schemas.compliance import ComplianceMapping
from sec_af.schemas.hunt import FindingType, Severity
from sec_af.schemas.output import SecurityAuditResult
from sec_af.schemas.prove import DataFlowStep, EvidenceLevel, Location, Proof, Verdict, VerifiedFinding


getattr(SecurityAuditResult, "model_rebuild")()


def _obj(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast(dict[str, object], value)


def _arr(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast(list[object], value)


def _text(value: object) -> str:
    assert isinstance(value, str)
    return value


@pytest.fixture
def sample_audit_result() -> SecurityAuditResult:
    flow_steps = [
        DataFlowStep(
            file="src/routes.py",
            line=15,
            description="User input enters via request body",
            tainted=True,
        ),
        DataFlowStep(
            file="src/users.py",
            line=42,
            description="Reaches SQL query without sanitization",
            tainted=True,
        ),
    ]
    sql_finding = VerifiedFinding(
        fingerprint="fp-sql-1",
        title="SQL Injection",
        description="Unsanitized user input flows into SQL query",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        owasp_category="A03:2021",
        tags={"sql-injection", "user-input"},
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
        rationale="Source to sink flow is reachable with no sanitization.",
        severity=Severity.CRITICAL,
        exploitability_score=9.0,
        proof=Proof(
            exploit_hypothesis="Inject SQL via request body id.",
            verification_method="static-flow-trace",
            evidence_level=EvidenceLevel.REACHABILITY_CONFIRMED,
            data_flow_trace=flow_steps,
        ),
        location=Location(
            file_path="src/users.py",
            start_line=42,
            end_line=42,
            start_column=5,
            end_column=65,
            code_snippet='cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
        ),
        related_locations=[
            Location(
                file_path="src/routes.py",
                start_line=15,
                end_line=15,
                code_snippet="user_id = request.json['id']",
            )
        ],
        compliance=[
            ComplianceMapping(
                framework="PCI-DSS",
                control_id="Req 6.2.4",
                control_name="Custom software addresses common coding vulnerabilities",
            ),
            ComplianceMapping(
                framework="SOC2",
                control_id="CC6",
                control_name="Logical and physical access controls",
            ),
        ],
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=9.0,
    )
    auth_finding = VerifiedFinding(
        fingerprint="fp-auth-1",
        title="Missing Authentication",
        description="Sensitive endpoint is accessible without authentication",
        finding_type=FindingType.API,
        cwe_id="CWE-306",
        cwe_name="Missing Authentication for Critical Function",
        owasp_category="A07:2021",
        verdict=Verdict.LIKELY,
        evidence_level=EvidenceLevel.FLOW_IDENTIFIED,
        rationale="Flow and route guards indicate likely bypass path.",
        severity=Severity.HIGH,
        exploitability_score=7.6,
        location=Location(
            file_path="src/api/admin.py",
            start_line=11,
            end_line=11,
        ),
        sarif_rule_id="sec-af/api/missing-authentication",
        sarif_security_severity=7.6,
    )
    ignored_finding = VerifiedFinding(
        fingerprint="fp-ignored-1",
        title="Safe SQL construction",
        description="False positive with parameterized query",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        verdict=Verdict.NOT_EXPLOITABLE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Query is parameterized and validated.",
        severity=Severity.LOW,
        exploitability_score=0.5,
        location=Location(
            file_path="src/db.py",
            start_line=9,
            end_line=9,
        ),
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=0.5,
    )
    return SecurityAuditResult(
        repository="Agent-Field/sec-af",
        commit_sha="a" * 40,
        branch="issue-5-sarif",
        timestamp=datetime(2026, 3, 4, 10, 30, 0, tzinfo=UTC),
        depth_profile="deep",
        strategies_used=["injection", "auth"],
        provider="test-provider",
        findings=[sql_finding, auth_finding, ignored_finding],
        sarif="",
    )


def test_generate_sarif_envelope_and_tool_metadata(sample_audit_result: SecurityAuditResult) -> None:
    payload = _obj(cast(object, json.loads(generate_sarif(sample_audit_result))))
    runs = _arr(payload["runs"])

    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    assert len(runs) == 1

    run = _obj(runs[0])
    tool = _obj(_obj(run["tool"])["driver"])
    automation_details = _obj(run["automationDetails"])

    assert tool["name"] == "SEC-AF"
    assert tool["semanticVersion"] == "0.1.0"
    assert tool["informationUri"] == "https://github.com/Agent-Field/sec-af"
    assert automation_details["id"] == "sec-af/audit/Agent-Field/sec-af/2026-03-04T10:30:00+00:00"


def test_generate_sarif_results_and_custom_properties(sample_audit_result: SecurityAuditResult) -> None:
    payload = _obj(cast(object, json.loads(generate_sarif(sample_audit_result))))
    runs = _arr(payload["runs"])
    run = _obj(runs[0])
    results = _arr(run["results"])

    assert len(results) == 2
    assert {_text(_obj(result)["ruleId"]) for result in results} == {
        "sec-af/sast/sql-injection",
        "sec-af/api/missing-authentication",
    }

    sql_result = next(_obj(result) for result in results if _obj(result)["ruleId"] == "sec-af/sast/sql-injection")
    sql_message = _obj(sql_result["message"])
    sql_properties = _obj(sql_result["properties"])
    compliance = _arr(sql_properties["sec-af/compliance"])
    tags = _arr(sql_properties["tags"])

    assert sql_result["level"] == "error"
    assert _text(sql_message["text"]).startswith("[CONFIRMED] SQL Injection:")
    assert sql_properties["sec-af/verdict"] == "confirmed"
    assert sql_properties["sec-af/evidence_level"] == 3
    assert sql_properties["sec-af/exploitability_score"] == 9.0
    assert sql_properties["security-severity"] == "9.0"
    assert "PCI-DSS:Req-6.2.4" in compliance
    assert "compliance:PCI-DSS:Req-6.2.4" in tags


def test_generate_sarif_locations_code_flows_and_rules(sample_audit_result: SecurityAuditResult) -> None:
    payload = _obj(cast(object, json.loads(generate_sarif(sample_audit_result))))
    run = _obj(_arr(payload["runs"])[0])

    rules_raw = _arr(_obj(_obj(run["tool"])["driver"])["rules"])
    rules = {_text(_obj(rule)["id"]): _obj(rule) for rule in rules_raw}
    assert set(rules) == {"sec-af/sast/sql-injection", "sec-af/api/missing-authentication"}
    sql_rule = rules["sec-af/sast/sql-injection"]
    sql_rule_defaults = _obj(sql_rule["defaultConfiguration"])
    sql_rule_properties = _obj(sql_rule["properties"])
    sql_rule_tags = _arr(sql_rule_properties["tags"])
    assert sql_rule_defaults["level"] == "error"
    assert sql_rule_properties["security-severity"] == "9.0"
    assert "CWE-89" in sql_rule_tags
    assert "OWASP-A03:2021" in sql_rule_tags

    run_results = _arr(run["results"])
    sql_result = next(_obj(result) for result in run_results if _obj(result)["ruleId"] == "sec-af/sast/sql-injection")
    locations = _arr(sql_result["locations"])
    primary_location = _obj(_obj(locations[0])["physicalLocation"])
    artifact = _obj(primary_location["artifactLocation"])
    region = _obj(primary_location["region"])
    assert artifact["uri"] == "src/users.py"
    assert artifact["uriBaseId"] == "%SRCROOT%"
    assert region["startLine"] == 42
    assert region["startColumn"] == 5

    partial = _obj(sql_result["partialFingerprints"])
    code_flows = _arr(sql_result["codeFlows"])
    first_flow = _obj(code_flows[0])
    thread_flows = _arr(first_flow["threadFlows"])
    first_thread = _obj(thread_flows[0])
    flow_locations = _arr(first_thread["locations"])
    related = _arr(sql_result["relatedLocations"])
    first_related = _obj(related[0])
    related_physical = _obj(first_related["physicalLocation"])
    related_artifact = _obj(related_physical["artifactLocation"])
    assert partial["primaryLocationLineHash"] == "fp-sql-1"
    assert len(flow_locations) == 2
    assert related_artifact["uri"] == "src/routes.py"
