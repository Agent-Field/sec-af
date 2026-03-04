from __future__ import annotations

import json
from typing import TYPE_CHECKING, cast

from sec_af.output.sarif import generate_sarif, render_sarif

if TYPE_CHECKING:
    from sec_af.schemas.output import SecurityAuditResult


def _obj(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def _arr(value: object) -> list[object]:
    assert isinstance(value, list)
    return cast("list[object]", value)


def test_generate_sarif_has_valid_2_1_0_envelope(sample_security_audit_result: SecurityAuditResult) -> None:
    payload = _obj(cast("object", json.loads(generate_sarif(sample_security_audit_result))))
    runs = _arr(payload["runs"])
    run = _obj(runs[0])
    tool = _obj(_obj(run["tool"])["driver"])

    assert payload["$schema"] == "https://json.schemastore.org/sarif-2.1.0.json"
    assert payload["version"] == "2.1.0"
    assert tool["name"] == "SEC-AF"
    assert tool["informationUri"] == "https://github.com/Agent-Field/sec-af"
    assert _obj(run["automationDetails"])["id"] == "sec-af/audit/Agent-Field/sec-af/2026-03-04T10:30:00+00:00"


def test_generate_sarif_filters_not_exploitable_and_maps_severity(
    sample_security_audit_result: SecurityAuditResult,
) -> None:
    payload = _obj(cast("object", json.loads(generate_sarif(sample_security_audit_result))))
    run = _obj(_arr(payload["runs"])[0])
    results = [_obj(item) for item in _arr(run["results"])]
    by_rule = {cast("str", result["ruleId"]): result for result in results}

    assert len(results) == 2
    assert "sec-af/sast/xss" not in by_rule
    assert by_rule["sec-af/sast/sql-injection"]["level"] == "error"
    assert by_rule["sec-af/api/missing-authentication"]["level"] == "error"


def test_generate_sarif_includes_compliance_tags_codeflow_and_locations(
    sample_security_audit_result: SecurityAuditResult,
) -> None:
    payload = _obj(cast("object", json.loads(generate_sarif(sample_security_audit_result))))
    run = _obj(_arr(payload["runs"])[0])
    results = [_obj(item) for item in _arr(run["results"])]
    sql = next(result for result in results if result["ruleId"] == "sec-af/sast/sql-injection")
    properties = _obj(sql["properties"])
    locations = _arr(sql["locations"])
    physical = _obj(_obj(locations[0])["physicalLocation"])
    region = _obj(physical["region"])
    related = _arr(sql["relatedLocations"])
    code_flows = _arr(sql["codeFlows"])

    assert "PCI-DSS:Req-6.2.4" in _arr(properties["sec-af/compliance"])
    assert "compliance:PCI-DSS:Req-6.2.4" in _arr(properties["tags"])
    assert region["startLine"] == 42
    assert region["startColumn"] == 9
    assert _obj(_obj(_obj(related[0])["physicalLocation"])["artifactLocation"])["uri"] == "src/routes.py"
    assert len(_arr(_obj(_arr(_obj(code_flows[0])["threadFlows"])[0])["locations"])) == 2


def test_generate_sarif_rule_entries_aggregate_precision_and_severity(
    sample_security_audit_result: SecurityAuditResult,
) -> None:
    payload = _obj(cast("object", json.loads(generate_sarif(sample_security_audit_result))))
    run = _obj(_arr(payload["runs"])[0])
    rules = [_obj(rule) for rule in _arr(_obj(_obj(run["tool"])["driver"])["rules"])]
    sql_rule = next(rule for rule in rules if rule["id"] == "sec-af/sast/sql-injection")
    sql_properties = _obj(sql_rule["properties"])

    assert _obj(sql_rule["defaultConfiguration"])["level"] == "error"
    assert sql_properties["precision"] == "very-high"
    assert sql_properties["security-severity"] == "10.0"
    assert "CWE-89" in _arr(sql_properties["tags"])


def test_generate_sarif_is_stable_for_same_input(sample_security_audit_result: SecurityAuditResult) -> None:
    first = generate_sarif(sample_security_audit_result)
    second = generate_sarif(sample_security_audit_result)

    assert first == second
    assert render_sarif(sample_security_audit_result) == first
