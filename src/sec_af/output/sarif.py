"""SARIF output stub from DESIGN.md §7.5."""

from __future__ import annotations

import json
import re
from typing import TYPE_CHECKING

from .. import __version__

if TYPE_CHECKING:
    from ..schemas.output import SecurityAuditResult
    from ..schemas.prove import Location, VerifiedFinding


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}

_LEVEL_RANK = {"error": 3, "warning": 2, "note": 1}

_VERDICT_TO_PRECISION = {
    "confirmed": "very-high",
    "likely": "high",
    "inconclusive": "medium",
    "not_exploitable": "low",
}

_PRECISION_RANK = {"very-high": 4, "high": 3, "medium": 2, "low": 1}


def generate_sarif(result: SecurityAuditResult) -> str:
    included_findings = [finding for finding in result.findings if finding.verdict.value != "not_exploitable"]
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": _build_tool_section(included_findings),
                "results": [_build_result(finding) for finding in included_findings],
                "automationDetails": {"id": f"sec-af/audit/{result.repository}/{result.timestamp.isoformat()}"},
            }
        ],
    }
    return json.dumps(sarif, indent=2)


def render_sarif(audit_result: SecurityAuditResult) -> str:
    return generate_sarif(audit_result)


def _build_tool_section(findings: list[VerifiedFinding]) -> dict[str, object]:
    rules_by_id: dict[str, list[VerifiedFinding]] = {}
    for finding in findings:
        rules_by_id.setdefault(finding.sarif_rule_id, []).append(finding)

    rules = [_build_rule(rule_id, rule_findings) for rule_id, rule_findings in sorted(rules_by_id.items())]
    return {
        "driver": {
            "name": "SEC-AF",
            "semanticVersion": __version__,
            "informationUri": "https://github.com/Agent-Field/sec-af",
            "rules": rules,
        }
    }


def _build_rule(rule_id: str, findings: list[VerifiedFinding]) -> dict[str, object]:
    representative = findings[0]
    level = _max_level(findings)
    security_severity = _format_security_severity(max(finding.exploitability_score for finding in findings))
    precision = _max_precision(findings)
    tags = _aggregate_rule_tags(findings)
    cwe_number = _cwe_number(representative.cwe_id)
    return {
        "id": rule_id,
        "name": _rule_name(rule_id),
        "shortDescription": {"text": f"{representative.title} vulnerability"},
        "fullDescription": {"text": representative.description},
        "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe_number}.html",
        "defaultConfiguration": {"level": level},
        "properties": {
            "precision": precision,
            "security-severity": security_severity,
            "tags": tags,
        },
    }


def _build_result(finding: VerifiedFinding) -> dict[str, object]:
    locations = [{"physicalLocation": _physical_location(finding.location)}]
    result: dict[str, object] = {
        "ruleId": finding.sarif_rule_id,
        "level": _severity_to_level(finding.severity.value),
        "message": {"text": _message_text(finding)},
        "locations": locations,
        "partialFingerprints": {
            "primaryLocationLineHash": finding.fingerprint,
        },
        "properties": {
            "security-severity": _format_security_severity(finding.sarif_security_severity),
            "sec-af/verdict": finding.verdict.value,
            "sec-af/evidence_level": int(finding.evidence_level),
            "sec-af/exploitability_score": finding.exploitability_score,
            "sec-af/chain_id": finding.chain_id,
            "sec-af/compliance": _compliance_list(finding),
            "tags": _result_tags(finding),
        },
    }

    related_locations = _related_locations(finding.related_locations)
    if related_locations:
        result["relatedLocations"] = related_locations

    code_flows = _code_flows(finding)
    if code_flows:
        result["codeFlows"] = code_flows

    return result


def _message_text(finding: VerifiedFinding) -> str:
    verdict = finding.verdict.value.upper()
    return f"[{verdict}] {finding.title}: {finding.description}. Evidence level: {finding.evidence_level.name}."


def _physical_location(location: Location) -> dict[str, object]:
    region: dict[str, object] = {
        "startLine": location.start_line,
        "endLine": location.end_line,
    }
    if location.start_column is not None:
        region["startColumn"] = location.start_column
    if location.end_column is not None:
        region["endColumn"] = location.end_column
    if location.code_snippet:
        region["snippet"] = {"text": location.code_snippet}

    return {
        "artifactLocation": {
            "uri": location.file_path,
            "uriBaseId": "%SRCROOT%",
        },
        "region": region,
    }


def _related_locations(locations: list[Location]) -> list[dict[str, object]]:
    related: list[dict[str, object]] = []
    for index, location in enumerate(locations, start=1):
        related.append(
            {
                "id": index,
                "physicalLocation": _physical_location(location),
                "message": {"text": "Related location"},
            }
        )
    return related


def _code_flows(finding: VerifiedFinding) -> list[dict[str, object]]:
    if not finding.proof or not finding.proof.data_flow_trace:
        return []
    flow_locations = [
        {
            "location": {
                "physicalLocation": {
                    "artifactLocation": {
                        "uri": step.file,
                    },
                    "region": {
                        "startLine": step.line,
                    },
                },
                "message": {
                    "text": step.description,
                },
            }
        }
        for step in finding.proof.data_flow_trace
    ]
    return [{"threadFlows": [{"locations": flow_locations}]}]


def _severity_to_level(severity: str) -> str:
    return _SEVERITY_TO_LEVEL.get(severity, "warning")


def _max_level(findings: list[VerifiedFinding]) -> str:
    levels = [_severity_to_level(finding.severity.value) for finding in findings]
    return max(levels, key=lambda level: _LEVEL_RANK[level])


def _max_precision(findings: list[VerifiedFinding]) -> str:
    precisions = [_VERDICT_TO_PRECISION.get(finding.verdict.value, "medium") for finding in findings]
    return max(precisions, key=lambda precision: _PRECISION_RANK[precision])


def _compliance_list(finding: VerifiedFinding) -> list[str]:
    return [_compliance_entry(mapping.framework, mapping.control_id) for mapping in finding.compliance]


def _aggregate_rule_tags(findings: list[VerifiedFinding]) -> list[str]:
    tags: set[str] = set()
    for finding in findings:
        tags.update(_base_tags(finding))
        tags.update(_compliance_tags(finding))
    return sorted(tags)


def _result_tags(finding: VerifiedFinding) -> list[str]:
    tags = set(_base_tags(finding))
    tags.update(_compliance_tags(finding))
    return sorted(tags)


def _base_tags(finding: VerifiedFinding) -> list[str]:
    tags = ["security", finding.cwe_id.upper()]
    if finding.owasp_category:
        tags.append(f"OWASP-{finding.owasp_category}")
    tags.extend(sorted(finding.tags))
    return tags


def _compliance_tags(finding: VerifiedFinding) -> list[str]:
    return [
        f"compliance:{mapping.framework}:{_normalize_control_id(mapping.control_id)}" for mapping in finding.compliance
    ]


def _compliance_entry(framework: str, control_id: str) -> str:
    return f"{framework}:{_normalize_control_id(control_id)}"


def _normalize_control_id(control_id: str) -> str:
    return re.sub(r"\s+", "-", control_id.strip())


def _format_security_severity(score: float) -> str:
    bounded = min(10.0, max(0.0, score))
    return f"{bounded:.1f}"


def _rule_name(rule_id: str) -> str:
    raw_name = rule_id.split("/")[-1]
    chunks = [chunk for chunk in raw_name.split("-") if chunk]
    return "".join(chunk.capitalize() for chunk in chunks) or "SecAfRule"


def _cwe_number(cwe_id: str) -> str:
    normalized = cwe_id.upper().replace("CWE-", "")
    return normalized
