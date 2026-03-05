from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, cast

import pytest
from pydantic_core import ValidationError as PydanticValidationError

from sec_af.schemas import gates
from sec_af.schemas.compliance import ComplianceGap, ComplianceMapping
from sec_af.schemas.hunt import (
    Confidence,
    FindingType,
    HuntResult,
    HuntStrategy,
    RawFinding,
    Severity,
)
from sec_af.schemas.input import AuditInput
from sec_af.schemas.output import AttackChain, AuditMetrics, AuditProgress, MitreMapping, SecurityAuditResult
from sec_af.schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding
from sec_af.schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)


def _validate(model_cls: type[Any], payload: dict[str, Any]) -> Any:
    validate = getattr(model_cls, "model_validate", None)
    if callable(validate):
        return validate(payload)
    return model_cls.parse_obj(payload)


def _dump(model: Any) -> dict[str, Any]:
    dump = getattr(model, "model_dump", None)
    if callable(dump):
        return cast("dict[str, Any]", dump())
    return cast("dict[str, Any]", model.dict())


def _json_schema(model_cls: type[Any]) -> dict[str, Any]:
    schema_builder = getattr(model_cls, "model_json_schema", None)
    if callable(schema_builder):
        return cast("dict[str, Any]", schema_builder())
    return cast("dict[str, Any]", model_cls.schema())


def test_schema_validation_and_required_fields(sample_verified_findings: list[VerifiedFinding]) -> None:
    with pytest.raises(PydanticValidationError):
        _validate(AuditInput, {"branch": "main"})

    with pytest.raises(PydanticValidationError):
        _validate(
            RawFinding,
            {
                "hunter_strategy": "injection",
                "title": "missing fields",
                "description": "missing required fields",
            },
        )

    with pytest.raises(PydanticValidationError):
        _validate(
            VerifiedFinding,
            {
                "title": "missing fingerprint",
                "description": "bad",
                "finding_type": "sast",
                "cwe_id": "CWE-79",
                "cwe_name": "XSS",
                "verdict": "confirmed",
                "evidence_level": 3,
                "rationale": "test",
                "severity": "high",
                "exploitability_score": 7.2,
            },
        )

    assert sample_verified_findings[0].location.file_path == "src/users.py"


def test_schema_roundtrip_serialization(sample_security_audit_result: SecurityAuditResult) -> None:
    payload = _dump(sample_security_audit_result)
    restored = _validate(SecurityAuditResult, payload)

    assert restored.repository == sample_security_audit_result.repository
    assert restored.findings[0].fingerprint == "fp-sql-1"
    assert restored.findings[1].verdict == Verdict.LIKELY
    assert restored.findings[2].verdict == Verdict.NOT_EXPLOITABLE


def test_enum_values_are_stable() -> None:
    assert FindingType.SAST.value == "sast"
    assert FindingType.API.value == "api"
    assert Severity.CRITICAL.value == "critical"
    assert Confidence.HIGH.value == "high"
    assert Verdict.CONFIRMED.value == "confirmed"
    assert EvidenceLevel.FULL_EXPLOIT == 6
    assert HuntStrategy.CONFIG_SECRETS.value == "config_secrets"


def test_json_schema_generation_contains_expected_fields() -> None:
    audit_input_schema = _json_schema(AuditInput)
    finding_schema = _json_schema(VerifiedFinding)
    result_schema = _json_schema(SecurityAuditResult)

    assert "repo_url" in audit_input_schema["properties"]
    assert "repo_url" in audit_input_schema["required"]
    assert "fingerprint" in finding_schema["properties"]
    assert "location" in finding_schema["properties"]
    assert "findings" in result_schema["properties"]
    assert "repository" in result_schema["required"]


def test_recon_hunt_output_and_gate_models_instantiate() -> None:
    recon = ReconResult(
        architecture=ArchitectureMap(app_type="web"),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(direct_count=1, transitive_count=2),
        config=ConfigReport(),
        security_context=SecurityContext(auth_model="jwt", auth_details="bearer token"),
        languages=["python"],
        frameworks=["fastapi"],
        lines_of_code=1200,
        file_count=34,
        recon_duration_seconds=12.5,
    )
    hunt = HuntResult(total_raw=2, deduplicated_count=2, chain_count=1, strategies_run=["injection"])
    attack_chain = AttackChain(
        chain_id="chain-123",
        title="Privilege escalation path",
        description="Two-step attack",
        findings=["f1", "f2"],
        combined_severity=Severity.HIGH,
        combined_impact="Privilege escalation",
        mitre_attack_mapping=[
            MitreMapping(
                tactic="Privilege Escalation",
                technique_id="T1068",
                technique_name="Exploitation for Privilege Escalation",
            )
        ],
    )
    progress = AuditProgress(
        phase="prove",
        phase_progress=0.75,
        agents_total=6,
        agents_completed=4,
        agents_running=2,
        findings_so_far=3,
        elapsed_seconds=45.0,
        estimated_remaining_seconds=15.0,
        cost_so_far_usd=1.23,
    )
    metrics = AuditMetrics(duration_seconds=180.0, agent_invocations=22, cost_usd=2.9)
    compliance = ComplianceGap(
        framework="PCI-DSS",
        control_id="Req 6.2.4",
        control_name="Prevent injection",
        finding_count=2,
        max_severity="critical",
        cwe_ids=["CWE-79", "CWE-89"],
    )
    gate = gates.SeverityClassification(severity="high", confidence=0.9, rationale="validated")
    compliance_gate = gates.ComplianceGate(
        mappings=[
            gates.ComplianceSuggestion(
                framework="OWASP",
                control_id="A03:2021",
                control_name="Injection",
            )
        ],
        confidence="high",
    )

    assert recon.lines_of_code == 1200
    assert hunt.total_raw == 2
    assert attack_chain.mitre_attack_mapping is not None
    assert progress.phase == "prove"
    assert metrics.budget_exhausted is False
    assert compliance.framework == "PCI-DSS"
    assert gate.severity == "high"
    assert compliance_gate.mappings[0].framework == "OWASP"


def test_model_validate_accepts_nested_dictionaries() -> None:
    payload = {
        "repository": "Agent-Field/sec-af",
        "commit_sha": "b" * 40,
        "branch": "main",
        "timestamp": datetime(2026, 3, 4, 12, 0, 0, tzinfo=UTC).isoformat(),
        "depth_profile": "quick",
        "provider": "opencode",
        "sarif": "{}",
        "findings": [
            {
                "fingerprint": "fp-1",
                "title": "Weak hash",
                "description": "Uses md5",
                "finding_type": "sast",
                "cwe_id": "CWE-327",
                "cwe_name": "Broken crypto",
                "verdict": "likely",
                "evidence_level": 2,
                "rationale": "hash algorithm is weak",
                "severity": "medium",
                "exploitability_score": 1.5,
                "location": {"file_path": "src/auth.py", "start_line": 7, "end_line": 7},
                "sarif_rule_id": "sec-af/sast/weak-hash",
                "sarif_security_severity": 4.1,
                "compliance": [
                    {
                        "framework": "OWASP",
                        "control_id": "A02:2021",
                        "control_name": "Cryptographic Failures",
                    }
                ],
            }
        ],
    }

    model = _validate(SecurityAuditResult, payload)
    assert isinstance(model.findings[0].location, Location)
    assert isinstance(model.findings[0].compliance[0], ComplianceMapping)
