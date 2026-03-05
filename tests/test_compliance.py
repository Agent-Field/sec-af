import importlib
import asyncio
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

sys.modules.pop("sec_af.compliance.mapping", None)
mapping = importlib.import_module("sec_af.compliance.mapping")
COMPLIANCE_MAP = mapping.COMPLIANCE_MAP
get_compliance_gaps = mapping.get_compliance_gaps
get_compliance_mappings = mapping.get_compliance_mappings
get_supported_frameworks = mapping.get_supported_frameworks


REQUIRED_CWES = {
    "CWE-78",
    "CWE-79",
    "CWE-89",
    "CWE-90",
    "CWE-91",
    "CWE-94",
    "CWE-917",
    "CWE-287",
    "CWE-306",
    "CWE-352",
    "CWE-862",
    "CWE-863",
    "CWE-326",
    "CWE-327",
    "CWE-328",
    "CWE-330",
    "CWE-916",
    "CWE-840",
    "CWE-841",
    "CWE-200",
    "CWE-209",
    "CWE-312",
    "CWE-319",
    "CWE-532",
    "CWE-829",
    "CWE-1104",
    "CWE-16",
    "CWE-259",
    "CWE-321",
    "CWE-798",
    "CWE-285",
    "CWE-346",
    "CWE-601",
    "CWE-918",
}


@pytest.mark.parametrize(
    ("cwe_id", "owasp_control"),
    [
        ("CWE-89", "A03:2021"),
        ("CWE-79", "A03:2021"),
        ("CWE-287", "A07:2021"),
        ("CWE-862", "A01:2021"),
        ("CWE-326", "A02:2021"),
        ("CWE-840", "A04:2021"),
        ("CWE-200", "A01:2021"),
        ("CWE-1104", "A06:2021"),
        ("CWE-16", "A05:2021"),
        ("CWE-918", "A10:2021"),
    ],
)
def test_key_cwes_include_required_framework_mappings(cwe_id: str, owasp_control: str) -> None:
    mappings = get_compliance_mappings(cwe_id)
    frameworks = {mapping.framework for mapping in mappings}

    assert "PCI-DSS" in frameworks
    assert "SOC2" in frameworks
    assert "OWASP" in frameworks
    assert any(mapping.framework == "OWASP" and mapping.control_id == owasp_control for mapping in mappings)


def test_all_required_cwes_are_mapped() -> None:
    assert set(COMPLIANCE_MAP.keys()) == REQUIRED_CWES


def test_get_compliance_mappings_handles_cwe_normalization() -> None:
    normalized = get_compliance_mappings("CWE-89")
    shorthand = get_compliance_mappings("89")
    mixed_case = get_compliance_mappings("cwe89")

    assert normalized
    assert shorthand == normalized
    assert mixed_case == normalized


def test_get_compliance_mappings_can_filter_frameworks() -> None:
    filtered = get_compliance_mappings("CWE-319", frameworks=["pci-dss", "owasp"])
    assert {mapping.framework for mapping in filtered} == {"PCI-DSS", "OWASP"}


def test_get_supported_frameworks_returns_expected_set() -> None:
    assert get_supported_frameworks() == [
        "HIPAA",
        "ISO27001",
        "OWASP",
        "PCI-DSS",
        "SOC2",
    ]


def test_get_compliance_gaps_aggregates_count_and_max_severity() -> None:
    findings = [
        {"cwe_id": "CWE-89", "severity": "high"},
        {"cwe_id": "CWE-79", "severity": "critical"},
        {"cwe_id": "CWE-918", "severity": "medium"},
    ]

    gaps = get_compliance_gaps(findings)
    pci_injection = [gap for gap in gaps if gap.framework == "PCI-DSS" and gap.control_id == "Req 6.2.4"]

    assert len(pci_injection) == 1
    assert pci_injection[0].finding_count == 2
    assert pci_injection[0].max_severity == "critical"
    assert set(pci_injection[0].cwe_ids) == {"CWE-79", "CWE-89"}


def test_get_compliance_mappings_returns_empty_for_unmapped_cwe() -> None:
    assert get_compliance_mappings("CWE-9999") == []


def test_get_compliance_mappings_returns_deep_copies() -> None:
    first = get_compliance_mappings("CWE-89")
    second = get_compliance_mappings("CWE-89")

    first[0].control_name = "mutated"

    assert second[0].control_name != "mutated"


def test_get_compliance_mappings_framework_filter_with_unknown_framework() -> None:
    filtered = get_compliance_mappings("CWE-89", frameworks=["owasp", "does-not-exist"])
    assert {mapping.framework for mapping in filtered} == {"OWASP"}


def test_get_compliance_gaps_accepts_object_findings_and_normalizes_cwe() -> None:
    findings = [
        SimpleNamespace(cwe_id="89", severity="high"),
        SimpleNamespace(cwe_id="cwe89", severity="critical"),
    ]

    gaps = get_compliance_gaps(findings)
    owasp_gap = next(gap for gap in gaps if gap.framework == "OWASP" and gap.control_id == "A03:2021")

    assert owasp_gap.finding_count == 2
    assert owasp_gap.max_severity == "critical"
    assert owasp_gap.cwe_ids == ["CWE-89"]


def test_get_compliance_gaps_ignores_entries_without_valid_cwe() -> None:
    findings = [
        {"severity": "critical"},
        {"cwe_id": None, "severity": "high"},
        {"cwe_id": "CWE-9999", "severity": "critical"},
    ]

    assert get_compliance_gaps(findings) == []


class _FakeAIGate:
    def __init__(self, response: object):
        self.calls = 0
        self.response = response

    async def invoke(self, *, user: str, schema: object, system: str | None = None) -> object:
        _ = user, schema, system
        self.calls += 1
        return self.response


def test_get_compliance_mappings_hybrid_uses_ai_fallback_for_unknown_cwe() -> None:
    assert hasattr(mapping, "get_compliance_mappings_hybrid")
    mapping._AI_COMPLIANCE_CACHE.clear()
    gate = _FakeAIGate(
        mapping.ComplianceGate(
            mappings=[
                {
                    "framework": "OWASP",
                    "control_id": "A03:2021",
                    "control_name": "Injection",
                },
                {
                    "framework": "PCI-DSS",
                    "control_id": "Req 6.2.4",
                    "control_name": "Prevent injection attacks",
                },
            ],
            confidence="high",
        )
    )

    results = asyncio.run(mapping.get_compliance_mappings_hybrid("CWE-9999", ai_gate=gate))

    assert gate.calls == 1
    assert len(results) == 2
    assert {item.framework for item in results} == {"OWASP", "PCI-DSS"}


def test_get_compliance_mappings_hybrid_uses_cache_for_ai_results() -> None:
    mapping._AI_COMPLIANCE_CACHE.clear()
    gate = _FakeAIGate(
        mapping.ComplianceGate(
            mappings=[
                {
                    "framework": "OWASP",
                    "control_id": "A03:2021",
                    "control_name": "Injection",
                }
            ],
            confidence="high",
        )
    )

    first = asyncio.run(mapping.get_compliance_mappings_hybrid("CWE-9999", ai_gate=gate))
    second = asyncio.run(mapping.get_compliance_mappings_hybrid("CWE-9999", ai_gate=gate))

    assert gate.calls == 1
    assert first == second


def test_get_compliance_mappings_hybrid_keeps_fast_path_for_known_cwe() -> None:
    mapping._AI_COMPLIANCE_CACHE.clear()
    gate = _FakeAIGate(
        mapping.ComplianceGate(
            mappings=[],
            confidence="low",
        )
    )

    results = asyncio.run(mapping.get_compliance_mappings_hybrid("CWE-89", ai_gate=gate))

    assert gate.calls == 0
    assert results == get_compliance_mappings("CWE-89")
