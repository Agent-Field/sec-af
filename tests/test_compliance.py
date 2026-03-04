from pathlib import Path
import importlib
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

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
def test_key_cwes_include_required_framework_mappings(
    cwe_id: str, owasp_control: str
) -> None:
    mappings = get_compliance_mappings(cwe_id)
    frameworks = {mapping.framework for mapping in mappings}

    assert "PCI-DSS" in frameworks
    assert "SOC2" in frameworks
    assert "OWASP" in frameworks
    assert any(
        mapping.framework == "OWASP" and mapping.control_id == owasp_control
        for mapping in mappings
    )


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
    pci_injection = [
        gap
        for gap in gaps
        if gap.framework == "PCI-DSS" and gap.control_id == "Req 6.2.4"
    ]

    assert len(pci_injection) == 1
    assert pci_injection[0].finding_count == 2
    assert pci_injection[0].max_severity == "critical"
    assert set(pci_injection[0].cwe_ids) == {"CWE-79", "CWE-89"}
