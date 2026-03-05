from collections.abc import Iterable
from typing import TYPE_CHECKING, Any, Protocol

from ..schemas.compliance import ComplianceGap, ComplianceMapping
from ..schemas.gates import ComplianceGate

if TYPE_CHECKING:
    from pydantic import BaseModel


def _cm(framework: str, control_id: str, control_name: str) -> ComplianceMapping:
    return ComplianceMapping(
        framework=framework,
        control_id=control_id,
        control_name=control_name,
    )


COMPLIANCE_MAP: dict[str, list[ComplianceMapping]] = {
    "CWE-78": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-79": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-89": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-90": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-91": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-94": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-917": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A03:2021", "Injection"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-287": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A07:2021", "Identification and Authentication Failures"),
        _cm("HIPAA", "\u00a7164.312(d)", "Person or entity authentication"),
        _cm("ISO27001", "A.5.17", "Authentication information"),
    ],
    "CWE-306": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A07:2021", "Identification and Authentication Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.5.15", "Access control"),
    ],
    "CWE-352": [
        _cm(
            "PCI-DSS",
            "Req 6.2.4",
            "Custom software addresses common coding vulnerabilities",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.8.5", "Secure authentication"),
    ],
    "CWE-862": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.5.15", "Access control"),
    ],
    "CWE-863": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.5.18", "Access rights"),
    ],
    "CWE-326": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(2)(iv)", "Encryption and decryption"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-327": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(2)(iv)", "Encryption and decryption"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-328": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(2)(iv)", "Encryption and decryption"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-330": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-916": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A07:2021", "Identification and Authentication Failures"),
        _cm("HIPAA", "\u00a7164.312(d)", "Person or entity authentication"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-840": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A04:2021", "Insecure Design"),
        _cm("HIPAA", "\u00a7164.308(a)(1)(ii)(A)", "Risk analysis"),
        _cm("ISO27001", "A.8.25", "Secure development lifecycle"),
    ],
    "CWE-841": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A04:2021", "Insecure Design"),
        _cm("HIPAA", "\u00a7164.308(a)(1)(ii)(A)", "Risk analysis"),
        _cm("ISO27001", "A.8.25", "Secure development lifecycle"),
    ],
    "CWE-200": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.8.12", "Data leakage prevention"),
    ],
    "CWE-209": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A09:2021", "Security Logging and Monitoring Failures"),
        _cm("HIPAA", "\u00a7164.312(b)", "Audit controls"),
        _cm("ISO27001", "A.8.15", "Logging"),
    ],
    "CWE-312": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(2)(iv)", "Encryption and decryption"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-319": [
        _cm(
            "PCI-DSS",
            "Req 4",
            "Protect cardholder data with strong cryptography during transmission",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(e)(1)", "Transmission security"),
        _cm("ISO27001", "A.8.20", "Network security"),
    ],
    "CWE-532": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A09:2021", "Security Logging and Monitoring Failures"),
        _cm("HIPAA", "\u00a7164.312(b)", "Audit controls"),
        _cm("ISO27001", "A.8.15", "Logging"),
    ],
    "CWE-829": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC8", "Change management"),
        _cm("OWASP", "A08:2021", "Software and Data Integrity Failures"),
        _cm("HIPAA", "\u00a7164.308(a)(1)(ii)(B)", "Risk management"),
        _cm("ISO27001", "A.8.25", "Secure development lifecycle"),
    ],
    "CWE-1104": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC8", "Change management"),
        _cm("OWASP", "A06:2021", "Vulnerable and Outdated Components"),
        _cm("HIPAA", "\u00a7164.308(a)(1)(ii)(B)", "Risk management"),
        _cm("ISO27001", "A.8.8", "Management of technical vulnerabilities"),
    ],
    "CWE-16": [
        _cm("PCI-DSS", "Req 2", "Apply secure configurations to all system components"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A05:2021", "Security Misconfiguration"),
        _cm("HIPAA", "\u00a7164.308(a)(1)(ii)(B)", "Risk management"),
        _cm("ISO27001", "A.8.9", "Configuration management"),
    ],
    "CWE-259": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A07:2021", "Identification and Authentication Failures"),
        _cm("HIPAA", "\u00a7164.312(d)", "Person or entity authentication"),
        _cm("ISO27001", "A.5.17", "Authentication information"),
    ],
    "CWE-321": [
        _cm("PCI-DSS", "Req 3", "Protect stored account data"),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A02:2021", "Cryptographic Failures"),
        _cm("HIPAA", "\u00a7164.312(a)(2)(iv)", "Encryption and decryption"),
        _cm("ISO27001", "A.8.24", "Use of cryptography"),
    ],
    "CWE-798": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A07:2021", "Identification and Authentication Failures"),
        _cm("HIPAA", "\u00a7164.312(d)", "Person or entity authentication"),
        _cm("ISO27001", "A.5.17", "Authentication information"),
    ],
    "CWE-285": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.5.15", "Access control"),
    ],
    "CWE-346": [
        _cm(
            "PCI-DSS",
            "Req 8",
            "Identify users and authenticate access to system components",
        ),
        _cm("SOC2", "CC6", "Logical and physical access controls"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(a)(1)", "Access control"),
        _cm("ISO27001", "A.5.16", "Identity management"),
    ],
    "CWE-601": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A01:2021", "Broken Access Control"),
        _cm("HIPAA", "\u00a7164.312(c)(1)", "Integrity"),
        _cm("ISO27001", "A.8.28", "Secure coding"),
    ],
    "CWE-918": [
        _cm("PCI-DSS", "Req 6", "Develop and maintain secure systems and software"),
        _cm("SOC2", "CC7", "System operations"),
        _cm("OWASP", "A10:2021", "Server-Side Request Forgery"),
        _cm("HIPAA", "\u00a7164.312(e)(1)", "Transmission security"),
        _cm("ISO27001", "A.8.20", "Network security"),
    ],
}

_SEVERITY_RANK = {
    "critical": 5,
    "high": 4,
    "medium": 3,
    "low": 2,
    "info": 1,
}

_DEFAULT_FRAMEWORKS = ["OWASP", "PCI-DSS", "SOC2", "HIPAA", "ISO27001"]
_AI_COMPLIANCE_CACHE: dict[tuple[str, tuple[str, ...] | None], list[ComplianceMapping]] = {}


class _AIGateLike(Protocol):
    async def invoke(
        self,
        *,
        user: str,
        schema: type["BaseModel"],
        system: str | None = None,
    ) -> Any: ...


def _normalize_cwe_id(cwe_id: str) -> str:
    raw = cwe_id.strip().upper()
    if raw.startswith("CWE-"):
        return raw
    if raw.startswith("CWE"):
        return f"CWE-{raw[3:]}"
    return f"CWE-{raw}"


def _normalize_framework(framework: str) -> str:
    return framework.strip().lower().replace("_", "-")


def get_compliance_mappings(
    cwe_id: str,
    frameworks: list[str] | None = None,
) -> list[ComplianceMapping]:
    normalized_cwe = _normalize_cwe_id(cwe_id)
    mappings = COMPLIANCE_MAP.get(normalized_cwe, [])
    if not frameworks:
        return [mapping.model_copy(deep=True) for mapping in mappings]

    allowed = {_normalize_framework(framework) for framework in frameworks}
    return [mapping.model_copy(deep=True) for mapping in mappings if _normalize_framework(mapping.framework) in allowed]


async def get_compliance_mappings_hybrid(
    cwe_id: str,
    frameworks: list[str] | None = None,
    ai_gate: _AIGateLike | None = None,
) -> list[ComplianceMapping]:
    normalized_cwe = _normalize_cwe_id(cwe_id)
    cached_mappings = get_compliance_mappings(normalized_cwe, frameworks=frameworks)
    if cached_mappings:
        return cached_mappings
    if ai_gate is None:
        return []

    cache_frameworks = None
    framework_list = list(_DEFAULT_FRAMEWORKS)
    if frameworks:
        cache_frameworks = tuple(sorted({_normalize_framework(framework) for framework in frameworks}))
        framework_list = list(frameworks)

    cache_key = (normalized_cwe, cache_frameworks)
    if cache_key in _AI_COMPLIANCE_CACHE:
        return [mapping.model_copy(deep=True) for mapping in _AI_COMPLIANCE_CACHE[cache_key]]

    cwe_description = "Unknown CWE"
    framework_prompt = ", ".join(framework_list) if framework_list else ", ".join(_DEFAULT_FRAMEWORKS)
    prompt = (
        f"Map {normalized_cwe} ({cwe_description}) to compliance framework controls. "
        f"Frameworks: {framework_prompt}. Return specific control IDs."
    )

    try:
        suggestion = await ai_gate.invoke(user=prompt, schema=ComplianceGate)
    except Exception:
        return []

    ai_mappings = [
        ComplianceMapping(
            framework=item.framework,
            control_id=item.control_id,
            control_name=item.control_name,
        )
        for item in suggestion.mappings
    ]
    if frameworks:
        allowed = {_normalize_framework(framework) for framework in frameworks}
        ai_mappings = [mapping for mapping in ai_mappings if _normalize_framework(mapping.framework) in allowed]

    _AI_COMPLIANCE_CACHE[cache_key] = [mapping.model_copy(deep=True) for mapping in ai_mappings]
    return [mapping.model_copy(deep=True) for mapping in ai_mappings]


def get_supported_frameworks() -> list[str]:
    return sorted({mapping.framework for mappings in COMPLIANCE_MAP.values() for mapping in mappings})


def _read_field(finding: dict[str, Any] | Any, field_name: str) -> Any:
    if isinstance(finding, dict):
        return finding.get(field_name)
    return getattr(finding, field_name, None)


def get_compliance_gaps(
    findings: Iterable[dict[str, Any] | Any],
) -> list[ComplianceGap]:
    aggregated: dict[tuple[str, str, str], dict[str, Any]] = {}

    for finding in findings:
        cwe_id = _read_field(finding, "cwe_id")
        severity = str(_read_field(finding, "severity") or "low").lower()
        if not cwe_id:
            continue

        normalized_cwe = _normalize_cwe_id(str(cwe_id))
        mappings = get_compliance_mappings(normalized_cwe)
        if not mappings:
            continue

        for mapping in mappings:
            key = (mapping.framework, mapping.control_id, mapping.control_name)
            if key not in aggregated:
                aggregated[key] = {
                    "count": 0,
                    "max_severity": "info",
                    "cwe_ids": [],
                }

            entry = aggregated[key]
            entry["count"] += 1
            if normalized_cwe not in entry["cwe_ids"]:
                entry["cwe_ids"].append(normalized_cwe)

            current_rank = _SEVERITY_RANK.get(entry["max_severity"], 0)
            new_rank = _SEVERITY_RANK.get(severity, 0)
            if new_rank > current_rank:
                entry["max_severity"] = severity

    gaps = [
        ComplianceGap(
            framework=framework,
            control_id=control_id,
            control_name=control_name,
            finding_count=data["count"],
            max_severity=data["max_severity"],
            cwe_ids=sorted(data["cwe_ids"]),
        )
        for (framework, control_id, control_name), data in aggregated.items()
    ]
    return sorted(gaps, key=lambda gap: (gap.framework, gap.control_id, gap.control_name))
