"""Schema-compatibility tests for the committed example findings.

Example `*.finding.json` files under `exampl/` are advertised as SEC-AF
findings, so consumers must be able to load them with the repository schema
(`sec_af.schemas.prove.VerifiedFinding`). This guards against a fixture that
omits required schema fields or carries non-schema-shaped nested objects
(`Proof`, `RemediationSuggestion`) - which Pydantic would reject at import time.
"""

from __future__ import annotations

import json
import pathlib

import pytest

from sec_af.schemas.prove import EvidenceLevel, Verdict, VerifiedFinding

_EXAMPLE_DIR = pathlib.Path(__file__).resolve().parents[1] / "exampl"
_FINDING_FIXTURES = sorted(_EXAMPLE_DIR.glob("*.finding.json"))


def _fixture_id(path: pathlib.Path) -> str:
    return path.name


@pytest.mark.parametrize("fixture", _FINDING_FIXTURES, ids=_fixture_id)
def test_example_finding_loads_as_verified_finding(fixture: pathlib.Path) -> None:
    """Every `exampl/*.finding.json` must validate against VerifiedFinding."""
    data = json.loads(fixture.read_text(encoding="utf-8"))

    finding = VerifiedFinding.model_validate(data)

    # Core required fields resolve to their typed values.
    assert finding.title
    assert finding.fingerprint
    assert isinstance(finding.verdict, Verdict)
    assert isinstance(finding.evidence_level, EvidenceLevel)
    assert finding.rationale, "rationale is a required VerifiedFinding field"
    assert finding.sarif_rule_id, "sarif_rule_id is a required VerifiedFinding field"
    assert finding.sarif_security_severity >= 0.0

    # If a proof is supplied it must be a fully-formed Proof, not a bag of
    # non-schema keys - the failure mode this fixture previously exhibited.
    if finding.proof is not None:
        assert finding.proof.exploit_hypothesis
        assert finding.proof.verification_method
        assert isinstance(finding.proof.evidence_level, EvidenceLevel)

    # Likewise for remediation -> RemediationSuggestion.
    if finding.remediation is not None:
        assert finding.remediation.fix_description
        assert finding.remediation.patch_diff
        assert finding.remediation.confidence in {"high", "medium", "low"}


def test_at_least_one_example_finding_present() -> None:
    """Fail loudly if the example-finding fixtures disappear or are renamed."""
    assert _FINDING_FIXTURES, f"no *.finding.json fixtures found in {_EXAMPLE_DIR}"
