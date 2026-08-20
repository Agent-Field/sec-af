#!/usr/bin/env python3
"""Committed schema-fixture generator for the SEC-AF Go port.

This script is the SINGLE SOURCE OF TRUTH for the JSON-schema fixtures under
``go/internal/harnessx/testdata/schemas/``. It imports the REAL pydantic models
that SEC-AF hands to ``app.harness(..., schema=Model)`` / ``app.ai(..., schema=Model)``
and writes, for each one, exactly the schema the Python SDK builds from it —
``Model.model_json_schema()`` (agentfield ``harness/_schema.py:49`` and
``agent_ai.py:803`` both call precisely that).

WHY THIS EXISTS
---------------
The Go SDK validates every parsed harness output against the schema map with a
strict JSON-Schema validator (``santhosh-tekuri/jsonschema/v5``, see
``sdk/go/harness/schema.go``) and drives its schema-retry loop off validation
failures; it ALSO pretty-prints the map into the OUTPUT REQUIREMENTS section of
the prompt. Reflecting the Go destination struct with invopop instead would
mark every field required, make ``X | None`` fields non-nullable and set
``additionalProperties: false`` — so output that Python accepts would be
REJECTED by the Go node (wasted retries, dropped findings) and the prompt the
model sees would differ from the Python node's. Embedding the pydantic schema
removes all three divergences at once.

There are NO deliberate deviations from ``model_json_schema()`` for SEC-AF.
(pr-af has one, for a severity field with a pydantic ``BeforeValidator`` that
JSON-Schema cannot express. SEC-AF's ``Severity``/``Confidence``/``HuntStrategy``
are plain ``str, Enum`` classes with no coercion, so the emitted enum matches
Python's runtime validation exactly. If a ``BeforeValidator`` is ever added to a
SEC-AF schema field, revisit this paragraph.)

MODEL LIST
----------
``MODELS`` below is the enumerated, explicit list of every model this repo passes
as ``schema=``. Re-derive it with, from the repo root:

    grep -rn "schema=" src/ | grep -v "schema=schema"

Every entry is keyed by the pydantic CLASS NAME, because that is the contract
``harnessx.SchemaFor[T]`` resolves against: the Go struct name equals the
pydantic class name, and the fixture basename equals both.

REPRODUCE (from the repo root):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_schemas.py

Deterministic and idempotent: rerunning overwrites the fixtures with identical
bytes unless a Python model changed — exactly the signal the Go tests exist to
catch.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any

# Make `sec_af` importable when run from the repo root without an install.
_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_SRC = os.path.join(_REPO_ROOT, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

from sec_af import policies  # noqa: E402
from sec_af.schemas import gates, hunt, output, prove, recon  # noqa: E402

TESTDATA = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "internal",
    "harnessx",
    "testdata",
    "schemas",
)

# fixture basename (== pydantic class name == Go struct name) -> model.
#
# Grouped by the call site that passes it as `schema=`. Keep this list in sync
# with `grep -rn "schema=" src/`; the Go test TestEveryFixtureIsAnObjectSchema
# only checks what is here, so a model added in Python without an entry here is
# caught by review, not by CI.
MODELS: dict[str, Any] = {
    # --- .harness(schema=...) : RECON -------------------------------------
    # agents/recon/architecture.py:35
    "ArchitectureMapRaw": recon.ArchitectureMapRaw,
    # agents/recon/dependencies.py:34
    "DependencyReportRaw": recon.DependencyReportRaw,
    # agents/recon/config_scanner.py:34
    "ConfigReportRaw": recon.ConfigReportRaw,
    # agents/recon/data_flow.py:40
    "DataFlowMapRaw": recon.DataFlowMapRaw,
    # agents/recon/security_context.py:40
    "SecurityContextRaw": recon.SecurityContextRaw,
    # --- .harness(schema=...) : HUNT --------------------------------------
    # agents/hunt/_scan_enrich.py:65
    "ScanLocationsResult": hunt.ScanLocationsResult,
    # agents/hunt/_scan_enrich.py:93
    "EnrichedFinding": hunt.EnrichedFinding,
    # agents/dedup.py:303
    "ChainCorrelationResult": hunt.ChainCorrelationResult,
    # --- .harness(schema=...) : PROVE -------------------------------------
    # agents/prove/tracer.py:76
    "DataFlowTrace": prove.DataFlowTrace,
    # agents/prove/sanitization.py:73
    "SanitizationResult": prove.SanitizationResult,
    # agents/prove/exploit.py:92
    "ExploitHypothesis": prove.ExploitHypothesis,
    # agents/prove/dep_reachability.py:58
    "ReachabilityProof": prove.ReachabilityProof,
    # agents/prove/dast_verifier.py:63
    "DastVerificationResult": prove.DastVerificationResult,
    # agents/prove/cross_service.py:58
    "CrossServiceFinding": output.CrossServiceFinding,
    # --- .harness(schema=...) : REMEDIATION / POLICIES --------------------
    # agents/remediation.py:67 and :126
    "RemediationSuggestion": prove.RemediationSuggestion,
    # policies.py:66
    "PolicyEvalResult": policies.PolicyEvalResult,
    # --- .ai(schema=...) gates --------------------------------------------
    # agents/prove/verdict.py:101
    "VerdictDecision": prove.VerdictDecision,
    # reasoners/phases.py:127
    "CWEExpansion": gates.CWEExpansion,
    # harness.py:442 (AIGateWrapper.classify_severity)
    "SeverityClassification": gates.SeverityClassification,
    # harness.py:451 (AIGateWrapper.check_duplicate) and agents/dedup.py:113
    "DuplicateCheck": gates.DuplicateCheck,
    # harness.py:466 (AIGateWrapper.select_strategy)
    "StrategySelection": gates.StrategySelection,
    # harness.py:475 (AIGateWrapper.assess_reachability)
    "ReachabilityGate": gates.ReachabilityGate,
    # compliance/mapping.py:410 (get_compliance_mappings_hybrid)
    "ComplianceGate": gates.ComplianceGate,
}


def emit(name: str, model: Any) -> None:
    schema = model.model_json_schema()
    # sort_keys makes the committed fixture diff-stable, and it costs nothing at
    # runtime: the Go SDK re-marshals the decoded map (encoding/json sorts map
    # keys) before it reaches either the validator or the prompt. It also makes
    # aix.Strictify's `required` list — which it emits in sorted key order,
    # because a Go map carries no insertion order — identical to what Python's
    # `list(props.keys())` produces from this same fixture.
    text = json.dumps(schema, indent=2, sort_keys=True) + "\n"
    path = os.path.join(TESTDATA, name + ".json")
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    print(f"  wrote {name}.json ({len(text)} bytes)")


def main() -> None:
    os.makedirs(TESTDATA, exist_ok=True)
    for name in sorted(MODELS):
        emit(name, MODELS[name])
    print(f"done. {len(MODELS)} schema fixtures.")


if __name__ == "__main__":
    main()
