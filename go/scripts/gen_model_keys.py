#!/usr/bin/env python3
"""Emit the pydantic ground truth the Go `internal/schemas` parity test asserts against.

Run from the repo root with the sec-af venv (pydantic v2 + the package deps):

    PYTHONPATH=$PWD/src ~/.agentfield/packages/sec-af/venv/bin/python \
        go/scripts/gen_model_keys.py

Writes ``go/internal/schemas/testdata/model_keys.json``.

For every pydantic model that the Go port mirrors, the file records:

* ``go_name``  – the Go struct name (differs from the Python class name only for
  ``recon.DataFlowStep``, which ``sec_af.schemas.__init__`` re-exports as
  ``ReconDataFlowStep`` because ``prove.DataFlowStep`` owns the bare name).
* ``keys``     – ``model_dump()`` key order.  Go marshals struct fields in
  declaration order, so the Go test asserts the ORDERED list, which pins field
  order as well as the key set.
* ``required`` – fields with no default (``FieldInfo.is_required()``).
* ``null_fields`` / ``empty_list_fields`` / ``empty_dict_fields`` /
  ``scalar_defaults`` – what a minimally-constructed instance serialises to for
  every non-required field.  The Go test asserts the same JSON values, which is
  what pins ``Optional[X] -> *X`` (null), ``default_factory=list -> []`` (never
  null) and the non-zero scalar defaults.
* ``int_fields`` / ``float_fields`` – the fields whose annotation is ``int`` /
  ``float`` (``Optional`` unwrapped, ``IntEnum`` counted as int, ``bool``
  excluded because it subclasses ``int``).  pydantic's LAX mode coerces a
  string-encoded number into those (``start_line="10"`` -> ``10``,
  ``end_line="12.0"`` -> ``12``), which ``json.Unmarshal`` refuses outright.
* ``accepts_null`` – the fields that VALIDATE when the caller passes an explicit
  ``None``, measured by actually constructing the model once per field.  This is
  NOT the same as "has a default": a non-``Optional`` field with a default
  (``HuntResult.findings``) REJECTS an explicit ``None``, while a required field
  carrying a ``mode="before"`` validator that maps ``None`` to a value
  (``DataFlowTrace.source`` -> ``"unknown"``) ACCEPTS one.  Go's
  ``json.Unmarshal`` does neither: a null is a no-op for scalars and ZEROES a
  slice/map/pointer, so ``internal/phases`` needs the explicit list.

Required fields are filled with type-derived placeholders so the model can be
instantiated; their serialised values are deliberately NOT asserted in Go.

Enums are recorded separately (``enums``) with their member name -> value map,
in declaration order, including value aliases.
"""

from __future__ import annotations

import enum
import importlib
import inspect
import json
import types
import typing
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel
from pydantic.fields import FieldInfo

# --------------------------------------------------------------------------
# The models the Go port mirrors, grouped by Python module.  The Go package
# flattens all of them into one package, so name collisions across modules are
# resolved here (see GO_NAME_OVERRIDES / DUPLICATE_OF).
# --------------------------------------------------------------------------

MODULES: dict[str, list[str]] = {
    "sec_af.schemas.compliance": ["ComplianceMapping", "ComplianceGap"],
    "sec_af.schemas.gates": [
        "SeverityClassification",
        "DuplicateCheck",
        "StrategySelection",
        "CWEExpansion",
        "RelevanceGate",
        "VerdictGate",
        "ComplianceSuggestion",
        "ComplianceGate",
        "ReachabilityGate",
    ],
    "sec_af.schemas.hunt": [
        "VulnLocation",
        "EnrichedFinding",
        "ScanLocationsResult",
        "RawFinding",
        "PotentialChain",
        "HuntResult",
        "DeduplicatedResult",
        "ChainCorrelationResult",
    ],
    "sec_af.schemas.input": ["AuditInput"],
    "sec_af.schemas.output": [
        "Location",
        "CvssV4Score",
        "EpssScore",
        "MitreMapping",
        "AttackChain",
        "ReproductionStep",
        "ServiceDefinition",
        "CrossServiceFinding",
        "RegressionFinding",
        "MonitoringResult",
        "PolicyViolation",
        "SecurityAuditResult",
        "AuditProgress",
        "AuditMetrics",
    ],
    "sec_af.schemas.prove": [
        "DataFlowTrace",
        "ReachabilityProof",
        "SanitizationResult",
        "ExploitHypothesis",
        "DastVerificationResult",
        "VerdictDecision",
        "RemediationSuggestion",
        "DataFlowStep",
        "DataFlowEvidence",
        "SanitizationAnalysis",
        "HttpEvidence",
        "ReachabilityEvidence",
        "ChainStep",
        "Proof",
        "ProverSignal",
        "VerifiedFinding",
        # Byte-identical re-declarations of the output.py models (DUPLICATE_OF).
        "Location",
        "CvssV4Score",
        "EpssScore",
        "ReproductionStep",
    ],
    "sec_af.schemas.recon": [
        "Module",
        "EntryPoint",
        "TrustBoundary",
        "Service",
        "APIEndpoint",
        "ArchitectureMap",
        "DataFlowStep",
        "SanitizationPoint",
        "Sink",
        "DataFlow",
        "DataFlowMap",
        "Dependency",
        "KnownCVE",
        "OutdatedDep",
        "DependencyReport",
        "SecretFinding",
        "MisconfigFinding",
        "ConfigReport",
        "CryptoUsage",
        "SecurityContext",
        "ReconResult",
        "ArchitectureMapRaw",
        "DataFlowMapRaw",
        "DependencyReportRaw",
        "ConfigReportRaw",
        "SecurityContextRaw",
    ],
    "sec_af.schemas.views": [
        "FindingForVerifier",
        "FindingForDedup",
        "FindingForReachability",
    ],
    # BaseModel defined outside schemas/ that crosses a JSON boundary
    # (policies.evaluate_policy passes it to app.harness(schema=...)).
    "sec_af.policies": ["PolicyEvalResult"],
}

# Python class name -> Go struct name, where the Go package cannot reuse the
# Python name because another module already claims it.
GO_NAME_OVERRIDES: dict[tuple[str, str], str] = {
    ("sec_af.schemas.recon", "DataFlowStep"): "ReconDataFlowStep",
}

# (module, class) pairs that are byte-identical re-declarations of a model
# another module already declares.  The Go package keeps ONE struct; the
# generator still emits them so the Go test proves the shapes really are equal.
DUPLICATE_OF: dict[tuple[str, str], str] = {
    ("sec_af.schemas.prove", "Location"): "Location",
    ("sec_af.schemas.prove", "CvssV4Score"): "CvssV4Score",
    ("sec_af.schemas.prove", "EpssScore"): "EpssScore",
    ("sec_af.schemas.prove", "ReproductionStep"): "ReproductionStep",
}

ENUMS: dict[str, list[str]] = {
    "sec_af.schemas.hunt": ["FindingType", "Severity", "Confidence", "HuntStrategy"],
    "sec_af.schemas.prove": ["Verdict", "EvidenceLevel"],
}

# Modules whose BaseModel subclasses must ALL appear in MODULES.  Guards against
# a new pydantic model landing in Python without a Go counterpart.
COVERAGE_MODULES = [
    "sec_af.schemas.compliance",
    "sec_af.schemas.gates",
    "sec_af.schemas.hunt",
    "sec_af.schemas.input",
    "sec_af.schemas.output",
    "sec_af.schemas.prove",
    "sec_af.schemas.recon",
    "sec_af.schemas.views",
]

_PLACEHOLDER_DT = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)


def _unwrap_optional(ann: Any) -> tuple[Any, bool]:
    """Return (inner, is_optional) for ``X | None`` / ``Optional[X]``."""
    origin = typing.get_origin(ann)
    if origin is typing.Union or origin is types.UnionType:
        args = [a for a in typing.get_args(ann) if a is not type(None)]
        if len(args) != len(typing.get_args(ann)):
            return (args[0] if len(args) == 1 else typing.Union[tuple(args)], True)
    return ann, False


def _placeholder(ann: Any) -> Any:
    """Build a minimal value satisfying ``ann`` (required-field filler)."""
    ann, optional = _unwrap_optional(ann)
    if optional:
        return None
    origin = typing.get_origin(ann)
    if origin in (list, set, frozenset, tuple):
        return []
    if origin is dict:
        return {}
    if inspect.isclass(ann):
        if issubclass(ann, enum.Enum):
            return next(iter(ann)).value
        if issubclass(ann, BaseModel):
            return _minimal_kwargs(ann)
        if issubclass(ann, bool):
            return False
        if issubclass(ann, int):
            return 0
        if issubclass(ann, float):
            return 0.0
        if issubclass(ann, str):
            return "x"
        if issubclass(ann, datetime):
            return _PLACEHOLDER_DT
    return "x"


def _minimal_kwargs(model: type[BaseModel]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, field in model.model_fields.items():
        if field.is_required():
            out[name] = _placeholder(field.annotation)
    return out


def _numeric_kind(ann: Any) -> str | None:
    """"int" / "float" for a numeric field annotation, else None.

    ``bool`` is excluded even though it subclasses ``int``: pydantic does not
    parse a string into a bool through the int path, and Go's `bool` field takes
    a JSON bool.  An ``IntEnum`` counts as int (``Proof(evidence_level="3")``
    validates on the pinned interpreter).
    """
    ann, _ = _unwrap_optional(ann)
    if not inspect.isclass(ann):
        return None
    if issubclass(ann, bool):
        return None
    if issubclass(ann, enum.Enum):
        return "int" if issubclass(ann, int) else None
    if issubclass(ann, int):
        return "int"
    if issubclass(ann, float):
        return "float"
    return None


def _accepts_null(model: type[BaseModel], fields: dict[str, FieldInfo]) -> list[str]:
    """Fields that validate when the caller passes an explicit ``None``.

    Measured, not inferred: pydantic runs ``mode="before"`` validators ahead of
    the required/type check, so a required ``str`` field can still swallow a
    ``None`` (``DataFlowTrace.source``), while a defaulted non-``Optional`` field
    cannot (``HuntResult.findings``).
    """
    out: list[str] = []
    for name in fields:
        kwargs = _minimal_kwargs(model)
        kwargs[name] = None
        try:
            _ = model(**kwargs)
        except Exception:
            continue
        out.append(name)
    return out


def _describe(module_name: str, class_name: str) -> dict[str, Any]:
    module = importlib.import_module(module_name)
    model: type[BaseModel] = getattr(module, class_name)
    fields: dict[str, FieldInfo] = model.model_fields

    instance = model(**_minimal_kwargs(model))
    dumped = instance.model_dump(mode="json")

    keys = list(dumped.keys())
    assert keys == list(fields.keys()), f"{class_name}: dump order != field order"

    required = [n for n, f in fields.items() if f.is_required()]
    accepts_null = _accepts_null(model, fields)
    int_fields = [n for n, f in fields.items() if _numeric_kind(f.annotation) == "int"]
    float_fields = [n for n, f in fields.items() if _numeric_kind(f.annotation) == "float"]
    null_fields: list[str] = []
    empty_list_fields: list[str] = []
    empty_dict_fields: list[str] = []
    scalar_defaults: dict[str, Any] = {}
    uuid_defaults: list[str] = []

    for name, field in fields.items():
        if field.is_required():
            continue
        value = dumped[name]
        if value is None:
            null_fields.append(name)
        elif value == [] and isinstance(value, list):
            empty_list_fields.append(name)
        elif value == {} and isinstance(value, dict):
            empty_dict_fields.append(name)
        elif field.default_factory is not None:
            # Non-empty container default (e.g. AuditInput.scan_types) or a
            # uuid4 factory.  A uuid4 default is per-instance random; record it
            # as such instead of as a fixed value.
            second = model(**_minimal_kwargs(model)).model_dump(mode="json")[name]
            if second != value:
                uuid_defaults.append(name)
            else:
                scalar_defaults[name] = value
        else:
            scalar_defaults[name] = value

    return {
        "python_module": module_name,
        "python_class": class_name,
        "go_name": GO_NAME_OVERRIDES.get((module_name, class_name), class_name),
        "duplicate_of": DUPLICATE_OF.get((module_name, class_name)),
        "keys": keys,
        "required": required,
        "accepts_null": accepts_null,
        "int_fields": int_fields,
        "float_fields": float_fields,
        "null_fields": null_fields,
        "empty_list_fields": empty_list_fields,
        "empty_dict_fields": empty_dict_fields,
        "scalar_defaults": scalar_defaults,
        "uuid_defaults": uuid_defaults,
    }


def _check_coverage() -> None:
    for module_name in COVERAGE_MODULES:
        module = importlib.import_module(module_name)
        declared = {
            name
            for name, obj in vars(module).items()
            if inspect.isclass(obj)
            and issubclass(obj, BaseModel)
            and obj is not BaseModel
            and obj.__module__ == module_name
        }
        listed = set(MODULES.get(module_name, []))
        missing = declared - listed
        if missing:
            raise SystemExit(f"{module_name}: pydantic models missing from MODULES: {sorted(missing)}")


def main() -> None:
    _check_coverage()

    models: list[dict[str, Any]] = []
    for module_name, class_names in MODULES.items():
        for class_name in class_names:
            models.append(_describe(module_name, class_name))

    enums: dict[str, Any] = {}
    for module_name, names in ENUMS.items():
        module = importlib.import_module(module_name)
        for name in names:
            cls = getattr(module, name)
            enums[name] = {
                "python_module": module_name,
                # __members__ keeps declaration order AND value aliases.
                "members": {k: v.value for k, v in cls.__members__.items()},
                "kind": "int" if issubclass(cls, int) and not issubclass(cls, str) else "str",
            }

    # sec_af.schemas.__init__.__all__ — the public surface the Go package must
    # expose under the SAME names (docs/DESIGN.md §0: struct name == class name).
    schemas_pkg = importlib.import_module("sec_af.schemas")
    exports = list(schemas_pkg.__all__)

    out = {
        "_generated_by": "go/scripts/gen_model_keys.py",
        "models": models,
        "enums": enums,
        "schemas_all": exports,
    }

    target = Path(__file__).resolve().parents[1] / "internal" / "schemas" / "testdata" / "model_keys.json"
    target.parent.mkdir(parents=True, exist_ok=True)
    _ = target.write_text(json.dumps(out, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(f"wrote {target} ({len(models)} models, {len(enums)} enums, {len(exports)} exports)")


if __name__ == "__main__":
    main()
