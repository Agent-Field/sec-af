#!/usr/bin/env python3
"""Committed golden generator for internal/phases and internal/orch.

Every string these two Go packages must reproduce byte-for-byte — the prompts
`expand_cwes_for_hunt` and `_assess_reachability_parallel` build, the
`model_dump_json()` progress note, the `_write_checkpoint` file body — plus the
pure-function tables (`_default_strategies`, `_prover_cap`,
`_prioritize_findings`, `merge_recon_findings_into_hunt`,
`_verified_finding_fallback`, `_track_drop`) is produced HERE by calling the
REAL Python function with a fixed input.

The inputs live next to the outputs as ``*_fixture.json`` so the Go test decodes
the very same bytes rather than transcribing literals.

REPRODUCE (from the repo root):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_phases.py

Deterministic and idempotent: the two clock-dependent producers
(``_write_checkpoint``'s ``created_at`` and ``_emit_progress``'s elapsed times)
are pinned by swapping the module-level ``datetime`` / ``time`` names for stubs,
which is the same seam internal/orch exposes to its Go tests (``nowUTC``,
``StartedAt``).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from datetime import UTC, datetime
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_GO_ROOT = os.path.dirname(_HERE)
_REPO_ROOT = os.path.dirname(_GO_ROOT)
_SRC = os.path.join(_REPO_ROOT, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# IMPORT ORDER IS LOAD-BEARING — see the same note in gen_golden.py: importing
# sec_af.context before sec_af.agents.hunt turns all eleven hunters into no-op
# stubs.
import sec_af.agents.hunt as _bootstrap_hunt_import_order  # noqa: E402,F401

from pydantic import BaseModel  # noqa: E402
from pydantic import Field as PydanticField  # noqa: E402

import sec_af.orchestrator as orch_mod  # noqa: E402
from sec_af.reasoners import phases as phases_mod  # noqa: E402
from sec_af.schemas.hunt import HuntResult, RawFinding  # noqa: E402
from sec_af.schemas.input import AuditInput  # noqa: E402
from sec_af.schemas.output import AuditProgress  # noqa: E402
from sec_af.schemas.prove import VerifiedFinding  # noqa: E402
from sec_af.schemas.recon import ReconResult  # noqa: E402

_PHASES_TESTDATA = os.path.join(_GO_ROOT, "internal", "phases", "testdata")
_PHASES_GOLDEN = os.path.join(_PHASES_TESTDATA, "golden")
_ORCH_TESTDATA = os.path.join(_GO_ROOT, "internal", "orch", "testdata")
_ORCH_GOLDEN = os.path.join(_ORCH_TESTDATA, "golden")


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"  wrote {os.path.relpath(path, _GO_ROOT)} ({len(text.encode('utf-8'))} bytes)")


def _write_json(path: str, value: Any) -> None:
    _write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------

# A recon result that exercises EVERY branch of _recon_summary_string and of
# both _default_strategies variants: languages + frameworks, non-zero metrics,
# an auth model, crypto usage, direct dependencies, known CVEs, an API surface,
# secrets and misconfigs.
RECON_FULL: dict[str, Any] = {
    "architecture": {
        "app_type": "web_api",
        "modules": [
            {"name": "api", "path": "src/api", "language": "Python", "dependencies": []},
            {"name": "web", "path": "web", "language": "TypeScript", "dependencies": []},
            {"name": "legacy", "path": "legacy", "language": "python", "dependencies": []},
            {"name": "blank", "path": "blank", "language": "", "dependencies": []},
        ],
        "entry_points": [],
        "trust_boundaries": [],
        "services": [],
        "api_surface": [
            {
                "method": "GET",
                "path": "/users",
                "handler": "list_users",
                "file_path": "src/api/users.py",
                "line": 12,
                "auth_required": True,
                "rate_limited": False,
            },
            {
                "method": "DELETE",
                "path": "/users/{id}",
                "handler": "delete_user",
                "file_path": "src/api/users.py",
                "line": 40,
                "auth_required": False,
                "rate_limited": False,
            },
        ],
    },
    "data_flows": {},
    "dependencies": {
        "sbom": [],
        "known_cves": [
            {
                "cve_id": "CVE-2024-0001",
                "package": "requests",
                "installed_version": "2.20.0",
                "fixed_version": "2.32.0",
                "cvss_v4_score": 9.1,
                "direct": True,
            },
        ],
        "outdated": [],
        "direct_count": 5,
        "transitive_count": 20,
    },
    "config": {
        "secrets": [
            {
                "id": "secret-1",
                "secret_type": "api_key",
                "file_path": "src/config.py",
                "line": 7,
                "match": "API_KEY = \"sk-live-123\"",
                "confidence": "high",
            },
        ],
        "misconfigs": [
            {
                "id": "misconfig-1",
                "category": "tls",
                "file_path": "nginx.conf",
                "line": 3,
                "key": "ssl_protocols",
                "value": "TLSv1",
                "risk": "TLS 1.0 enabled",
            },
        ],
    },
    "security_context": {
        "auth_model": "jwt",
        "auth_details": "Bearer token",
        "crypto_usage": [
            {"algorithm": "TLSv1.0", "usage_context": "legacy tls terminator", "is_weak": True},
            {"algorithm": "AES-256-GCM", "usage_context": "at-rest encryption", "is_weak": False},
        ],
        "framework_security": ["django-rest-framework", "", "django-rest-framework", "Django"],
        "security_headers": [],
        "deployment_signals": [],
    },
    "languages": ["python", "typescript"],
    "frameworks": ["django"],
    "lines_of_code": 5000,
    "file_count": 42,
}

# The all-empty counterpart: every truthiness guard is False, so
# _recon_summary_string returns its "Unknown application" fallback and the
# strategy lists shrink to the unconditional base.
RECON_MINIMAL: dict[str, Any] = {
    "architecture": {},
    "data_flows": {},
    "dependencies": {},
    "config": {},
    "security_context": {"auth_model": "", "auth_details": ""},
    "languages": [],
    "frameworks": [],
    "lines_of_code": 0,
    "file_count": 0,
}

# Findings for the prioritisation and merge goldens. The ids encode the
# (severity, confidence) pair so the expected order reads at a glance; the two
# "medium/medium" entries pin the STABLE tie-break.
FINDINGS_FIXTURE: list[dict[str, Any]] = [
    {
        "id": "low-high",
        "hunter_strategy": "injection",
        "title": "Low severity, high confidence",
        "description": "d",
        "finding_type": "sast",
        "cwe_id": "CWE-200",
        "cwe_name": "Information Exposure",
        "file_path": "a.py",
        "start_line": 1,
        "end_line": 1,
        "code_snippet": "x",
        "estimated_severity": "low",
        "confidence": "high",
        "related_files": [],
        "fingerprint": "fp-low-high",
    },
    {
        "id": "medium-medium-a",
        "hunter_strategy": "auth",
        "title": "Medium A",
        "description": "d",
        "finding_type": "sast",
        "cwe_id": "CWE-287",
        "cwe_name": "Improper Authentication",
        "file_path": "b.py",
        "start_line": 2,
        "end_line": 2,
        "code_snippet": "x",
        "estimated_severity": "medium",
        "confidence": "medium",
        "related_files": [],
        "fingerprint": "fp-medium-a",
    },
    {
        "id": "critical-low",
        "hunter_strategy": "injection",
        "title": "Critical, low confidence",
        "description": "d",
        "finding_type": "sast",
        "cwe_id": "CWE-89",
        "cwe_name": "SQL Injection",
        "file_path": "c.py",
        "start_line": 3,
        "end_line": 3,
        "code_snippet": "x",
        "estimated_severity": "critical",
        "confidence": "low",
        "related_files": [],
        "fingerprint": "fp-critical-low",
    },
    {
        "id": "medium-medium-b",
        "hunter_strategy": "dos",
        "title": "Medium B",
        "description": "d",
        "finding_type": "sast",
        "cwe_id": "CWE-400",
        "cwe_name": "Resource Exhaustion",
        "file_path": "d.py",
        "start_line": 4,
        "end_line": 4,
        "code_snippet": "x",
        "estimated_severity": "medium",
        "confidence": "medium",
        "related_files": [],
        "fingerprint": "fp-medium-b",
    },
    {
        "id": "unknown-unknown",
        "hunter_strategy": "xss",
        "title": "Unrecognised severity",
        "description": "d",
        "finding_type": "sast",
        "cwe_id": "CWE-79",
        "cwe_name": "XSS",
        "file_path": "e.py",
        "start_line": 5,
        "end_line": 5,
        "code_snippet": "x",
        "estimated_severity": "info",
        "confidence": "low",
        "related_files": [],
        "fingerprint": "fp-info",
    },
]

# One RawFinding for _verified_finding_fallback, carrying a function_name so the
# Location projection is exercised.
FALLBACK_FINDING: dict[str, Any] = {
    "id": "raw-1",
    "hunter_strategy": "injection",
    "title": "Potential SQL injection",
    "description": "Potential injection from request parameter",
    "finding_type": "sast",
    "cwe_id": "CWE-89",
    "cwe_name": "SQL Injection",
    "owasp_category": "A03:2021",
    "file_path": "src/users.py",
    "start_line": 10,
    "end_line": 12,
    "function_name": "get_user",
    "code_snippet": 'cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")',
    "estimated_severity": "high",
    "confidence": "high",
    "data_flow": [],
    "related_files": [],
    "fingerprint": "fp-1",
}

# A VerifiedFinding for the reachability prompt.
VERIFIED_FIXTURE: dict[str, Any] = {
    "id": "vf-1",
    "fingerprint": "fp-1",
    "title": "SQL injection in user lookup",
    "description": "User id flows unsanitised into an f-string query",
    "finding_type": "sast",
    "cwe_id": "CWE-89",
    "cwe_name": "SQL Injection",
    "tags": [],
    "verdict": "confirmed",
    "evidence_level": 4,
    "rationale": "Traced source to sink",
    "severity": "high",
    "exploitability_score": 0.0,
    "location": {"file_path": "src/users.py", "start_line": 10, "end_line": 12},
    "sarif_rule_id": "sec-af/sast/sql-injection",
    "sarif_security_severity": 0.0,
}


def _recon(payload: dict[str, Any]) -> ReconResult:
    return ReconResult.model_validate(payload)


# ---------------------------------------------------------------------------
# stubs
# ---------------------------------------------------------------------------


class _CaptureRouter:
    """Stands in for reasoners/phases.py's module-global `_runtime_router`.

    `.ai` records the prompt and then raises, which is enough: the caller
    (`expand_cwes_for_hunt`) swallows the exception and returns [], and the
    prompt is what we are after.
    """

    def __init__(self) -> None:
        self.prompts: list[str] = []
        self.notes: list[tuple[str, list[str] | None]] = []

    async def ai(self, *, user: str, schema: object) -> object:
        _ = schema
        self.prompts.append(user)
        msg = "captured"
        raise RuntimeError(msg)

    def note(self, message: str, tags: list[str] | None = None) -> None:
        self.notes.append((message, tags))


class _NoteApp:
    """The minimal `Agent` AuditOrchestrator needs for the pure paths."""

    def __init__(self) -> None:
        self.notes: list[tuple[str, list[str] | None]] = []

    def note(self, message: str, tags: list[str] | None = None) -> None:
        self.notes.append((message, tags))


class _CaptureGate:
    """Stands in for AIGateWrapper in _assess_reachability_parallel."""

    def __init__(self) -> None:
        self.summaries: list[str] = []

    async def assess_reachability(self, summary: str) -> object:
        self.summaries.append(summary)
        msg = "captured"
        raise RuntimeError(msg)


class _FakeMonotonic:
    """A `time` stand-in whose monotonic() walks a fixed sequence.

    The last value repeats forever, so a caller that reads the clock more often
    than we scripted still gets a deterministic answer.
    """

    def __init__(self, values: list[float]) -> None:
        self._values = values
        self._index = 0

    def monotonic(self) -> float:
        value = self._values[min(self._index, len(self._values) - 1)]
        self._index += 1
        return value


class _FixedDatetime:
    """A `datetime` stand-in whose now(tz) is pinned."""

    _PINNED = datetime(2026, 1, 2, 3, 4, 5, 123456, tzinfo=UTC)

    @classmethod
    def now(cls, tz: object = None) -> datetime:
        _ = tz
        return cls._PINNED


def _orchestrator(depth: str = "standard", **input_kwargs: Any) -> orch_mod.AuditOrchestrator:
    """Build an AuditOrchestrator whose input.depth is exactly `depth`.

    AuditConfig.from_input uses the STRICT `DepthProfile(...)` constructor, so a
    non-canonical spelling ("QUICK", "bogus", "") cannot survive construction —
    it raises ValueError, which app.py maps to HTTP 400. The orchestrator's own
    `_depth_profile()` is LENIENT, though, so the strategy/cap tables still have
    to answer for those spellings. Construct with a valid depth and then assign
    the case onto the (mutable) pydantic model, which is the only way those
    branches are reachable at all.
    """
    payload: dict[str, Any] = {"repo_url": "https://example.invalid/repo", "depth": "standard"}
    payload.update(input_kwargs)
    orch = orch_mod.AuditOrchestrator(app=_NoteApp(), input=AuditInput(**payload))
    orch.input.depth = depth
    return orch


# ---------------------------------------------------------------------------
# internal/phases
# ---------------------------------------------------------------------------

DEPTH_CASES = ["quick", "standard", "thorough", "QUICK", "Thorough", "bogus", ""]
PROVER_CAP_CASES: list[tuple[str, int | None]] = [
    ("quick", None),
    ("standard", None),
    ("thorough", None),
    ("bogus", None),
    ("quick", 3),
    ("quick", 50),
    ("standard", 0),
    ("standard", -5),
    ("thorough", 12345),
]


def gen_phases() -> None:
    print("internal/phases:")

    _write_json(
        os.path.join(_PHASES_TESTDATA, "recon_fixture.json"),
        {"full": RECON_FULL, "minimal": RECON_MINIMAL},
    )
    _write_json(os.path.join(_PHASES_TESTDATA, "findings_fixture.json"), FINDINGS_FIXTURE)

    # ---- _recon_summary_string --------------------------------------------
    for name, payload in (("full", RECON_FULL), ("minimal", RECON_MINIMAL)):
        _write(
            os.path.join(_PHASES_GOLDEN, f"recon_summary_{name}.txt"),
            phases_mod._recon_summary_string(_recon(payload)),
        )

    # ---- expand_cwes_for_hunt's prompt ------------------------------------
    original_router = phases_mod._runtime_router
    try:
        for name, summary, strategies in (
            ("full", "Python/Django app, 5000 LOC, JWT auth", ["injection", "auth", "crypto"]),
            ("no_strategies", "Unknown application", []),
        ):
            router = _CaptureRouter()
            phases_mod._runtime_router = router
            result = asyncio.run(phases_mod.expand_cwes_for_hunt(summary, strategies))
            assert result == [], result  # the stub raises, so the fallback fires
            _write(os.path.join(_PHASES_GOLDEN, f"cwe_expansion_prompt_{name}.txt"), router.prompts[0])
    finally:
        phases_mod._runtime_router = original_router

    # ---- _default_strategies(recon, depth) --------------------------------
    default_strategies: dict[str, list[str]] = {}
    for recon_name, payload in (("full", RECON_FULL), ("minimal", RECON_MINIMAL)):
        for depth in DEPTH_CASES:
            key = f"{recon_name}|{depth}"
            default_strategies[key] = [
                s.value for s in phases_mod._default_strategies(_recon(payload), depth)
            ]
    _write_json(os.path.join(_PHASES_GOLDEN, "default_strategies.json"), default_strategies)

    # ---- _prover_cap(depth, max_provers) ----------------------------------
    prover_caps = {
        f"{depth}|{'null' if cap is None else cap}": phases_mod._prover_cap(depth, cap)
        for depth, cap in PROVER_CAP_CASES
    }
    _write_json(os.path.join(_PHASES_GOLDEN, "prover_cap.json"), prover_caps)

    # ---- _prioritize_findings ---------------------------------------------
    findings = [RawFinding.model_validate(row) for row in FINDINGS_FIXTURE]
    _write_json(
        os.path.join(_PHASES_GOLDEN, "prioritize_findings.json"),
        [f.id for f in phases_mod._prioritize_findings(findings)],
    )

    # ---- _track_drop -------------------------------------------------------
    original_router = phases_mod._runtime_router
    try:
        router = _CaptureRouter()
        phases_mod._runtime_router = router
        summary: dict[str, Any] = {"demoted_total": 0, "by_reason": {}, "findings": []}
        phases_mod._track_drop(
            summary=summary, finding_title="First", original_verdict=None, reason="verifier_error"
        )
        phases_mod._track_drop(
            summary=summary, finding_title="Second", original_verdict="unverified", reason="verdict_unverified"
        )
        phases_mod._track_drop(
            summary=summary, finding_title="Third", original_verdict="", reason="verifier_error"
        )
        _write_json(
            os.path.join(_PHASES_GOLDEN, "track_drop.json"),
            {"summary": summary, "notes": [note for note, _ in router.notes]},
        )
    finally:
        phases_mod._runtime_router = original_router

    # ---- prove_phase, unverified-verdict demotion --------------------------
    # The full reasoner result for tests/test_prove_phase_demotion.py's first
    # case. Deterministic end to end: the fallback's rationale is a fixed
    # string on this branch (unlike the schema-parse branch, whose rationale
    # embeds pydantic's message).
    _write_json(os.path.join(_PHASES_TESTDATA, "prove_phase_input.json"), _prove_phase_input())
    original_router = phases_mod._runtime_router
    try:
        router = _ProveRouter(_UNVERIFIED_PAYLOAD)
        phases_mod._runtime_router = router
        result = asyncio.run(
            phases_mod.prove_phase(repo_path="/tmp/repo", hunt_result=_prove_phase_input())
        )
        _write_json(os.path.join(_PHASES_GOLDEN, "prove_phase_unverified.json"), result)
        _write_json(
            os.path.join(_PHASES_GOLDEN, "prove_phase_unverified_notes.json"),
            [note for note, _ in router.notes],
        )
    finally:
        phases_mod._runtime_router = original_router


_UNVERIFIED_PAYLOAD: dict[str, Any] = {
    "id": FALLBACK_FINDING["id"],
    "fingerprint": FALLBACK_FINDING["fingerprint"],
    "title": FALLBACK_FINDING["title"],
    "description": FALLBACK_FINDING["description"],
    "finding_type": FALLBACK_FINDING["finding_type"],
    "cwe_id": FALLBACK_FINDING["cwe_id"],
    "cwe_name": FALLBACK_FINDING["cwe_name"],
    "verdict": "unverified",
    "evidence_level": 1,
    "rationale": "Could not fully verify",
    "severity": FALLBACK_FINDING["estimated_severity"],
    "exploitability_score": 0.0,
    "location": {
        "file_path": FALLBACK_FINDING["file_path"],
        "start_line": FALLBACK_FINDING["start_line"],
        "end_line": FALLBACK_FINDING["end_line"],
        "code_snippet": FALLBACK_FINDING["code_snippet"],
    },
    "sarif_rule_id": "sec-af/sast/sql-injection",
    "sarif_security_severity": 0.0,
}


class _ProveRouter(_CaptureRouter):
    """The _RouterStub of tests/test_prove_phase_demotion.py."""

    def __init__(self, verifier_payload: dict[str, Any]) -> None:
        super().__init__()
        self._verifier_payload = verifier_payload
        self.calls: list[tuple[str, dict[str, object]]] = []

    async def call(self, name: str, **kwargs: object) -> dict[str, Any]:
        self.calls.append((name, kwargs))
        if name.endswith("run_verifier"):
            return {"output": self._verifier_payload}
        msg = f"unexpected call: {name}"
        raise AssertionError(msg)


def _prove_phase_input() -> dict[str, Any]:
    return {
        "findings": [RawFinding.model_validate(FALLBACK_FINDING).model_dump()],
        "chains": [],
        "total_raw": 1,
        "deduplicated_count": 1,
        "chain_count": 0,
        "strategies_run": ["injection"],
        "hunt_duration_seconds": 0.0,
    }


# ---------------------------------------------------------------------------
# internal/orch
# ---------------------------------------------------------------------------

PROGRESS_CASES: list[tuple[str, str, int, int, int]] = [
    # name, phase, agents_total, agents_completed, findings_so_far
    ("recon_half", "recon", 2, 1, 0),
    ("recon_full", "recon", 2, 2, 0),
    ("hunt_done", "hunt", 1, 1, 7),
    ("zero_total", "prove", 0, 0, 0),
    ("overshoot", "prove", 2, 5, 3),
]


def gen_orch() -> None:
    print("internal/orch:")

    _write_json(
        os.path.join(_ORCH_TESTDATA, "recon_fixture.json"),
        {"full": RECON_FULL, "minimal": RECON_MINIMAL},
    )
    _write_json(os.path.join(_ORCH_TESTDATA, "findings_fixture.json"), FINDINGS_FIXTURE)
    _write_json(os.path.join(_ORCH_TESTDATA, "fallback_finding.json"), FALLBACK_FINDING)
    _write_json(os.path.join(_ORCH_TESTDATA, "verified_fixture.json"), VERIFIED_FIXTURE)

    # ---- _default_strategies(recon) ---------------------------------------
    default_strategies: dict[str, list[str]] = {}
    for recon_name, payload in (("full", RECON_FULL), ("minimal", RECON_MINIMAL)):
        for depth in DEPTH_CASES:
            orch = _orchestrator(depth=depth)
            default_strategies[f"{recon_name}|{depth}"] = [
                s.value for s in orch._default_strategies(_recon(payload))
            ]
    _write_json(os.path.join(_ORCH_GOLDEN, "default_strategies.json"), default_strategies)

    # ---- _prover_cap() -----------------------------------------------------
    prover_caps: dict[str, int] = {}
    for depth, cap in PROVER_CAP_CASES:
        orch = _orchestrator(depth=depth, max_provers=cap)
        prover_caps[f"{depth}|{'null' if cap is None else cap}"] = orch._prover_cap()
    _write_json(os.path.join(_ORCH_GOLDEN, "prover_cap.json"), prover_caps)

    # ---- _prioritize_findings ---------------------------------------------
    findings = [RawFinding.model_validate(row) for row in FINDINGS_FIXTURE]
    _write_json(
        os.path.join(_ORCH_GOLDEN, "prioritize_findings.json"),
        [f.id for f in _orchestrator()._prioritize_findings(findings)],
    )

    # ---- _verified_finding_fallback ---------------------------------------
    fallback = orch_mod._verified_finding_fallback(RawFinding.model_validate(FALLBACK_FINDING))
    _write_json(os.path.join(_ORCH_GOLDEN, "verified_finding_fallback.json"), fallback.model_dump())

    # ---- merge_recon_findings_into_hunt ------------------------------------
    hunt = HuntResult(
        findings=[RawFinding.model_validate(FINDINGS_FIXTURE[0])],
        chains=[],
        total_raw=1,
        deduplicated_count=1,
        chain_count=0,
        strategies_run=["injection"],
    )
    recon_findings = [RawFinding.model_validate(FINDINGS_FIXTURE[2])]
    _write_json(
        os.path.join(_ORCH_GOLDEN, "merge_recon_findings.json"),
        {
            "merged": orch_mod.merge_recon_findings_into_hunt(hunt, recon_findings).model_dump(),
            "empty_recon_is_identity": orch_mod.merge_recon_findings_into_hunt(hunt, []).model_dump()
            == hunt.model_dump(),
            "already_present": orch_mod.merge_recon_findings_into_hunt(
                HuntResult(
                    findings=[],
                    chains=[],
                    total_raw=0,
                    deduplicated_count=0,
                    chain_count=0,
                    strategies_run=["recon", "injection"],
                ),
                recon_findings,
            ).strategies_run,
        },
    )

    # ---- _assess_reachability_parallel's prompt ----------------------------
    orch = _orchestrator()
    gate = _CaptureGate()
    orch.ai_gate = gate  # type: ignore[assignment]
    finding = VerifiedFinding.model_validate(VERIFIED_FIXTURE)
    asyncio.run(orch._assess_reachability_parallel([finding]))
    _write(os.path.join(_ORCH_GOLDEN, "reachability_summary.txt"), gate.summaries[0])
    _write_json(
        os.path.join(_ORCH_GOLDEN, "reachability_fallback_tags.json"),
        {"tags_after_gate_failure": finding.tags},
    )

    # ---- _emit_progress' note ---------------------------------------------
    # AuditProgress.model_dump_json() is pydantic's serializer, not json.dumps:
    # no whitespace after ':' or ',', and every float carries a decimal point.
    progress_notes: dict[str, str] = {}
    progress_fields: dict[str, dict[str, Any]] = {}
    real_time = orch_mod.time
    try:
        for name, phase, total, completed, findings_so_far in PROGRESS_CASES:
            # monotonic(): the first read is __init__'s started_at, the second
            # is _emit_progress' elapsed -> a pinned 2.5s.
            orch_mod.time = _FakeMonotonic([100.0, 102.5])  # type: ignore[assignment]
            orch = _orchestrator()
            orch.total_cost_usd = 0.123456
            orch._emit_progress(
                phase=phase,
                agents_total=total,
                agents_completed=completed,
                findings_so_far=findings_so_far,
            )
            note_message = orch.app.notes[-1][0]
            progress_notes[name] = note_message
            progress_fields[name] = json.loads(note_message)
    finally:
        orch_mod.time = real_time
    _write_json(os.path.join(_ORCH_GOLDEN, "progress_notes.json"), progress_notes)
    _write_json(os.path.join(_ORCH_GOLDEN, "progress_fields.json"), progress_fields)

    # A stand-alone model_dump_json() matrix so pyfmt.DumpsModelJSON is pinned
    # independently of the orchestrator's arithmetic.
    _write_json(
        os.path.join(_ORCH_GOLDEN, "progress_model_dump_json.json"),
        {
            "unit_progress": AuditProgress(
                phase="recon",
                phase_progress=1.0,
                agents_total=2,
                agents_completed=2,
                agents_running=0,
                findings_so_far=0,
                elapsed_seconds=2.5,
                estimated_remaining_seconds=0.0,
                cost_so_far_usd=0.0,
            ).model_dump_json(),
            "fractional": AuditProgress(
                phase="hunt",
                phase_progress=0.5,
                agents_total=4,
                agents_completed=2,
                agents_running=2,
                findings_so_far=13,
                elapsed_seconds=1.25,
                estimated_remaining_seconds=1.25,
                cost_so_far_usd=0.1235,
            ).model_dump_json(),
        },
    )

    # ---- _write_checkpoint's file body ------------------------------------
    real_datetime = orch_mod.datetime
    try:
        orch_mod.datetime = _FixedDatetime  # type: ignore[assignment]
        orch = _orchestrator()
        checkpoint_dir = os.path.join(_ORCH_TESTDATA, "_checkpoints")
        orch.checkpoint_dir = __import__("pathlib").Path(checkpoint_dir)

        orch._write_checkpoint("recon", _recon(RECON_MINIMAL))
        with open(os.path.join(checkpoint_dir, "checkpoint-recon.json"), encoding="utf-8") as handle:
            _write(os.path.join(_ORCH_GOLDEN, "checkpoint_recon.txt"), handle.read())

        verified = [VerifiedFinding.model_validate(VERIFIED_FIXTURE)]
        orch._write_checkpoint("prove", verified)
        with open(os.path.join(checkpoint_dir, "checkpoint-prove.json"), encoding="utf-8") as handle:
            _write(os.path.join(_ORCH_GOLDEN, "checkpoint_prove.txt"), handle.read())

        orch._write_checkpoint("prove_empty", [])
        with open(os.path.join(checkpoint_dir, "checkpoint-prove_empty.json"), encoding="utf-8") as handle:
            _write(os.path.join(_ORCH_GOLDEN, "checkpoint_prove_empty.txt"), handle.read())

        for name in ("checkpoint-recon.json", "checkpoint-prove.json", "checkpoint-prove_empty.json"):
            os.remove(os.path.join(checkpoint_dir, name))
        os.rmdir(checkpoint_dir)
    finally:
        orch_mod.datetime = real_datetime

    _write_json(
        os.path.join(_ORCH_GOLDEN, "checkpoint_created_at.json"),
        {"pinned": _FixedDatetime.now(UTC).isoformat()},
    )


# ---------------------------------------------------------------------------
# internal/pyfmt — BaseModel.model_dump_json() parity
# ---------------------------------------------------------------------------

_PYFMT_GOLDEN = os.path.join(_GO_ROOT, "internal", "pyfmt", "testdata", "golden")


class _Inner(BaseModel):
    x: float
    y: int


class _ModelJSONFixture(BaseModel):
    """The Go test declares a struct with these fields, in this order."""

    name: str
    ratio: float
    count: int
    flag: bool
    opt: str | None = None
    items: list[str] = PydanticField(default_factory=list)
    inner: _Inner | None = None
    mapping: dict[str, float] = PydanticField(default_factory=dict)


class _FloatOnly(BaseModel):
    v: float


# The float values whose spelling separates pydantic's Rust serializer from
# CPython's repr(). Keys are the literal Go writes in its test table.
_MODEL_JSON_FLOATS = [
    "0", "-0.0", "1", "1.5", "0.1", "2.5", "0.0001", "1e-5", "1e-6", "1e-7",
    "1.23e-5", "1.23e-6", "1e15", "9.9e15", "1e16", "1e17", "1e22", "1e300",
    "5e-324", "0.3333333333333333", "-12.75", "1e-3",
]


def gen_pyfmt_model_json() -> None:
    print("internal/pyfmt (model_dump_json):")

    cases = {
        "rich": _ModelJSONFixture(
            name='héllo <&> " \\ \t \U0001F600 \x01',
            ratio=1.0,
            count=3,
            flag=True,
            items=["a", "b"],
            inner=_Inner(x=1e15, y=0),
            # Alphabetical on purpose: a Go map carries no insertion order, so
            # DumpsModelJSON sorts its keys (documented deviation). Keeping the
            # fixture already sorted lets the two agree byte for byte.
            mapping={"a": 2.0, "b": 0.5},
        ),
        "defaults": _ModelJSONFixture(name="", ratio=-0.0, count=-5, flag=False),
        "small_float": _ModelJSONFixture(name="x", ratio=1e-5, count=0, flag=False),
    }
    _write_json(
        os.path.join(_PYFMT_GOLDEN, "model_dump_json_models.json"),
        {name: model.model_dump_json() for name, model in cases.items()},
    )
    _write_json(
        os.path.join(_PYFMT_GOLDEN, "model_dump_json_floats.json"),
        {literal: _FloatOnly(v=float(literal)).model_dump_json() for literal in _MODEL_JSON_FLOATS},
    )


def main() -> None:
    gen_phases()
    gen_orch()
    gen_pyfmt_model_json()
    print("done")


if __name__ == "__main__":
    main()
