#!/usr/bin/env python3
"""Committed golden generator for the SEC-AF Go port.

Every string this repo's Python code hands to an LLM — or writes into a file a
test compares textually — is produced here by calling the REAL Python function
with a fixed input, and written under the owning Go package's
``testdata/golden/`` directory. The matching Go test renders the same input and
compares byte for byte, so a divergence between the two implementations is a
test failure rather than a silent prompt drift.

REPRODUCE (from the repo root):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py

Deterministic and idempotent: rerunning overwrites the goldens with identical
bytes unless the Python source changed.

SECTIONS
--------
The file is organized one section per owning Go package. Each section declares
its INPUTS as module-level constants (the Go test repeats the same literals) and
writes its outputs into that package's testdata directory. Adding a new prompt
builder means adding its inputs to the relevant section — not inventing a new
generator script.

  * internal/pyfmt     — pyfmt.Dumps / DumpsCompact parity against json.dumps
  * internal/recontext  — src/sec_af/context.py + the hunt hint tables
  * internal/gates      — src/sec_af/harness.py prompt builders and gate prompts
"""

from __future__ import annotations

import hashlib
import json
import os
import sys
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_GO_ROOT = os.path.dirname(_HERE)
_REPO_ROOT = os.path.dirname(_GO_ROOT)
_SRC = os.path.join(_REPO_ROOT, "src")
if os.path.isdir(_SRC) and _SRC not in sys.path:
    sys.path.insert(0, _SRC)

# IMPORT ORDER IS LOAD-BEARING. `sec_af.agents.hunt.__init__` builds its
# _STRATEGY_RUNNERS table with `_load_hunter`, which swallows ImportError and
# substitutes a no-op `_missing_<strategy>_hunter`. Each hunter module imports
# `sec_af.context`, and `sec_af.context` imports back into
# `sec_af.agents.hunt._framework_hints` — so whichever of the two is imported
# FIRST wins: import `sec_af.agents.hunt` first and every hunter loads for real;
# import `sec_af.context` first and all eleven silently become stubs. The live
# node reaches hunt first (app.py -> orchestrator.py -> `.agents.hunt`), so
# force that order here before anything pulls in sec_af.context.
import sec_af.agents.hunt as _bootstrap_hunt_import_order  # noqa: E402,F401

from sec_af import context as sec_context  # noqa: E402
from sec_af import harness as sec_harness  # noqa: E402
from sec_af import policies  # noqa: E402
from sec_af.agents.hunt._framework_hints import get_framework_hints  # noqa: E402
from sec_af.agents.hunt._language_hints import get_language_hints  # noqa: E402
from sec_af.schemas import gates, hunt, output, prove, recon  # noqa: E402
from sec_af.schemas.hunt import HuntStrategy  # noqa: E402
from sec_af.schemas.recon import ReconResult  # noqa: E402


def _write(path: str, text: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(text)
    print(f"  wrote {os.path.relpath(path, _GO_ROOT)} ({len(text.encode('utf-8'))} bytes)")


def _write_json(path: str, value: Any) -> None:
    _write(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


# ===========================================================================
# internal/pyfmt — json.dumps parity
# ===========================================================================

_PYFMT_TESTDATA = os.path.join(_GO_ROOT, "internal", "pyfmt", "testdata")
_PYFMT_GOLDEN = os.path.join(_PYFMT_TESTDATA, "golden")

# Fixture key -> pydantic model. The key is also the Go struct name, so the Go
# test can decode the same sub-object into the same shape.
PYFMT_MODELS: dict[str, Any] = {
    "ArchitectureMap": recon.ArchitectureMap,
    "DependencyReport": recon.DependencyReport,
    "SecurityContext": recon.SecurityContext,
    "ConfigReport": recon.ConfigReport,
}


def gen_pyfmt() -> None:
    print("internal/pyfmt:")
    with open(os.path.join(_PYFMT_TESTDATA, "models_fixture.json"), encoding="utf-8") as handle:
        fixture = json.load(handle)

    for name, model in PYFMT_MODELS.items():
        dumped = model(**fixture[name]).model_dump()
        _write(os.path.join(_PYFMT_GOLDEN, f"dumps_{name}_indent2.txt"), json.dumps(dumped, indent=2))
        _write(os.path.join(_PYFMT_GOLDEN, f"dumps_{name}_compact.txt"), json.dumps(dumped))

    # 'edge_cases' is a plain JSON document, not a model: it pins the float
    # spellings (1.0 / 0.5 / 1e-05 / -0.0 / 1e+16), the ensure_ascii escaping,
    # the empty list/dict/None renderings and the sorted-key deviation.
    edge = fixture["edge_cases"]
    _write(os.path.join(_PYFMT_GOLDEN, "dumps_edge_cases_indent2.txt"), json.dumps(edge, indent=2, sort_keys=True))
    _write(os.path.join(_PYFMT_GOLDEN, "dumps_edge_cases_compact.txt"), json.dumps(edge, sort_keys=True))


# ===========================================================================
# internal/recontext — context.py + the hunt hint tables
# ===========================================================================

_RECONTEXT_TESTDATA = os.path.join(_GO_ROOT, "internal", "recontext", "testdata")
_RECONTEXT_GOLDEN = os.path.join(_RECONTEXT_TESTDATA, "golden")

# One golden per builder. The key is the golden's basename; the value is the
# Python function.
RECON_BUILDERS = {
    "injection": sec_context.recon_context_for_injection,
    "auth": sec_context.recon_context_for_auth,
    "crypto": sec_context.recon_context_for_crypto,
    "data_exposure": sec_context.recon_context_for_data_exposure,
    "config_secrets": sec_context.recon_context_for_config_secrets,
    "supply_chain": sec_context.recon_context_for_supply_chain,
    "api_security": sec_context.recon_context_for_api_security,
    "logic": sec_context.recon_context_for_logic,
    "generic": sec_context.recon_context_generic,
}

# Hint-table input vectors. Each is (case name, argument list).
LANGUAGE_HINT_CASES: list[tuple[str, list[str]]] = [
    ("empty", []),
    ("unknown_only", ["Rust", "haskell"]),
    ("single", ["Python"]),
    ("mixed_case_and_repeat", ["Python", "python", "JavaScript", "Rust", "GO"]),
    ("all_known", ["python", "javascript", "typescript", "go", "java", "ruby", "csharp"]),
]

FRAMEWORK_HINT_CASES: list[tuple[str, list[str]]] = [
    ("empty", []),
    ("unknown_only", ["hanami", "phoenix"]),
    ("aliases", ["Next", "next.js", "NEXTJS", "Spring Boot", "spring-boot", "ASP.NET Core"]),
    ("padded", ["  React  ", "\tvue\n", "Django"]),
    ("all_known", [
        "django", "flask", "fastapi", "express", "nextjs",
        "spring", "rails", "aspnet", "react", "vue", "angular",
    ]),
]

# Strategies to emit a full pruned-dict golden for. "unknown_strategy" exercises
# the STRATEGY_CONTEXT_MAP miss that falls through to the full model_dump().
PRUNE_GOLDEN_STRATEGIES = ["injection", "crypto", "supply_chain", "config_secrets", "unknown_strategy"]


def _load_recon_fixture() -> ReconResult:
    with open(os.path.join(_RECONTEXT_TESTDATA, "recon_fixture.json"), encoding="utf-8") as handle:
        return ReconResult(**json.load(handle))


def gen_recontext() -> None:
    print("internal/recontext:")
    recon_result = _load_recon_fixture()

    for name, builder in RECON_BUILDERS.items():
        _write(os.path.join(_RECONTEXT_GOLDEN, f"{name}.txt"), builder(recon_result))

    # The two *_for_context wrappers, applied to the fixture's own language and
    # framework lists.
    _write(
        os.path.join(_RECONTEXT_GOLDEN, "language_hints_for_context.txt"),
        sec_context.language_hints_for_context(recon_result),
    )
    _write(
        os.path.join(_RECONTEXT_GOLDEN, "framework_hints_for_context.txt"),
        sec_context.framework_hints_for_context(recon_result),
    )

    for case, languages in LANGUAGE_HINT_CASES:
        _write(os.path.join(_RECONTEXT_GOLDEN, f"language_hints_{case}.txt"), get_language_hints(languages))
    for case, frameworks in FRAMEWORK_HINT_CASES:
        _write(os.path.join(_RECONTEXT_GOLDEN, f"framework_hints_{case}.txt"), get_framework_hints(frameworks))

    # get_context_for_strategy dispatch: which builder each HuntStrategy lands
    # on, pinned by the SHA-256 of the rendered text so the file stays small.
    dispatch = {}
    for strategy in HuntStrategy:
        text = sec_context.get_context_for_strategy(strategy, recon_result)
        dispatch[strategy.value] = hashlib.sha256(text.encode("utf-8")).hexdigest()
    _write_json(os.path.join(_RECONTEXT_GOLDEN, "strategy_dispatch.json"), dispatch)

    # prune_recon_for_strategy: the surviving key SET for every strategy value
    # plus two misses, and the full rendering for a representative few.
    keys = {}
    for strategy in [s.value for s in HuntStrategy] + ["unknown_strategy", ""]:
        keys[strategy] = sorted(sec_context.prune_recon_for_strategy(recon_result, strategy))
    _write_json(os.path.join(_RECONTEXT_GOLDEN, "prune_keys.json"), keys)

    for strategy in PRUNE_GOLDEN_STRATEGIES:
        pruned = sec_context.prune_recon_for_strategy(recon_result, strategy)
        # Go renders this map with SORTED top-level keys (a Go map carries no
        # insertion order) while the NESTED models keep declaration order,
        # because pyfmt.Dumps walks Go structs field by field. Sorting only the
        # top level here produces exactly the document the Go side emits, so the
        # comparison stays byte-exact where it is meaningful.
        top_sorted = {key: pruned[key] for key in sorted(pruned)}
        _write(os.path.join(_RECONTEXT_GOLDEN, f"prune_{strategy}.json"), json.dumps(top_sorted, indent=2))


# ===========================================================================
# internal/gates — harness.py prompt builders and AI-gate prompts
# ===========================================================================

_GATES_GOLDEN = os.path.join(_GO_ROOT, "internal", "gates", "testdata", "golden")

GATES_CWD = "/tmp/secaf-golden"
GATES_PROMPT = "Analyze the repository for SQL injection.\nCite file:line for every claim.   \n\n"

# (case name, phase argument). The phase is `str | None` in Python; the Go
# signature takes a plain string, because `(phase or "")` maps both to "".
PHASE_CASES: list[tuple[str, Any]] = [
    ("recon", "recon"),
    ("hunt", "hunt"),
    ("prove", "prove"),
    ("none", None),
    ("empty", ""),
    ("padded_mixed_case", "  Recon  "),
    ("unknown", "unknown-phase"),
]

# (case name, prompt, cwd)
FILE_WRITE_HINT_CASES: list[tuple[str, str, str]] = [
    ("basic", "Constraints:\n- first\n- second", GATES_CWD),
    ("trailing_whitespace", "keep me\t \n\n  ", GATES_CWD + "/"),
    ("empty_cwd", "no directory", ""),
    ("relative_cwd", "relative", "./work/../work"),
]

# Every model gen_schemas.py emits a fixture for; the Go struct of the same name
# drives both SchemaGuidance's field order and BuildSchemaRetryPrompt's
# properties order, so covering all of them pins that contract repo-wide.
GATES_SCHEMAS: dict[str, Any] = {
    "ArchitectureMapRaw": recon.ArchitectureMapRaw,
    "DependencyReportRaw": recon.DependencyReportRaw,
    "ConfigReportRaw": recon.ConfigReportRaw,
    "DataFlowMapRaw": recon.DataFlowMapRaw,
    "SecurityContextRaw": recon.SecurityContextRaw,
    "ScanLocationsResult": hunt.ScanLocationsResult,
    "EnrichedFinding": hunt.EnrichedFinding,
    "ChainCorrelationResult": hunt.ChainCorrelationResult,
    "DataFlowTrace": prove.DataFlowTrace,
    "SanitizationResult": prove.SanitizationResult,
    "ExploitHypothesis": prove.ExploitHypothesis,
    "ReachabilityProof": prove.ReachabilityProof,
    "DastVerificationResult": prove.DastVerificationResult,
    "CrossServiceFinding": output.CrossServiceFinding,
    "RemediationSuggestion": prove.RemediationSuggestion,
    "PolicyEvalResult": policies.PolicyEvalResult,
    "VerdictDecision": prove.VerdictDecision,
    "CWEExpansion": gates.CWEExpansion,
    "SeverityClassification": gates.SeverityClassification,
    "DuplicateCheck": gates.DuplicateCheck,
    "StrategySelection": gates.StrategySelection,
    "ReachabilityGate": gates.ReachabilityGate,
    "ComplianceGate": gates.ComplianceGate,
}

SCHEMA_RETRY_ERROR_DETAIL = "Retry attempt 1/3"

# AI-gate prompt inputs. AIGateWrapper's four prompt builders are pure string
# assembly around these, so the goldens are produced by re-deriving the same
# f-strings the methods use (they are not separable from the awaited call).
CLASSIFY_SEVERITY_SUMMARY = (
    "SQL injection in app/db/raw.py:42 — request.args['q'] reaches cursor.execute unsanitized."
)
CHECK_DUPLICATE_CANDIDATE = {
    "id": "finding-1",
    "file_path": "app/db/raw.py",
    "start_line": 42,
    "cwe_id": "CWE-89",
    "confirmed": True,
    "score": 9.5,
    "notes": None,
}
CHECK_DUPLICATE_EXISTING = {
    "id": "finding-0",
    "file_path": "app/db/raw.py",
    "start_line": 41,
    "cwe_id": "CWE-89",
    "confirmed": False,
    "score": 1.0,
    "notes": "seen before",
}
SELECT_STRATEGY_SUMMARY = "General recon summary.\n\nProfile: 3 files, 120 LOC."
SELECT_STRATEGY_CASES: list[tuple[str, str, list[str]]] = [
    ("standard", "standard", ["injection", "auth", "crypto"]),
    ("empty_candidates", "quick", []),
]
ASSESS_REACHABILITY_SUMMARY = "Hardcoded AWS key in config/prod.yaml:12, repository is public."


def _classify_severity_prompt(finding_summary: str) -> str:
    return (
        "Classify severity for this potential security finding. "
        "Use only critical/high/medium/low and keep rationale brief.\n\n"
        f"{finding_summary}"
    )


def _check_duplicate_prompt(candidate: dict, existing: dict) -> str:
    return (
        "Decide whether candidate finding is a duplicate of existing finding. "
        "Return duplicate decision only.\n\n"
        f"Candidate: {candidate}\n"
        f"Existing: {existing}"
    )


def _select_strategy_prompt(recon_summary: str, depth: str, default_candidates: list[str]) -> str:
    return (
        "Select SEC-AF hunt strategies from recon context. Return only selected strategies and rationale.\n"
        f"Depth profile: {depth}\n"
        f"Default candidates: {default_candidates}\n"
        f"Recon summary: {recon_summary}"
    )


def _assess_reachability_prompt(finding_summary: str) -> str:
    return (
        "Assess the reachability of this security finding. "
        "Determine if it is externally_reachable, requires_auth, internal_only, or unreachable. "
        "Consider the attack surface, authentication requirements, and network exposure.\n\n"
        f"{finding_summary}"
    )


def gen_gates() -> None:
    print("internal/gates:")

    # PHASE_GUIDANCE, verbatim.
    _write_json(os.path.join(_GATES_GOLDEN, "phase_guidance.json"), dict(sec_harness.PHASE_GUIDANCE))

    for case, phase in PHASE_CASES:
        _write(
            os.path.join(_GATES_GOLDEN, f"with_phase_guidance_{case}.txt"),
            sec_harness._with_phase_guidance(GATES_PROMPT, phase, GATES_CWD),
        )

    for case, prompt, cwd in FILE_WRITE_HINT_CASES:
        _write(
            os.path.join(_GATES_GOLDEN, f"with_file_write_hint_{case}.txt"),
            sec_harness._with_file_write_hint(prompt, cwd),
        )

    for name, model in GATES_SCHEMAS.items():
        _write(
            os.path.join(_GATES_GOLDEN, f"schema_guidance_{name}.txt"),
            sec_harness._schema_guidance(model),
        )
        _write(
            os.path.join(_GATES_GOLDEN, f"schema_retry_{name}.txt"),
            sec_harness._build_schema_retry_prompt(model, SCHEMA_RETRY_ERROR_DETAIL, GATES_CWD),
        )

    _write(
        os.path.join(_GATES_GOLDEN, "ai_gate_classify_severity.txt"),
        _classify_severity_prompt(CLASSIFY_SEVERITY_SUMMARY),
    )
    _write(
        os.path.join(_GATES_GOLDEN, "ai_gate_check_duplicate.txt"),
        _check_duplicate_prompt(CHECK_DUPLICATE_CANDIDATE, CHECK_DUPLICATE_EXISTING),
    )
    for case, depth, candidates in SELECT_STRATEGY_CASES:
        _write(
            os.path.join(_GATES_GOLDEN, f"ai_gate_select_strategy_{case}.txt"),
            _select_strategy_prompt(SELECT_STRATEGY_SUMMARY, depth, candidates),
        )
    _write(
        os.path.join(_GATES_GOLDEN, "ai_gate_assess_reachability.txt"),
        _assess_reachability_prompt(ASSESS_REACHABILITY_SUMMARY),
    )


# ---------------------------------------------------------------------------
# internal/agents/recon (S3)
# ---------------------------------------------------------------------------
# Fixtures for the five RECON mappers, the _parsers helpers, _repo_metrics and
# the end-to-end run_recon / run_fast_recon. Everything is produced by calling
# the REAL functions in sec_af.agents.recon.

# This section is deliberately SELF-CONTAINED — its own imports, its own path
# computation and its own writer — because several porting agents extend this
# file concurrently and the shared helpers around it have been reshaped more
# than once. Nothing here reads a module-level name defined outside the block.
import asyncio as _s3_asyncio
import json as _s3_json
import os as _s3_os

# A stable, fixture-controlled repository path. The mappers only interpolate it
# into their CONTEXT block, and it deliberately does NOT exist on disk so
# _repo_metrics reports (0, 0) on any machine.
_S3_FIXTURE_REPO = "/fixtures/demo-repo"
_S3_GOLDEN_DIR = _s3_os.path.join(
    _s3_os.path.dirname(_s3_os.path.dirname(_s3_os.path.abspath(__file__))),
    "internal", "agents", "recon", "testdata", "golden",
)


def _s3_write(name: str, text: str) -> None:
    _s3_os.makedirs(_S3_GOLDEN_DIR, exist_ok=True)
    path = _s3_os.path.join(_S3_GOLDEN_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        _ = handle.write(text)
    print(f"  wrote internal/agents/recon/testdata/golden/{name} ({len(text.encode('utf-8'))} bytes)")


class _S3Captured(Exception):
    """Raised by the fake harness once a mapper's prompt has been recorded."""


class _S3CaptureApp:
    """Records the single app.harness(prompt=...) call each mapper makes.

    Aborting with _S3Captured short-circuits the mapper before
    extract_harness_result runs; its `finally:` still removes the temp dir.
    """

    def __init__(self) -> None:
        self.prompt = None

    async def harness(self, prompt, schema=None, cwd=None, project_dir=None, **kwargs):
        self.prompt = prompt
        raise _S3Captured()


def _s3_capture(make_coro) -> str:
    app = _S3CaptureApp()
    try:
        _s3_asyncio.run(make_coro(app))
    except _S3Captured:
        pass
    assert app.prompt is not None, "mapper did not call app.harness"
    return app.prompt


def _s3_emit_text(name: str, text: str) -> None:
    _s3_write(name + ".txt", text)


def _s3_emit_json(name, obj) -> None:
    _s3_write(name + ".json", _s3_json.dumps(obj, indent=2, sort_keys=False) + "\n")


def _s3_scrub_ids(obj):
    """Replace nondeterministic uuid4 `id` values with a stable placeholder."""
    if isinstance(obj, dict):
        return {k: ("<uuid>" if k == "id" and isinstance(v, str) else _s3_scrub_ids(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [_s3_scrub_ids(v) for v in obj]
    return obj


def _s3_arch_rich():
    """Every optional populated, plus the characters json.dumps treats specially.

    `<` / `&` are NOT escaped by json.dumps (Go's encoder escapes them unless
    SetEscapeHTML(false)), and `e-acute` / `->` ARE escaped as \\uXXXX by the
    default ensure_ascii=True (Go never escapes non-ASCII). Both traps covered.
    """
    from sec_af.schemas.recon import APIEndpoint, ArchitectureMap, EntryPoint, Module, Service, TrustBoundary

    return ArchitectureMap(
        app_type="web_api",
        modules=[
            Module(name="auth", path="src/auth/", language="Python", description="Sessions & tokens", dependencies=["db", "cache"]),
            Module(name="ui", path="web/", language="TypeScript", description=None, dependencies=[]),
        ],
        entry_points=[
            EntryPoint(kind="http", identifier="POST /api/login", file_path="src/routes.py", line=42, method="POST", route="/api/login", auth_required=False),
            EntryPoint(kind="cli", identifier="migrate", file_path="src/cli.py", line=8, method=None, route=None, auth_required=None),
        ],
        trust_boundaries=[
            TrustBoundary(name="API Gateway", source_zone="external", target_zone="internal", description="Rate limiting <and> auth — café → app", enforcement=["waf"]),
        ],
        services=[
            Service(name="PostgreSQL", service_type="database", endpoint="localhost:5432", purpose="primary store", auth_mechanism="password"),
        ],
        api_surface=[
            APIEndpoint(method="GET", path="/api/users", handler="get_users", file_path="src/api.py", line=15, auth_required=True, rate_limited=False),
        ],
    )


def _s3_arch_empty():
    """All pydantic defaults — the shape an empty harness run produces."""
    from sec_af.schemas.recon import ArchitectureMap

    return ArchitectureMap()


def _s3_raw_fixtures():
    """One deliberately nasty *Raw model per parser.

    Covers: surplus pipes kept in the last field, short rows padded, n/a and
    empty optionals, unparseable booleans/ints/floats, a "file:line" with no
    positive line, and every security-signal bucket.
    """
    from sec_af.schemas.recon import (
        ArchitectureMapRaw,
        ConfigReportRaw,
        DataFlowMapRaw,
        DependencyReportRaw,
        SecurityContextRaw,
    )

    return {
        "architecture": ArchitectureMapRaw(
            app_type="web_api",
            modules=[
                "auth | src/auth/ | Python | Authentication and session management",
                "ui|web/|TypeScript|",
                "orphan",
                "  a  |  b  |  c  |  d | e  ",
            ],
            entry_points=[
                "http | POST /api/login | src/routes.py:42 | false",
                "cli | migrate | src/cli.py | yes",
                "event | queue:jobs | src/worker.py:0 | maybe",
            ],
            trust_boundaries=["API Gateway | external | internal | Rate limiting and auth", "edge|dmz"],
            services=[
                "PostgreSQL | database | localhost:5432 | password",
                "Stripe | payments | n/a | NONE",
                "Redis | cache | | unknown",
            ],
            api_endpoints=[
                "GET | /api/users | get_users | src/api.py:15 | true | false",
                "POST | /api/users | create | src/api.py | 1 | 0",
                "PUT | /x | h | a:b:12 | | ",
            ],
        ),
        "data_flow": DataFlowMapRaw(
            flows=[
                "request.body | sql.execute | false | src/db.py, src/routes.py",
                "argv | os.system | TRUE | ",
                "env | log | garbage | a, , b ,",
            ],
            sanitization_points=[
                "src/valid.py:12 | sanitize | escape | sqli, xss",
                "src/valid.py |  | strip | ",
            ],
            sinks=[
                "sql | src/db.py:88 | execute | user-controlled query string",
                "exec | src/run.py |  | ",
            ],
        ),
        "dependency_report": DependencyReportRaw(
            sbom=[
                "django | 3.2.1 | pypi | true | BSD-3-Clause",
                "urllib3 | 1.26.5 | pypi | false | n/a",
                "left-pad | 1.0.0 | npm | notabool | ",
            ],
            known_cves=[
                "CVE-2021-1 | django | 3.2.1 | 3.2.13 | 9.8 | true | true",
                "CVE-2021-2 | urllib3 | 1.26.5 | none | notafloat | 0 | ",
            ],
            outdated=[
                "django | 3.2.1 | 5.0.0 | true",
                "requests | 2.0 | 2.31 | 0",
            ],
        ),
        "config_report": ConfigReportRaw(
            secrets=[
                'api_key | src/config.py:7 | API_KEY = "sk-live-123" | high | false',
                "password | src/settings.py | pw=hunter2 |  | ",
            ],
            misconfigs=[
                "dangerous_config | deploy/prod.yaml:22 | DEBUG | Debug mode enabled in production | Set DEBUG=false",
                "cors | deploy/nginx.conf | N/A | Wildcard origin | unknown",
            ],
        ),
        "security_context": SecurityContextRaw(
            auth_model="jwt",
            auth_details="Bearer token validated by middleware",
            crypto_usage=[
                "AES | 256 | GCM | data encryption | false",
                "TLSv1.0 | n/a | none | legacy tls terminator | true",
                "MD5 | notanint |  |  | TRUE",
            ],
            security_signals=[
                "CSRF protection enabled",
                "HSTS header present",
                "Runs in Docker",
                "CSP configured",
                "Uses Kubernetes secrets",
                "Input validation via pydantic",
            ],
        ),
    }


# One canned FLAT harness payload per mapper for the end-to-end run_recon
# fixture. Deliberately exercises the derivations run_recon layers on top of the
# parsers: a duplicate language in a different case, a module with an EMPTY
# language (dropped by the truthiness guard), a repeated security signal
# (collapsed by the set), and one signal for each of the three buckets.
_S3_CANNED_RAW = {
    "architecture": {
        "app_type": "web_api",
        "modules": [
            "auth | src/auth | Python | sessions",
            "ui | web | TypeScript | ",
            "api | src/api | python | dup-language",
            "legacy | old | | no language",
        ],
        "entry_points": ["http | POST /login | src/routes.py:42 | false"],
        "trust_boundaries": ["edge | external | internal | tls"],
        "services": ["pg | database | localhost:5432 | password"],
        "api_endpoints": ["GET | /users | list | src/api.py:15 | true | false"],
    },
    "dependencies": {
        "sbom": ["django | 3.2 | pypi | true | BSD"],
        "known_cves": ["CVE-1 | django | 3.2 | 3.3 | 9.8 | true | true"],
        "outdated": ["django | 3.2 | 5.0 | true"],
    },
    "config_scanner": {
        "secrets": ["api_key | src/config.py:7 | KEY=1 | high | false"],
        "misconfigs": ["debug | deploy/prod.yaml:22 | DEBUG | on in prod | turn it off"],
    },
    "data_flow": {
        "flows": ["request.body | sql.execute | false | src/db.py"],
        "sanitization_points": ["src/valid.py:12 | clean | escape | sqli"],
        "sinks": ["sql | src/db.py:88 | execute | tainted"],
    },
    "security_context": {
        "auth_model": "jwt",
        "auth_details": "bearer",
        "crypto_usage": ["AES | 256 | GCM | data | false"],
        "security_signals": [
            "Uses Flask-Login",
            "HSTS header present",
            "Runs in Docker",
            "Uses Flask-Login",
        ],
    },
}

# The *Raw class each mapper asks for -> its canned key, so the fake answers by
# the model requested rather than by sniffing the prompt.
_S3_SCHEMA_TO_CANNED = {
    "ArchitectureMapRaw": "architecture",
    "DependencyReportRaw": "dependencies",
    "ConfigReportRaw": "config_scanner",
    "DataFlowMapRaw": "data_flow",
    "SecurityContextRaw": "security_context",
}


class _S3CannedResult:
    """Shaped like the SDK's HarnessResult so extract_harness_result accepts it."""

    def __init__(self, parsed) -> None:
        self.is_error = False
        self.parsed = parsed
        self.result = ""


class _S3CannedApp:
    async def harness(self, prompt=None, *, schema=None, cwd=None, project_dir=None, **kwargs):
        key = _S3_SCHEMA_TO_CANNED[schema.__name__]
        return _S3CannedResult(schema.model_validate(_S3_CANNED_RAW[key]))


def _s3_normalize_recon(dumped: dict) -> dict:
    """Scrub the two nondeterministic parts of a ReconResult dump."""
    out = _s3_scrub_ids(dumped)
    out["recon_duration_seconds"] = 0.0
    return out


# relpath -> raw bytes for the _repo_metrics fixture tree. Chosen to exercise:
# universal-newline counting (\n, \r\n, \r, no trailing terminator, empty file),
# Path.suffix semantics (dotfiles have NO suffix, a trailing dot has none, only
# the LAST extension counts, matching is case-insensitive), non-code files
# (counted in file_count, never in line_count), and every _SKIP_DIRS component.
_S3_REPO_TREE = {
    "main.py": b"import os\nprint(1)\n",
    "trailing_none.go": b"package main\nfunc main() {}",
    "crlf.ts": b"const a = 1;\r\nconst b = 2;\r\n",
    "cr_only.rb": b"puts 1\rputs 2\r",
    "empty.py": b"",
    "just_newline.sql": b"\n",
    "invalid_utf8.js": b"var a = '\xff\xfe';\nvar b = 2;\n",
    "UPPER.PY": b"a\nb\n",
    "archive.tar.gz": b"not really gzip\n",
    ".gitignore": b"node_modules\n.venv\n",
    "Makefile": b"all:\n\tgo build\n",
    "trailingdot.": b"x\n",
    "README.md": b"# docs\nnot code\n",
    "pkg/lib.go": b"package pkg\n\nfunc F() {}\n",
    "pkg/deep/nested/util.rs": b"fn main() {}\n",
    "conf/app.yaml": b"a: 1\nb: 2\nc: 3\n",
    "conf/app.YML": b"x: 1\n",
    ".git/config": b"[core]\n",
    "node_modules/left-pad/index.js": b"module.exports = 1;\n",
    "vendor/dep/dep.go": b"package dep\n",
    ".venv/lib/site.py": b"pass\n",
    "venv/lib/site.py": b"pass\n",
    "__pycache__/main.cpython-311.pyc": b"\x00\x01",
    "src/.hg/store.py": b"pass\n",
    "src/.svn/entries.py": b"pass\n",
}

# relpath -> symlink target (relative to the link's own directory).
_S3_REPO_SYMLINKS = {
    "link_to_main.py": "main.py",
    "broken_link.py": "does_not_exist.py",
    "link_to_pkg": "pkg",
}


def _s3_materialize(root: str) -> None:
    for rel, data in _S3_REPO_TREE.items():
        path = _s3_os.path.join(root, rel)
        _s3_os.makedirs(_s3_os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            _ = f.write(data)
    for rel, target in _S3_REPO_SYMLINKS.items():
        path = _s3_os.path.join(root, rel)
        _s3_os.makedirs(_s3_os.path.dirname(path), exist_ok=True)
        _s3_os.symlink(target, path)


def s3_emit_goldens() -> None:
    """internal/agents/recon: prompts, parser tables, metrics, run_recon."""
    import base64
    import shutil
    import tempfile

    from sec_af.agents.recon import _parsers, _repo_metrics, run_fast_recon, run_recon
    from sec_af.agents.recon.architecture import architecture_context_block, run_architecture_mapper
    from sec_af.agents.recon.config_scanner import run_config_scanner
    from sec_af.agents.recon.data_flow import run_data_flow_mapper
    from sec_af.agents.recon.dependencies import run_dependency_auditor
    from sec_af.agents.recon.security_context import run_security_context_profiler

    repo = _S3_FIXTURE_REPO

    # ---- prompts -----------------------------------------------------------
    _s3_emit_text("architecture_prompt", _s3_capture(lambda app: run_architecture_mapper(app, repo)))
    _s3_emit_text("dependencies_prompt", _s3_capture(lambda app: run_dependency_auditor(app, repo)))
    _s3_emit_text("config_scanner_prompt", _s3_capture(lambda app: run_config_scanner(app, repo)))

    for case, arch in (("A", _s3_arch_rich()), ("B", _s3_arch_empty())):
        _s3_emit_text(f"architecture_context_block_{case}", architecture_context_block(arch))
        _s3_emit_text(f"data_flow_prompt_{case}", _s3_capture(lambda app, a=arch: run_data_flow_mapper(app, repo, a)))
        _s3_emit_text(f"security_context_prompt_{case}", _s3_capture(lambda app, a=arch: run_security_context_profiler(app, repo, a)))

    # ---- parser primitives -------------------------------------------------
    split_cases = [
        ("a | b | c | d", 4),
        ("a|b", 4),
        ("", 4),
        ("  a  |  b  |  c  |  d | e  ", 4),
        ("a|b|c|d|e|f|g", 6),
        ("only", 1),
        ("a|b|c", 1),
        ("|||", 4),
        (" x ", 2),
    ]
    bool_cases = ["true", "TRUE", " True ", "yes", "1", "false", "No", "0", "", "maybe", "n/a", " 01 "]
    int_cases = ["0", "12", " 42 ", "-7", "+3", "1_0", "abc", "", "3.5", "0x10", "  "]
    float_cases = ["1.5", " 9.8 ", "0", "-2", "1e3", "abc", "", "inf", "nan", "1_0.5", "+.5"]
    file_line_cases = ["src/api.py:15", "src/api.py", "a:b:12", "src/x.py:0", "src/x.py:-3", ":", "", " a.py : 4 ", "C:/x.py:9"]
    na_cases = ["", " ", "na", "N/A", "None", "UNKNOWN", "unknown ", "value", "0"]

    _s3_emit_json("parse_primitives", {
        "split_pipe": [{"s": s, "expected": n, "want": _parsers._split_pipe(s, n)} for s, n in split_cases],
        "parse_bool": [{"s": s, "want": _parsers._parse_bool(s)} for s in bool_cases],
        "parse_int": [{"s": s, "want": _parsers._parse_int(s)} for s in int_cases],
        "parse_int_default9": [{"s": s, "want": _parsers._parse_int(s, 9)} for s in int_cases],
        # Emitted as Python repr() STRINGS, not JSON numbers: float("inf") /
        # float("nan") are not representable in JSON and Go's decoder rejects
        # the Infinity/NaN literals Python's json module writes for them. The Go
        # test formats its own parsed float with pyfmt.FormatFloat (an exact
        # port of Python's str(float)) and compares the strings.
        "parse_float": [
            {"s": s, "want": (None if _parsers._parse_float(s) is None else repr(_parsers._parse_float(s)))}
            for s in float_cases
        ],
        "parse_file_line": [
            {"s": s, "path": _parsers._parse_file_line(s)[0], "line": _parsers._parse_file_line(s)[1]}
            for s in file_line_cases
        ],
        "is_na": [{"s": s, "want": _parsers._is_na(s)} for s in na_cases],
    })

    # ---- parser outputs ----------------------------------------------------
    raws = _s3_raw_fixtures()
    for name, parse in (
        ("architecture", _parsers.parse_architecture_raw),
        ("data_flow", _parsers.parse_data_flow_raw),
        ("dependency_report", _parsers.parse_dependency_report_raw),
        ("config_report", _parsers.parse_config_report_raw),
        ("security_context", _parsers.parse_security_context_raw),
    ):
        raw = raws[name]
        _s3_emit_json(f"parse_{name}", {
            "input": raw.model_dump(),
            "want": _s3_scrub_ids(parse(raw).model_dump()),
        })

    # ---- end-to-end run_recon ---------------------------------------------
    # _S3_FIXTURE_REPO does not exist on disk, so _repo_metrics reports (0, 0)
    # in both runtimes and the fixture stays machine-independent.
    _s3_emit_json("run_recon", {
        "repo_path": repo,
        "canned": _S3_CANNED_RAW,
        "standard": _s3_normalize_recon(_s3_asyncio.run(run_recon(_S3CannedApp(), repo, "standard")).model_dump()),
        "quick": _s3_normalize_recon(_s3_asyncio.run(run_recon(_S3CannedApp(), repo, "quick")).model_dump()),
        "fast": _s3_normalize_recon(_s3_asyncio.run(run_fast_recon(_S3CannedApp(), repo)).model_dump()),
    })

    # ---- repo metrics ------------------------------------------------------
    root = tempfile.mkdtemp(prefix="secaf-golden-metrics-")
    try:
        _s3_materialize(root)
        lines, files = _repo_metrics(root)
        _s3_emit_json("repo_metrics", {
            "files": {rel: base64.b64encode(data).decode("ascii") for rel, data in _S3_REPO_TREE.items()},
            "symlinks": _S3_REPO_SYMLINKS,
            "lines_of_code": lines,
            "file_count": files,
        })
    finally:
        shutil.rmtree(root, ignore_errors=True)


# ---------------------------------------------------------------------------
# internal/agents/hunt (S4)
# ---------------------------------------------------------------------------
# Fixtures for the HUNT phase: the shared scan/enrich prompt builders in
# _scan_enrich.py, the twelve hunter modules, and the run_hunt orchestration in
# src/sec_af/agents/hunt/__init__.py. Everything is produced by calling the REAL
# Python functions.
#
# Like the S3 block above, this section is deliberately SELF-CONTAINED — its own
# imports, its own paths, its own writer — because several porting agents extend
# this file concurrently.
#
# GOLDEN BUDGET. A hunter's scan prompt embeds a full recon context, so a sweep
# over 3 depths x 11 hunters against the rich fixture would be a megabyte of
# testdata. Only the STANDARD sweep uses the rich ReconResult (that is where the
# per-hunter context substitution is proved); quick and thorough reuse an
# all-defaults ReconResult, because the only thing a depth change moves is the
# interpolated depth label and the early-stop value. Enrich prompts are pinned
# by SHA-256 per hunter — their template mechanics get one full-text golden of
# their own, and the recon context they carry is already pinned by the scan
# prompt goldens and by internal/recontext's.
import asyncio as _s4_asyncio
import hashlib as _s4_hashlib
import inspect as _s4_inspect
import json as _s4_json
import os as _s4_os

# A stable, fixture-controlled repository path. The hunters only interpolate it
# into their CONTEXT block; it deliberately does not exist on disk.
_S4_FIXTURE_REPO = "/fixtures/demo-repo"
_S4_TESTDATA = _s4_os.path.join(
    _s4_os.path.dirname(_s4_os.path.dirname(_s4_os.path.abspath(__file__))),
    "internal", "agents", "hunt", "testdata",
)
_S4_GOLDEN_DIR = _s4_os.path.join(_S4_TESTDATA, "golden")

# depth -> which recon fixture the cascade sweep runs against (see GOLDEN BUDGET).
_S4_DEPTH_FIXTURE = {"quick": "small", "standard": "rich", "thorough": "small"}


def _s4_write(name: str, text: str) -> None:
    _s4_os.makedirs(_S4_GOLDEN_DIR, exist_ok=True)
    path = _s4_os.path.join(_S4_GOLDEN_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        _ = handle.write(text)
    print(f"  wrote internal/agents/hunt/testdata/golden/{name} ({len(text.encode('utf-8'))} bytes)")


def _s4_emit_text(name: str, text: str) -> None:
    _s4_write(name + ".txt", text)


def _s4_emit_json(name, obj) -> None:
    _s4_write(name + ".json", _s4_json.dumps(obj, indent=2, sort_keys=False) + "\n")


def _s4_sha(text: str) -> str:
    return _s4_hashlib.sha256(text.encode("utf-8")).hexdigest()


def _s4_recon():
    """The shared rich ReconResult fixture (a copy of internal/recontext's)."""
    from sec_af.schemas.recon import ReconResult

    with open(_s4_os.path.join(_S4_TESTDATA, "recon_fixture.json"), encoding="utf-8") as handle:
        return ReconResult(**_s4_json.load(handle))


def _s4_recon_small():
    """A small but COMPLETE ReconResult.

    Used for the quick/thorough sweeps: every hunter gate must open (crypto
    needs crypto_usage, supply_chain needs direct_count > 0, api_security needs
    api_surface) or the sweep would capture no prompt at all, while the recon
    context stays a few hundred bytes so the goldens stay reviewable. It is
    written to testdata/recon_small.json so the Go test binds the identical
    input rather than transcribing a literal.
    """
    from sec_af.schemas.recon import (
        APIEndpoint,
        ArchitectureMap,
        ConfigReport,
        CryptoUsage,
        DataFlow,
        DataFlowMap,
        DataFlowStep,
        Dependency,
        DependencyReport,
        EntryPoint,
        KnownCVE,
        MisconfigFinding,
        Module,
        ReconResult,
        SecretFinding,
        SecurityContext,
        Service,
        Sink,
        TrustBoundary,
    )

    return ReconResult(
        architecture=ArchitectureMap(
            app_type="web_api",
            modules=[Module(name="api", path="app/api/", language="Python", description="HTTP layer",
                            dependencies=["db"])],
            entry_points=[
                EntryPoint(kind="http", identifier="POST /login", file_path="app/api/auth.py", line=12,
                           method="POST", route="/login", auth_required=False),
                EntryPoint(kind="cli", identifier="seed", file_path="app/cli.py", line=3),
            ],
            trust_boundaries=[TrustBoundary(name="edge", source_zone="internet", target_zone="app",
                                            description="TLS terminator", enforcement=["waf"])],
            services=[Service(name="postgres", service_type="database", endpoint="db:5432",
                              purpose="primary store", auth_mechanism="password")],
            api_surface=[
                APIEndpoint(method="POST", path="/login", handler="login", file_path="app/api/auth.py",
                            line=12, auth_required=False, rate_limited=False),
                APIEndpoint(method="GET", path="/users/{id}", handler="get_user",
                            file_path="app/api/users.py", line=40, auth_required=True, rate_limited=True),
            ],
        ),
        data_flows=DataFlowMap(
            flows=[DataFlow(source="request.json", sink="cursor.execute", sanitized=False,
                            files=["app/api/users.py"],
                            path=[DataFlowStep(file_path="app/api/users.py", line=41, component="handler",
                                               operation="read id")])],
            sinks=[Sink(sink_type="sql", file_path="app/api/users.py", line=42, function_name="get_user",
                        exploitability_notes="f-string query")],
        ),
        dependencies=DependencyReport(
            sbom=[Dependency(name="django", version="4.2.1", ecosystem="pypi", direct=True, license="BSD-3")],
            known_cves=[KnownCVE(cve_id="CVE-2024-0001", package="django", installed_version="4.2.1",
                                 fixed_version="4.2.11", cvss_v4_score=7.5, epss_score=0.42, direct=True,
                                 reachable=True)],
            direct_count=3,
            transitive_count=9,
        ),
        config=ConfigReport(
            secrets=[SecretFinding(secret_type="api_key", file_path=".env", line=2, match="AKIA...",
                                   confidence="high", is_test_value=False)],
            misconfigs=[MisconfigFinding(category="debug", file_path="settings.py", line=9, key="DEBUG",
                                         value="True", risk="high", remediation="disable in production")],
        ),
        security_context=SecurityContext(
            auth_model="jwt",
            auth_details="HS256 access tokens",
            crypto_usage=[
                CryptoUsage(algorithm="MD5", usage_context="password hashing", is_weak=True),
                CryptoUsage(algorithm="SHA256", usage_context="etag cache key", is_weak=False),
            ],
            framework_security=["django-csrf"],
            security_headers=["Content-Security-Policy"],
            deployment_signals=["docker"],
        ),
        languages=["python"],
        frameworks=["django"],
        lines_of_code=1234,
        file_count=56,
    )


def _s4_recon_empty():
    """All-default ReconResult — the shape the QUICK profile's placeholders give."""
    from sec_af.schemas.recon import (
        ArchitectureMap,
        ConfigReport,
        DataFlowMap,
        DependencyReport,
        ReconResult,
        SecurityContext,
    )

    return ReconResult(
        architecture=ArchitectureMap(),
        data_flows=DataFlowMap(),
        dependencies=DependencyReport(),
        config=ConfigReport(),
        security_context=SecurityContext(auth_model="session", auth_details="cookie"),
    )


def _s4_scrub(obj):
    """Replace the uuid4 `id` / `fingerprint` defaults with a stable placeholder."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if k in ("id", "fingerprint") and isinstance(v, str):
                out[k] = "<uuid>"
            else:
                out[k] = _s4_scrub(v)
        return out
    if isinstance(obj, list):
        return [_s4_scrub(v) for v in obj]
    return obj


class _S4Result:
    """Shaped like the SDK's HarnessResult so extract_harness_result accepts it."""

    def __init__(self, parsed) -> None:
        self.is_error = False
        self.parsed = parsed
        self.result = ""


class _S4App:
    """Answers app.harness by the schema requested and records every prompt.

    Step 1 (ScanLocationsResult) yields ``locations``; step 2 (EnrichedFinding)
    yields ``enriched[i]`` for the i-th enrichment, in call order.
    """

    def __init__(self, locations=None, enriched=None) -> None:
        from sec_af.schemas.hunt import ScanLocationsResult

        self._scan_cls = ScanLocationsResult
        self.locations = list(locations or [])
        self.enriched = list(enriched or [])
        self.scan_prompts: list[str] = []
        self.enrich_prompts: list[str] = []

    async def harness(self, prompt, *, schema=None, cwd=None, project_dir=None, **kwargs):
        name = getattr(schema, "__name__", None)
        if name == "ScanLocationsResult":
            self.scan_prompts.append(prompt)
            return _S4Result(self._scan_cls(locations=self.locations))
        if name == "EnrichedFinding":
            index = len(self.enrich_prompts)
            self.enrich_prompts.append(prompt)
            return _S4Result(self.enriched[index % len(self.enriched)])
        raise AssertionError(f"unexpected harness schema {name!r}")


def _s4_locations():
    """Two canned VulnLocations: a multi-line snippet and a single-line one."""
    from sec_af.schemas.hunt import VulnLocation

    return [
        VulnLocation(
            file_path="app/api/users.py",
            start_line=42,
            code_snippet='query = f"SELECT * FROM users WHERE id = {user_id}"\ncursor.execute(query)',
            pattern_type="sql_injection",
        ),
        VulnLocation(
            file_path="app/utils/hash.py",
            start_line=7,
            code_snippet="digest = hashlib.md5(password).hexdigest()",
            pattern_type="weak_hash",
        ),
    ]


def _s4_enriched():
    """Two canned EnrichedFindings: a well-formed one and a coercion torture case."""
    from sec_af.schemas.hunt import EnrichedFinding

    return [
        EnrichedFinding(
            title="SQL injection in user lookup",
            description="user_id flows unescaped into an f-string query.",
            cwe_id="CWE-89",
            severity="HIGH",
            confidence="high",
            data_flow_summary="  request.args['id'] -> query -> cursor.execute  ",
        ),
        EnrichedFinding(
            title="Weak hash for password storage",
            description="MD5 used to derive a credential digest.",
            cwe_id="CWE-327",
            severity="catastrophic",
            confidence="certain",
            data_flow_summary="   ",
        ),
    ]


def _s4_wrap_runner(strategy_value, runner, sink):
    """Wrap a hunter so its prompts are captured WITHOUT disturbing the cascade.

    ``_run_single_hunter`` probes five different call shapes and relies on a
    TypeError to move on to the next, so the wrapper must reject exactly the
    argument lists the real function rejects. Binding the ORIGINAL signature
    first reproduces that: ``Signature.bind`` raises TypeError for precisely the
    calls Python would reject at the call site.
    """
    sig = _s4_inspect.signature(runner)

    async def inner(*args, **kwargs):
        bound = sig.bind(*args, **kwargs)
        bound.apply_defaults()
        app = _S4App()
        bound.arguments["app"] = app
        recorded = {}
        for key, value in bound.arguments.items():
            if key == "app":
                continue
            recorded[key] = "<recon>" if key in ("recon", "recon_result") else value
        try:
            return await runner(*bound.args, **bound.kwargs)
        finally:
            sink[strategy_value] = {"bound": recorded, "scan_prompts": list(app.scan_prompts)}

    return inner


def s4_emit_goldens() -> None:
    """internal/agents/hunt: scan/enrich prompts, the 12 hunters, run_hunt."""
    from sec_af.agents import hunt as _hunt
    from sec_af.agents.hunt import _scan_enrich
    from sec_af.agents.hunt import api_security as _api_security
    from sec_af.agents.hunt import auth as _auth
    from sec_af.agents.hunt import business_logic as _business_logic
    from sec_af.agents.hunt import config_secrets as _config_secrets
    from sec_af.agents.hunt import crypto as _crypto
    from sec_af.agents.hunt import data_exposure as _data_exposure
    from sec_af.agents.hunt import dos as _dos
    from sec_af.agents.hunt import injection as _injection
    from sec_af.agents.hunt import logic as _logic
    from sec_af.agents.hunt import ssrf as _ssrf
    from sec_af.agents.hunt import supply_chain as _supply_chain
    from sec_af.agents.hunt import xss as _xss
    from sec_af.schemas.hunt import EnrichedFinding, VulnLocation
    from sec_af.schemas.recon import CryptoUsage, DependencyReport, SecurityContext

    print("internal/agents/hunt:")
    # Guard the import-order trap documented at the top of this file: a stubbed
    # table would silently produce empty goldens.
    for _strategy, _runner in _hunt._STRATEGY_RUNNERS.items():
        assert not _runner.__name__.startswith("missing_"), (
            f"sec_af.agents.hunt._STRATEGY_RUNNERS[{_strategy.value}] is a stub "
            "- sec_af.context was imported before sec_af.agents.hunt"
        )

    recon = _s4_recon()
    empty = _s4_recon_empty()
    small = _s4_recon_small()
    repo = _S4_FIXTURE_REPO

    with open(_s4_os.path.join(_S4_TESTDATA, "recon_small.json"), "w", encoding="utf-8") as handle:
        _ = handle.write(_s4_json.dumps(_s4_scrub(small.model_dump()), indent=2) + "\n")
    print("  wrote internal/agents/hunt/testdata/recon_small.json")

    # ---- run_hunt end-to-end: the effective per-hunter call + scan prompt ----
    # Every hunter is reached through _run_single_hunter's TypeError cascade, so
    # these prompts (and the `bound` maps) are what the LIVE pipeline produces.
    original_runners = dict(_hunt._STRATEGY_RUNNERS)
    cascade = {}
    try:
        for depth, fixture in _S4_DEPTH_FIXTURE.items():
            sink = {}
            for strategy, runner in original_runners.items():
                _hunt._STRATEGY_RUNNERS[strategy] = _s4_wrap_runner(strategy.value, runner, sink)
            _ = _s4_asyncio.run(
                _hunt.run_hunt(
                    app=_S4App(),
                    repo_path=repo,
                    recon_result={"rich": recon, "small": small}[fixture],
                    depth=depth,
                )
            )
            cascade[depth] = {"fixture": fixture, "hunters": {}}
            for strategy_value in sorted(sink):
                entry = sink[strategy_value]
                cascade[depth]["hunters"][strategy_value] = entry["bound"]
                assert len(entry["scan_prompts"]) == 1, (depth, strategy_value, len(entry["scan_prompts"]))
                _s4_emit_text(f"prompt_{strategy_value}_{depth}", entry["scan_prompts"][0])
    finally:
        _hunt._STRATEGY_RUNNERS.clear()
        _hunt._STRATEGY_RUNNERS.update(original_runners)

    _s4_emit_json("cascade_binding", cascade)

    # ---- strategy selection -------------------------------------------------
    _s4_emit_json("select_strategies", {
        case: [s.value for s in _hunt._select_strategies(_hunt._normalize_depth(case))]
        for case in ["quick", "QUICK", " quick", "standard", "thorough", "Thorough", "bogus", ""]
    })
    _s4_emit_json("normalize_depth", {
        case: _hunt._normalize_depth(case).value
        for case in ["quick", "QUICK", "Standard", "thorough", "bogus", "", " quick "]
    })
    _s4_emit_json("quick_strategies", [s.value for s in _hunt._QUICK_STRATEGIES])
    _s4_emit_json("strategy_runner_order", [s.value for s in _hunt._STRATEGY_RUNNERS])

    # ---- scan_locations: the template wrapper -------------------------------
    hunter_prompt = "HUNTER PROMPT BODY\nwith {{braces}} and <html> & café →\n"
    app = _S4App(locations=[])
    _ = _s4_asyncio.run(_scan_enrich.scan_locations(app=app, prompt=hunter_prompt, repo_path=repo))
    _s4_emit_json("scan_locations_input", {"hunter_prompt": hunter_prompt})
    _s4_emit_text("scan_locations_prompt", app.scan_prompts[0])

    # ---- enrich_location: the template wrapper ------------------------------
    location = _s4_locations()[0]
    enrich_recon_context = "RECON CONTEXT LINE 1\nRECON CONTEXT LINE 2"
    app = _S4App(locations=[], enriched=_s4_enriched()[:1])
    _ = _s4_asyncio.run(
        _scan_enrich.enrich_location(
            app=app,
            location=location,
            finding_type="sast",
            strategy="injection",
            recon_context=enrich_recon_context,
            repo_path=repo,
        )
    )
    _s4_emit_json("enrich_location_input", {
        "location": location.model_dump(),
        "finding_type": "sast",
        "strategy": "injection",
        "recon_context": enrich_recon_context,
    })
    _s4_emit_text("enrich_location_prompt", app.enrich_prompts[0])

    # ---- assemble_finding ---------------------------------------------------
    assemble_cases = [
        {
            "name": "multiline_snippet_sast",
            "location": _s4_locations()[0],
            "enriched": _s4_enriched()[0],
            "finding_type": "sast",
            "strategy": "injection",
        },
        {
            "name": "single_line_bad_enums",
            "location": _s4_locations()[1],
            "enriched": _s4_enriched()[1],
            "finding_type": "sast",
            "strategy": "crypto",
        },
        {
            "name": "empty_snippet_unknown_type",
            "location": VulnLocation(file_path="a.py", start_line=0, code_snippet="", pattern_type=""),
            "enriched": EnrichedFinding(
                title="t", description="d", cwe_id="", severity="", confidence="", data_flow_summary="x"
            ),
            "finding_type": "not_a_type",
            "strategy": "logic",
        },
        {
            "name": "trailing_newline_snippet_uppercase_type",
            "location": VulnLocation(
                file_path="b/c.js", start_line=10, code_snippet="one\ntwo\n", pattern_type="p"
            ),
            "enriched": EnrichedFinding(
                title="t", description="d", cwe_id="CWE-1", severity="INFO", confidence="LOW",
                data_flow_summary="\n  flow  \n",
            ),
            "finding_type": "SCA",
            "strategy": "supply_chain",
        },
    ]
    _s4_emit_json("assemble_finding", [
        {
            "name": case["name"],
            "location": case["location"].model_dump(),
            "enriched": case["enriched"].model_dump(),
            "finding_type": case["finding_type"],
            "strategy": case["strategy"],
            "want": _s4_scrub(
                _scan_enrich.assemble_finding(
                    location=case["location"],
                    enriched=case["enriched"],
                    finding_type=case["finding_type"],
                    strategy=case["strategy"],
                ).model_dump()
            ),
        }
        for case in assemble_cases
    ])

    # ---- per-hunter direct call with two canned locations -------------------
    # Each hunter invoked through its OWN signature (max_files_without_signal at
    # its 30 default), which is how src/sec_af/reasoners/hunt.py reaches them.
    direct = {
        "injection": lambda a: _injection.run_injection_hunter(a, repo, recon, "standard"),
        "xss": lambda a: _xss.run_xss_hunter(a, repo, recon, "standard"),
        "dos": lambda a: _dos.run_dos_hunter(a, repo, recon, "standard"),
        "ssrf": lambda a: _ssrf.run_ssrf_hunter(a, repo, recon, "standard"),
        "auth": lambda a: _auth.run_auth_hunter(a, repo, recon, "standard"),
        "crypto": lambda a: _crypto.run_crypto_hunter(a, repo, recon),
        "business_logic": lambda a: _business_logic.run_business_logic_hunter(a, repo, recon, "standard"),
        "logic": lambda a: _logic.run_logic_hunter(a, repo, recon, "standard"),
        "data_exposure": lambda a: _data_exposure.run_data_exposure_hunter(a, repo, recon),
        "supply_chain": lambda a: _supply_chain.run_supply_chain_hunter(a, repo, recon),
        "config_secrets": lambda a: _config_secrets.run_config_secrets_hunter(a, repo, recon),
        "api_security": lambda a: _api_security.run_api_security_hunter(a, repo, recon),
    }
    # The six hunters whose direct-call prompt differs from their cascade prompt.
    # The other six take a `depth` parameter, so the cascade reaches them with
    # exactly the direct-call arguments and prompt_<h>_standard.txt already pins
    # the text; the Go test asserts that equality instead of re-storing it.
    # `logic` is omitted deliberately: run_logic_hunter forwards verbatim to
    # run_business_logic_hunter, so its prompt is byte-identical to
    # prompt_business_logic_standard.txt. direct_prompt_sha256.json pins that
    # equality without storing a 27 KB duplicate.
    direct_text_goldens = {
        "crypto", "data_exposure", "supply_chain", "config_secrets", "api_security",
    }
    results = {}
    scan_sha = {}
    enrich_sha = {}
    for name, make in direct.items():
        app = _S4App(locations=_s4_locations(), enriched=_s4_enriched())
        result = _s4_asyncio.run(make(app))
        results[name] = _s4_scrub(result.model_dump())
        assert len(app.scan_prompts) == 1, name
        assert len(app.enrich_prompts) == 2, name
        scan_sha[name] = _s4_sha(app.scan_prompts[0])
        enrich_sha[name] = [_s4_sha(text) for text in app.enrich_prompts]
        if name in direct_text_goldens:
            _s4_emit_text(f"direct_prompt_{name}", app.scan_prompts[0])
    _s4_emit_json("hunter_results", results)
    _s4_emit_json("direct_prompt_sha256", {"scan": scan_sha, "enrich": enrich_sha})

    # ---- guard branches (no harness call at all) ----------------------------
    no_crypto = _s4_recon()
    no_crypto.security_context = SecurityContext(
        auth_model="jwt", auth_details="x", crypto_usage=[],
        framework_security=list(recon.security_context.framework_security),
        security_headers=list(recon.security_context.security_headers),
        deployment_signals=list(recon.security_context.deployment_signals),
    )
    no_deps = _s4_recon()
    no_deps.dependencies = DependencyReport(direct_count=0, transitive_count=9)
    no_api = _s4_recon()
    no_api.architecture.api_surface = []

    skips = {}

    def _skip(name, coro_factory):
        app = _S4App(locations=_s4_locations(), enriched=_s4_enriched())
        result = _s4_asyncio.run(coro_factory(app))
        skips[name] = {
            "harness_calls": len(app.scan_prompts) + len(app.enrich_prompts),
            "want": _s4_scrub(result.model_dump()),
        }

    _skip("crypto_no_usage", lambda a: _crypto.run_crypto_hunter(a, repo, no_crypto))
    _skip("crypto_empty_recon", lambda a: _crypto.run_crypto_hunter(a, repo, empty))
    _skip("supply_chain_no_direct_deps", lambda a: _supply_chain.run_supply_chain_hunter(a, repo, no_deps))
    _skip("api_security_no_surface", lambda a: _api_security.run_api_security_hunter(a, repo, no_api))
    _skip("business_logic_quick", lambda a: _business_logic.run_business_logic_hunter(a, repo, recon, "quick"))
    _skip("logic_quick", lambda a: _logic.run_logic_hunter(a, repo, recon, "quick"))
    _s4_emit_json("hunter_skips", skips)

    # ---- empty-location early returns (scan ran, no enrichment) -------------
    empties = {}
    for name, make in direct.items():
        app = _S4App(locations=[], enriched=_s4_enriched())
        result = _s4_asyncio.run(make(app))
        empties[name] = {
            "scan_calls": len(app.scan_prompts),
            "enrich_calls": len(app.enrich_prompts),
            "want": _s4_scrub(result.model_dump()),
        }
    _s4_emit_json("hunter_empty_locations", empties)

    # ---- crypto usage-context partitioning ---------------------------------
    crypto_cases = {}
    for case_name, contexts in {
        "mixed": ["password hashing", "file integrity checksum", "etag generation for cache",
                  "TLS session key derivation", "unrelated purpose", None, ""],
        "none": ["unrelated purpose", "widget rendering"],
        "both_terms": ["auth token cache"],
    }.items():
        usage_recon = _s4_recon_empty()
        usage_recon.security_context.crypto_usage = [
            CryptoUsage(algorithm="MD5", usage_context=c, is_weak=True) for c in contexts
        ]
        usage_contexts = _crypto._usage_contexts(usage_recon)
        crypto_cases[case_name] = {
            "usage_contexts": usage_contexts,
            "security_critical": _crypto._filter_contexts_by_terms(
                usage_contexts, _crypto._SECURITY_CRITICAL_TERMS
            ),
            "non_security": _crypto._filter_contexts_by_terms(usage_contexts, _crypto._NON_SECURITY_TERMS),
            "should_run": _crypto.should_run_crypto_hunter(usage_recon),
        }
        app = _S4App(locations=[], enriched=_s4_enriched())
        _ = _s4_asyncio.run(_crypto.run_crypto_hunter(app, repo, usage_recon))
        _s4_emit_text(f"crypto_prompt_{case_name}", app.scan_prompts[0])
    _s4_emit_json("crypto_usage_partition", crypto_cases)
    _s4_emit_json("crypto_term_tables", {
        "security_critical": list(_crypto._SECURITY_CRITICAL_TERMS),
        "non_security": list(_crypto._NON_SECURITY_TERMS),
    })

    # ---- auth depth labels + business_logic depth_prompt --------------------
    _s4_emit_json("auth_depth_label", {
        case: _auth._depth_label(case)
        for case in ["quick", "Standard", " THOROUGH ", "bogus", "", "  "]
    })
    _s4_emit_json("auth_target_cwes", list(_auth._TARGET_CWES))

    app = _S4App(locations=[], enriched=_s4_enriched())
    _ = _s4_asyncio.run(
        _business_logic.run_business_logic_hunter(
            app, repo, small, "thorough", 30,
            "Use deep, multi-turn analysis. Trace cross-file flows and hunt secondary pivots.",
        )
    )
    _s4_emit_text("business_logic_prompt_with_depth_prompt", app.scan_prompts[0])

    _s4_emit_json("business_logic_enabled", {
        case: _business_logic.is_business_logic_hunter_enabled(case)
        for case in ["quick", "QUICK", "standard", "thorough", "bogus", ""]
    })

    # ---- the JSON recon-context blocks the four inline hunters build --------
    _s4_emit_text("recon_context_block_dos", _dos._recon_context_block(recon))
    _s4_emit_text("recon_context_block_ssrf", _ssrf._recon_context_block(recon))
    _s4_emit_text("recon_context_block_xss", _xss._recon_context_block(recon))
    _s4_emit_text("recon_context_block_business_logic", _business_logic._recon_context_block(recon))
    _s4_emit_text("recon_context_block_dos_empty", _dos._recon_context_block(empty))
    _s4_emit_text("recon_context_block_business_logic_empty", _business_logic._recon_context_block(empty))


# internal/output's goldens (SARIF, full/summary JSON, Markdown reports) live in
# their own module because they carry four SecurityAuditResult fixtures with
# them; gen_golden_output.py also runs standalone.
from gen_golden_output import gen_output  # noqa: E402

# internal/agents/prove's goldens (S5) live in their own module for the same
# reason; gen_golden_prove.py also runs standalone.
from gen_golden_prove import gen_prove  # noqa: E402

# internal/phases + internal/orch goldens (S10) live in their own module because
# they carry the recon/finding fixtures and the clock stubs that pin
# _write_checkpoint and _emit_progress; gen_golden_phases.py also runs
# standalone.
from gen_golden_phases import gen_orch, gen_phases  # noqa: E402


# ---------------------------------------------------------------------------
# COVERAGE GAP — read before trusting a run of this script.
#
# Four packages have committed goldens under testdata/golden/ but NO generator
# section in this file (or in the three modules imported above):
#
#     internal/monitoring        baseline.json, baseline_empty.json
#     internal/policies          build_prompt*.txt, evaluate_policy_prompt.txt
#     internal/agents/dedup      chain_correlation_prompt_*.txt,
#                                duplicate_check_prompt.txt
#     internal/agents/remediation  generate_prompt*.txt, run_prompt*.txt
#
# Their sections existed while the port was being written and were lost when
# several agents rewrote this file concurrently; the goldens themselves are the
# ones those sections produced from the real Python functions and their tests
# pass, so nothing is WRONG today — but running this script does NOT refresh
# them, and it will not notice if they go stale.
#
# Consequence: if you change a prompt builder in
# src/sec_af/{monitoring,policies}.py or src/sec_af/agents/{dedup,remediation}.py,
# this script's "done" is not evidence that the goldens followed. Re-derive
# those files from the Python functions by hand (each package's test file
# documents the exact fixture it was generated from) or restore the sections.
# ---------------------------------------------------------------------------


def main() -> None:
    s3_emit_goldens()
    s4_emit_goldens()
    gen_pyfmt()
    gen_recontext()
    gen_gates()
    gen_output()
    gen_prove()
    gen_phases()
    gen_orch()
    print("done")
    print(
        "NOTE: monitoring, policies, agents/dedup and agents/remediation goldens "
        "have no generator here — see the COVERAGE GAP comment above."
    )


if __name__ == "__main__":
    main()
