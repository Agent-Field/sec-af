#!/usr/bin/env python3
"""Golden generator for internal/agents/prove (assignment S5).

Every string src/sec_af/agents/prove hands to an LLM, and every structure its
pure helpers build, is produced here by calling the REAL Python functions with
fixed inputs. The Go tests in internal/agents/prove render the same inputs and
compare byte for byte.

Run through the umbrella generator (preferred):

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden.py

or standalone:

    PYTHONPATH=src ~/.agentfield/packages/sec-af/venv/bin/python go/scripts/gen_golden_prove.py

This module is deliberately SELF-CONTAINED — its own imports, its own path
computation and its own writer — because several porting agents extend the
generator concurrently.
"""

from __future__ import annotations

import asyncio
import json
import os
from types import SimpleNamespace
from typing import Any

_HERE = os.path.dirname(os.path.abspath(__file__))
_GO_ROOT = os.path.dirname(_HERE)
_GOLDEN_DIR = os.path.join(_GO_ROOT, "internal", "agents", "prove", "testdata", "golden")

# A stable, fixture-controlled repository path. The prove agents only
# interpolate it into their CONTEXT block; it deliberately does not exist.
FIXTURE_REPO = "/fixtures/demo-repo"


def _write(name: str, text: str) -> None:
    os.makedirs(_GOLDEN_DIR, exist_ok=True)
    path = os.path.join(_GOLDEN_DIR, name)
    with open(path, "w", encoding="utf-8") as handle:
        _ = handle.write(text)
    print(f"  wrote internal/agents/prove/testdata/golden/{name} ({len(text.encode('utf-8'))} bytes)")


def _emit_text(name: str, text: str) -> None:
    _write(name + ".txt", text)


def _emit_json(name: str, obj: Any) -> None:
    _write(name + ".json", json.dumps(obj, indent=2, sort_keys=False) + "\n")


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------


def _finding_rich():
    """Every optional populated, plus the two substitution-ORDER traps.

    * ``{{TITLE}}`` sits inside the DESCRIPTION. ``_build_prompt`` substitutes
      TITLE *before* DESCRIPTION, so the marker must survive verbatim.
    * ``{{DEPTH}}`` sits inside the CODE_SNIPPET. DEPTH is substituted *after*
      CODE_SNIPPET, so the marker must be replaced by the depth string.

    ``related_files`` carries the characters json.dumps treats specially:
    ``<`` and ``&`` are NOT escaped by json.dumps (Go's encoder escapes them
    unless SetEscapeHTML(false)) while non-ASCII IS escaped as \\uXXXX by the
    default ensure_ascii=True (Go never escapes non-ASCII).
    """
    from sec_af.schemas.hunt import Confidence, FindingType, RawFinding, Severity
    from sec_af.schemas.recon import DataFlowStep

    return RawFinding(
        id="raw-1",
        hunter_strategy="injection",
        title="Potential SQL injection in user lookup",
        description="Request parameter reaches a formatted SQL string. Marker: {{TITLE}}",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="Improper Neutralization/Escaping of Special Elements",
        owasp_category="A03:2021 - Injection",
        file_path="src/users.py",
        start_line=42,
        end_line=44,
        function_name="get_user",
        code_snippet='cursor.execute("SELECT * FROM users WHERE id = " + user_id)  # depth={{DEPTH}}',
        estimated_severity=Severity.HIGH,
        confidence=Confidence.HIGH,
        data_flow=[
            DataFlowStep(file_path="src/routes.py", line=10, component="handler", operation="read request.args"),
            DataFlowStep(file_path="src/users.py", line=42, component="db", operation="execute"),
        ],
        related_files=["src/routes.py", "src/café <b>&</b>.py"],
        fingerprint="fp-1",
    )


def _finding_bare():
    """Every optional at its pydantic default: no data_flow, no related files."""
    from sec_af.schemas.hunt import Confidence, FindingType, RawFinding, Severity

    return RawFinding(
        id="raw-2",
        hunter_strategy="crypto",
        title="Weak hash",
        description="MD5 used for password hashing",
        finding_type=FindingType.SAST,
        cwe_id="CWE-327",
        cwe_name="Broken Crypto",
        file_path="src/hash.py",
        start_line=7,
        end_line=7,
        code_snippet="hashlib.md5(pw).hexdigest()",
        estimated_severity=Severity.MEDIUM,
        confidence=Confidence.LOW,
        fingerprint="fp-2",
    )


def _trace_rich():
    from sec_af.schemas.prove import DataFlowTrace

    return DataFlowTrace(
        source="request.args['id']",
        sink="cursor.execute(query)",
        steps=["src/routes.py:10 read request.args", "src/users.py:42 execute"],
        sink_reached=True,
    )


def _trace_bare():
    from sec_af.schemas.prove import DataFlowTrace

    return DataFlowTrace(source="unknown", sink="unknown", steps=[], sink_reached=False)


def _sanitization_rich():
    from sec_af.schemas.prove import SanitizationResult

    return SanitizationResult(
        found=True,
        type="parameterized query",
        sufficient=False,
        bypass_method="second-order injection through the audit log",
    )


def _sanitization_bare():
    from sec_af.schemas.prove import SanitizationResult

    return SanitizationResult(found=False, sufficient=None, bypass_method=None)


def _exploit_rich():
    from sec_af.schemas.prove import ExploitHypothesis

    return ExploitHypothesis(
        hypothesis="Attacker supplies id=1 OR 1=1 to dump the table",
        payload="1 OR 1=1",
        expected_outcome="Full users table returned",
    )


def _exploit_bare():
    from sec_af.schemas.prove import ExploitHypothesis

    return ExploitHypothesis(hypothesis="unknown", payload=None, expected_outcome="unknown")


def _verdict_decision(verdict: str, level: int):
    from sec_af.schemas.prove import VerdictDecision

    return VerdictDecision(
        verdict=verdict,
        evidence_level=level,
        rationale=f"rationale for {verdict}",
        confidence="high",
    )


def _verified(finding_id: str, fingerprint: str, score: float, level: int, tags=None):
    """A minimal VerifiedFinding for the chain-builder / sort fixtures."""
    from sec_af.schemas.hunt import FindingType, Severity
    from sec_af.schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding

    return VerifiedFinding(
        id=finding_id,
        fingerprint=fingerprint,
        title=f"finding {finding_id}",
        description="d",
        finding_type=FindingType.SAST,
        cwe_id="CWE-89",
        cwe_name="SQL Injection",
        verdict=Verdict.CONFIRMED,
        evidence_level=EvidenceLevel(level),
        rationale="r",
        severity=Severity.HIGH,
        exploitability_score=score,
        location=Location(file_path="src/users.py", start_line=1, end_line=2),
        tags=list(tags or []),
        sarif_rule_id="sec-af/sast/sql-injection",
        sarif_security_severity=score,
    )


# ---------------------------------------------------------------------------
# prompt capture
# ---------------------------------------------------------------------------


class _Captured(Exception):
    """Raised by the fake harness/ai once the prompt has been recorded."""


class _CaptureApp:
    """Records the single app.harness(prompt=...) / app.ai(user=...) call.

    Aborting with _Captured short-circuits the agent before
    extract_harness_result runs; its ``finally:`` still removes the temp dir.
    """

    def __init__(self) -> None:
        self.prompt: str | None = None

    async def harness(self, prompt, schema=None, cwd=None, project_dir=None, **kwargs):
        self.prompt = prompt
        raise _Captured()

    async def ai(self, *, user, schema=None, system=None, **kwargs):
        self.prompt = user
        raise _Captured()


def _capture(make_coro) -> str:
    app = _CaptureApp()
    try:
        asyncio.run(make_coro(app))
    except _Captured:
        pass
    assert app.prompt is not None, "agent did not call app.harness/app.ai"
    return app.prompt


# ---------------------------------------------------------------------------
# canned harness for the end-to-end run_prove fixture
# ---------------------------------------------------------------------------


class _CannedApp:
    """Answers each prove sub-agent by recognising its ROLE line."""

    def __init__(self, verdict: str = "confirmed", level: int = 5) -> None:
        self._verdict = verdict
        self._level = level

    async def harness(self, prompt, schema=None, cwd=None, project_dir=None, **kwargs):
        if "You are DataFlowTracer" in prompt:
            return SimpleNamespace(is_error=False, parsed=_trace_rich(), result=None)
        if "You are SanitizationAnalyzer" in prompt:
            return SimpleNamespace(is_error=False, parsed=_sanitization_rich(), result=None)
        if "You are ExploitHypothesizer" in prompt:
            return SimpleNamespace(is_error=False, parsed=_exploit_rich(), result=None)
        raise AssertionError(f"unexpected harness prompt: {prompt[:120]!r}")

    async def ai(self, *, user, schema=None, system=None, **kwargs):
        return {
            "verdict": self._verdict,
            "evidence_level": self._level,
            "rationale": "canned rationale",
            "confidence": "high",
        }


# ---------------------------------------------------------------------------
# emitters
# ---------------------------------------------------------------------------


def _prompts() -> None:
    from sec_af.agents.prove.chain_builder import PROMPT_PATH as CHAIN_PROMPT
    from sec_af.agents.prove.chain_builder import _build_prompt as chain_build_prompt
    from sec_af.agents.prove.cross_service import run_cross_service_analyzer
    from sec_af.agents.prove.dast_verifier import run_dast_verifier
    from sec_af.agents.prove.dep_reachability import run_dep_reachability
    from sec_af.agents.prove.exploit import run_exploit_hypothesizer
    from sec_af.agents.prove.sanitization import run_sanitization_analyzer
    from sec_af.agents.prove.tracer import run_tracer
    from sec_af.agents.prove.verdict import run_verdict_agent

    rich, bare = _finding_rich(), _finding_bare()

    # ---- tracer ------------------------------------------------------------
    _emit_text(
        "tracer_prompt_A",
        _capture(lambda app: run_tracer(app=app, repo_path=FIXTURE_REPO, finding=rich, depth="thorough")),
    )
    _emit_text(
        "tracer_prompt_B",
        _capture(lambda app: run_tracer(app=app, repo_path=FIXTURE_REPO, finding=bare, depth="quick")),
    )

    # ---- sanitization ------------------------------------------------------
    _emit_text(
        "sanitization_prompt_A",
        _capture(
            lambda app: run_sanitization_analyzer(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=rich,
                data_flow_trace=_trace_rich(),
                depth="thorough",
            )
        ),
    )
    _emit_text(
        "sanitization_prompt_B",
        _capture(
            lambda app: run_sanitization_analyzer(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=bare,
                data_flow_trace=_trace_bare(),
                depth="quick",
            )
        ),
    )

    # ---- exploit -----------------------------------------------------------
    _emit_text(
        "exploit_prompt_A",
        _capture(
            lambda app: run_exploit_hypothesizer(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=rich,
                data_flow_trace=_trace_rich(),
                sanitization=_sanitization_rich(),
                depth="thorough",
            )
        ),
    )
    _emit_text(
        "exploit_prompt_B",
        _capture(
            lambda app: run_exploit_hypothesizer(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=bare,
                data_flow_trace=_trace_bare(),
                sanitization=_sanitization_bare(),
                depth="quick",
            )
        ),
    )

    # ---- verdict (.ai, no CONTEXT suffix) ----------------------------------
    _emit_text(
        "verdict_prompt_A",
        _capture(
            lambda app: run_verdict_agent(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=rich,
                data_flow=_trace_rich(),
                sanitization=_sanitization_rich(),
                exploit=_exploit_rich(),
            )
        ),
    )
    _emit_text(
        "verdict_prompt_B",
        _capture(
            lambda app: run_verdict_agent(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=bare,
                data_flow=_trace_bare(),
                sanitization=_sanitization_bare(),
                exploit=_exploit_bare(),
            )
        ),
    )

    # ---- dependency reachability ------------------------------------------
    # NOTE ON KEY ORDER: `evidence` is rendered with json.dumps, which follows
    # the dict's INSERTION order. A Go map[string]any carries no order, so the
    # port renders it sorted (DESIGN.md §2b). The fixture therefore declares
    # `evidence` with alphabetically ordered keys so the two agree byte for
    # byte; the divergence for an unsorted dict is documented on the Go
    # builder and pinned by a Go-only test.
    dep_finding_rich: dict[str, Any] = {
        "cve": "CVE-2021-44228",
        "package": "log4j-core",
        "vulnerable_function": "JndiLookup.lookup",
        "version": "2.14.1",
        "evidence": {
            "direct": True,
            "manifest": "pom.xml",
            "nested": {"a": 1, "b": [True, None]},
            "score": 9.8,
            "transitive_depth": 2,
        },
    }
    _emit_json("dep_reachability_input_A", dep_finding_rich)
    _emit_text(
        "dep_reachability_prompt_A",
        _capture(
            lambda app: run_dep_reachability(app=app, repo_path=FIXTURE_REPO, finding=dep_finding_rich, depth="thorough")
        ),
    )
    # Empty dict: every `.get(key, "")` falls back, `evidence` becomes `{}`.
    _emit_text(
        "dep_reachability_prompt_B",
        _capture(lambda app: run_dep_reachability(app=app, repo_path=FIXTURE_REPO, finding={}, depth="quick")),
    )
    # Non-string scalars exercise `str(...)`; an explicit None is str()'d to
    # "None" rather than falling back to "".
    dep_finding_odd: dict[str, Any] = {
        "cve": 1234,
        "package": None,
        "vulnerable_function": 3.5,
        "version": True,
        "evidence": [1, "two"],
    }
    _emit_json("dep_reachability_input_C", dep_finding_odd)
    _emit_text(
        "dep_reachability_prompt_C",
        _capture(
            lambda app: run_dep_reachability(app=app, repo_path=FIXTURE_REPO, finding=dep_finding_odd, depth="standard")
        ),
    )

    # ---- DAST --------------------------------------------------------------
    _emit_text(
        "dast_prompt_A",
        _capture(
            lambda app: run_dast_verifier(
                app=app,
                repo_path=FIXTURE_REPO,
                finding=rich,
                exploit_payload="1 OR 1=1 -- {{DEPTH}}",
                depth="thorough",
            )
        ),
    )
    _emit_text(
        "dast_prompt_B",
        _capture(
            lambda app: run_dast_verifier(
                app=app, repo_path=FIXTURE_REPO, finding=bare, exploit_payload="", depth="quick"
            )
        ),
    )

    # ---- cross service -----------------------------------------------------
    _emit_text(
        "cross_service_prompt_A",
        _capture(
            lambda app: run_cross_service_analyzer(
                app=app,
                repo_path=FIXTURE_REPO,
                services=["gateway", "billing-café", "db<&>"],
                findings_summary="- gateway: SSRF\n- billing: IDOR",
                depth="thorough",
            )
        ),
    )
    _emit_text(
        "cross_service_prompt_B",
        _capture(
            lambda app: run_cross_service_analyzer(
                app=app, repo_path=FIXTURE_REPO, services=[], findings_summary="", depth="quick"
            )
        ),
    )

    # ---- chain builder -----------------------------------------------------
    from sec_af.schemas.hunt import PotentialChain, Severity

    chains = [
        PotentialChain(
            chain_id="chain-1",
            title="SSRF to internal API",
            finding_ids=["v1", "v2"],
            combined_impact="Internal service access",
            estimated_severity=Severity.CRITICAL,
        )
    ]
    findings = [_verified("v1", "fp-v1", 7.5, 4), _verified("v2", "fp-v2", 3.0, 2)]
    _emit_text(
        "chain_builder_prompt",
        chain_build_prompt(CHAIN_PROMPT.read_text(encoding="utf-8"), chains, findings, "standard"),
    )
    _emit_json(
        "chain_builder_prompt_input",
        {
            "depth": "standard",
            "chains": [chain.model_dump() for chain in chains],
            "findings": [finding.model_dump() for finding in findings],
        },
    )


def _pure_helpers() -> None:
    from sec_af.agents.prove import _apply_metadata, _priority_sort
    from sec_af.agents.prove.assembler import assemble_verified_finding
    from sec_af.agents.prove.chain_builder import _apply_validated_chain
    from sec_af.agents.prove.verifier import fallback as verifier_fallback

    rich, bare = _finding_rich(), _finding_bare()

    # ---- verifier.fallback -------------------------------------------------
    _emit_json(
        "fallback",
        {
            "plain": verifier_fallback(rich, "harness blew up").model_dump(),
            "with_drop_reason": verifier_fallback(rich, "boom", drop_reason="verifier_error").model_dump(),
            "demoted": verifier_fallback(
                bare,
                "Verifier returned unverified verdict; demoted for manual review",
                drop_reason="verdict_unverified",
                original_verdict="unverified",
            ).model_dump(),
            "original_verdict_only": verifier_fallback(bare, "why", original_verdict="unverified").model_dump(),
        },
    )

    # ---- assembler ---------------------------------------------------------
    cases = {}
    for name, verdict, level, finding, trace, san, exploit in (
        ("confirmed", "confirmed", 5, rich, _trace_rich(), _sanitization_rich(), _exploit_rich()),
        ("not_exploitable", "not_exploitable", 1, rich, _trace_rich(), _sanitization_rich(), _exploit_rich()),
        ("unknown_verdict", "unverified", 9, bare, _trace_bare(), _sanitization_bare(), _exploit_bare()),
        ("clamped_low", "likely", 0, bare, _trace_bare(), _sanitization_bare(), _exploit_bare()),
    ):
        cases[name] = assemble_verified_finding(
            finding, trace, san, exploit, _verdict_decision(verdict, level)
        ).model_dump()
    _emit_json("assemble", cases)

    # ---- _apply_metadata ---------------------------------------------------
    meta_cases = {}
    for name, verified in (
        ("keeps_rule_id", _verified("m1", "fp-m1", 0.0, 3)),
        ("mints_rule_id", _verified("m2", "fp-m2", 0.0, 6)),
        ("with_reachability_tag", _verified("m3", "fp-m3", 0.0, 6, tags=["externally_reachable"])),
    ):
        if name == "mints_rule_id":
            verified.sarif_rule_id = ""
            verified.cwe_name = "Broken Access/Control Check"
        meta_cases[name] = _apply_metadata(verified).model_dump()
    _emit_json("apply_metadata", meta_cases)

    # ---- _priority_sort ----------------------------------------------------
    from sec_af.schemas.hunt import Confidence, FindingType, RawFinding, Severity

    def _mk(fid: str, severity: Severity, confidence: Confidence) -> RawFinding:
        return RawFinding(
            id=fid,
            hunter_strategy="s",
            title=fid,
            description="d",
            finding_type=FindingType.SAST,
            cwe_id="CWE-89",
            cwe_name="n",
            file_path="f.py",
            start_line=1,
            end_line=1,
            code_snippet="c",
            estimated_severity=severity,
            confidence=confidence,
            fingerprint="fp-" + fid,
        )

    unsorted = [
        _mk("a", Severity.LOW, Confidence.HIGH),
        _mk("b", Severity.CRITICAL, Confidence.LOW),
        _mk("c", Severity.CRITICAL, Confidence.HIGH),
        _mk("d", Severity.INFO, Confidence.MEDIUM),
        _mk("e", Severity.CRITICAL, Confidence.LOW),
        _mk("f", Severity.MEDIUM, Confidence.MEDIUM),
    ]
    _emit_json(
        "priority_sort",
        {
            "input": [
                {"id": f.id, "estimated_severity": f.estimated_severity.value, "confidence": f.confidence.value}
                for f in unsorted
            ],
            "want_ids": [f.id for f in _priority_sort(unsorted)],
        },
    )

    # ---- chain_builder._apply_validated_chain ------------------------------
    # Python parity landmine: VerifiedFinding.tags is a `list[str]`, but the
    # function calls `finding.tags.add(...)` — an AttributeError the caller
    # does NOT catch. Recorded here so the Go port reproduces it.
    chain_cases = {}

    def _snapshot(findings):
        return [
            {
                "id": f.id,
                "chain_id": f.chain_id,
                "chain_step": f.chain_step,
                "enables": f.enables,
                "tags": list(f.tags),
            }
            for f in findings
        ]

    def _run_case(name, chain, findings):
        by_id = {f.id: f for f in findings}
        error = None
        try:
            _apply_validated_chain(by_id, chain)
        except BaseException as exc:  # noqa: BLE001 - recording the parity quirk
            # str(exc), NOT f"{type(exc).__name__}: {exc}": this exception
            # escapes to app.py's `except Exception`, which interpolates `{exc}`
            # into both the note and the 500 body, so str(exc) is the text the
            # Go error must carry.
            error = str(exc)
        chain_cases[name] = {"chain": chain, "error": error, "findings": _snapshot(findings)}

    _run_case(
        "not_validated",
        {"chain_id": "c1", "title": "t", "validated": False, "rationale": "r",
         "steps": [{"step_number": 1, "finding_id": "v1", "description": "d", "enables": "e"}]},
        [_verified("v1", "fp-v1", 1.0, 1), _verified("v2", "fp-v2", 1.0, 1)],
    )
    _run_case(
        "no_steps",
        {"chain_id": "c1", "title": "t", "validated": True, "rationale": "r", "steps": []},
        [_verified("v1", "fp-v1", 1.0, 1)],
    )
    _run_case(
        "no_matching_finding",
        {"chain_id": "c1", "title": "t", "validated": True, "rationale": "r",
         "steps": [{"step_number": 2, "finding_id": "zz", "description": "d", "enables": "e"},
                   {"step_number": 1, "finding_id": "yy", "description": "d", "enables": "e"}]},
        [_verified("v1", "fp-v1", 1.0, 1)],
    )
    _run_case(
        "matching_finding_raises",
        {"chain_id": "c1", "title": "t", "validated": True, "rationale": "r",
         "steps": [{"step_number": 2, "finding_id": "v2", "description": "d", "enables": "e"},
                   {"step_number": 1, "finding_id": "v1", "description": "d", "enables": "e"}]},
        [_verified("v1", "fp-v1", 1.0, 1), _verified("v2", "fp-v2", 1.0, 1)],
    )
    _run_case(
        "second_step_matches",
        {"chain_id": "c9", "title": "t", "validated": True, "rationale": "r",
         "steps": [{"step_number": 1, "finding_id": "missing", "description": "d", "enables": "e"},
                   {"step_number": 2, "finding_id": "v1", "description": "d", "enables": "e"}]},
        [_verified("v1", "fp-v1", 1.0, 1)],
    )
    _emit_json("apply_validated_chain", chain_cases)


def _end_to_end() -> None:
    from sec_af.agents.prove import run_prove
    from sec_af.schemas.hunt import HuntResult

    rich, bare = _finding_rich(), _finding_bare()
    hunt = HuntResult(findings=[bare, rich], chains=[], total_raw=2, deduplicated_count=2, strategies_run=["injection"])

    verified = asyncio.run(run_prove(_CannedApp(), FIXTURE_REPO, hunt, "standard", 3))
    _emit_json(
        "run_prove",
        {
            "repo_path": FIXTURE_REPO,
            "depth": "standard",
            "hunt_result": hunt.model_dump(),
            "canned": {
                "tracer": _trace_rich().model_dump(),
                "sanitization": _sanitization_rich().model_dump(),
                "exploit": _exploit_rich().model_dump(),
                "verdict": {
                    "verdict": "confirmed",
                    "evidence_level": 5,
                    "rationale": "canned rationale",
                    "confidence": "high",
                },
            },
            "want": [finding.model_dump() for finding in verified],
        },
    )

    # run_verifier on its own — pins the reproduction-step backfill and the
    # sarif_rule_id backfill that run_prove's _apply_metadata would hide.
    from sec_af.agents.prove.verifier import run_verifier

    single = asyncio.run(run_verifier(_CannedApp(verdict="not_exploitable", level=1), FIXTURE_REPO, rich, "quick"))
    both = asyncio.run(run_verifier(_CannedApp(verdict="likely", level=3), FIXTURE_REPO, bare, "quick"))
    _emit_json(
        "run_verifier",
        {"not_exploitable": single.model_dump(), "likely": both.model_dump()},
    )


def gen_prove() -> None:
    print("internal/agents/prove goldens:")
    _prompts()
    _pure_helpers()
    _end_to_end()


if __name__ == "__main__":
    gen_prove()
    print("done")
