from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from agentfield import Agent  # noqa: TC001
from pydantic import BaseModel

from .agents.hunt import run_hunt
from .agents.prove import run_prove
from .agents.recon import extract_recon_findings, run_recon
from .compliance.mapping import get_compliance_gaps, get_compliance_mappings, get_compliance_mappings_hybrid
from .config import DepthProfile
from .harness import AIGateWrapper
from .output.json_output import generate_json
from .output.report import generate_report
from .output.sarif import generate_sarif
from .schemas.hunt import Confidence, HuntResult, HuntStrategy, RawFinding, Severity
from .schemas.input import AuditInput  # noqa: TC001
from .schemas.output import AttackChain, AuditProgress, SecurityAuditResult
from .schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding
from .schemas.recon import ReconResult
from .scoring import compute_exploitability_score

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class BudgetExhausted(RuntimeError):  # noqa: N818
    pass


class _PhaseHarnessProxy:
    def __init__(self, orchestrator: AuditOrchestrator, phase: str):
        self._orchestrator = orchestrator
        self._phase = phase

    async def harness(self, prompt: str, *, schema: object = None, cwd: str | None = None, **kwargs: object) -> object:
        if self._orchestrator._budget_or_timeout_exhausted(self._phase):
            raise BudgetExhausted(f"{self._phase} budget exhausted")
        result = await self._orchestrator.app.harness(prompt, schema=schema, cwd=cwd, **kwargs)
        self._orchestrator.agent_invocations += 1
        self._orchestrator._register_cost(self._phase, getattr(result, "cost_usd", None))
        return result


class AuditOrchestrator:
    _PHASE_BUDGETS: dict[str, float] = {"recon": 0.15, "hunt": 0.35, "prove": 0.50}
    _PHASE_ORDER: tuple[str, ...] = ("recon", "hunt", "prove")

    def __init__(self, app: Agent, input: AuditInput):
        self.app = cast("Any", app)
        self.input = input
        self.started_at = time.monotonic()
        self.repo_path = Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve()
        self.checkpoint_dir = self.repo_path / ".sec-af"
        self.max_cost_usd = input.max_cost_usd
        self.max_duration_seconds = input.max_duration_seconds
        self.total_cost_usd = 0.0
        self.cost_breakdown: dict[str, float] = {phase: 0.0 for phase in self._PHASE_ORDER}
        self.agent_invocations = 0
        self.budget_exhausted = False
        self.findings_not_verified = 0
        self.prove_drop_summary: dict[str, Any] = {"demoted_total": 0, "by_reason": {}, "findings": []}
        self.ai_gate = AIGateWrapper(app=self.app)

    async def run(self) -> SecurityAuditResult:
        self.app.note("Starting SEC-AF orchestrator", tags=["audit", "start"])
        recon = await self._run_recon()
        self._write_checkpoint("recon", recon)

        hunt = await self._run_hunt(recon)
        self._write_checkpoint("hunt", hunt)

        verified = await self._run_prove(recon, hunt)
        self._write_checkpoint("prove", verified)

        result = await self._generate_output(recon=recon, hunt=hunt, verified=verified)
        self.app.note("SEC-AF audit complete", tags=["audit", "complete"])
        return result

    async def run_from_checkpoint(self, phase: str) -> SecurityAuditResult:
        normalized_phase = phase.lower().strip()
        if normalized_phase not in {"recon", "hunt", "prove"}:
            msg = f"Unknown checkpoint phase: {phase}"
            raise ValueError(msg)

        recon: ReconResult
        hunt: HuntResult
        verified: list[VerifiedFinding]

        if normalized_phase == "recon":
            recon = self._read_checkpoint("recon", ReconResult)
            hunt = await self._run_hunt(recon)
            self._write_checkpoint("hunt", hunt)
            verified = await self._run_prove(recon, hunt)
            self._write_checkpoint("prove", verified)
        elif normalized_phase == "hunt":
            recon = self._read_checkpoint("recon", ReconResult)
            hunt = self._read_checkpoint("hunt", HuntResult)
            verified = await self._run_prove(recon, hunt)
            self._write_checkpoint("prove", verified)
        else:
            recon = self._read_checkpoint("recon", ReconResult)
            hunt = self._read_checkpoint("hunt", HuntResult)
            verified = self._read_checkpoint_list("prove", VerifiedFinding)

        return await self._generate_output(recon=recon, hunt=hunt, verified=verified)

    async def _run_recon(self) -> ReconResult:
        self.app.note("Phase: RECON", tags=["audit", "recon"])
        recon = await run_recon(
            app=_PhaseHarnessProxy(self, "recon"),
            repo_path=str(self.repo_path),
            depth=self.input.depth,
        )
        self._emit_progress(phase="recon", agents_total=1, agents_completed=1, findings_so_far=0)
        return recon

    async def _run_hunt(self, recon: ReconResult) -> HuntResult:
        self.app.note("Phase: HUNT", tags=["audit", "hunt"])
        hunt = await run_hunt(
            app=_PhaseHarnessProxy(self, "hunt"),
            repo_path=str(self.repo_path),
            recon_result=recon,
            depth=self.input.depth,
        )
        recon_findings = extract_recon_findings(recon)
        hunt = merge_recon_findings_into_hunt(hunt, recon_findings)
        self._emit_progress(phase="hunt", agents_total=1, agents_completed=1, findings_so_far=len(hunt.findings))
        return hunt

    async def _run_prove(self, recon: ReconResult, hunt: HuntResult) -> list[VerifiedFinding]:
        _ = recon
        self.app.note("Phase: PROVE", tags=["audit", "prove"])
        prioritized = self._prioritize_findings(hunt.findings)
        prover_cap = self._prover_cap()
        limited_hunt = HuntResult(
            findings=prioritized[:prover_cap],
            chains=hunt.chains,
            total_raw=hunt.total_raw,
            deduplicated_count=hunt.deduplicated_count,
            chain_count=hunt.chain_count,
            strategies_run=hunt.strategies_run,
            hunt_duration_seconds=hunt.hunt_duration_seconds,
        )
        self.findings_not_verified = max(0, len(hunt.findings) - len(limited_hunt.findings))
        verified = await run_prove(
            app=_PhaseHarnessProxy(self, "prove"),
            repo_path=str(self.repo_path),
            hunt_result=limited_hunt,
            depth=self.input.depth,
        )
        self.prove_drop_summary = {"demoted_total": 0, "by_reason": {}, "findings": []}
        for finding in verified:
            if finding.drop_reason:
                self._track_drop(
                    finding_title=finding.title,
                    original_verdict=None,
                    reason=finding.drop_reason,
                )
        self._emit_progress(phase="prove", agents_total=1, agents_completed=1, findings_so_far=len(verified))
        return verified

    async def _generate_output(
        self,
        *,
        recon: ReconResult,
        hunt: HuntResult,
        verified: list[VerifiedFinding],
    ) -> SecurityAuditResult:
        _ = recon
        for finding in verified:
            finding.exploitability_score = compute_exploitability_score(finding)
            finding.sarif_security_severity = finding.exploitability_score
            finding.compliance = await get_compliance_mappings_hybrid(
                finding.cwe_id,
                frameworks=self.input.compliance_frameworks or None,
                ai_gate=self.ai_gate,
            )

        verdict_counts: dict[Verdict, int] = {
            Verdict.CONFIRMED: 0,
            Verdict.LIKELY: 0,
            Verdict.INCONCLUSIVE: 0,
            Verdict.NOT_EXPLOITABLE: 0,
        }
        severity_counts: dict[str, int] = {severity.value: 0 for severity in Severity}
        for finding in verified:
            verdict_counts[finding.verdict] += 1
            severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1

        total_raw = hunt.total_raw
        not_exploitable = verdict_counts[Verdict.NOT_EXPLOITABLE]
        noise_reduction = (not_exploitable / total_raw * 100.0) if total_raw > 0 else 0.0

        chains = [
            AttackChain(
                chain_id=chain.chain_id,
                title=chain.title,
                description=chain.combined_impact,
                findings=chain.finding_ids,
                combined_severity=chain.estimated_severity,
                combined_impact=chain.combined_impact,
            )
            for chain in hunt.chains
        ]

        if self.budget_exhausted:
            self.app.note(
                f"Budget exhausted; unverified findings: {self.findings_not_verified}",
                tags=["audit", "budget", "exhausted"],
            )

        compliance_gaps = get_compliance_gaps(verified)
        result = SecurityAuditResult(
            repository=self.input.repo_url,
            commit_sha=self.input.commit_sha or "HEAD",
            branch=self.input.branch,
            timestamp=datetime.now(UTC),
            depth_profile=self.input.depth,
            strategies_used=hunt.strategies_run,
            provider="harness",
            findings=verified,
            attack_chains=chains,
            total_raw_findings=total_raw,
            confirmed=verdict_counts[Verdict.CONFIRMED],
            likely=verdict_counts[Verdict.LIKELY],
            inconclusive=verdict_counts[Verdict.INCONCLUSIVE],
            not_exploitable=not_exploitable,
            noise_reduction_pct=round(noise_reduction, 2),
            by_severity=severity_counts,
            compliance_gaps=compliance_gaps,
            duration_seconds=time.monotonic() - self.started_at,
            agent_invocations=self.agent_invocations,
            cost_usd=round(self.total_cost_usd, 4),
            cost_breakdown={phase: round(cost, 4) for phase, cost in self.cost_breakdown.items()},
            metadata={
                "findings_not_verified": self.findings_not_verified,
                "prove_drop_summary": self.prove_drop_summary,
            },
            sarif="",
        )

        result.sarif = generate_sarif(result)
        _ = generate_json(result, pretty=True)
        _ = generate_report(result)
        return result

    def _write_checkpoint(self, phase: str, payload: BaseModel | list[VerifiedFinding]) -> None:
        self.checkpoint_dir.mkdir(parents=True, exist_ok=True)
        path = self._checkpoint_path(phase)
        data: Any = [item.model_dump() for item in payload] if isinstance(payload, list) else payload.model_dump()
        body = {
            "phase": phase,
            "created_at": datetime.now(UTC).isoformat(),
            "data": data,
        }
        path.write_text(json.dumps(body, indent=2), encoding="utf-8")

    def _read_checkpoint(self, phase: str, schema: type[SchemaT]) -> SchemaT:
        path = self._checkpoint_path(phase)
        payload = json.loads(path.read_text(encoding="utf-8"))
        return schema(**payload.get("data", {}))

    def _read_checkpoint_list(self, phase: str, schema: type[SchemaT]) -> list[SchemaT]:
        path = self._checkpoint_path(phase)
        payload = json.loads(path.read_text(encoding="utf-8"))
        rows = payload.get("data", [])
        return [schema(**row) for row in rows]

    def _checkpoint_path(self, phase: str) -> Path:
        return self.checkpoint_dir / f"checkpoint-{phase}.json"

    def _depth_profile(self) -> DepthProfile:
        try:
            return DepthProfile(self.input.depth.lower())
        except ValueError:
            return DepthProfile.STANDARD

    def _default_strategies(self, recon: ReconResult) -> list[HuntStrategy]:
        strategies: list[HuntStrategy] = [
            HuntStrategy.INJECTION,
            HuntStrategy.AUTH,
            HuntStrategy.DATA_EXPOSURE,
            HuntStrategy.CONFIG_SECRETS,
        ]
        if recon.security_context.crypto_usage:
            strategies.append(HuntStrategy.CRYPTO)
        if recon.dependencies.direct_count > 0:
            strategies.append(HuntStrategy.SUPPLY_CHAIN)
        if recon.architecture.api_surface:
            strategies.append(HuntStrategy.API_SECURITY)

        depth = self._depth_profile()
        if depth in {DepthProfile.STANDARD, DepthProfile.THOROUGH}:
            strategies.append(HuntStrategy.LOGIC_BUGS)
        if depth == DepthProfile.THOROUGH and "python" in {lang.lower() for lang in recon.languages}:
            strategies.append(HuntStrategy.PYTHON_SPECIFIC)
        if depth == DepthProfile.THOROUGH and any(
            lang.lower() in {"javascript", "typescript"} for lang in recon.languages
        ):
            strategies.append(HuntStrategy.JAVASCRIPT_SPECIFIC)

        ordered: list[HuntStrategy] = []
        for strategy in strategies:
            if strategy not in ordered:
                ordered.append(strategy)
        return ordered

    def _prioritize_findings(self, findings: list[RawFinding]) -> list[RawFinding]:
        severity_rank = {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }
        confidence_rank = {Confidence.HIGH: 3, Confidence.MEDIUM: 2, Confidence.LOW: 1}
        return sorted(
            findings,
            key=lambda finding: (
                severity_rank.get(finding.estimated_severity, 0),
                confidence_rank.get(finding.confidence, 0),
            ),
            reverse=True,
        )

    def _prover_cap(self) -> int:
        defaults = {
            DepthProfile.QUICK: 10,
            DepthProfile.STANDARD: 30,
            DepthProfile.THOROUGH: 10_000,
        }
        default_cap = defaults[self._depth_profile()]
        if self.input.max_provers is None:
            return default_cap
        return max(0, min(self.input.max_provers, default_cap))

    def _check_time_budget(self) -> None:
        if self.max_duration_seconds is None:
            return
        elapsed = time.monotonic() - self.started_at
        if elapsed > self.max_duration_seconds:
            self.budget_exhausted = True
            raise BudgetExhausted("Duration budget exhausted")

    def _phase_budget_limit(self, phase: str) -> float | None:
        if self.max_cost_usd is None:
            return None
        return self.max_cost_usd * self._PHASE_BUDGETS[phase]

    def _check_cost_budget(self, phase: str) -> None:
        if self.max_cost_usd is not None and self.total_cost_usd >= self.max_cost_usd:
            self.budget_exhausted = True
            raise BudgetExhausted("Total budget exhausted")

        phase_limit = self._phase_budget_limit(phase)
        if phase_limit is not None and self.cost_breakdown[phase] >= phase_limit:
            self.budget_exhausted = True
            raise BudgetExhausted(f"{phase} budget exhausted")

    def _budget_or_timeout_exhausted(self, phase: str) -> bool:
        try:
            self._check_time_budget()
            self._check_cost_budget(phase)
            return False
        except BudgetExhausted:
            return True

    def _register_cost(self, phase: str, cost_usd: float | None) -> None:
        if cost_usd is None or cost_usd < 0:
            return
        self.total_cost_usd += cost_usd
        self.cost_breakdown[phase] += cost_usd

    def _emit_progress(self, *, phase: str, agents_total: int, agents_completed: int, findings_so_far: int) -> None:
        elapsed = time.monotonic() - self.started_at
        safe_total = max(1, agents_total)
        phase_progress = min(1.0, agents_completed / safe_total)
        estimated_total = elapsed / phase_progress if phase_progress > 0 else elapsed
        progress = AuditProgress(
            phase=phase,
            phase_progress=phase_progress,
            agents_total=agents_total,
            agents_completed=agents_completed,
            agents_running=max(0, agents_total - agents_completed),
            findings_so_far=findings_so_far,
            elapsed_seconds=elapsed,
            estimated_remaining_seconds=max(0.0, estimated_total - elapsed),
            cost_so_far_usd=round(self.total_cost_usd, 4),
        )
        self.app.note(progress.model_dump_json(), tags=["audit", "progress", phase])

    def _track_drop(self, *, finding_title: str, original_verdict: str | None, reason: str) -> None:
        self.prove_drop_summary["demoted_total"] = int(self.prove_drop_summary.get("demoted_total", 0)) + 1
        by_reason = cast("dict[str, int]", self.prove_drop_summary.setdefault("by_reason", {}))
        by_reason[reason] = by_reason.get(reason, 0) + 1
        findings = cast("list[dict[str, str | None]]", self.prove_drop_summary.setdefault("findings", []))
        findings.append(
            {
                "title": finding_title,
                "original_verdict": original_verdict,
                "reason": reason,
            }
        )
        self.app.note(
            f"Demoted finding '{finding_title}' (verdict={original_verdict or 'unknown'}): {reason}",
            tags=["audit", "prove", "drop"],
        )


def _verified_finding_fallback(finding: RawFinding) -> VerifiedFinding:
    return VerifiedFinding(
        id=finding.id,
        fingerprint=finding.fingerprint,
        title=finding.title,
        description=finding.description,
        finding_type=finding.finding_type,
        cwe_id=finding.cwe_id,
        cwe_name=finding.cwe_name,
        owasp_category=finding.owasp_category,
        tags=[],
        verdict=Verdict.INCONCLUSIVE,
        evidence_level=EvidenceLevel.STATIC_MATCH,
        rationale="Automated proof unavailable; requires manual review.",
        severity=finding.estimated_severity,
        exploitability_score=0.0,
        location=Location(
            file_path=finding.file_path,
            start_line=finding.start_line,
            end_line=finding.end_line,
            function_name=finding.function_name,
            code_snippet=finding.code_snippet,
        ),
        sarif_rule_id=f"sec-af/{finding.finding_type.value}/{finding.cwe_id.lower()}",
        sarif_security_severity=0.0,
    )


def merge_recon_findings_into_hunt(hunt: HuntResult, recon_findings: list[RawFinding]) -> HuntResult:
    if not recon_findings:
        return hunt

    merged_findings = [*recon_findings, *hunt.findings]
    strategies_run = list(hunt.strategies_run)
    if "recon" not in strategies_run:
        strategies_run.insert(0, "recon")

    return HuntResult(
        findings=merged_findings,
        chains=hunt.chains,
        total_raw=hunt.total_raw + len(recon_findings),
        deduplicated_count=len(merged_findings),
        chain_count=hunt.chain_count,
        strategies_run=strategies_run,
        hunt_duration_seconds=hunt.hunt_duration_seconds,
    )
