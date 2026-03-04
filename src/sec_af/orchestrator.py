from __future__ import annotations

import json
import os
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, TypeVar, cast

from agentfield import Agent  # noqa: TC001
from pydantic import BaseModel

from .config import DepthProfile
from .schemas.gates import StrategySelection
from .schemas.hunt import Confidence, HuntResult, HuntStrategy, RawFinding, Severity
from .schemas.input import AuditInput  # noqa: TC001
from .schemas.output import AttackChain, AuditProgress, SecurityAuditResult
from .schemas.prove import EvidenceLevel, Location, Verdict, VerifiedFinding
from .schemas.recon import (
    ArchitectureMap,
    ConfigReport,
    DataFlowMap,
    DependencyReport,
    ReconResult,
    SecurityContext,
)

SchemaT = TypeVar("SchemaT", bound=BaseModel)


class BudgetExhausted(RuntimeError):  # noqa: N818
    pass


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

    async def run(self) -> SecurityAuditResult:
        self.app.note("Starting SEC-AF orchestrator", tags=["audit", "start"])
        recon = await self._run_recon()
        self._write_checkpoint("recon", recon)

        hunt = await self._run_hunt(recon)
        self._write_checkpoint("hunt", hunt)

        verified = await self._run_prove(recon, hunt)
        self._write_checkpoint("prove", verified)

        result = self._generate_output(recon=recon, hunt=hunt, verified=verified)
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

        return self._generate_output(recon=recon, hunt=hunt, verified=verified)

    async def _run_recon(self) -> ReconResult:
        self.app.note("Phase: RECON", tags=["audit", "recon"])
        started = time.monotonic()
        depth = self._depth_profile()

        jobs: list[tuple[str, str, type[BaseModel]]] = [
            (
                "architecture",
                "Map architecture, entry points, trust boundaries, and API surface.",
                ArchitectureMap,
            ),
            (
                "dependencies",
                "Audit dependencies, build SBOM, and enumerate CVEs.",
                DependencyReport,
            ),
            (
                "config",
                "Scan configuration and secrets for security issues.",
                ConfigReport,
            ),
        ]
        if depth != DepthProfile.QUICK:
            jobs.extend(
                [
                    (
                        "data_flows",
                        "Trace user-controlled data from source to sink.",
                        DataFlowMap,
                    ),
                    (
                        "security_context",
                        "Profile auth model, crypto usage, and framework security features.",
                        SecurityContext,
                    ),
                ]
            )

        results: dict[str, BaseModel] = {}
        for index, (name, task, schema) in enumerate(jobs, start=1):
            if self._budget_or_timeout_exhausted("recon"):
                break
            prompt = (
                "ROLE: SEC-AF RECON analyst\n"
                f"TARGET: {self.input.repo_url}@{self.input.branch}\n"
                f"TASK: {task}\n"
                "OUTPUT: Return valid JSON matching the provided schema."
            )
            parsed = await self._run_harness(prompt=prompt, schema=schema, phase="recon")
            if parsed is not None:
                results[name] = parsed
            self._emit_progress(
                phase="recon",
                agents_total=len(jobs),
                agents_completed=index,
                findings_so_far=0,
            )

        architecture = cast("ArchitectureMap", results.get("architecture") or ArchitectureMap())
        dependencies = cast(
            "DependencyReport",
            results.get("dependencies") or DependencyReport(direct_count=0, transitive_count=0),
        )
        config = cast("ConfigReport", results.get("config") or ConfigReport())
        data_flows = cast("DataFlowMap", results.get("data_flows") or DataFlowMap())
        security_context = cast(
            "SecurityContext",
            results.get("security_context") or SecurityContext(auth_model="unknown", auth_details="unknown"),
        )

        recon = ReconResult(
            architecture=architecture,
            data_flows=data_flows,
            dependencies=dependencies,
            config=config,
            security_context=security_context,
            recon_duration_seconds=time.monotonic() - started,
        )
        recon.languages = sorted({module.language.lower() for module in recon.architecture.modules if module.language})
        recon.frameworks = sorted({framework for framework in recon.security_context.framework_security if framework})
        return recon

    async def _run_hunt(self, recon: ReconResult) -> HuntResult:
        self.app.note("Phase: HUNT", tags=["audit", "hunt"])
        started = time.monotonic()
        selection = await self._select_strategies(recon)
        strategy_names = [name for name in selection.strategies if name]
        if not strategy_names:
            strategy_names = [strategy.value for strategy in self._default_strategies(recon)]

        collected: list[RawFinding] = []
        for index, strategy_name in enumerate(strategy_names, start=1):
            if self._budget_or_timeout_exhausted("hunt"):
                break
            prompt = (
                "ROLE: SEC-AF HUNT specialist\n"
                f"TARGET: {self.input.repo_url}@{self.input.branch}\n"
                f"STRATEGY: {strategy_name}\n"
                "TASK: Discover potential vulnerabilities for this strategy.\n"
                f"RECON: {recon.model_dump_json()}"
            )
            hunt_result = await self._run_harness(prompt=prompt, schema=HuntResult, phase="hunt")
            if hunt_result is not None:
                collected.extend(hunt_result.findings)
            self._emit_progress(
                phase="hunt",
                agents_total=len(strategy_names),
                agents_completed=index,
                findings_so_far=len(collected),
            )

        deduped = HuntResult(findings=collected)
        if not self._budget_or_timeout_exhausted("hunt"):
            dedup_prompt = (
                "ROLE: SEC-AF dedup/correlation analyst\n"
                "TASK: Deduplicate findings and correlate attack chains.\n"
                f"RAW_FINDINGS: {json.dumps([finding.model_dump() for finding in collected])}"
            )
            dedup_result = await self._run_harness(prompt=dedup_prompt, schema=HuntResult, phase="hunt")
            if dedup_result is not None:
                deduped = dedup_result

        deduped.total_raw = len(collected)
        deduped.deduplicated_count = len(deduped.findings)
        deduped.chain_count = len(deduped.chains)
        deduped.strategies_run = strategy_names
        deduped.hunt_duration_seconds = time.monotonic() - started
        return deduped

    async def _run_prove(self, recon: ReconResult, hunt: HuntResult) -> list[VerifiedFinding]:
        self.app.note("Phase: PROVE", tags=["audit", "prove"])
        prioritized = self._prioritize_findings(hunt.findings)
        prover_cap = self._prover_cap()
        targets = prioritized[:prover_cap]
        self.findings_not_verified = max(0, len(hunt.findings) - len(targets))

        verified: list[VerifiedFinding] = []
        total_agents = max(1, len(targets))
        for index, finding in enumerate(targets, start=1):
            if self._budget_or_timeout_exhausted("prove"):
                self.findings_not_verified += len(targets) - (index - 1)
                break
            prompt = (
                "ROLE: SEC-AF adversarial prover\n"
                "TASK: determine exploitability and return a VerifiedFinding.\n"
                f"RECON: {recon.model_dump_json()}\n"
                f"FINDING: {finding.model_dump_json()}"
            )
            proved = await self._run_harness(prompt=prompt, schema=VerifiedFinding, phase="prove")
            verified.append(proved if proved is not None else _verified_finding_fallback(finding))
            self._emit_progress(
                phase="prove",
                agents_total=total_agents,
                agents_completed=index,
                findings_so_far=len(verified),
            )

        return verified

    def _generate_output(
        self,
        *,
        recon: ReconResult,
        hunt: HuntResult,
        verified: list[VerifiedFinding],
    ) -> SecurityAuditResult:
        _ = recon
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

        return SecurityAuditResult(
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
            compliance_gaps=[],
            duration_seconds=time.monotonic() - self.started_at,
            agent_invocations=self.agent_invocations,
            cost_usd=round(self.total_cost_usd, 4),
            cost_breakdown={phase: round(cost, 4) for phase, cost in self.cost_breakdown.items()},
            sarif=self._render_sarif(verified),
        )

    async def _select_strategies(self, recon: ReconResult) -> StrategySelection:
        defaults = [strategy.value for strategy in self._default_strategies(recon)]
        prompt = (
            "Select SEC-AF hunt strategies from recon context.\n"
            "Return StrategySelection with flat fields only.\n"
            f"Depth: {self.input.depth}\n"
            f"Default candidates: {defaults}\n"
            f"Recon summary: {recon.model_dump_json()}"
        )
        try:
            result = await self.app.ai(user=prompt, schema=StrategySelection)
        except Exception as exc:
            self.app.note(f"Strategy selection fallback: {exc}", tags=["audit", "hunt", "ai", "fallback"])
            return StrategySelection(strategies=defaults, rationale="fallback")

        if isinstance(result, StrategySelection):
            parsed = result
        elif isinstance(result, dict):
            parsed = StrategySelection(**result)
        else:
            parsed = StrategySelection(strategies=defaults, rationale="fallback")

        selected = [name for name in parsed.strategies if name]
        return StrategySelection(strategies=selected or defaults, rationale=parsed.rationale)

    async def _run_harness(
        self,
        *,
        prompt: str,
        schema: type[SchemaT],
        phase: str,
    ) -> SchemaT | None:
        try:
            result = await self.app.harness(
                prompt,
                schema=schema,
                cwd=str(self.repo_path),
                max_budget_usd=self._phase_budget_limit(phase),
            )
        except Exception as exc:
            self.app.note(f"Harness call failed: {exc}", tags=["audit", phase, "harness", "error"])
            return None

        self.agent_invocations += 1
        self._register_cost(phase, getattr(result, "cost_usd", None))

        if getattr(result, "is_error", False):
            message = getattr(result, "error_message", "unknown")
            self.app.note(
                f"Harness returned error for {schema.__name__}: {message}",
                tags=["audit", phase, "harness", "error"],
            )
            return None

        parsed = getattr(result, "parsed", None)
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            try:
                return schema(**parsed)
            except Exception:
                return None
        if isinstance(result, schema):
            return result
        return None

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

    def _render_sarif(self, findings: list[VerifiedFinding]) -> str:
        rules: dict[str, dict[str, Any]] = {}
        results: list[dict[str, Any]] = []

        for finding in findings:
            if finding.sarif_rule_id not in rules:
                rules[finding.sarif_rule_id] = {
                    "id": finding.sarif_rule_id,
                    "name": finding.title,
                    "shortDescription": {"text": finding.title},
                    "fullDescription": {"text": finding.description},
                    "properties": {
                        "security-severity": str(finding.sarif_security_severity),
                        "tags": [finding.cwe_id],
                    },
                }

            location = finding.location
            results.append(
                {
                    "ruleId": finding.sarif_rule_id,
                    "level": self._sarif_level(finding.severity),
                    "message": {
                        "text": f"[{finding.verdict.value.upper()}] {finding.title}: {finding.rationale}",
                    },
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": location.file_path},
                                "region": {
                                    "startLine": location.start_line,
                                    "endLine": location.end_line,
                                },
                            }
                        }
                    ],
                }
            )

        payload = {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "SEC-AF",
                            "semanticVersion": "0.1.0",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        return json.dumps(payload)

    def _sarif_level(self, severity: Severity) -> str:
        if severity in {Severity.CRITICAL, Severity.HIGH}:
            return "error"
        if severity == Severity.MEDIUM:
            return "warning"
        return "note"


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
        tags=set(),
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
