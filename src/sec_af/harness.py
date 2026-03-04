from __future__ import annotations

import asyncio
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from pydantic import BaseModel

from .config import AIIntegrationConfig
from .schemas.gates import DuplicateCheck, SeverityClassification, StrategySelection

if TYPE_CHECKING:
    from agentfield import Agent

SchemaT = TypeVar("SchemaT", bound=BaseModel)

_TRANSIENT_PATTERNS = (
    "rate limit",
    "rate_limit",
    "overloaded",
    "timeout",
    "timed out",
    "connection reset",
    "connection refused",
    "temporarily unavailable",
    "service unavailable",
    "503",
    "502",
    "504",
    "internal server error",
    "500",
)


class AIIntegrationError(RuntimeError):
    pass


def _is_transient_error(error: str) -> bool:
    lowered = error.lower()
    return any(pattern in lowered for pattern in _TRANSIENT_PATTERNS)


def _with_multi_turn_prompt(prompt: str) -> str:
    return (
        f"{prompt.rstrip()}\n\n"
        "IMPORTANT: This is a complex task. Take multiple turns. "
        "Explore first, gather evidence, build analysis incrementally, and write final JSON only when complete."
    )


def _with_file_write_hint(prompt: str, cwd: str) -> str:
    output_path = Path(cwd) / ".agentfield_output.json"
    return (
        f"{prompt.rstrip()}\n"
        f"If output is large or complex, use the file-write pattern and ensure final JSON is written to {output_path}."
    )


class _RetryMixin:
    async def _run_with_retry(
        self,
        operation: Any,
        config: AIIntegrationConfig,
    ) -> Any:
        last_error: Exception | None = None
        for attempt in range(config.max_retries + 1):
            try:
                return await operation()
            except Exception as exc:
                last_error = exc
                if attempt >= config.max_retries or not _is_transient_error(str(exc)):
                    raise
                await asyncio.sleep(
                    min(
                        config.initial_backoff_seconds * (2**attempt),
                        config.max_backoff_seconds,
                    )
                )

        if last_error is not None:
            raise last_error
        raise AIIntegrationError("AI operation failed without an error payload")


@dataclass
class _CostTracker:
    total_cost_usd: float = 0.0
    invocation_count: int = 0

    def register_invocation(self) -> None:
        self.invocation_count += 1

    def register_cost(self, cost_usd: float | None) -> None:
        if cost_usd is None or cost_usd < 0:
            return
        self.total_cost_usd += cost_usd


class HarnessWrapper(_RetryMixin, Generic[SchemaT]):
    def __init__(self, app: Agent, config: AIIntegrationConfig | None = None):
        self.app = cast("Any", app)
        self.config = config or AIIntegrationConfig.from_env()
        self._cost_tracker = _CostTracker()

    @property
    def total_cost_usd(self) -> float:
        return self._cost_tracker.total_cost_usd

    @property
    def invocation_count(self) -> int:
        return self._cost_tracker.invocation_count

    async def invoke(
        self,
        *,
        prompt: str,
        schema: type[SchemaT],
        cwd: str,
        project_dir: str | None = None,
        model: str | None = None,
        max_turns: int | None = None,
        max_budget_usd: float | None = None,
        phase: str | None = None,
    ) -> SchemaT:
        self._cost_tracker.register_invocation()
        enhanced_prompt = _with_file_write_hint(_with_multi_turn_prompt(prompt), cwd)

        async def _operation() -> Any:
            extra_kwargs: dict[str, Any] = {}
            if self.config.opencode_server:
                extra_kwargs["opencode_server"] = self.config.opencode_server
            if project_dir:
                extra_kwargs["project_dir"] = project_dir
            return await self.app.harness(
                enhanced_prompt,
                schema=schema,
                cwd=cwd,
                provider=self.config.provider,
                model=model or self.config.harness_model,
                max_turns=max_turns or self.config.max_turns,
                max_budget_usd=max_budget_usd,
                env=self.config.provider_env(),
                **extra_kwargs,
            )

        result = await self._run_with_retry(_operation, self.config)
        self._cost_tracker.register_cost(getattr(result, "cost_usd", None))

        if getattr(result, "is_error", False):
            message = getattr(result, "error_message", "unknown harness error")
            raise AIIntegrationError(f"Harness failure{f' ({phase})' if phase else ''}: {message}")

        parsed = getattr(result, "parsed", None)
        if isinstance(parsed, schema):
            return parsed
        if isinstance(parsed, dict):
            return schema(**parsed)
        if isinstance(result, schema):
            return result
        raise AIIntegrationError(f"Harness returned invalid payload for schema {schema.__name__}")

    async def invoke_batch(
        self,
        requests: list[dict[str, Any]],
        *,
        max_concurrent: int | None = None,
    ) -> list[SchemaT | BaseException]:
        semaphore = asyncio.Semaphore(max_concurrent) if max_concurrent else None

        async def _run_request(request: dict[str, Any]) -> SchemaT:
            if semaphore is None:
                return await self.invoke(**request)
            async with semaphore:
                return await self.invoke(**request)

        tasks = [_run_request(request) for request in requests]
        return await asyncio.gather(*tasks, return_exceptions=True)

    async def run_recon_analysis(
        self, *, prompt: str, schema: type[SchemaT], cwd: str, project_dir: str | None = None
    ) -> SchemaT:
        return await self.invoke(prompt=prompt, schema=schema, cwd=cwd, project_dir=project_dir, phase="recon")

    async def run_hunt_analysis(
        self, *, prompt: str, schema: type[SchemaT], cwd: str, project_dir: str | None = None
    ) -> SchemaT:
        return await self.invoke(prompt=prompt, schema=schema, cwd=cwd, project_dir=project_dir, phase="hunt")

    async def run_prove_analysis(
        self, *, prompt: str, schema: type[SchemaT], cwd: str, project_dir: str | None = None
    ) -> SchemaT:
        return await self.invoke(prompt=prompt, schema=schema, cwd=cwd, project_dir=project_dir, phase="prove")


class AIGateWrapper(_RetryMixin):
    def __init__(self, app: Agent, config: AIIntegrationConfig | None = None):
        self.app = cast("Any", app)
        self.config = config or AIIntegrationConfig.from_env()
        self._cost_tracker = _CostTracker()

    @property
    def total_cost_usd(self) -> float:
        return self._cost_tracker.total_cost_usd

    @property
    def invocation_count(self) -> int:
        return self._cost_tracker.invocation_count

    async def invoke(self, *, user: str, schema: type[SchemaT], system: str | None = None) -> SchemaT:
        self._cost_tracker.register_invocation()

        async def _operation() -> Any:
            return await self.app.ai(
                system=system,
                user=user,
                schema=schema,
                model=self.config.ai_model,
            )

        result = await self._run_with_retry(_operation, self.config)
        self._cost_tracker.register_cost(getattr(result, "cost_usd", None))

        if isinstance(result, schema):
            return result
        if isinstance(result, dict):
            return schema(**result)
        raise AIIntegrationError(f"AI gate returned invalid payload for schema {schema.__name__}")

    async def classify_severity(self, finding_summary: str) -> SeverityClassification:
        prompt = (
            "Classify severity for this potential security finding. "
            "Use only critical/high/medium/low and keep rationale brief.\n\n"
            f"{finding_summary}"
        )
        return await self.invoke(user=prompt, schema=SeverityClassification)

    async def check_duplicate(self, candidate: dict[str, Any], existing: dict[str, Any]) -> DuplicateCheck:
        prompt = (
            "Decide whether candidate finding is a duplicate of existing finding. "
            "Return duplicate decision only.\n\n"
            f"Candidate: {candidate}\n"
            f"Existing: {existing}"
        )
        return await self.invoke(user=prompt, schema=DuplicateCheck)

    async def select_strategy(
        self,
        *,
        recon_summary: str,
        depth: str,
        default_candidates: list[str],
    ) -> StrategySelection:
        prompt = (
            "Select SEC-AF hunt strategies from recon context. Return only selected strategies and rationale.\n"
            f"Depth profile: {depth}\n"
            f"Default candidates: {default_candidates}\n"
            f"Recon summary: {recon_summary}"
        )
        return await self.invoke(user=prompt, schema=StrategySelection)


def build_ai_integration(
    app: Agent, config: AIIntegrationConfig | None = None
) -> tuple[HarnessWrapper[Any], AIGateWrapper]:
    resolved = config or AIIntegrationConfig.from_env()
    return HarnessWrapper(app=app, config=resolved), AIGateWrapper(app=app, config=resolved)
