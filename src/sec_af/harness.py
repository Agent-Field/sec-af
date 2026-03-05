from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Generic, TypeVar, cast

from pydantic import BaseModel

from .config import AIIntegrationConfig
from .schemas.gates import DuplicateCheck, ReachabilityGate, SeverityClassification, StrategySelection

if TYPE_CHECKING:
    from agentfield import Agent

SchemaT = TypeVar("SchemaT", bound=BaseModel)

logger = logging.getLogger(__name__)

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


PHASE_GUIDANCE: dict[str, str] = {
    "recon": ("Survey -> Identify -> Map -> Synthesize. Report what IS present, not what MIGHT be present."),
    "hunt": (
        "Review context -> Identify relevant files -> Trace data flow -> Report with evidence. "
        "False negatives are better than false positives. "
        "Every finding MUST cite specific file paths and line numbers."
    ),
    "prove": (
        "Read actual code -> Trace flow -> Check sanitization -> Construct exploit -> Verdict. "
        "INCONCLUSIVE is a valid outcome. "
        "You MUST read the actual code and not rely on descriptions alone."
    ),
}


def _schema_guidance(schema: type[SchemaT]) -> str:
    field_lines: list[str] = []
    for field_name, field in schema.model_fields.items():
        description = (field.description or "").strip()
        if description:
            field_lines.append(f"- `{field_name}`: {description}")

    if not field_lines:
        return (
            "Output format:\n"
            "- Return valid JSON only (no markdown fences, no extra text).\n"
            "- Follow the provided Pydantic schema exactly."
        )

    return (
        "Output format:\n"
        "- Return valid JSON only (no markdown fences, no extra text).\n"
        "- Follow the provided Pydantic schema exactly.\n"
        "- Field guidance from schema descriptions:\n"
        f"{'\n'.join(field_lines)}"
    )


def _with_phase_guidance(prompt: str, phase: str | None, cwd: str) -> str:
    normalized_phase = (phase or "").strip().lower()
    phase_context = PHASE_GUIDANCE.get(
        normalized_phase,
        "Build conclusions from repository evidence in iterative passes. "
        "Prefer explicit evidence over speculation, and clearly separate confirmed facts from uncertainty.",
    )

    constraints = _with_file_write_hint(
        (
            "Constraints:\n"
            "- Use evidence-first reasoning; do not speculate beyond available artifacts.\n"
            "- Keep analysis bounded to the task scope and produce only schema-conformant output.\n"
            "- Cite concrete repository evidence whenever making security-relevant claims."
        ),
        cwd,
    )

    return (
        f"Context:\n- {phase_context}\n\n"
        f"{constraints}\n\n"
        f"Task:\n{prompt.rstrip()}\n\n"
        "Output:\n"
        "- Return a single JSON object matching the requested schema."
    )


def _with_file_write_hint(prompt: str, cwd: str) -> str:
    output_path = Path(cwd) / ".agentfield_output.json"
    return (
        f"{prompt.rstrip()}\n"
        f"- If output is large or complex, use the file-write pattern and ensure final JSON is written to {output_path}."
    )


def _build_schema_retry_prompt(schema: type[SchemaT], error_detail: str, cwd: str) -> str:
    """Build a retry prompt that includes the full schema JSON definition.

    This ensures the model can see exactly what schema it needs to conform to,
    improving retry success rates when schema validation fails.
    """
    output_path = Path(cwd) / ".agentfield_output.json"

    # Get the JSON schema from the Pydantic model
    schema_json = schema.model_json_schema()
    schema_json_str = json.dumps(schema_json, indent=2)

    return (
        f"The JSON output at {output_path} failed validation.\n"
        f"Error: {error_detail}\n\n"
        f"Your response must conform to this JSON schema:\n"
        f"```json\n{schema_json_str}\n```\n\n"
        f"Rewrite the COMPLETE, corrected JSON to: {output_path}\n"
        f"The file must contain ONLY valid JSON matching the schema above. "
        f"No markdown fences, no extra text, no comments."
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

    async def _invoke_with_schema_retry(
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
        retry_count: int = 0,
    ) -> SchemaT:
        """Retry harness invocation with schema context included in the retry prompt."""
        max_schema_retries = 3

        if retry_count >= max_schema_retries:
            raise AIIntegrationError(f"Schema validation failed after {max_schema_retries} retries with schema context")

        error_detail = f"Retry attempt {retry_count + 1}/{max_schema_retries}"
        retry_task = _build_schema_retry_prompt(schema, error_detail, cwd)
        retry_prompt = f"{_with_phase_guidance(retry_task, phase, cwd)}\n\n{_schema_guidance(schema)}"

        logger.info(
            "Schema validation retry %d/%d with schema context",
            retry_count + 1,
            max_schema_retries,
        )

        async def _retry_operation() -> Any:
            extra_kwargs: dict[str, Any] = {}
            if self.config.opencode_server:
                extra_kwargs["opencode_server"] = self.config.opencode_server
            if project_dir:
                extra_kwargs["project_dir"] = project_dir
            return await self.app.harness(
                retry_prompt,
                schema=schema,
                cwd=cwd,
                provider=self.config.provider,
                model=model or self.config.harness_model,
                max_turns=max_turns or self.config.max_turns,
                max_budget_usd=max_budget_usd,
                env=self.config.provider_env(),
                schema_max_retries=0,
                **extra_kwargs,
            )

        result = await self._run_with_retry(_retry_operation, self.config)
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

        if not parsed:
            return await self._invoke_with_schema_retry(
                prompt=prompt,
                schema=schema,
                cwd=cwd,
                project_dir=project_dir,
                model=model,
                max_turns=max_turns,
                max_budget_usd=max_budget_usd,
                phase=phase,
                retry_count=retry_count + 1,
            )

        raise AIIntegrationError(f"Harness returned invalid payload for schema {schema.__name__}")

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
        enhanced_prompt = f"{_with_phase_guidance(prompt, phase, cwd)}\n\n{_schema_guidance(schema)}"

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
                schema_max_retries=0,
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

        if not parsed and not getattr(result, "is_error", False):
            return await self._invoke_with_schema_retry(
                prompt=enhanced_prompt,
                schema=schema,
                cwd=cwd,
                project_dir=project_dir,
                model=model,
                max_turns=max_turns,
                max_budget_usd=max_budget_usd,
                phase=phase,
            )

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

    async def assess_reachability(self, finding_summary: str) -> ReachabilityGate:
        prompt = (
            "Assess the reachability of this security finding. "
            "Determine if it is externally_reachable, requires_auth, internal_only, or unreachable. "
            "Consider the attack surface, authentication requirements, and network exposure.\n\n"
            f"{finding_summary}"
        )
        return await self.invoke(user=prompt, schema=ReachabilityGate)


def build_ai_integration(
    app: Agent, config: AIIntegrationConfig | None = None
) -> tuple[HarnessWrapper[Any], AIGateWrapper]:
    resolved = config or AIIntegrationConfig.from_env()
    return HarnessWrapper(app=app, config=resolved), AIGateWrapper(app=app, config=resolved)
