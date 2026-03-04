from __future__ import annotations

import asyncio
import importlib
import json
import os
from pathlib import Path
from typing import Any

from pydantic import BaseModel


class SimpleResponse(BaseModel):
    greeting: str
    number: int


def _print_header(title: str) -> None:
    print("\n" + "=" * 88)
    print(title)
    print("=" * 88)


def _preview_file(path: Path, max_chars: int = 500) -> str:
    if not path.exists():
        return "<missing>"
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "\n...<truncated>..."


async def _run_case(
    *,
    app: Any,
    case_name: str,
    prompt: str,
    schema: Any,
    cwd: str,
) -> None:
    schema_mod = importlib.import_module("agentfield.harness._schema")
    runner_mod = importlib.import_module("agentfield.harness._runner")
    runner_mod_any: Any = runner_mod

    output_path = Path(schema_mod.get_output_path(cwd))
    schema_path = Path(schema_mod.get_schema_path(cwd))
    output_path.unlink(missing_ok=True)
    schema_path.unlink(missing_ok=True)

    suffix = schema_mod.build_prompt_suffix(schema, cwd)
    effective_prompt = prompt + suffix

    _print_header(f"CASE: {case_name}")
    print(f"cwd arg: {cwd}")
    print(f"cwd realpath: {Path(cwd).resolve()}")
    print(f"output path (expected): {output_path}")
    print(f"schema path (large-schema fallback): {schema_path}")
    print(f"schema file pre-run exists: {schema_path.exists()}")
    print("\n--- FULL PROMPT SENT (prompt + OUTPUT REQUIREMENTS) ---")
    print(effective_prompt)
    print("--- END FULL PROMPT ---")

    cleanup_events: list[dict[str, Any]] = []
    original_cleanup = runner_mod_any.cleanup_temp_files

    def debug_cleanup(cwd_arg: str) -> None:
        event = {
            "cwd_arg": cwd_arg,
            "cwd_realpath": str(Path(cwd_arg).resolve()),
            "output_exists_before_cleanup": output_path.exists(),
            "output_size_before_cleanup": output_path.stat().st_size if output_path.exists() else None,
            "schema_exists_before_cleanup": schema_path.exists(),
            "schema_size_before_cleanup": schema_path.stat().st_size if schema_path.exists() else None,
            "output_preview_before_cleanup": _preview_file(output_path),
        }
        cleanup_events.append(event)
        print("\n[debug] cleanup_temp_files invoked with:")
        print(json.dumps(event, indent=2))
        original_cleanup(cwd_arg)

    runner_mod_any.cleanup_temp_files = debug_cleanup
    try:
        result = await app.harness(
            prompt,
            schema=schema,
            cwd=cwd,
        )
    finally:
        runner_mod_any.cleanup_temp_files = original_cleanup

    print("\n--- HARNESS RESULT ---")
    print(f"is_error: {result.is_error}")
    print(f"error_message: {result.error_message!r}")
    print(f"parsed_type: {type(result.parsed).__name__ if result.parsed is not None else None}")
    print(f"session_id: {result.session_id!r}")
    print(f"num_turns: {result.num_turns}")
    print(f"cost_usd: {result.cost_usd}")
    print(f"duration_ms: {result.duration_ms}")
    print(f"raw_result_preview: {(result.result or '')[:300]!r}")

    if result.parsed is not None:
        if hasattr(result.parsed, "model_dump"):
            parsed_data = result.parsed.model_dump()
        else:
            parsed_data = str(result.parsed)
        print("parsed preview:")
        print(json.dumps(parsed_data, indent=2)[:900])

    if result.messages:
        print(f"messages_count: {len(result.messages)}")
        print("last_message:")
        print(json.dumps(result.messages[-1], indent=2, default=str)[:1200])

    print("\n--- OUTPUT FILE STATE AFTER RUN RETURNS ---")
    print(f"output exists: {output_path.exists()}")
    print(f"schema exists: {schema_path.exists()}")
    if cleanup_events:
        print(f"cleanup events captured: {len(cleanup_events)}")
    else:
        print("cleanup events captured: 0")


async def main() -> None:
    agentfield_mod = importlib.import_module("agentfield")
    recon_mod = importlib.import_module("sec_af.schemas.recon")

    HarnessConfig = getattr(agentfield_mod, "HarnessConfig")
    Agent = getattr(agentfield_mod, "Agent")
    ArchitectureMap = getattr(recon_mod, "ArchitectureMap")
    ReconResult = getattr(recon_mod, "ReconResult")

    provider = os.getenv("HARNESS_PROVIDER", "claude-code")
    model = os.getenv("HARNESS_MODEL", "claude-sonnet-4-20250514")
    cwd = os.getenv("HARNESS_CWD", "/tmp/dvga")

    if not Path(cwd).exists():
        raise FileNotFoundError(f"HARNESS_CWD does not exist: {cwd}")

    os.environ.setdefault("HARNESS_PROVIDER", provider)
    os.environ.setdefault("HARNESS_MODEL", model)

    _print_header("HARNESS DEBUG CONFIG")
    print(f"provider: {provider}")
    print(f"model: {model}")
    print("permission_mode: auto")
    print(f"cwd: {cwd}")
    print(f"cwd realpath: {Path(cwd).resolve()}")

    config = HarnessConfig(
        provider=provider,
        model=model,
        permission_mode="auto",
    )
    app = Agent(node_id="harness-debug", harness_config=config, auto_register=False)

    simple_prompt = (
        'Return JSON with greeting="Hello from harness debug" and number=42. Follow the OUTPUT REQUIREMENTS exactly.'
    )
    await _run_case(
        app=app,
        case_name="simple-schema",
        prompt=simple_prompt,
        schema=SimpleResponse,
        cwd=cwd,
    )

    complex_prompt = (
        "Analyze repository architecture at high level and return an ArchitectureMap. "
        "Use realistic modules, services, trust boundaries, and API endpoints. "
        "Follow the OUTPUT REQUIREMENTS exactly."
    )
    await _run_case(
        app=app,
        case_name="complex-schema-ArchitectureMap",
        prompt=complex_prompt,
        schema=ArchitectureMap,
        cwd=cwd,
    )

    deep_prompt = (
        "Produce a full security recon result for this repository. "
        "Return a complete ReconResult JSON with architecture, data flows, dependencies, "
        "config findings, and security context. Keep content concise but valid. "
        "Follow the OUTPUT REQUIREMENTS exactly."
    )
    await _run_case(
        app=app,
        case_name="deeply-nested-schema-ReconResult",
        prompt=deep_prompt,
        schema=ReconResult,
        cwd=cwd,
    )


if __name__ == "__main__":
    asyncio.run(main())
