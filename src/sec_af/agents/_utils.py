from __future__ import annotations

from typing import TypeVar

from pydantic import BaseModel

T = TypeVar("T", bound=BaseModel)


def extract_harness_result(result: object, schema: type[T], agent_name: str) -> T:
    is_error = bool(getattr(result, "is_error", False))
    if is_error:
        error_message = getattr(result, "error_message", None)
        result_text = getattr(result, "result", None)
        num_turns = getattr(result, "num_turns", "?")
        duration_ms = getattr(result, "duration_ms", "?")
        print(
            f"[{agent_name}] HARNESS ERROR: {error_message}\n"
            f"  turns={num_turns}, duration_ms={duration_ms}\n"
            f"  result_text={str(result_text)[:500] if result_text else None}",
            flush=True,
        )
        raise RuntimeError(f"{agent_name} harness error: {error_message}")

    parsed = getattr(result, "parsed", None)
    if isinstance(parsed, schema):
        return parsed

    debug_message = (
        f"[{agent_name}] harness result type={type(result).__name__}, "
        + f"is_error={getattr(result, 'is_error', '?')}, "
        + f"parsed type={type(getattr(result, 'parsed', None)).__name__}"
    )

    if isinstance(parsed, dict):
        try:
            return schema.model_validate(parsed)
        except Exception:
            print(debug_message, flush=True)
            raise

    print(debug_message, flush=True)
    raise TypeError(f"{agent_name} did not return a valid {schema.__name__}")
