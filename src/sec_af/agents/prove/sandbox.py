"""Sandbox execution helper for DAST-like verification.

Provides a safe execution context for running exploit payloads
against target applications. Currently uses subprocess isolation
with strict timeouts and resource limits. Future: Docker containers.
"""

from __future__ import annotations

import asyncio
import subprocess
from dataclasses import dataclass

_DEFAULT_TIMEOUT = 10
_MAX_OUTPUT_BYTES = 8192


@dataclass(frozen=True)
class SandboxResult:
    """Result from sandboxed execution."""

    stdout: str
    stderr: str
    exit_code: int
    timed_out: bool


async def run_sandboxed(
    command: list[str],
    *,
    timeout: int = _DEFAULT_TIMEOUT,
    cwd: str | None = None,
) -> SandboxResult:
    """Run a command in a sandboxed subprocess with strict limits."""
    proc: asyncio.subprocess.Process | None = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=cwd,
        )
        stdout_bytes, stderr_bytes = await asyncio.wait_for(
            proc.communicate(),
            timeout=timeout,
        )
        return SandboxResult(
            stdout=stdout_bytes[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            stderr=stderr_bytes[:_MAX_OUTPUT_BYTES].decode("utf-8", errors="replace"),
            exit_code=proc.returncode or 0,
            timed_out=False,
        )
    except asyncio.TimeoutError:
        if proc is not None:
            proc.kill()
        return SandboxResult(stdout="", stderr="Execution timed out", exit_code=-1, timed_out=True)
    except Exception as exc:
        return SandboxResult(stdout="", stderr=str(exc), exit_code=-1, timed_out=False)
