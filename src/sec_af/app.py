"""Agent entry point scaffold from DESIGN.md §1 and §2.3."""

from __future__ import annotations

import os
from typing import Any, cast

from fastapi import HTTPException

from agentfield import Agent, AgentRouter

from .orchestrator import AuditOrchestrator
from .schemas.input import AuditInput  # noqa: TC001

app = Agent(
    node_id="sec-af",
    version="0.1.0",
    description="AI-Native Security Analysis and Red-Teaming Agent",
    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
    api_key=os.getenv("AGENTFIELD_API_KEY"),
)

router = AgentRouter(tags=["security", "audit", "red-team"])


@router.reasoner()
async def audit(input: AuditInput) -> dict[str, object]:
    orchestrator = AuditOrchestrator(app=app, input=input)
    resume_phase = getattr(input, "resume_from_checkpoint", None)
    try:
        if isinstance(resume_phase, str) and resume_phase.strip():
            result = await orchestrator.run_from_checkpoint(resume_phase)
        else:
            result = await orchestrator.run()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
    except Exception as exc:
        cast("Any", app).note(f"Audit pipeline failed: {exc}", tags=["audit", "error"])
        raise HTTPException(status_code=500, detail={"error": "audit execution failed"}) from exc

    return result.model_dump()


async def health() -> dict[str, str]:
    return {"status": "healthy", "version": "0.1.0"}


cast("Any", app).add_api_route("/health", health, methods=["GET"])


app.include_router(router)


def main() -> None:
    """Entry point for the SEC-AF agent."""
    app.run(port=8003, host="0.0.0.0")


if __name__ == "__main__":
    main()
