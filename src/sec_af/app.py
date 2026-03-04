"""Agent entry point scaffold from DESIGN.md §1 and §2.3."""

from __future__ import annotations

import os

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
    result = await orchestrator.run()
    return result.model_dump()


app.include_router(router)


def main() -> None:
    """Entry point for the SEC-AF agent."""
    app.run(port=8003, host="0.0.0.0")


if __name__ == "__main__":
    main()
