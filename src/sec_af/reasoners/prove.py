from __future__ import annotations

from typing import Any

from sec_af.agents.prove.verifier import run_verifier as _run_verifier
from sec_af.schemas.hunt import RawFinding

from . import router


@router.reasoner()
async def run_verifier(repo_path: str, finding: dict[str, Any], depth: str) -> dict[str, Any]:
    runtime_router: Any = router
    runtime_router.note("Verifier starting", tags=["prove", "verifier"])
    finding_model = RawFinding(**finding)
    result = await _run_verifier(runtime_router, repo_path, finding_model, depth)
    return result.model_dump()
