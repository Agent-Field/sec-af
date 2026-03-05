"""Agent entry point scaffold from DESIGN.md §1 and §2.3."""

from __future__ import annotations

# pyright: reportMissingImports=false

import os
import subprocess
import time
from pathlib import Path
from typing import Any, cast

import agentfield as _agentfield
from dotenv import load_dotenv

_project_root = Path(__file__).resolve().parents[2]
load_dotenv(_project_root / ".env")

from fastapi import HTTPException

from agentfield import Agent, AIConfig

from .config import AIIntegrationConfig
from .orchestrator import AuditOrchestrator
from .reasoners import router as reasoner_router
from .schemas.hunt import HuntResult
from .schemas.input import AuditInput  # noqa: TC001
from .schemas.prove import VerifiedFinding
from .schemas.recon import ReconResult

_ai_config = AIIntegrationConfig.from_env()
NODE_ID = os.getenv("NODE_ID", "sec-af")
HarnessConfig = getattr(_agentfield, "HarnessConfig")

app = Agent(
    node_id=NODE_ID,
    version="0.1.0",
    description="AI-Native Security Analysis and Red-Teaming Agent",
    agentfield_server=os.getenv("AGENTFIELD_SERVER", "http://localhost:8080"),
    callback_url=os.getenv("AGENT_CALLBACK_URL", "http://127.0.0.1:8003"),
    api_key=os.getenv("AGENTFIELD_API_KEY"),
    harness_config=HarnessConfig(
        provider=_ai_config.provider,
        model=_ai_config.harness_model,
        max_turns=_ai_config.max_turns,
        env=_ai_config.provider_env(),
        opencode_bin=_ai_config.opencode_bin,
        permission_mode="auto",
    ),
    ai_config=AIConfig(
        model=_ai_config.ai_model,
        api_key=os.getenv("OPENROUTER_API_KEY", ""),
        api_base="https://openrouter.ai/api/v1",
    ),
)


def _unwrap(result: object, name: str) -> object:
    if isinstance(result, dict):
        if "error" in result and isinstance(result["error"], dict):
            message = result["error"].get("message") or result["error"].get("detail") or str(result["error"])
            raise RuntimeError(f"{name} failed: {message}")
        if "output" in result:
            return result["output"]
        if "result" in result:
            return result["result"]
    return result


def _as_dict(payload: object, name: str) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise RuntimeError(f"{name} returned non-dict payload: {type(payload).__name__}")
    return payload


def _resolve_repo(repo_url: str) -> str:
    """Resolve repo_url to a local path, cloning from URL if needed."""
    # Local path — return as-is
    if os.path.isdir(repo_url):
        return str(Path(repo_url).resolve())

    # GitHub/HTTP URL — clone to /workspaces/
    if repo_url.startswith(("https://", "http://", "git@")):
        repo_name = repo_url.rstrip("/").split("/")[-1].replace(".git", "")
        target_dir = f"/workspaces/{repo_name}"
        os.makedirs("/workspaces", exist_ok=True)

        if os.path.isdir(target_dir):
            # Already cloned — pull latest
            subprocess.run(
                ["git", "pull", "--ff-only"],
                cwd=target_dir,
                env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"},
                timeout=60,
                capture_output=True,
            )
            return target_dir

        result = subprocess.run(
            ["git", "clone", "--depth", "1", repo_url, target_dir],
            env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GIT_ASKPASS": "echo"},
            timeout=120,
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(f"git clone failed: {result.stderr.strip()}")
        return target_dir

    # Fallback: treat as local path
    return str(Path(os.getenv("SEC_AF_REPO_PATH", os.getcwd())).resolve())


@app.reasoner()
async def audit(
    repo_url: str,
    depth: str = "standard",
    branch: str = "main",
    commit_sha: str | None = None,
    base_commit_sha: str | None = None,
    severity_threshold: str = "low",
    scan_types: list[str] | None = None,
    output_formats: list[str] | None = None,
    compliance_frameworks: list[str] | None = None,
    max_cost_usd: float | None = None,
    max_provers: int | None = None,
    max_duration_seconds: int | None = None,
    include_paths: list[str] | None = None,
    exclude_paths: list[str] | None = None,
    is_pr: bool = False,
    pr_id: str | None = None,
    post_pr_comments: bool = False,
    fail_on_findings: bool = False,
    resume_from_checkpoint: str | None = None,
) -> dict[str, object]:
    audit_input = AuditInput(
        repo_url=repo_url,
        depth=depth,
        branch=branch,
        commit_sha=commit_sha,
        base_commit_sha=base_commit_sha,
        severity_threshold=severity_threshold,
        scan_types=scan_types or ["sast", "sca", "secrets", "config"],
        output_formats=output_formats or ["json"],
        compliance_frameworks=compliance_frameworks or [],
        max_cost_usd=max_cost_usd,
        max_provers=max_provers,
        max_duration_seconds=max_duration_seconds,
        include_paths=include_paths,
        exclude_paths=exclude_paths or ["tests/", "vendor/", "node_modules/", ".git/"],
        is_pr=is_pr,
        pr_id=pr_id,
        post_pr_comments=post_pr_comments,
        fail_on_findings=fail_on_findings,
    )
    orchestrator = AuditOrchestrator(app=app, input=audit_input)
    repo_path = _resolve_repo(repo_url)
    orchestrator.repo_path = Path(repo_path)
    orchestrator.checkpoint_dir = orchestrator.repo_path / ".sec-af"
    try:
        if isinstance(resume_from_checkpoint, str) and resume_from_checkpoint.strip():
            result = await orchestrator.run_from_checkpoint(resume_from_checkpoint)
        else:
            app.note("Starting SEC-AF audit pipeline", tags=["audit", "start"])
            started = time.monotonic()

            recon_raw = await app.call(
                f"{NODE_ID}.recon_phase",
                repo_path=repo_path,
                depth=depth,
            )
            recon_dict = _as_dict(_unwrap(recon_raw, "recon_phase"), "recon_phase")
            recon = ReconResult.model_validate(recon_dict)
            recon.recon_duration_seconds = time.monotonic() - started
            orchestrator._write_checkpoint("recon", recon)

            hunt_raw = await app.call(
                f"{NODE_ID}.hunt_phase",
                repo_path=repo_path,
                recon_context=recon_dict,
                depth=depth,
            )
            hunt = HuntResult.model_validate(_as_dict(_unwrap(hunt_raw, "hunt_phase"), "hunt_phase"))
            hunt.hunt_duration_seconds = time.monotonic() - started - recon.recon_duration_seconds
            orchestrator._write_checkpoint("hunt", hunt)

            prove_raw = await app.call(
                f"{NODE_ID}.prove_phase",
                repo_path=repo_path,
                hunt_result=hunt.model_dump(),
                depth=depth,
                max_provers=max_provers,
            )
            prove_dict = _as_dict(_unwrap(prove_raw, "prove_phase"), "prove_phase")
            verified = [VerifiedFinding.model_validate(v) for v in prove_dict["verified"]]
            orchestrator.findings_not_verified = prove_dict.get("not_verified", 0)
            orchestrator.prove_drop_summary = prove_dict.get(
                "drop_summary",
                {"demoted_total": 0, "by_reason": {}, "findings": []},
            )
            orchestrator._write_checkpoint("prove", verified)

            orchestrator.agent_invocations = prove_dict.get("total_selected", 0) + len(hunt.strategies_run) + 3
            result = await orchestrator._generate_output(recon=recon, hunt=hunt, verified=verified)
            app.note("SEC-AF audit complete", tags=["audit", "complete"])
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
    except Exception as exc:
        import traceback

        tb = traceback.format_exc()
        print(f"AUDIT ERROR: {exc}\n{tb}", flush=True)
        cast("Any", app).note(f"Audit pipeline failed: {exc}", tags=["audit", "error"])
        raise HTTPException(status_code=500, detail={"error": f"audit execution failed: {exc}"}) from exc

    return result.model_dump()


async def health() -> dict[str, str]:
    return {"status": "healthy", "version": "0.1.0"}


cast("Any", app).add_api_route("/health", health, methods=["GET"])


app.include_router(reasoner_router)


def main() -> None:
    """Entry point for the SEC-AF agent."""
    app.run(port=8003, host="0.0.0.0")


if __name__ == "__main__":
    main()
