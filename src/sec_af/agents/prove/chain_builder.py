from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, TypedDict, cast

if TYPE_CHECKING:
    from sec_af.schemas.hunt import PotentialChain
    from sec_af.schemas.prove import VerifiedFinding


class HarnessCapable(Protocol):
    async def harness(
        self,
        prompt: str,
        *,
        schema: object = None,
        cwd: str | None = None,
        **kwargs: object,
    ) -> object: ...


class ChainStepPayload(TypedDict):
    step_number: int
    finding_id: str
    description: str
    enables: str


class VerifiedChainPayload(TypedDict):
    chain_id: str
    title: str
    validated: bool
    rationale: str
    steps: list[ChainStepPayload]


class ChainAnalysisPayload(TypedDict):
    chains: list[VerifiedChainPayload]


PROMPT_PATH = Path(__file__).resolve().parents[4] / "prompts" / "prove" / "chain_builder.txt"


def _build_prompt(
    template: str,
    potential_chains: list[PotentialChain],
    findings: list[VerifiedFinding],
    depth: str,
) -> str:
    findings_by_id: dict[str, dict[str, object]] = {finding.id: finding.model_dump() for finding in findings}
    chains_payload: list[dict[str, object]] = [chain.model_dump() for chain in potential_chains]

    prompt = template.replace("{{DEPTH}}", depth)
    prompt = prompt.replace("{{CHAINS_JSON}}", json.dumps(chains_payload, indent=2))
    prompt = prompt.replace("{{FINDINGS_JSON}}", json.dumps(findings_by_id, indent=2))
    return prompt


def _parse_payload(result: object) -> ChainAnalysisPayload | None:
    payload: dict[str, object]
    parsed = getattr(result, "parsed", None)
    if isinstance(parsed, dict):
        payload = cast("dict[str, object]", parsed)
    elif isinstance(result, dict):
        payload = cast("dict[str, object]", result)
    elif isinstance(parsed, str):
        try:
            payload = cast("dict[str, object]", json.loads(parsed))
        except json.JSONDecodeError:
            return None
    else:
        text = getattr(result, "text", None)
        if isinstance(text, str):
            try:
                payload = cast("dict[str, object]", json.loads(text))
            except json.JSONDecodeError:
                return None
        else:
            return None

    chains = payload.get("chains")
    if not isinstance(chains, list):
        return None
    return cast("ChainAnalysisPayload", cast("object", payload))


def _apply_validated_chain(findings_by_id: dict[str, VerifiedFinding], chain: VerifiedChainPayload) -> None:
    if not chain["validated"] or not chain["steps"]:
        return

    ordered = sorted(chain["steps"], key=lambda step: step["step_number"])
    ordered_ids = [step["finding_id"] for step in ordered]

    for index, step in enumerate(ordered):
        finding = findings_by_id.get(step["finding_id"])
        if finding is None:
            continue
        finding.chain_id = chain["chain_id"]
        finding.chain_step = step["step_number"]
        if index + 1 < len(ordered_ids):
            finding.enables = [ordered_ids[index + 1]]
        finding.tags.add("attack_chain")


async def run_chain_builder(
    app: HarnessCapable,
    repo_path: str,
    potential_chains: list[PotentialChain],
    findings: list[VerifiedFinding],
    depth: str,
) -> list[VerifiedFinding]:
    if not potential_chains or not findings:
        return findings

    prompt_template = PROMPT_PATH.read_text(encoding="utf-8")
    prompt = _build_prompt(prompt_template, potential_chains, findings, depth)

    try:
        result = await app.harness(prompt=prompt, cwd=repo_path)
        payload = _parse_payload(result)
    except Exception:
        payload = None

    if payload is None:
        return findings

    findings_by_id = {finding.id: finding for finding in findings}
    for chain in payload["chains"]:
        _apply_validated_chain(findings_by_id, chain)
    return list(findings_by_id.values())
